package servicesecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultSourceRefresh = 55 * time.Minute
	resolverTimeout      = 30 * time.Second
	maxResolvedSecret    = 8192
	maxResolverStderr    = 4096
	maxCachedSources     = 256
	maxResolverLocks     = 4096
	secretSourcePrefix   = "\x00rheic-secret-source:v1:"
)

var awsSecretARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$`)

// Source is a supported host-side dynamic credential source.
type Source struct {
	Reference  string
	Command    string
	Refresh    string
	NoVerify   bool
	ShowError  bool
	OPAccount  string
	AWSProfile string
}

type sourceEnvelope struct {
	Reference  string `json:"reference"`
	Command    string `json:"command,omitempty"`
	Refresh    string `json:"refresh"`
	OPAccount  string `json:"op_account,omitempty"`
	AWSProfile string `json:"aws_profile,omitempty"`
}

type sourceCacheEntry struct {
	value     []byte
	expiresAt time.Time
}

type sourceResolver struct {
	mu           sync.Mutex
	locks        map[string]*sync.Mutex
	entries      map[string]sourceCacheEntry
	overflowLock sync.Mutex
}

func newSourceResolver() *sourceResolver {
	return &sourceResolver{locks: make(map[string]*sync.Mutex), entries: make(map[string]sourceCacheEntry)}
}

func validateSource(source Source) (Source, error) {
	source.Reference = strings.TrimSpace(source.Reference)
	source.OPAccount = strings.TrimSpace(source.OPAccount)
	source.AWSProfile = strings.TrimSpace(source.AWSProfile)
	if err := validateSourceForm(&source); err != nil {
		return Source{}, err
	}
	if err := validateSourceProfile(source); err != nil {
		return Source{}, err
	}
	refresh, err := normalizeRefresh(source.Refresh)
	if err != nil {
		return Source{}, err
	}
	source.Refresh = refresh
	if source.NoVerify && source.ShowError {
		return Source{}, fmt.Errorf("%w: --show-error cannot be combined with --no-verify", ErrInvalid)
	}
	return source, nil
}

func validateSourceForm(source *Source) error {
	referenceProvided := source.Reference != ""
	commandProvided := strings.TrimSpace(source.Command) != ""
	if referenceProvided == commandProvided {
		return fmt.Errorf("%w: provide exactly one secret reference or command", ErrInvalid)
	}
	if !commandProvided {
		source.Command = ""
	}
	if source.Reference != "" {
		if len(source.Reference) > 4096 || strings.ContainsAny(source.Reference, "\x00\r\n") {
			return fmt.Errorf("%w: invalid secret reference", ErrInvalid)
		}
		return validateReference(source.Reference)
	}
	if len(source.Command) > 8192 || strings.ContainsRune(source.Command, '\x00') {
		return fmt.Errorf("%w: command must be at most 8192 bytes and contain no NUL", ErrInvalid)
	}
	return nil
}

func validateSourceProfile(source Source) error {
	if len(source.OPAccount) > 256 || strings.ContainsAny(source.OPAccount, "\x00\r\n") ||
		len(source.AWSProfile) > 256 || strings.ContainsAny(source.AWSProfile, "\x00\r\n") {
		return fmt.Errorf("%w: invalid provider account or profile", ErrInvalid)
	}
	if source.OPAccount != "" && !strings.HasPrefix(source.Reference, "op://") ||
		source.AWSProfile != "" && !strings.HasPrefix(source.Reference, "arn:") {
		return fmt.Errorf("%w: provider account/profile does not match secret source", ErrInvalid)
	}
	return nil
}

func validateReference(reference string) error {
	switch {
	case strings.HasPrefix(reference, "op://"):
		parsed, err := url.Parse(reference)
		if err != nil || parsed.Scheme != "op" || parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%w: invalid 1Password reference", ErrInvalid)
		}
	case awsSecretARN.MatchString(reference):
		return nil
	default:
		return fmt.Errorf("%w: reference must be a 1Password op:// URL or AWS Secrets Manager ARN", ErrInvalid)
	}
	return nil
}

func normalizeRefresh(refresh string) (string, error) {
	if refresh == "" {
		return defaultSourceRefresh.String(), nil
	}
	if refresh == "on-demand" {
		return refresh, nil
	}
	duration, err := time.ParseDuration(refresh)
	if err != nil || duration <= 0 {
		return "", fmt.Errorf("%w: refresh must be on-demand or a positive duration", ErrInvalid)
	}
	return duration.String(), nil
}

func encodeSource(source Source) ([]byte, error) {
	source, err := validateSource(source)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sourceEnvelope{
		Reference: source.Reference, Command: source.Command, Refresh: source.Refresh,
		OPAccount: source.OPAccount, AWSProfile: source.AWSProfile,
	})
	if err != nil {
		return nil, fmt.Errorf("encode secret source: %w", err)
	}
	return append([]byte(secretSourcePrefix), encoded...), nil
}

func decodeSource(value []byte) (Source, bool, error) {
	if !bytes.HasPrefix(value, []byte(secretSourcePrefix)) {
		return Source{}, false, nil
	}
	var envelope sourceEnvelope
	if err := json.Unmarshal(value[len(secretSourcePrefix):], &envelope); err != nil {
		return Source{}, true, fmt.Errorf("decode secret source: %w", ErrInvalid)
	}
	source, err := validateSource(Source{
		Reference: envelope.Reference, Command: envelope.Command, Refresh: envelope.Refresh,
		OPAccount: envelope.OPAccount, AWSProfile: envelope.AWSProfile,
	})
	if err != nil {
		return Source{}, true, err
	}
	return source, true, nil
}

func (s *Store) SaveSource(ctx context.Context, service string, scope Scope, sandboxName string, source Source) (Summary, error) {
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return Summary{}, err
	}
	source, err = validateSource(source)
	if err != nil {
		return Summary{}, err
	}
	if !source.NoVerify {
		resolved, err := resolveSource(ctx, source)
		clear(resolved)
		if err != nil {
			return Summary{}, err
		}
	}
	encoded, err := encodeSource(source)
	if err != nil {
		return Summary{}, err
	}
	defer clear(encoded)
	if err := s.vault.Set(ctx, vaultService, account(summary), string(encoded)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Summary{}, err
		}
		return Summary{}, errors.New("store service secret source in host keychain")
	}
	s.resolver().invalidate(account(summary))
	return summary, nil
}

// Resolve loads a secret value or resolves its saved host-side source. Callers
// must keep the returned value in memory only and clear it after use.
func (s *Store) Resolve(ctx context.Context, service string, scope Scope, sandboxName string) ([]byte, error) {
	value, err := s.Load(ctx, service, scope, sandboxName)
	if err != nil {
		return nil, err
	}
	source, dynamic, err := decodeSource(value)
	if err != nil {
		clear(value)
		return nil, err
	}
	if !dynamic {
		return value, nil
	}
	clear(value)
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return nil, err
	}
	return s.resolver().resolve(ctx, account(summary), source)
}

// IsDynamic reports whether the stored item is a resolver configuration.
func (s *Store) IsDynamic(ctx context.Context, service string, scope Scope, sandboxName string) (bool, error) {
	value, err := s.Load(ctx, service, scope, sandboxName)
	if err != nil {
		return false, err
	}
	_, dynamic, decodeErr := decodeSource(value)
	clear(value)
	return dynamic, decodeErr
}

func (s *Store) resolver() *sourceResolver {
	if s.sourceResolver == nil {
		s.sourceResolver = newSourceResolver()
	}
	return s.sourceResolver
}

func (r *sourceResolver) resolve(ctx context.Context, key string, source Source) ([]byte, error) {
	source, err := validateSource(source)
	if err != nil {
		return nil, err
	}
	if source.Refresh == "on-demand" {
		value, err := resolveSource(ctx, source)
		return value, err
	}
	duration, _ := time.ParseDuration(source.Refresh)
	lock := r.keyLock(key)
	lock.Lock()
	defer lock.Unlock()
	r.mu.Lock()
	if entry, ok := r.entries[key]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.Unlock()
		return append([]byte(nil), entry.value...), nil
	}
	r.mu.Unlock()
	value, err := resolveSource(ctx, source)
	if err != nil {
		return nil, err
	}
	r.cache(key, value, time.Now().Add(duration))
	return value, nil
}

func (r *sourceResolver) keyLock(key string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock := r.locks[key]
	if lock == nil {
		if len(r.locks) >= maxResolverLocks {
			return &r.overflowLock
		}
		lock = &sync.Mutex{}
		r.locks[key] = lock
	}
	return lock
}

func (r *sourceResolver) cache(key string, value []byte, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[key]; !exists && len(r.entries) >= maxCachedSources {
		oldestKey := ""
		var oldest time.Time
		for candidate, entry := range r.entries {
			if !time.Now().Before(entry.expiresAt) {
				oldestKey = candidate
				break
			}
			if oldestKey == "" || entry.expiresAt.Before(oldest) {
				oldestKey, oldest = candidate, entry.expiresAt
			}
		}
		if entry, ok := r.entries[oldestKey]; ok {
			clear(entry.value)
			delete(r.entries, oldestKey)
		}
	}
	if prior, ok := r.entries[key]; ok {
		clear(prior.value)
	}
	r.entries[key] = sourceCacheEntry{value: append([]byte(nil), value...), expiresAt: expiresAt}
}

func (r *sourceResolver) invalidate(key string) {
	lock := r.keyLock(key)
	lock.Lock()
	defer lock.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[key]; ok {
		clear(entry.value)
		delete(r.entries, key)
	}
}

func resolveSource(ctx context.Context, source Source) (resolved []byte, retErr error) {
	if _, err := validateSource(source); err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, resolverTimeout)
	defer cancel()
	tmp, err := os.MkdirTemp("", "rheic-secret-ref-")
	if err != nil {
		return nil, errors.New("prepare isolated secret resolver directory")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(tmp); cleanupErr != nil {
			clear(resolved)
			resolved = nil
			retErr = errors.New("clean up secret resolver directory")
		}
	}()
	if !filepath.IsAbs(tmp) {
		return nil, errors.New("secret resolver temporary directory must be absolute")
	}
	command := resolverCommand(commandCtx, source)
	command.Dir = tmp
	command.Env = resolverEnvironment(source)
	stdout, stderr, runErr := boundedCommandOutput(commandCtx, command)
	if runErr != nil {
		return nil, sourceResolutionError(source, stdout, stderr, runErr)
	}
	clear(stderr)
	value := bytes.TrimSpace(stdout)
	if len(value) == 0 || len(value) > maxResolvedSecret || bytes.Equal(value, []byte("None")) || !utf8.Valid(value) || bytes.Contains(value, []byte{0}) || bytes.ContainsAny(value, "\r\n") {
		clear(stdout)
		return nil, fmt.Errorf("%w: resolver output must be one non-empty UTF-8 value of at most %d bytes", ErrInvalid, maxResolvedSecret)
	}
	resolved = append([]byte(nil), value...)
	clear(stdout)
	return resolved, nil
}

func sourceResolutionError(source Source, stdout, stderr []byte, runErr error) error {
	var providerError string
	if source.ShowError && len(stderr) != 0 {
		providerError = strings.TrimSpace(string(stderr))
	}
	clear(stdout)
	clear(stderr)
	if providerError != "" {
		return fmt.Errorf("resolve secret reference: %s", providerError)
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return runErr
	}
	return errors.New("resolve secret reference with the configured host provider")
}

func resolverCommand(ctx context.Context, source Source) *exec.Cmd {
	if source.Command != "" {
		return hostShellCommand(ctx, source.Command)
	}
	if strings.HasPrefix(source.Reference, "op://") {
		//nolint:gosec // Fixed executable; validated op:// reference is one argv token and no shell is involved.
		command := exec.CommandContext(ctx, "op", "read", source.Reference)
		return command
	}
	//nolint:gosec // Fixed executable; validated AWS ARN is one argv token and no shell is involved.
	command := exec.CommandContext(ctx, "aws", "secretsmanager", "get-secret-value", "--secret-id", source.Reference, "--query", "SecretString", "--output", "text")
	return command
}

func resolverEnvironment(source Source) []string {
	allowed := []string{
		"PATH", "HOME", "XDG_CONFIG_HOME", "OP_CONFIG_DIR",
		"AWS_REGION", "AWS_DEFAULT_REGION",
		"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CA_BUNDLE",
	}
	if runtime.GOOS == "windows" {
		allowed = append(allowed,
			"USERPROFILE", "APPDATA", "LOCALAPPDATA",
			"SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
		)
	}
	env := make([]string, 0, len(allowed))
	for _, key := range allowed {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	if source.OPAccount != "" {
		env = append(env, "OP_ACCOUNT="+source.OPAccount)
	}
	if source.AWSProfile != "" {
		env = append(env, "AWS_PROFILE="+source.AWSProfile)
	}
	return env
}

type commandOutput struct {
	data []byte
	err  error
}

func boundedCommandOutput(ctx context.Context, command *exec.Cmd) (stdout, stderr []byte, retErr error) {
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, errors.New("open secret resolver output")
	}
	stderrPipe, err := command.StderrPipe()
	if err != nil {
		return nil, nil, errors.New("open secret resolver error output")
	}
	terminate, cleanup, err := startResolverProcess(command)
	if err != nil {
		return nil, nil, errors.New("start secret resolver")
	}
	defer func() {
		cleanupErr := errors.Join(terminate(), cleanup())
		if cleanupErr != nil {
			clear(stdout)
			clear(stderr)
			stdout, stderr = nil, nil
			retErr = errors.Join(retErr, errors.New("clean up secret resolver process"))
		}
	}()
	stdoutCh := make(chan commandOutput, 1)
	stderrCh := make(chan commandOutput, 1)
	go readCommandOutput(stdoutPipe, maxResolvedSecret, terminate, stdoutCh)
	go readCommandOutput(stderrPipe, maxResolverStderr, terminate, stderrCh)
	stopWatch := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = terminate()
			_ = stdoutPipe.Close()
			_ = stderrPipe.Close()
		case <-stopWatch:
		}
	}()
	waitErr := command.Wait()
	stdoutResult := <-stdoutCh
	stderrResult := <-stderrCh
	close(stopWatch)
	<-watcherDone
	stdout, stderr = stdoutResult.data, stderrResult.data
	if ctx.Err() != nil {
		clear(stdout)
		clear(stderr)
		return nil, nil, ctx.Err()
	}
	if stdoutResult.err != nil || stderrResult.err != nil {
		clear(stdout)
		clear(stderr)
		return nil, nil, errors.New("secret resolver output exceeded its limit")
	}
	if waitErr != nil {
		return stdout, stderr, waitErr
	}
	return stdout, stderr, nil
}

func readCommandOutput(reader io.Reader, limit int, terminate func() error, output chan<- commandOutput) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit+1)))
	if err == nil && len(data) > limit {
		err = errors.Join(errors.New("output limit exceeded"), terminate())
	}
	output <- commandOutput{data: data, err: err}
}
