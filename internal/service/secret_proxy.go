package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/sandbox"
	runtime "github.com/KLORQ/sandboxes-runtime"

	"github.com/KLORQ/sandboxes-daemon/internal/secretproxy"
	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
)

const (
	proxySocketPort      = uint32(1027)
	proxyGuestListenPort = uint16(3128)
	proxySettingPrefix   = "sandbox.proxy-service."
	proxyGuestHelperPath = "/tmp/klorq-proxy-helper"
)

type proxyRuntimeConfig struct {
	port        uint32
	socketPath  string
	helperPath  string
	guestPort   uint16
	serviceHost string
}

type proxyRuntime interface {
	CreateWithProxy(context.Context, *runtime.Config, string, uint16, string) (runtime.Handle, error)
}

type proxyEnvContract struct {
	serviceName   string
	credentialEnv string
	baseURLEnv    string
	baseURL       string
	upstreamHost  string
}

func proxyContract(name string) (proxyEnvContract, bool) {
	service, ok := secretproxy.Lookup(name)
	if !ok {
		return proxyEnvContract{}, false
	}
	upstream, err := url.Parse(service.Upstream)
	if err != nil || upstream.Scheme != "https" || upstream.Hostname() == "" || upstream.Port() != "" {
		return proxyEnvContract{}, false
	}
	contract := proxyEnvContract{serviceName: strings.ToLower(name), upstreamHost: upstream.Host}
	switch contract.serviceName {
	case "openai":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "OPENAI_API_KEY", "OPENAI_BASE_URL", "http://127.0.0.1:3128/v1"
	case "anthropic":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "http://127.0.0.1:3128"
	case "groq":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "GROQ_API_KEY", "GROQ_BASE_URL", "http://127.0.0.1:3128/openai/v1"
	case "mistral":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "MISTRAL_API_KEY", "MISTRAL_BASE_URL", "http://127.0.0.1:3128"
	case "openrouter":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "http://127.0.0.1:3128/api/v1"
	case "xai":
		contract.credentialEnv, contract.baseURLEnv, contract.baseURL = "XAI_API_KEY", "XAI_BASE_URL", "http://127.0.0.1:3128/v1"
	default:
		return proxyEnvContract{}, false
	}
	return contract, true
}

// stripProxyCreateEnv removes credential references from the container's
// persistent environment while returning the single service needed to prepare
// the per-VM channel before the guest init process starts.
func stripProxyCreateEnv(env []string) ([]string, string, error) {
	filtered := make([]string, 0, len(env))
	serviceName := ""
	keys := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, "", fmt.Errorf("%w: invalid environment entry", core.ErrConflict)
		}
		keys[key] = value
		if !strings.Contains(value, "${proxy:") {
			filtered = append(filtered, entry)
			continue
		}
		if !strings.HasPrefix(value, "${proxy:") || !strings.HasSuffix(value, "}") || strings.Count(value, "${proxy:") != 1 {
			return nil, "", fmt.Errorf("%w: invalid proxy reference for %s", core.ErrConflict, key)
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(value, "${proxy:"), "}"))
		contract, ok := proxyContract(name)
		if !ok || key != contract.credentialEnv {
			return nil, "", fmt.Errorf("%w: proxy reference is not supported for %s", core.ErrConflict, key)
		}
		if serviceName != "" && serviceName != name {
			return nil, "", fmt.Errorf("%w: one proxy service may be configured per sandbox", core.ErrConflict)
		}
		serviceName = name
	}
	if serviceName != "" {
		contract, _ := proxyContract(serviceName)
		if _, exists := keys[contract.baseURLEnv]; exists {
			return nil, "", fmt.Errorf("%w: %s is managed by the service proxy", core.ErrConflict, contract.baseURLEnv)
		}
	}
	return filtered, serviceName, nil
}

func proxyServiceSettingKey(id string) string { return proxySettingPrefix + id }

func (s *Service) proxyChannelConfig(ctx context.Context, sb sandbox.Sandbox, serviceName string) (proxyRuntimeConfig, error) {
	contract, ok := proxyContract(serviceName)
	if !ok || s.secretProxies == nil || s.serviceSecrets == nil {
		return proxyRuntimeConfig{}, fmt.Errorf("%w: service proxy is unavailable", core.ErrConflict)
	}
	if err := validateProxyHelperBinary(s.proxyHelperPath); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("%w: guest service proxy helper is unavailable", core.ErrConflict)
	}
	dir := proxySocketDirectory(s.proxyTempDir, sb.ID)
	if err := secretproxy.EnsurePrivateDir(dir); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("prepare proxy socket directory: %w", err)
	}
	if !s.secretProxies.Has(sb.Name, serviceName) {
		if err := secretproxy.RemoveStaleSocket(filepath.Join(dir, "p.sock")); err != nil {
			return proxyRuntimeConfig{}, fmt.Errorf("recover proxy socket: %w", err)
		}
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = secretproxy.RemovePrivateDir(dir)
		}
	}()
	secret, scope, err := s.loadServiceProxySecret(ctx, serviceName, sb.Name)
	if err != nil {
		return proxyRuntimeConfig{}, err
	}
	defer clear(secret)
	var randomToken [32]byte
	if _, err := rand.Read(randomToken[:]); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("generate per-sandbox proxy token: %w", err)
	}
	token := hex.EncodeToString(randomToken[:])
	clear(randomToken[:])
	socketPath := filepath.Join(dir, "p.sock")
	brokerService := contractService(serviceName)
	brokerService.CredentialScope = string(scope)
	brokerService.Authorize = func(ctx context.Context) error {
		decision, err := s.CheckPolicy(ctx, sb.ID, tcpProtocol, "", contract.upstreamHost, 443)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return errors.New("sandbox policy denied service proxy request")
		}
		return nil
	}
	if _, err := s.secretProxies.StartUnix(ctx, sb.Name, serviceName, brokerService, secret, socketPath, token); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("start host service proxy: %w", err)
	}
	prepared = true
	return proxyRuntimeConfig{
		port: proxySocketPort, socketPath: socketPath,
		helperPath: s.proxyHelperPath, guestPort: proxyGuestListenPort, serviceHost: contract.upstreamHost,
	}, nil
}

func (s *Service) prepareStoredProxy(ctx context.Context, sb sandbox.Sandbox) error {
	serviceName, err := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load sandbox proxy configuration: %w", err)
	}
	_, err = s.proxyChannelConfig(ctx, sb, serviceName)
	return err
}

func (s *Service) hasStoredProxy(ctx context.Context, sb sandbox.Sandbox) (bool, error) {
	_, err := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) stopProxyChannel(sandboxName, sandboxID string, removeDirectory bool) error {
	var failures []error
	if s.secretProxies != nil {
		if err := s.secretProxies.StopSandbox(sandboxName); err != nil {
			failures = append(failures, fmt.Errorf("stop secret proxy: %w", err))
		}
	}
	if removeDirectory {
		if err := secretproxy.RemovePrivateDir(proxySocketDirectory(s.proxyTempDir, sandboxID)); err != nil {
			failures = append(failures, fmt.Errorf("remove proxy socket directory: %w", err))
		}
	}
	return errors.Join(failures...)
}

func contractService(name string) secretproxy.Service {
	service, _ := secretproxy.Lookup(name)
	return service
}

func (s *Service) loadServiceProxySecret(ctx context.Context, name, sandboxName string) ([]byte, servicesecrets.Scope, error) {
	secret, err := s.serviceSecrets.Load(ctx, name, servicesecrets.ScopeSandbox, sandboxName)
	scope := servicesecrets.ScopeSandbox
	if errors.Is(err, servicesecrets.ErrNotFound) {
		secret, err = s.serviceSecrets.Load(ctx, name, servicesecrets.ScopeGlobal, "")
		scope = servicesecrets.ScopeGlobal
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: service secret %q is unavailable", core.ErrConflict, name)
	}
	return secret, scope, nil
}

func proxySocketDirectory(root, sandboxID string) string {
	if root == "" {
		root = "/tmp"
	}
	hash := sha256.Sum256([]byte(sandboxID))
	return filepath.Join(root, "kp-"+hex.EncodeToString(hash[:8]))
}

func validateProxyHelperBinary(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("proxy helper path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("proxy helper must be a regular executable file")
	}
	image, err := elf.Open(path)
	if err != nil {
		return errors.New("proxy helper must be a Linux ELF binary")
	}
	defer func() { _ = image.Close() }()
	if image.Machine != elf.EM_AARCH64 || image.Type != elf.ET_EXEC {
		return errors.New("proxy helper must be a static Linux ARM64 executable")
	}
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("proxy helper must not require a dynamic linker")
		}
	}
	return nil
}
