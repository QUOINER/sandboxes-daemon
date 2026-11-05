// Package servicesecrets stores service API keys in the host credential vault.
// Values never enter SQLite, logs, argv, or sandbox snapshots.
package servicesecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	keyring "github.com/zalando/go-keyring"
)

const vaultService = "com.rheic.service-secrets.v1"

var (
	ErrInvalid  = errors.New("invalid service secret")
	ErrNotFound = errors.New("service secret not found")
	ErrExists   = errors.New("service secret already exists")
)

// Scope controls where a secret may be used.
type Scope string

const (
	ScopeGlobal  Scope = "global"
	ScopeSandbox Scope = "sandbox"
)

// Services is the supported built-in service set.
var Services = []string{
	"anthropic", "copilot", "cursor", "devin", "droid", "github", "google",
	"groq", "mistral", "nebius", "openai", "openrouter", "xai",
}

// Summary is non-secret metadata.
type Summary struct {
	Service     string
	Scope       Scope
	SandboxName string
}

// Vault stores and retrieves opaque secret values.
type Vault interface {
	Set(ctx context.Context, service, account, secret string) error
	Get(ctx context.Context, service, account string) (string, error)
	Delete(ctx context.Context, service, account string) error
}

// NativeVault uses the OS credential vault and never falls back to plaintext.
type NativeVault struct{ Backend Backend }

// Backend is the narrow keyring subset used by tests.
type Backend interface {
	Set(service, account, secret string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type systemBackend struct{}

func (systemBackend) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}
func (systemBackend) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}
func (systemBackend) Delete(service, account string) error { return keyring.Delete(service, account) }

func (v NativeVault) backend() Backend {
	if v.Backend != nil {
		return v.Backend
	}
	return systemBackend{}
}

func (v NativeVault) Set(ctx context.Context, service, account, secret string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.backend().Set(service, account, secret)
}

func (v NativeVault) Get(ctx context.Context, service, account string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	secret, err := v.backend().Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return secret, err
}

func (v NativeVault) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := v.backend().Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Store persists service secrets in a host vault.
type Store struct{ vault Vault }

// NewStore creates a store.
func NewStore(vault Vault) (*Store, error) {
	if vault == nil {
		return nil, errors.New("host credential vault is required")
	}
	return &Store{vault: vault}, nil
}

// Save validates and stores one service secret.
func (s *Store) Save(ctx context.Context, service string, scope Scope, sandboxName string, value []byte) (Summary, error) {
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return Summary{}, err
	}
	if len(value) == 0 || len(value) > 8192 || !utf8.Valid(value) || strings.ContainsRune(string(value), '\x00') {
		return Summary{}, fmt.Errorf("%w: value must be valid UTF-8 and 1 to 8192 bytes", ErrInvalid)
	}
	if err := s.vault.Set(ctx, vaultService, account(summary), string(value)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Summary{}, err
		}
		return Summary{}, errors.New("store service secret in host keychain")
	}
	return summary, nil
}

// Load returns a secret value. Callers must keep it in memory and clear it.
func (s *Store) Load(ctx context.Context, service string, scope Scope, sandboxName string) ([]byte, error) {
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return nil, err
	}
	value, err := s.vault.Get(ctx, vaultService, account(summary))
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// Delete removes one secret.
func (s *Store) Delete(ctx context.Context, service string, scope Scope, sandboxName string) (bool, error) {
	summary, err := validate(service, scope, sandboxName)
	if err != nil {
		return false, err
	}
	err = s.vault.Delete(ctx, vaultService, account(summary))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func validate(service string, scope Scope, sandboxName string) (Summary, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	if !validService(service) {
		return Summary{}, fmt.Errorf("%w: unsupported service %q", ErrInvalid, service)
	}
	if scope == "" {
		scope = ScopeGlobal
	}
	sandboxName = strings.TrimSpace(sandboxName)
	switch scope {
	case ScopeGlobal:
		if sandboxName != "" {
			return Summary{}, fmt.Errorf("%w: sandbox name requires sandbox scope", ErrInvalid)
		}
	case ScopeSandbox:
		if sandboxName == "" || len(sandboxName) > 63 || strings.ContainsAny(sandboxName, "/\\\x00\r\n") {
			return Summary{}, fmt.Errorf("%w: sandbox scope requires a valid sandbox name", ErrInvalid)
		}
	default:
		return Summary{}, fmt.Errorf("%w: scope must be global or sandbox", ErrInvalid)
	}
	return Summary{Service: service, Scope: scope, SandboxName: sandboxName}, nil
}

func validService(service string) bool {
	for _, candidate := range Services {
		if service == candidate {
			return true
		}
	}
	return false
}

func account(summary Summary) string {
	if summary.Scope == ScopeSandbox {
		return summary.Service + "/sandbox/" + summary.SandboxName
	}
	return summary.Service + "/global"
}
