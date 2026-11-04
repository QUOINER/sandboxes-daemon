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
	"sort"
	"strings"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

const (
	proxySocketPort      = uint32(1027)
	proxySettingPrefix   = "sandbox.proxy-service."
	proxyGuestHelperPath = "/tmp/rheic-proxy-helper"
	proxyMaxRoutes       = 32
)

type proxyRuntimeConfig struct {
	port       uint32
	socketPath string
	helperPath string
	routes     []string
}

type proxyRuntime interface {
	CreateWithProxy(context.Context, *runtime.Config, string, uint16, string) (runtime.Handle, error)
}

type proxyRoutesRuntime interface {
	CreateWithProxyRouteArgs(context.Context, *runtime.Config, string, []string) (runtime.Handle, error)
}

type proxyEnvContract struct {
	serviceName   string
	credentialEnv string
	baseURLEnv    string
	baseURL       string
	upstreamHost  string
	guestPort     uint16
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
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "OPENAI_API_KEY", "OPENAI_BASE_URL", 3128
	case "anthropic":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", 43129
	case "groq":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "GROQ_API_KEY", "GROQ_BASE_URL", 43130
	case "mistral":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "MISTRAL_API_KEY", "MISTRAL_BASE_URL", 43131
	case "openrouter":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", 43132
	case "xai":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "XAI_API_KEY", "XAI_BASE_URL", 43133
	default:
		return proxyEnvContract{}, false
	}
	contract.baseURL = proxyBaseURL(contract.serviceName, contract.guestPort)
	return contract, true
}

func proxyBaseURL(service string, port uint16) string {
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	switch service {
	case "openai", "mistral", "xai":
		return base + "/v1"
	case "groq":
		return base + "/openai/v1"
	case "openrouter":
		return base + "/api/v1"
	default:
		return base
	}
}

// stripProxyCreateEnv removes credential references from the container's
// persistent environment and returns all required fixed proxy services.
func stripProxyCreateEnv(env []string) ([]string, []string, error) {
	filtered := make([]string, 0, len(env))
	serviceNames := make(map[string]struct{})
	keys := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, nil, fmt.Errorf("%w: invalid environment entry", core.ErrConflict)
		}
		keys[key] = value
		if !strings.Contains(value, "${proxy:") {
			filtered = append(filtered, entry)
			continue
		}
		if !strings.HasPrefix(value, "${proxy:") || !strings.HasSuffix(value, "}") || strings.Count(value, "${proxy:") != 1 {
			return nil, nil, fmt.Errorf("%w: invalid proxy reference for %s", core.ErrConflict, key)
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(value, "${proxy:"), "}"))
		contract, ok := proxyContract(name)
		if !ok || key != contract.credentialEnv {
			return nil, nil, fmt.Errorf("%w: proxy reference is not supported for %s", core.ErrConflict, key)
		}
		serviceNames[name] = struct{}{}
		if len(serviceNames) > proxyMaxRoutes {
			return nil, nil, fmt.Errorf("%w: too many proxy services configured", core.ErrConflict)
		}
	}
	names := make([]string, 0, len(serviceNames))
	for name := range serviceNames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, serviceName := range names {
		contract, _ := proxyContract(serviceName)
		if _, exists := keys[contract.baseURLEnv]; exists {
			return nil, nil, fmt.Errorf("%w: %s is managed by the service proxy", core.ErrConflict, contract.baseURLEnv)
		}
	}
	return filtered, names, nil
}

func proxyServiceSettingKey(id string) string { return proxySettingPrefix + id }

func (s *Service) proxyChannelConfig(ctx context.Context, sb sandbox.Sandbox, serviceNames []string) (proxyRuntimeConfig, error) {
	if !validProxyServiceNames(serviceNames) || s.secretProxies == nil || s.serviceSecrets == nil {
		return proxyRuntimeConfig{}, fmt.Errorf("%w: service proxy is unavailable", core.ErrConflict)
	}
	if err := validateProxyHelperBinary(s.proxyHelperPath); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("%w: guest service proxy helper is unavailable", core.ErrConflict)
	}
	dir := proxySocketDirectory(s.proxyTempDir, sb.ID)
	socketPath := filepath.Join(dir, "p.sock")
	if err := secretproxy.EnsurePrivateDir(dir); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("prepare proxy socket directory: %w", err)
	}
	if !s.proxyRoutesActive(sb.Name, serviceNames) {
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
	routes, runtimeRoutes, err := s.buildProxyRoutes(ctx, sb, serviceNames)
	if err != nil {
		return proxyRuntimeConfig{}, err
	}
	if _, err := s.secretProxies.StartUnixRoutes(ctx, sb.Name, routes, socketPath); err != nil {
		clearRouteSecrets(routes)
		return proxyRuntimeConfig{}, fmt.Errorf("start host service proxy: %w", err)
	}
	clearRouteSecrets(routes)
	prepared = true
	return proxyRuntimeConfig{port: proxySocketPort, socketPath: socketPath, helperPath: s.proxyHelperPath, routes: runtimeRoutes}, nil
}

func validProxyServiceNames(names []string) bool {
	if len(names) == 0 || len(names) > proxyMaxRoutes {
		return false
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !proxyRouteConfigured(name) {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func (s *Service) proxyRoutesActive(sandboxName string, names []string) bool {
	for _, name := range names {
		if s.secretProxies.Has(sandboxName, name) {
			return true
		}
	}
	return false
}

func (s *Service) buildProxyRoutes(ctx context.Context, sb sandbox.Sandbox, serviceNames []string) (map[string]secretproxy.RouteConfig, []string, error) {
	routes := make(map[string]secretproxy.RouteConfig, len(serviceNames))
	runtimeRoutes := make([]string, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		route, runtimeRoute, err := s.buildProxyRoute(ctx, sb, serviceName)
		if err != nil {
			clearRouteSecrets(routes)
			return nil, nil, err
		}
		routes[serviceName] = route
		runtimeRoutes = append(runtimeRoutes, runtimeRoute)
	}
	return routes, runtimeRoutes, nil
}

func (s *Service) buildProxyRoute(ctx context.Context, sb sandbox.Sandbox, name string) (secretproxy.RouteConfig, string, error) {
	contract, ok := proxyContract(name)
	if !ok {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: unsupported service proxy route", core.ErrConflict)
	}
	secret, scope, err := s.loadServiceProxySecret(ctx, name, sb.Name)
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	var randomToken [32]byte
	if _, err := rand.Read(randomToken[:]); err != nil {
		clear(secret)
		clear(randomToken[:])
		return secretproxy.RouteConfig{}, "", fmt.Errorf("generate per-sandbox proxy token: %w", err)
	}
	token := hex.EncodeToString(randomToken[:])
	clear(randomToken[:])
	service := contractService(name)
	service.CredentialScope = string(scope)
	service.Authorize = s.proxyPolicyAuthorizer(sb.ID, contract.upstreamHost)
	return secretproxy.RouteConfig{Service: service, Secret: secret, Token: token},
		fmt.Sprintf("%s=%s:%d", name, contract.upstreamHost, contract.guestPort), nil
}

func (s *Service) proxyPolicyAuthorizer(sandboxID, host string) func(context.Context) error {
	return func(ctx context.Context) error {
		decision, err := s.CheckPolicy(ctx, sandboxID, tcpProtocol, "", host, 443)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return errors.New("sandbox policy denied service proxy request")
		}
		return nil
	}
}

func decodeProxyServices(value string) []string {
	if value == "" {
		return nil
	}
	services := strings.Split(value, ",")
	for i := range services {
		services[i] = strings.TrimSpace(services[i])
	}
	sort.Strings(services)
	return services
}

func encodeProxyServices(services []string) string {
	ordered := append([]string(nil), services...)
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func proxyRouteConfigured(service string) bool {
	_, ok := proxyContract(service)
	return ok
}

func clearRouteSecrets(routes map[string]secretproxy.RouteConfig) {
	for _, route := range routes {
		clear(route.Secret)
	}
}

func (s *Service) prepareStoredProxy(ctx context.Context, sb sandbox.Sandbox) error {
	serviceSetting, err := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load sandbox proxy configuration: %w", err)
	}
	_, err = s.proxyChannelConfig(ctx, sb, decodeProxyServices(serviceSetting))
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
