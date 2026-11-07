package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
)

const (
	proxySocketPort         = uint32(1027)
	proxySettingPrefix      = "sandbox.proxy-service."
	proxyGuestHelperPath    = "/tmp/rheic-proxy-helper"
	proxyMaxRoutes          = 32
	openAIServiceName       = "openai"
	openAIOAuthRoute        = openAIServiceName + "-oauth"
	githubCredentialService = "github"
	cursorCredentialService = "cursor"
	droidCredentialService  = "droid"
)

type proxyRuntimeConfig struct {
	port        uint32
	socketPath  string
	helperPath  string
	routes      []string
	guestPort   uint16
	serviceHost string
}

type proxyRuntime interface {
	CreateWithProxy(context.Context, *runtime.Config, string, uint16, string) (runtime.Handle, error)
}

type proxyRoutesRuntime interface {
	CreateWithProxyRouteArgs(context.Context, *runtime.Config, string, []string) (runtime.Handle, error)
}

type proxyEnvContract struct {
	serviceName       string
	credentialService string
	credentialEnv     string
	baseURLEnv        string
	baseURL           string
	upstreamHost      string
	guestPort         uint16
}

func proxyContract(name string) (proxyEnvContract, bool) {
	lookupName := name
	if isOAuthProxyRoute(name) {
		lookupName = openAIServiceName
	}
	service, ok := secretproxy.Lookup(lookupName)
	if !ok {
		return proxyEnvContract{}, false
	}
	upstream, err := url.Parse(service.Upstream)
	if err != nil || upstream.Scheme != "https" || upstream.Hostname() == "" || upstream.Port() != "" {
		return proxyEnvContract{}, false
	}
	contract := proxyEnvContract{serviceName: strings.ToLower(name), credentialService: strings.ToLower(name), upstreamHost: upstream.Host}
	if configureAgentCredentialContract(&contract) {
		contract.baseURL = proxyBaseURL(contract.serviceName, contract.guestPort)
		return contract, true
	}
	if !configureProviderContract(&contract) {
		return proxyEnvContract{}, false
	}
	contract.baseURL = proxyBaseURL(contract.serviceName, contract.guestPort)
	return contract, true
}

func configureAgentCredentialContract(contract *proxyEnvContract) bool {
	switch contract.serviceName {
	case openAIServiceName, openAIOAuthRoute:
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "OPENAI_API_KEY", "OPENAI_BASE_URL", 3128
		return true
	case githubCredentialService, "github-web", "github-raw", "github-gist", "github-copilot", "github-copilot-api":
		contract.credentialService = githubCredentialService
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = proxyCredentialRouteEnv(contract.serviceName)
		return true
	case cursorCredentialService, "cursor-api3", "cursor-repo42", "cursor-web":
		contract.credentialService = cursorCredentialService
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = proxyCredentialRouteEnv(contract.serviceName)
		return true
	case droidCredentialService, "droid-app", "droid-relay":
		contract.credentialService = droidCredentialService
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = proxyCredentialRouteEnv(contract.serviceName)
		return true
	default:
		return false
	}
}

func configureProviderContract(contract *proxyEnvContract) bool {
	switch contract.serviceName {
	case "anthropic":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", 43129
	case "google":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL", 43134
	case "groq":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "GROQ_API_KEY", "GROQ_BASE_URL", 43130
	case "mistral":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "MISTRAL_API_KEY", "MISTRAL_BASE_URL", 43131
	case "openrouter":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", 43132
	case "xai":
		contract.credentialEnv, contract.baseURLEnv, contract.guestPort = "XAI_API_KEY", "XAI_BASE_URL", 43133
	default:
		return false
	}
	return true
}

func proxyCredentialRouteEnv(name string) (credentialEnv, baseURLEnv string, guestPort uint16) {
	switch name {
	case githubCredentialService:
		return "GH_TOKEN", "RHEIC_GITHUB_API_BASE_URL", 43135
	case "github-web":
		return "RHEIC_PROXY_GITHUB_WEB", "RHEIC_PROXY_GITHUB_WEB_BASE_URL", 43136
	case "github-raw":
		return "RHEIC_PROXY_GITHUB_RAW", "RHEIC_PROXY_GITHUB_RAW_BASE_URL", 43137
	case "github-gist":
		return "RHEIC_PROXY_GITHUB_GIST", "RHEIC_PROXY_GITHUB_GIST_BASE_URL", 43138
	case "github-copilot":
		return "RHEIC_PROXY_GITHUB_COPILOT", "RHEIC_PROXY_GITHUB_COPILOT_BASE_URL", 43139
	case "github-copilot-api":
		return "RHEIC_PROXY_GITHUB_COPILOT_API", "RHEIC_PROXY_GITHUB_COPILOT_API_BASE_URL", 43140
	case cursorCredentialService:
		return "CURSOR_API_KEY", "RHEIC_CURSOR_API_BASE_URL", 43141
	case "cursor-api3":
		return "RHEIC_PROXY_CURSOR_API3", "RHEIC_PROXY_CURSOR_API3_BASE_URL", 43142
	case "cursor-repo42":
		return "RHEIC_PROXY_CURSOR_REPO42", "RHEIC_PROXY_CURSOR_REPO42_BASE_URL", 43143
	case "cursor-web":
		return "RHEIC_PROXY_CURSOR_WEB", "RHEIC_PROXY_CURSOR_WEB_BASE_URL", 43144
	case droidCredentialService:
		return "FACTORY_API_KEY", "RHEIC_FACTORY_API_BASE_URL", 43145
	case "droid-app":
		return "RHEIC_PROXY_DROID_APP", "RHEIC_PROXY_DROID_APP_BASE_URL", 43146
	case "droid-relay":
		return "RHEIC_PROXY_DROID_RELAY", "RHEIC_PROXY_DROID_RELAY_BASE_URL", 43147
	default:
		return "", "", 0
	}
}

func proxyBaseURL(service string, port uint16) string {
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	switch service {
	case openAIServiceName, openAIOAuthRoute, "mistral", "xai":
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
		name, isProxyRef, err := parseProxyEnvReference(key, value)
		if err != nil {
			return nil, nil, err
		}
		if !isProxyRef {
			filtered = append(filtered, entry)
			continue
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
	if containsString(names, openAIServiceName) && containsString(names, openAIOAuthRoute) {
		return nil, nil, fmt.Errorf("%w: API-key and OAuth proxy routes cannot share OPENAI_API_KEY", core.ErrConflict)
	}
	return filtered, names, nil
}

func proxyServiceSettingKey(id string) string { return proxySettingPrefix + id }

func isOAuthProxyRoute(name string) bool { return name == openAIOAuthRoute }

func parseProxyEnvReference(key, value string) (string, bool, error) {
	proxyRef := strings.Contains(value, proxyRefPrefix)
	oauthRef := strings.Contains(value, oauthRefPrefix)
	if !proxyRef && !oauthRef {
		return "", false, nil
	}
	if proxyRef == oauthRef {
		return "", true, fmt.Errorf("%w: invalid proxy reference for %s", core.ErrConflict, key)
	}
	prefix := proxyRefPrefix
	if oauthRef {
		prefix = oauthRefPrefix
	}
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "}") ||
		strings.Count(value, proxyRefPrefix)+strings.Count(value, oauthRefPrefix) != 1 {
		return "", true, fmt.Errorf("%w: invalid proxy reference for %s", core.ErrConflict, key)
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(value, prefix), "}"))
	if oauthRef {
		if name != openAIServiceName {
			return "", true, fmt.Errorf("%w: OAuth proxy is not supported for %s", core.ErrConflict, key)
		}
		name = openAIOAuthRoute
	}
	contract, ok := proxyContract(name)
	if !ok || key != contract.credentialEnv {
		return "", true, fmt.Errorf("%w: proxy reference is not supported for %s", core.ErrConflict, key)
	}
	return name, true, nil
}

func registryProxySettingKey(id string) string { return "sandbox.registry-proxy." + id }

func (s *Service) proxyChannelConfig(ctx context.Context, sb sandbox.Sandbox, serviceNames []string, registryScope registrycredentials.Scope) (proxyRuntimeConfig, error) {
	needsServiceSecret := hasServiceSecretRoute(serviceNames)
	if !validProxyServiceNames(serviceNames) || s.secretProxies == nil || (needsServiceSecret && s.serviceSecrets == nil) {
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
	routes, runtimeRoutes, err := s.buildProxyRoutes(ctx, sb, serviceNames, registryScope)
	if err != nil {
		return proxyRuntimeConfig{}, err
	}
	if _, err := s.secretProxies.StartUnixRoutes(ctx, sb.Name, routes, socketPath); err != nil {
		clearRouteSecrets(routes)
		return proxyRuntimeConfig{}, fmt.Errorf("start host service proxy: %w", err)
	}
	clearRouteSecrets(routes)
	prepared = true
	config := proxyRuntimeConfig{port: proxySocketPort, socketPath: socketPath, helperPath: s.proxyHelperPath, routes: runtimeRoutes}
	config.guestPort, config.serviceHost = s.singleProxyEndpoint(serviceNames, runtimeRoutes)
	return config, nil
}

func hasServiceSecretRoute(serviceNames []string) bool {
	for _, name := range serviceNames {
		if name != dockerHubProxyService && !isOAuthProxyRoute(name) {
			return true
		}
	}
	return false
}

func (s *Service) singleProxyEndpoint(serviceNames, runtimeRoutes []string) (uint16, string) {
	if len(runtimeRoutes) != 1 || len(serviceNames) != 1 {
		return 0, ""
	}
	if serviceNames[0] == dockerHubProxyService {
		return dockerHubGuestPort, dockerHubRegistryHost
	}
	if serviceNames[0] == privateRegistryProxyService {
		return privateRegistryGuestPort, s.privateRegistryHost
	}
	if contract, ok := proxyContract(serviceNames[0]); ok {
		return contract.guestPort, contract.upstreamHost
	}
	return 0, ""
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

func (s *Service) buildProxyRoutes(ctx context.Context, sb sandbox.Sandbox, serviceNames []string, registryScope registrycredentials.Scope) (map[string]secretproxy.RouteConfig, []string, error) {
	routes := make(map[string]secretproxy.RouteConfig, len(serviceNames))
	runtimeRoutes := make([]string, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		if serviceName == privateRegistryProxyService {
			scope, err := s.privateRegistryScopeFor(ctx, sb.ID)
			if err != nil {
				clearRouteSecrets(routes)
				return nil, nil, err
			}
			route, runtimeRoute, err := s.buildPrivateRegistryProxy(ctx, sb, scope)
			if err != nil {
				clearRouteSecrets(routes)
				return nil, nil, err
			}
			routes[serviceName] = route
			runtimeRoutes = append(runtimeRoutes, runtimeRoute)
			continue
		}
		if serviceName == dockerHubProxyService {
			route, runtimeRoute, err := s.buildDockerHubProxy(ctx, sb, registryScope)
			if err != nil {
				clearRouteSecrets(routes)
				return nil, nil, err
			}
			routes[serviceName] = route
			runtimeRoutes = append(runtimeRoutes, runtimeRoute)
			continue
		}
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
	if isOAuthProxyRoute(name) {
		return s.buildOAuthProxyRoute(ctx, sb, contract)
	}
	secret, scope, err := s.loadServiceProxySecret(ctx, contract.credentialService, sb.Name)
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	token, err := newProxyToken()
	if err != nil {
		clear(secret)
		return secretproxy.RouteConfig{}, "", err
	}
	service := contractService(name)
	service.CredentialScope = string(scope)
	dynamic, err := s.serviceSecrets.IsDynamic(ctx, name, scope, secretScopeSandboxName(scope, sb.Name))
	if err != nil {
		clear(secret)
		return secretproxy.RouteConfig{}, "", fmt.Errorf("inspect service credential source: %w", err)
	}
	if dynamic {
		clear(secret)
		service.Credential = func(ctx context.Context) ([]byte, error) {
			return s.serviceSecrets.Resolve(ctx, name, scope, secretScopeSandboxName(scope, sb.Name))
		}
	}
	service.Authorize = s.proxyPolicyAuthorizer(sb.ID, contract.upstreamHost)
	service.AuthorizeAddress = s.proxyAddressAuthorizer(sb.ID, contract.upstreamHost)
	routeSecret := secret
	if dynamic {
		routeSecret = nil
	}
	return secretproxy.RouteConfig{Service: service, Secret: routeSecret, Token: token},
		fmt.Sprintf("%s=%s:%d", name, contract.upstreamHost, contract.guestPort), nil
}

func secretScopeSandboxName(scope servicesecrets.Scope, sandboxName string) string {
	if scope == servicesecrets.ScopeSandbox {
		return sandboxName
	}
	return ""
}

func (s *Service) buildOAuthProxyRoute(ctx context.Context, sb sandbox.Sandbox, contract proxyEnvContract) (secretproxy.RouteConfig, string, error) {
	provider, ok := s.oauthProviders[openAIServiceName]
	if !ok || provider.Config.Transport == nil || s.oauthRefresh == nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: OpenAI OAuth proxy is unavailable", core.ErrConflict)
	}
	sink, err := oauthsession.NewVaultSink(s.oauthVault(), openAIServiceName)
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: OAuth credential vault is unavailable", core.ErrConflict)
	}
	manager, err := oauthsession.NewTokenManager(sink, provider.Config.Transport, provider.Config.TokenEndpoint, provider.Config.ClientID, s.oauthRefresh)
	if err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: OpenAI OAuth refresh is unavailable", core.ErrConflict)
	}
	if _, err := manager.AccessToken(ctx); err != nil {
		return secretproxy.RouteConfig{}, "", fmt.Errorf("%w: OpenAI OAuth credentials are unavailable", core.ErrConflict)
	}
	token, err := newProxyToken()
	if err != nil {
		return secretproxy.RouteConfig{}, "", err
	}
	service := contractService(openAIServiceName)
	service.CredentialScope = "global-oauth"
	service.Credential = func(ctx context.Context) ([]byte, error) {
		accessToken, err := manager.AccessToken(ctx)
		if err != nil {
			return nil, err
		}
		return []byte(accessToken), nil
	}
	service.Authorize = s.proxyPolicyAuthorizer(sb.ID, contract.upstreamHost)
	service.AuthorizeAddress = s.proxyAddressAuthorizer(sb.ID, contract.upstreamHost)
	return secretproxy.RouteConfig{Service: service, Token: token},
		fmt.Sprintf("%s=%s:%d", openAIOAuthRoute, contract.upstreamHost, contract.guestPort), nil
}

func newProxyToken() (string, error) {
	var randomToken [32]byte
	if _, err := rand.Read(randomToken[:]); err != nil {
		clear(randomToken[:])
		return "", fmt.Errorf("generate per-sandbox proxy token: %w", err)
	}
	token := hex.EncodeToString(randomToken[:])
	clear(randomToken[:])
	return token, nil
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

func (s *Service) proxyAddressAuthorizer(sandboxID, host string) func(context.Context, netip.Addr) (bool, error) {
	return func(ctx context.Context, address netip.Addr) (bool, error) {
		decision, err := s.checkResolvedEgress(ctx, sandboxID, host, address)
		if err != nil {
			return false, err
		}
		return decision.Allowed, nil
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
	if service == dockerHubProxyService || service == privateRegistryProxyService {
		return true
	}
	_, ok := proxyContract(service)
	return ok
}

func clearRouteSecrets(routes map[string]secretproxy.RouteConfig) {
	for i := range routes {
		route := routes[i]
		clear(route.Secret)
	}
}

func (s *Service) prepareStoredProxy(ctx context.Context, sb sandbox.Sandbox) error {
	serviceSetting, err := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		serviceSetting = ""
	} else if err != nil {
		return fmt.Errorf("load sandbox proxy configuration: %w", err)
	}
	serviceNames := decodeProxyServices(serviceSetting)
	registryScopeValue, err := s.store.GetSetting(ctx, registryProxySettingKey(sb.ID))
	if errors.Is(err, core.ErrNotFound) {
		registryScopeValue = ""
	} else if err != nil {
		return fmt.Errorf("load sandbox registry proxy scope: %w", err)
	}
	serviceNames, registryScopeValue, err = s.discoverDockerHubProxy(ctx, sb, serviceNames, registryScopeValue)
	if err != nil {
		return err
	}
	if len(serviceNames) == 0 {
		return nil
	}
	if slices.Contains(serviceNames, dockerHubProxyService) && registryScopeValue == "" {
		return errors.New("sandbox registry proxy scope is missing")
	}
	_, err = s.proxyChannelConfig(ctx, sb, serviceNames, registrycredentials.Scope(registryScopeValue))
	return err
}

func (s *Service) discoverDockerHubProxy(ctx context.Context, sb sandbox.Sandbox, serviceNames []string, scopeValue string) ([]string, string, error) {
	if scopeValue != "" {
		if !slices.Contains(serviceNames, dockerHubProxyService) {
			serviceNames = append(serviceNames, dockerHubProxyService)
		}
		return serviceNames, scopeValue, nil
	}
	if slices.Contains(serviceNames, dockerHubProxyService) {
		return serviceNames, scopeValue, nil
	}
	dockerEnabled, err := s.dockerProfileEnabled(ctx, sb.ID)
	if err != nil || !dockerEnabled {
		return serviceNames, scopeValue, err
	}
	scope, err := s.availableDockerHubScope(ctx, sb.Name, false)
	if err != nil {
		return nil, "", fmt.Errorf("load sandbox-scoped Docker Hub credential: %w", err)
	}
	if scope == "" {
		return serviceNames, scopeValue, nil
	}
	scopeValue = string(scope)
	serviceNames = append(serviceNames, dockerHubProxyService)
	if err := s.store.SetSetting(ctx, registryProxySettingKey(sb.ID), scopeValue); err != nil {
		return nil, "", fmt.Errorf("store sandbox registry proxy scope: %w", err)
	}
	if err := s.store.SetSetting(ctx, proxyServiceSettingKey(sb.ID), encodeProxyServices(serviceNames)); err != nil {
		return nil, "", fmt.Errorf("store sandbox proxy route configuration: %w", err)
	}
	return serviceNames, scopeValue, nil
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
