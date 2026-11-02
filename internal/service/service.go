// Package service implements sandbox control-plane use cases.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	gatewaypolicy "github.com/KLORQ/sandboxes-gateway/policy"
	runtime "github.com/KLORQ/sandboxes-runtime"

	"github.com/KLORQ/sandboxes-daemon/internal/oauthsession"
	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
	"github.com/KLORQ/sandboxes-daemon/internal/secretproxy"
	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

const (
	tcpProtocol  = "tcp"
	udpProtocol  = "udp"
	tcp4Protocol = "tcp4"
	udp4Protocol = "udp4"
	tcp6Protocol = "tcp6"
	udp6Protocol = "udp6"
)

// Service coordinates durable sandbox state and operations.
type Service struct {
	store                *store.Store
	journal              *operation.Journal
	backend              runtime.Backend
	registryCredentials  *registrycredentials.Store
	serviceSecrets       *servicesecrets.Store
	secretProxies        *secretproxy.Manager
	proxyHelperPath      string
	proxyTempDir         string
	oauthProviders       map[string]OAuthProvider
	oauthVaultStore      oauthsession.Vault
	dockerHubAuth        http.RoundTripper
	DefaultImage         string
	DefaultCPUs          uint32
	DefaultMemoryMiB     uint32
	DefaultPolicyProfile string
	DockerVolumeDir      string
	DockerVolumeSize     string
	MkfsExt4             string
	now                  func() time.Time
	createGates          [64]chan struct{}
	lifecycleGates       [64]chan struct{}
	credentialGates      [64]chan struct{}
	execMu               sync.Mutex
	execSessions         map[string]map[*execSession]struct{}
	globalPolicyMu       sync.Mutex
}

const dockerHubRegistry = "docker.io"

// OAuthProvider contains trusted, daemon-side OAuth configuration. Never
// populate it from an RPC request, guest, workspace, or sandbox metadata.
type OAuthProvider struct {
	Config         oauthsession.Provider
	Device         oauthsession.DeviceProvider
	RevokeEndpoint string
	OpenBrowser    func(context.Context, string) error
	DeviceHandoff  func(context.Context, string, string) error
}

// SetOAuthProviders installs an immutable snapshot of trusted provider config.
func (s *Service) SetOAuthProviders(providers map[string]OAuthProvider) {
	copyOf := make(map[string]OAuthProvider, len(providers))
	for name := range providers {
		provider := providers[name]
		provider.Config.Scopes = append([]string(nil), provider.Config.Scopes...)
		provider.Device.Scopes = append([]string(nil), provider.Device.Scopes...)
		copyOf[name] = provider
	}
	s.oauthProviders = copyOf
}

// SetOAuthVault injects the host credential vault. Production defaults to the
// native OS keychain; this hook supports controlled provider tests.
func (s *Service) SetOAuthVault(vault oauthsession.Vault) { s.oauthVaultStore = vault }

// LoginAccount performs a browser-based host OAuth flow for a registered provider.
func (s *Service) LoginAccount(ctx context.Context, name string) error {
	release, err := s.acquireCredentialGate(ctx, accountGateKey(name))
	if err != nil {
		return err
	}
	defer release()
	provider, ok := s.oauthProviders[name]
	if !ok {
		return ErrOAuthProviderUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("OAuth login requires a bounded context")
	}
	sink, err := oauthsession.NewVaultSink(s.oauthVault(), name)
	if err != nil {
		return errors.New("OAuth host keychain is unavailable")
	}
	if err := s.checkAccountLoginAvailable(ctx, name, sink); err != nil {
		return err
	}
	if provider.Device.ClientID != "" {
		return s.authorizeDeviceAccount(ctx, provider, sink)
	}
	if provider.OpenBrowser == nil || provider.Config.Transport == nil {
		return ErrOAuthProviderUnavailable
	}
	return oauthsession.Authorize(ctx, provider.Config, provider.OpenBrowser, sink)
}

func (s *Service) checkAccountLoginAvailable(ctx context.Context, name string, sink *oauthsession.VaultSink) error {
	if name == "docker" {
		return s.checkDockerHubLoginAvailable(ctx, sink)
	}
	if _, _, err := sink.Load(ctx); err == nil {
		return ErrOAuthCredentialConflict
	} else if !errors.Is(err, oauthsession.ErrNoTokens) {
		return errors.New("inspect existing OAuth account credentials failed")
	}
	return nil
}

func (s *Service) authorizeDeviceAccount(ctx context.Context, provider OAuthProvider, sink *oauthsession.VaultSink) error {
	if provider.DeviceHandoff == nil || provider.Device.PATEndpoint == "" || s.registryCredentials == nil || !oauthsession.SameHTTPSOrigin(provider.Device.Audience, provider.Device.PATEndpoint) {
		return ErrOAuthProviderUnavailable
	}
	combined := dockerAccountSink{oauth: sink, registry: s.registryCredentials, provider: provider.Device}
	return oauthsession.AuthorizeDevice(ctx, provider.Device, provider.DeviceHandoff, combined)
}

// LogoutAccount deletes the local host token record and revokes the upstream
// refresh token when the trusted provider configuration supports revocation.
func (s *Service) LogoutAccount(ctx context.Context, name string) (bool, error) {
	release, err := s.acquireCredentialGate(ctx, accountGateKey(name))
	if err != nil {
		return false, err
	}
	defer release()
	sink, err := oauthsession.NewVaultSink(s.oauthVault(), name)
	if err != nil {
		return false, errors.New("OAuth host keychain is unavailable")
	}
	tokens, hasTokens, err := loadAccountTokens(ctx, sink)
	if err != nil {
		return false, err
	}
	fingerprint, hasFingerprint, err := loadAccountFingerprint(ctx, sink)
	if err != nil {
		return false, err
	}
	if !hasTokens && !hasFingerprint {
		return false, nil
	}
	var revokeErr error
	if hasTokens && tokens.RefreshToken != "" {
		revokeErr = s.revokeAccountRefreshToken(ctx, name, tokens.RefreshToken)
		if revokeErr != nil && !errors.Is(revokeErr, ErrOAuthRevocationUnavailable) {
			return true, revokeErr
		}
	}
	if err := deleteAccountTokens(ctx, sink, hasTokens); err != nil {
		return false, err
	}
	if hasFingerprint {
		if err := s.removeOAuthOwnedDockerHubCredentials(ctx, fingerprint); err != nil {
			return true, err
		}
		if err := sink.DeleteDockerHubPATFingerprint(ctx); err != nil {
			return true, err
		}
	}
	return true, revokeErr
}

func loadAccountTokens(ctx context.Context, sink *oauthsession.VaultSink) (oauthsession.Tokens, bool, error) {
	tokens, _, err := sink.Load(ctx)
	if errors.Is(err, oauthsession.ErrNoTokens) {
		return oauthsession.Tokens{}, false, nil
	}
	if err != nil {
		return oauthsession.Tokens{}, false, err
	}
	return tokens, true, nil
}

func loadAccountFingerprint(ctx context.Context, sink *oauthsession.VaultSink) (string, bool, error) {
	fingerprint, err := sink.DockerHubPATFingerprint(ctx)
	if errors.Is(err, oauthsession.ErrNoCredentialFingerprint) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return fingerprint, true, nil
}

func deleteAccountTokens(ctx context.Context, sink *oauthsession.VaultSink, present bool) error {
	if present {
		return sink.Delete(ctx)
	}
	return nil
}

func (s *Service) removeOAuthOwnedDockerHubCredentials(ctx context.Context, fingerprint string) error {
	if s.registryCredentials == nil {
		return errors.New("local Docker Hub credential store is unavailable")
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		if err := s.removeCredentialIfFingerprintMatches(ctx, scope, fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) removeCredentialIfFingerprintMatches(ctx context.Context, scope registrycredentials.Scope, fingerprint string) error {
	credential, err := s.registryCredentials.Load(ctx, dockerHubRegistry, scope, "")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.New("local Docker Hub credentials were only partially removed")
	}
	hash := sha256.Sum256(credential.Password)
	clear(credential.Password)
	actual := hex.EncodeToString(hash[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(fingerprint)) != 1 {
		return nil
	}
	if _, err := s.registryCredentials.Delete(ctx, dockerHubRegistry, scope, ""); err != nil {
		return errors.New("local Docker Hub credentials were only partially removed")
	}
	return nil
}

func (s *Service) revokeAccountRefreshToken(ctx context.Context, name, refreshToken string) error {
	provider, configured := s.oauthProviders[name]
	if !configured || provider.RevokeEndpoint == "" {
		return ErrOAuthRevocationUnavailable
	}
	transport, clientID := provider.Config.Transport, provider.Config.ClientID
	if provider.Device.Transport != nil {
		transport, clientID = provider.Device.Transport, provider.Device.ClientID
	}
	if err := oauthsession.Revoke(ctx, transport, provider.RevokeEndpoint, clientID, refreshToken); err != nil {
		return ErrOAuthRevocationFailed
	}
	return nil
}

type dockerAccountSink struct {
	oauth    *oauthsession.VaultSink
	registry *registrycredentials.Store
	provider oauthsession.DeviceProvider
}

func (s dockerAccountSink) Save(ctx context.Context, tokens oauthsession.Tokens) error {
	username, err := oauthsession.HubUsernameFromAccessToken(tokens.AccessToken)
	if err != nil {
		return err
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		existing, loadErr := s.registry.Load(ctx, dockerHubRegistry, scope, "")
		if loadErr == nil {
			clear(existing.Password)
			return ErrOAuthCredentialConflict
		}
		if !errors.Is(loadErr, registrycredentials.ErrNotFound) {
			return errors.New("inspect existing Docker Hub credentials failed")
		}
	}
	if err := s.oauth.Save(ctx, tokens); err != nil {
		return err
	}
	pat, err := oauthsession.GeneratePAT(ctx, s.provider.Transport, s.provider.PATEndpoint, tokens.AccessToken)
	if err != nil {
		return oauthsession.ErrOAuthPartialLogin
	}
	password := []byte(pat)
	defer clear(password)
	hash := sha256.Sum256(password)
	if err := s.oauth.SaveDockerHubPATFingerprint(ctx, hex.EncodeToString(hash[:])); err != nil {
		return oauthsession.ErrOAuthPartialLogin
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		if _, err := s.registry.Save(ctx, registrycredentials.Credential{Registry: dockerHubRegistry, Username: username, Password: password, Scope: scope}); err != nil {
			return oauthsession.ErrOAuthPartialLogin
		}
	}
	return nil
}

func (s *Service) oauthVault() oauthsession.Vault {
	if s.oauthVaultStore != nil {
		return s.oauthVaultStore
	}
	return registrycredentials.NativeVault{}
}

var ErrOAuthProviderUnavailable = errors.New("OAuth provider is not configured")
var ErrOAuthCredentialConflict = oauthsession.ErrCredentialConflict
var ErrOAuthPartialLogin = oauthsession.ErrOAuthPartialLogin
var ErrDockerHubCredentialRejected = oauthsession.ErrDockerHubCredentialRejected
var ErrOAuthRevocationFailed = errors.New("OAuth credentials were removed locally but provider revocation failed")
var ErrOAuthRevocationUnavailable = errors.New("OAuth credentials were removed locally but provider revocation is not configured")

// SetRegistryCredentialStore configures host-keychain storage for registry logins.
func (s *Service) SetRegistryCredentialStore(credentialStore *registrycredentials.Store) {
	s.registryCredentials = credentialStore
}

// SetServiceSecretStore configures host-keychain storage for service secrets.
func (s *Service) SetServiceSecretStore(secretStore *servicesecrets.Store) {
	s.serviceSecrets = secretStore
}

// SetSecretProxyManager configures host-side service proxies.
func (s *Service) SetSecretProxyManager(manager *secretproxy.Manager) {
	s.secretProxies = manager
}

// SetSecretProxyRuntime configures the static guest helper and short host-side
// socket directory used by the per-sandbox vsock broker.
func (s *Service) SetSecretProxyRuntime(helperPath, tempDir string) {
	s.proxyHelperPath = helperPath
	s.proxyTempDir = tempDir
}

// SetServiceSecret stores one service secret and a non-secret index entry.
func (s *Service) SetServiceSecret(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string, value []byte) (servicesecrets.Summary, error) {
	defer clear(value)
	if s.serviceSecrets == nil {
		return servicesecrets.Summary{}, errors.New("service secret store is unavailable")
	}
	release, err := s.acquireCredentialGate(ctx, "service-secret/"+service+"/"+string(scope)+"/"+sandboxName)
	if err != nil {
		return servicesecrets.Summary{}, err
	}
	defer release()
	summary, err := s.serviceSecrets.Save(ctx, service, scope, sandboxName, value)
	if err != nil {
		return servicesecrets.Summary{}, err
	}
	if err := s.store.UpsertServiceSecretIndex(ctx, store.ServiceSecretIndex{
		Service: summary.Service, Scope: string(summary.Scope), SandboxName: summary.SandboxName,
	}); err != nil {
		_, _ = s.serviceSecrets.Delete(ctx, summary.Service, summary.Scope, summary.SandboxName)
		return servicesecrets.Summary{}, err
	}
	if s.secretProxies != nil {
		s.secretProxies.RefreshSecret(summary.Service, summary.SandboxName, string(summary.Scope), value)
	}
	return summary, nil
}

// ListServiceSecrets returns non-secret summaries.
func (s *Service) ListServiceSecrets(ctx context.Context) ([]servicesecrets.Summary, error) {
	entries, err := s.store.ListServiceSecretIndex(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]servicesecrets.Summary, 0, len(entries))
	for _, entry := range entries {
		out = append(out, servicesecrets.Summary{
			Service: entry.Service, Scope: servicesecrets.Scope(entry.Scope), SandboxName: entry.SandboxName,
		})
	}
	return out, nil
}

// RemoveServiceSecret deletes one service secret from the host keychain.
func (s *Service) RemoveServiceSecret(ctx context.Context, service string, scope servicesecrets.Scope, sandboxName string) (bool, error) {
	if s.serviceSecrets == nil {
		return false, errors.New("service secret store is unavailable")
	}
	removed, err := s.serviceSecrets.Delete(ctx, service, scope, sandboxName)
	if err != nil || !removed {
		return removed, err
	}
	if s.secretProxies != nil {
		if err := s.secretProxies.RevokeSecret(strings.ToLower(strings.TrimSpace(service)), sandboxName, string(scope)); err != nil {
			return true, fmt.Errorf("revoke active service proxy: %w", err)
		}
	}
	if err := s.store.DeleteServiceSecretIndex(ctx, strings.ToLower(strings.TrimSpace(service)), string(scope), sandboxName); err != nil {
		return true, err
	}
	return true, nil
}

// PolicyDecision is the gateway-consistent result of a policy check.
type PolicyDecision struct {
	Allowed bool
	RuleID  string
	Reason  string
}

// CheckPolicy evaluates stored/global rules with the same deny precedence and
// matcher used by the gateway. It does not resolve DNS; domain checks operate
// on the supplied hostname and CIDR checks on the supplied IP.
func (s *Service) CheckPolicy(ctx context.Context, id, protocol, address, domain string, port uint16) (PolicyDecision, error) {
	if protocol != tcpProtocol && protocol != udpProtocol {
		return PolicyDecision{}, fmt.Errorf("%w: protocol must be tcp or udp", core.ErrConflict)
	}
	if (address == "") == (domain == "") {
		return PolicyDecision{}, fmt.Errorf("%w: exactly one of address or domain is required", core.ErrConflict)
	}
	allow, deny, err := s.checkPolicyRules(ctx, id)
	if err != nil {
		return PolicyDecision{}, err
	}
	toRules := func(rules []sandbox.NetworkRule, action gatewaypolicy.Action) []gatewaypolicy.Rule {
		out := make([]gatewaypolicy.Rule, 0, len(rules))
		for i := range rules {
			out = append(out, gatewaypolicy.Rule{ID: rules[i].RuleID, Action: action, Protocol: rules[i].Protocol, Domain: rules[i].Domain, CIDR: rules[i].CIDR, Port: rules[i].Port})
		}
		return out
	}
	decision := gatewaypolicy.Check(toRules(allow, gatewaypolicy.Allow), toRules(deny, gatewaypolicy.Deny), gatewaypolicy.Request{
		Protocol: protocol, Address: address, Domain: domain, Port: port,
	})
	return PolicyDecision{Allowed: decision.Allow, RuleID: decision.RuleID, Reason: decision.Reason}, nil
}

// checkPolicyRules returns the effective allow/deny rules for a sandbox ID,
// or the stored global rules when the ID is empty.
func (s *Service) checkPolicyRules(ctx context.Context, id string) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	if id == "" {
		allow, deny, err := s.GlobalPolicy(ctx)
		if err != nil {
			return nil, nil, err
		}
		profile, err := s.GetPolicyProfile(ctx)
		if err != nil {
			return nil, nil, err
		}
		_, profileRules, err := normalizePolicyProfile(profile)
		if err != nil {
			return nil, nil, err
		}
		return mergePolicyRules(profileRules, allow), deny, nil
	}
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	allow, deny, err := s.effectivePolicy(ctx, sb)
	if err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

// SetDockerHubAuthTransport injects the HTTP transport used only to validate
// Docker Hub username/PAT login. Production uses a direct TLS transport.
func (s *Service) SetDockerHubAuthTransport(transport http.RoundTripper) {
	s.dockerHubAuth = transport
}

// LoginDockerHubPAT verifies a Docker Hub username/PAT pair, then stores the
// PAT in the host-only and all-sandboxes vault scopes for registry use.
func (s *Service) LoginDockerHubPAT(ctx context.Context, username string, password []byte) error {
	defer clear(password)
	if s.registryCredentials == nil || s.dockerHubAuth == nil {
		return errors.New("docker Hub credential services are unavailable")
	}
	if !validDockerHubPATInput(username, password) {
		return registrycredentials.ErrInvalidCredential
	}
	release, err := s.acquireCredentialGate(ctx, accountGateKey("docker"))
	if err != nil {
		return err
	}
	defer release()
	sink, err := oauthsession.NewVaultSink(s.oauthVault(), "docker")
	if err != nil {
		return errors.New("docker account host keychain is unavailable")
	}
	if err := s.checkDockerHubLoginAvailable(ctx, sink); err != nil {
		return err
	}
	if err := oauthsession.ValidateDockerHubCredentials(ctx, s.dockerHubAuth, username, password); err != nil {
		return err
	}
	return s.persistDockerHubPAT(ctx, sink, username, password)
}

func validDockerHubPATInput(username string, password []byte) bool {
	return username != "" && len(username) <= 255 && strings.TrimSpace(username) == username && !strings.ContainsAny(username, "\x00\r\n") &&
		len(password) > 0 && len(password) <= 2048 && utf8.Valid(password)
}

func (s *Service) persistDockerHubPAT(ctx context.Context, sink *oauthsession.VaultSink, username string, password []byte) error {
	hash := sha256.Sum256(password)
	if err := sink.SaveDockerHubPATFingerprint(ctx, hex.EncodeToString(hash[:])); err != nil {
		return oauthsession.ErrOAuthPartialLogin
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		if _, err := s.registryCredentials.Save(ctx, registrycredentials.Credential{
			Registry: dockerHubRegistry, Username: username, Password: password, Scope: scope,
		}); err != nil {
			return oauthsession.ErrOAuthPartialLogin
		}
	}
	return nil
}

func (s *Service) checkDockerHubLoginAvailable(ctx context.Context, sink *oauthsession.VaultSink) error {
	if s.registryCredentials == nil {
		return errors.New("docker Hub credential services are unavailable")
	}
	if _, _, err := sink.Load(ctx); err == nil {
		return ErrOAuthCredentialConflict
	} else if !errors.Is(err, oauthsession.ErrNoTokens) {
		return errors.New("inspect existing Docker account credentials failed")
	}
	if _, err := sink.DockerHubPATFingerprint(ctx); err == nil {
		return ErrOAuthCredentialConflict
	} else if !errors.Is(err, oauthsession.ErrNoCredentialFingerprint) {
		return errors.New("inspect existing Docker account ownership failed")
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		credential, err := s.registryCredentials.Load(ctx, dockerHubRegistry, scope, "")
		if err == nil {
			clear(credential.Password)
			return ErrOAuthCredentialConflict
		}
		if !errors.Is(err, registrycredentials.ErrNotFound) {
			return errors.New("inspect existing Docker Hub credentials failed")
		}
	}
	return nil
}

// LoginRegistry stores registry credentials on the host and returns safe metadata.
func (s *Service) LoginRegistry(ctx context.Context, credential registrycredentials.Credential) (registrycredentials.Summary, error) {
	if s.registryCredentials == nil {
		return registrycredentials.Summary{}, fmt.Errorf("host registry credential store is unavailable")
	}
	release, err := s.acquireCredentialGate(ctx, registryGateKey(credential.Registry))
	if err != nil {
		return registrycredentials.Summary{}, err
	}
	defer release()
	summary, err := s.registryCredentials.Save(ctx, credential)
	if err != nil {
		return registrycredentials.Summary{}, err
	}
	if err := s.store.UpsertRegistryCredentialIndex(ctx, store.RegistryCredentialIndex{
		Registry: summary.Registry, Username: summary.Username, Scope: string(summary.Scope), SandboxName: summary.SandboxName,
	}); err != nil {
		_, _ = s.registryCredentials.Delete(ctx, summary.Registry, summary.Scope, summary.SandboxName)
		return registrycredentials.Summary{}, err
	}
	return summary, nil
}

// LogoutRegistry removes a scoped registry login from the host keychain.
func (s *Service) LogoutRegistry(ctx context.Context, registry string, scope registrycredentials.Scope, sandboxName string) (bool, error) {
	if s.registryCredentials == nil {
		return false, fmt.Errorf("host registry credential store is unavailable")
	}
	release, err := s.acquireCredentialGate(ctx, registryGateKey(registry))
	if err != nil {
		return false, err
	}
	defer release()
	canonical := registry
	if loaded, loadErr := s.registryCredentials.Load(ctx, registry, scope, sandboxName); loadErr == nil {
		canonical = loaded.Registry
		clear(loaded.Password)
	}
	removed, err := s.registryCredentials.Delete(ctx, registry, scope, sandboxName)
	if err != nil || !removed {
		return removed, err
	}
	if err := s.store.DeleteRegistryCredentialIndex(ctx, canonical, string(scope), sandboxName); err != nil {
		return true, err
	}
	return true, nil
}

// ListRegistryCredentials returns non-secret summaries of stored registry logins.
func (s *Service) ListRegistryCredentials(ctx context.Context) ([]registrycredentials.Summary, error) {
	entries, err := s.store.ListRegistryCredentialIndex(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]registrycredentials.Summary, 0, len(entries))
	for _, entry := range entries {
		out = append(out, registrycredentials.Summary{
			Registry: entry.Registry, Username: entry.Username,
			Scope: registrycredentials.Scope(entry.Scope), SandboxName: entry.SandboxName,
		})
	}
	return out, nil
}

func (s *Service) cleanupSandboxRegistryCredentials(ctx context.Context, sandboxName string) error {
	if s.registryCredentials == nil {
		return nil
	}
	if err := s.deleteSandboxRegistryCredentials(ctx, sandboxName); err != nil {
		return fmt.Errorf("remove sandbox registry credentials: %w", err)
	}
	return nil
}

func (s *Service) cleanupSandboxServiceSecrets(ctx context.Context, sandboxName string) error {
	if s.serviceSecrets == nil {
		return nil
	}
	entries, err := s.store.ListServiceSecretIndex(ctx)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Scope != string(servicesecrets.ScopeSandbox) || entry.SandboxName != sandboxName {
			continue
		}
		if _, err := s.serviceSecrets.Delete(ctx, entry.Service, servicesecrets.ScopeSandbox, sandboxName); err != nil {
			return err
		}
		if err := s.store.DeleteServiceSecretIndex(ctx, entry.Service, entry.Scope, entry.SandboxName); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) deleteSandboxRegistryCredentials(ctx context.Context, sandboxName string) error {
	entries, err := s.store.ListRegistryCredentialIndex(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if entry.Scope != string(registrycredentials.ScopeSandbox) || entry.SandboxName != sandboxName {
			continue
		}
		if _, err := s.registryCredentials.Delete(ctx, entry.Registry, registrycredentials.ScopeSandbox, sandboxName); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := s.store.DeleteRegistryCredentialIndex(ctx, entry.Registry, entry.Scope, entry.SandboxName); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) acquireCredentialGate(ctx context.Context, key string) (func(), error) {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	gate := s.credentialGates[hash.Sum64()%uint64(len(s.credentialGates))]
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func accountGateKey(provider string) string {
	if provider == "docker" {
		return "registry/docker.io"
	}
	return "oauth/" + provider
}

func registryGateKey(registry string) string {
	host := strings.ToLower(strings.TrimSpace(registry))
	if host == "" || host == "docker.io" || host == "index.docker.io" {
		return "registry/docker.io"
	}
	return "registry/" + host
}

// New creates a control-plane service.
func New(st *store.Store, backend runtime.Backend) *Service {
	cpus, memoryMiB := hostResourceDefaults()
	s := &Service{
		store:            st,
		journal:          operation.NewJournal(st.Operations()),
		backend:          backend,
		DefaultImage:     "alpine:3.22",
		DefaultCPUs:      cpus,
		DefaultMemoryMiB: memoryMiB,
		now:              time.Now,
		dockerHubAuth:    oauthsession.NewDockerHubAuthTransport(),
	}
	for i := range s.createGates {
		s.createGates[i] = make(chan struct{}, 1)
		s.lifecycleGates[i] = make(chan struct{}, 1)
		s.credentialGates[i] = make(chan struct{}, 1)
	}
	return s
}

// CreateRequest describes a new sandbox.
type CreateRequest struct {
	Name           string
	Image          string
	Workspace      string
	IdempotencyKey string
	// Zero selects the daemon default.
	CPUs          uint32
	MemoryMiB     uint32
	Workspaces    []sandbox.Workspace
	Ports         []sandbox.Port
	Allow         []sandbox.NetworkRule
	Deny          []sandbox.NetworkRule
	Agent         string
	Detached      bool
	PolicyProfile string
	Privileged    bool
	// Env is baked into the sandbox runtime; it is never written to SQLite.
	Env map[string]string
}

// Create creates a stopped sandbox and a completed create operation.
//
//nolint:gocyclo,cyclop,gocognit,funlen // Create is the orchestration boundary for validation, idempotency, runtime startup and persistence.
func (s *Service) Create(ctx context.Context, req CreateRequest) (operation.Operation, error) {
	name := strings.TrimSpace(req.Name)
	if !validSandboxName(name) {
		return operation.Operation{}, fmt.Errorf("%w: invalid sandbox name", core.ErrConflict)
	}
	release, err := s.acquireCreateGates(ctx, name, req.IdempotencyKey)
	if err != nil {
		return operation.Operation{}, err
	}
	defer release()
	image, cpus, memoryMiB, env, err := s.resolveCreateResources(req)
	if err != nil {
		return operation.Operation{}, err
	}
	env, proxyServiceName, err := stripProxyCreateEnv(env)
	if err != nil {
		return operation.Operation{}, err
	}
	if proxyServiceName != "" && s.backend == nil {
		return operation.Operation{}, fmt.Errorf("%w: service proxy requires a VM runtime", core.ErrConflict)
	}
	workspace, workspaces, err := normalizeCreateWorkspaces(req)
	if err != nil {
		return operation.Operation{}, err
	}
	profile, ports, allow, deny, err := s.normalizeCreatePolicy(ctx, req)
	if err != nil {
		return operation.Operation{}, err
	}
	intent := createIntent{
		name: name, image: image, workspace: workspace, workspaces: workspaces, ports: ports,
		allow: allow, deny: deny, agent: req.Agent, detached: req.Detached, cpus: cpus, memoryMiB: memoryMiB,
		proxyService: proxyServiceName,
	}
	if existing, found, err := s.replayCreateIfRequested(ctx, req.IdempotencyKey, intent); err != nil {
		return operation.Operation{}, err
	} else if found {
		return existing, nil
	}
	if err := s.ensureNameAvailable(ctx, name); err != nil {
		return operation.Operation{}, err
	}
	now := s.now().UTC()
	sbID, err := newID("sb")
	if err != nil {
		return operation.Operation{}, err
	}
	cleanupProxy := func() error {
		if proxyServiceName == "" {
			return nil
		}
		return s.stopProxyChannel(name, sbID, true)
	}
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	if !req.Privileged {
		if inspector, ok := s.backend.(runtime.ImageInspector); ok {
			if labels, err := inspector.ImageLabels(ctx, image); err == nil && labels["com.docker.sandboxes.start-docker"] == "true" {
				req.Privileged = true
			}
		}
	}
	var blockVolumes []runtime.BlockVolume
	if req.Privileged {
		volume, err := s.ensureDockerVolume(ctx, sbID)
		if err != nil {
			return operation.Operation{}, err
		}
		blockVolumes = append(blockVolumes, runtime.BlockVolume{Source: volume, Destination: "/var/lib/docker"})
	}
	state := sandbox.Stopped
	var handle runtime.Handle
	var proxyConfig proxyRuntimeConfig
	if proxyServiceName != "" {
		proxyConfig, err = s.proxyChannelConfig(ctx, sandbox.Sandbox{ID: sbID, Name: name}, proxyServiceName)
		if err != nil {
			return operation.Operation{}, err
		}
	}
	if s.backend != nil {
		effectiveAllow, effectiveDeny, policyErr := s.effectiveRules(ctx, allow, deny)
		if policyErr != nil {
			return operation.Operation{}, errors.Join(policyErr, cleanupProxy())
		}
		runtimeConfig := runtime.Config{
			Name:         name,
			Image:        image,
			Workspace:    workspace,
			Workspaces:   runtimeWorkspaces(workspaces),
			BlockVolumes: blockVolumes,
			Ports:        runtimePorts(ports),
			Allow:        runtimeRules(effectiveAllow),
			Deny:         runtimeRules(effectiveDeny),
			CPUs:         uint8(cpus), //nolint:gosec // resolveCreateResources bounds cpus to 1..64.
			MemoryMiB:    memoryMiB,
			Env:          env,
			Privileged:   req.Privileged,
			ProxyPort:    proxyConfig.port,
			ProxySocket:  proxyConfig.socketPath,
		}
		handle, err = s.createRuntimeSandbox(ctx, &runtimeConfig, proxyServiceName, proxyConfig)
		if err != nil {
			return operation.Operation{}, errors.Join(err, cleanupProxy())
		}
		if err := s.ensureDockerProfile(ctx, req.Privileged, handle); err != nil {
			return operation.Operation{}, errors.Join(err, s.cleanupCreateFailure(ctx, handle, errors.New("docker profile startup failed")), cleanupProxy())
		}
		state = sandbox.Running
	}
	sb := newSandboxRecord(sbID, name, state, image, workspace, workspaces, ports, allow, deny, req.Agent, req.Detached, profile, cpus, memoryMiB, now)
	if err := s.setDockerProfile(ctx, sbID, req.Privileged); err != nil {
		return operation.Operation{}, errors.Join(s.cleanupCreateFailure(ctx, handle, err), cleanupProxy())
	}
	if proxyServiceName != "" {
		if err := s.store.SetSetting(ctx, proxyServiceSettingKey(sbID), proxyServiceName); err != nil {
			return operation.Operation{}, errors.Join(s.cleanupCreateFailure(ctx, handle, err), s.stopProxyChannel(name, sbID, true))
		}
	}
	op := operation.Operation{
		ID:             opID,
		SandboxID:      sbID,
		Kind:           operation.KindCreate,
		State:          operation.Done,
		Generation:     1,
		IdempotencyKey: req.IdempotencyKey,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.CreateSandboxWithOperation(ctx, sb, op); err != nil {
		if proxyServiceName != "" {
			_ = s.store.DeleteSetting(ctx, proxyServiceSettingKey(sbID))
		}
		return operation.Operation{}, errors.Join(s.cleanupCreateFailure(ctx, handle, err), cleanupProxy())
	}
	return op, nil
}

func (s *Service) createRuntimeSandbox(ctx context.Context, cfg *runtime.Config, proxyService string, proxyConfig proxyRuntimeConfig) (runtime.Handle, error) {
	if proxyService == "" {
		return s.backend.Create(ctx, *cfg)
	}
	proxyBackend, ok := s.backend.(proxyRuntime)
	if !ok {
		return runtime.Handle{}, fmt.Errorf("%w: runtime backend does not support the service proxy helper", core.ErrConflict)
	}
	return proxyBackend.CreateWithProxy(ctx, cfg, proxyConfig.helperPath, proxyConfig.guestPort, proxyConfig.serviceHost)
}

func (s *Service) replayCreateIfRequested(ctx context.Context, key string, intent createIntent) (operation.Operation, bool, error) {
	if key == "" {
		return operation.Operation{}, false, nil
	}
	existing, err := s.replayCreate(ctx, key, intent)
	if err == nil {
		return existing, true, nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return operation.Operation{}, false, err
	}
	return operation.Operation{}, false, nil
}

func (s *Service) resolveCreateResources(req CreateRequest) (string, uint32, uint32, []string, error) {
	image := req.Image
	if image == "" {
		image = s.DefaultImage
	}
	cpus, memoryMiB := req.CPUs, req.MemoryMiB
	if cpus == 0 {
		cpus = s.DefaultCPUs
	}
	if cpus == 0 {
		cpus = 2
	}
	if memoryMiB == 0 {
		memoryMiB = s.DefaultMemoryMiB
	}
	if memoryMiB == 0 {
		memoryMiB = 1024
	}
	if cpus > 64 || memoryMiB < 128 || memoryMiB > 65536 {
		return "", 0, 0, nil, fmt.Errorf("%w: invalid CPU or memory request", core.ErrConflict)
	}
	env, err := normalizeCreateEnv(req.Env)
	if err != nil {
		return "", 0, 0, nil, err
	}
	return image, cpus, memoryMiB, env, nil
}

func normalizeCreateWorkspaces(req CreateRequest) (string, []sandbox.Workspace, error) {
	workspaces, err := normalizeWorkspaces(req)
	if err != nil {
		return "", nil, err
	}
	if len(workspaces) == 0 {
		return "", workspaces, nil
	}
	return workspaces[0].Path, workspaces, nil
}

func newSandboxRecord(id, name string, state sandbox.State, image, workspace string, workspaces []sandbox.Workspace, ports []sandbox.Port, allow, deny []sandbox.NetworkRule, agent string, detached bool, profile string, cpus, memoryMiB uint32, now time.Time) sandbox.Sandbox {
	stoppedAt := time.Time{}
	if state == sandbox.Stopped {
		stoppedAt = now
	}
	return sandbox.Sandbox{
		ID: id, Name: name, State: state, Generation: 1, Image: image,
		Workspace: workspace, Workspaces: workspaces, Ports: ports, Policy: networkPolicy(allow, deny),
		Meta: &sandbox.Meta{Agent: agent, Detached: detached, PolicyProfile: profile, LastUsedAt: now},
		CPUs: cpus, MemoryMiB: memoryMiB, StoppedAt: stoppedAt, CreatedAt: now, UpdatedAt: now,
	}
}

func normalizeWorkspaces(req CreateRequest) ([]sandbox.Workspace, error) {
	workspaces := append([]sandbox.Workspace(nil), req.Workspaces...)
	if len(workspaces) == 0 && req.Workspace != "" {
		workspaces = []sandbox.Workspace{{Path: req.Workspace}}
	}
	if len(workspaces) > 16 {
		return nil, fmt.Errorf("%w: too many workspaces", core.ErrConflict)
	}
	seen := make(map[string]struct{}, len(workspaces))
	for i := range workspaces {
		workspace := &workspaces[i]
		if workspace.Path == "" || !filepath.IsAbs(workspace.Path) || strings.ContainsRune(workspace.Path, '\x00') {
			return nil, fmt.Errorf("%w: workspace path must be absolute", core.ErrConflict)
		}
		workspace.Path = filepath.Clean(workspace.Path)
		if _, exists := seen[workspace.Path]; exists {
			return nil, fmt.Errorf("%w: duplicate workspace", core.ErrConflict)
		}
		seen[workspace.Path] = struct{}{}
	}
	return workspaces, nil
}

func runtimeWorkspaces(workspaces []sandbox.Workspace) []runtime.Workspace {
	out := make([]runtime.Workspace, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, runtime.Workspace{Path: workspaces[i].Path, ReadOnly: workspaces[i].ReadOnly})
	}
	return out
}

func normalizePorts(ports []sandbox.Port) ([]sandbox.Port, error) {
	if len(ports) > 32 {
		return nil, fmt.Errorf("%w: too many ports", core.ErrConflict)
	}
	seen := make(map[string]struct{}, len(ports))
	out := make([]sandbox.Port, 0, len(ports))
	for _, port := range ports {
		if port.Host == 0 || port.Guest == 0 {
			return nil, fmt.Errorf("%w: host and guest ports must be non-zero", core.ErrConflict)
		}
		protocol, hostIP, err := normalizePortEndpoint(port.Protocol, port.HostIP)
		if err != nil {
			return nil, err
		}
		port.Protocol = protocol
		port.HostIP = hostIP
		key := port.Protocol + ":" + port.HostIP + ":" + strconv.Itoa(int(port.Host))
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: duplicate host port", core.ErrConflict)
		}
		seen[key] = struct{}{}
		out = append(out, port)
	}
	return out, nil
}

func normalizePortEndpoint(protocol, hostIP string) (string, string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = tcpProtocol
	}
	explicitFamily := ""
	switch protocol {
	case tcpProtocol, udpProtocol:
	case tcp4Protocol, udp4Protocol:
		explicitFamily = "4"
		if protocol == tcp4Protocol {
			protocol = tcpProtocol
		} else {
			protocol = udpProtocol
		}
	case tcp6Protocol, udp6Protocol:
		explicitFamily = "6"
		if protocol == tcp6Protocol {
			protocol = tcpProtocol
		} else {
			protocol = udpProtocol
		}
	default:
		return "", "", fmt.Errorf("%w: port protocol must be tcp, udp, tcp4, udp4, tcp6 or udp6", core.ErrConflict)
	}
	if hostIP == "" {
		hostIP = "127.0.0.1"
		if explicitFamily == "6" {
			hostIP = "::1"
		}
	}
	ip := net.ParseIP(hostIP)
	if ip == nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("%w: host IP must be loopback (127.0.0.1 or ::1)", core.ErrConflict)
	}
	family := "4"
	if ip.To4() == nil {
		family = "6"
	}
	if explicitFamily != "" && explicitFamily != family {
		return "", "", fmt.Errorf("%w: host IP family does not match port protocol", core.ErrConflict)
	}
	return protocol, ip.String(), nil
}

func runtimePorts(ports []sandbox.Port) []runtime.Port {
	out := make([]runtime.Port, 0, len(ports))
	for i := range ports {
		out = append(out, runtime.Port{Host: ports[i].Host, Guest: ports[i].Guest, Protocol: ports[i].Protocol, HostIP: ports[i].HostIP})
	}
	return out
}

func portConflictKey(port sandbox.Port) string {
	hostIP := port.HostIP
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	return port.Protocol + ":" + hostIP + ":" + strconv.Itoa(int(port.Host))
}

func sandboxAgent(sb sandbox.Sandbox) string {
	if sb.Meta == nil {
		return ""
	}
	return sb.Meta.Agent
}

func sandboxDetached(sb sandbox.Sandbox) bool {
	return sb.Meta != nil && sb.Meta.Detached
}

func normalizeCreateNetwork(req CreateRequest) ([]sandbox.Port, []sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	ports, err := normalizePorts(req.Ports)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := checkHostPorts(ports); err != nil {
		return nil, nil, nil, err
	}
	allow, deny, err := normalizeCreateRules(req)
	if err != nil {
		return nil, nil, nil, err
	}
	return ports, allow, deny, nil
}

func checkHostPorts(ports []sandbox.Port) error {
	for _, port := range ports {
		closeProbe, err := probeHostPort(port)
		if err != nil {
			return err
		}
		if err := closeProbe(); err != nil {
			return fmt.Errorf("release host port %d probe: %w", port.Host, err)
		}
	}
	return nil
}

func probeHostPort(port sandbox.Port) (func() error, error) {
	address := net.JoinHostPort(port.HostIP, strconv.Itoa(int(port.Host)))
	network := tcp4Protocol
	if net.ParseIP(port.HostIP).To4() == nil {
		network = tcp6Protocol
	}
	if port.Protocol == udpProtocol {
		if network == tcp6Protocol {
			network = udp6Protocol
		} else {
			network = udp4Protocol
		}
		packet, err := net.ListenPacket(network, address)
		if err != nil {
			return nil, hostPortProbeError(port, err)
		}
		return packet.Close, nil
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, hostPortProbeError(port, err)
	}
	return listener.Close, nil
}

func hostPortProbeError(port sandbox.Port, err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "address already in use") || strings.Contains(message, "address in use") {
		return fmt.Errorf("%w: host port %s:%d/%s is already in use", core.ErrConflict, port.HostIP, port.Host, port.Protocol)
	}
	return fmt.Errorf("%w: host port %s:%d/%s is unavailable: %w", core.ErrConflict, port.HostIP, port.Host, port.Protocol, err)
}

func normalizeCreateRules(req CreateRequest) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	allow, err := normalizeRules(req.Allow)
	if err != nil {
		return nil, nil, err
	}
	deny, err := normalizeRules(req.Deny)
	if err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

func normalizeRules(rules []sandbox.NetworkRule) ([]sandbox.NetworkRule, error) {
	if len(rules) > 64 {
		return nil, fmt.Errorf("%w: too many network rules", core.ErrConflict)
	}
	out := make([]sandbox.NetworkRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Protocol == "" {
			rule.Protocol = tcpProtocol
		}
		if rule.Protocol != tcpProtocol && rule.Protocol != udpProtocol {
			return nil, fmt.Errorf("%w: network rule protocol must be tcp or udp", core.ErrConflict)
		}
		rule.Domain = normalizeDomainPattern(rule.Domain)
		switch {
		case rule.Domain != "" && rule.CIDR != "":
			return nil, fmt.Errorf("%w: network rule must specify either domain or CIDR, not both", core.ErrConflict)
		case rule.Domain != "":
			if err := validateDomainPattern(rule.Domain); err != nil {
				return nil, fmt.Errorf("%w: %w", core.ErrConflict, err)
			}
		default:
			ip, _, err := net.ParseCIDR(rule.CIDR)
			if err != nil || ip.To4() == nil {
				return nil, fmt.Errorf("%w: network rule CIDR must be IPv4", core.ErrConflict)
			}
		}
		key := rule.Protocol + "|" + rule.CIDR + "|" + rule.Domain + "|" + strconv.Itoa(int(rule.Port))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		rule.RuleID = networkRuleID(rule)
		out = append(out, rule)
	}
	return out, nil
}

func normalizeDomainPattern(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// validateDomainPattern accepts exact names, *.example.com,
// **.example.com, and single-label ? or [] globs. A bare * and backslashes are
// rejected so a rule cannot silently match nothing.
//
//nolint:gocognit,gocyclo,cyclop // one compact grammar validator is clearer than a dispatch table.
func validateDomainPattern(pattern string) error {
	if pattern == "" || len(pattern) > 253 || strings.ContainsAny(pattern, "\\ ") {
		return fmt.Errorf("invalid domain rule %q", pattern)
	}
	// Domain rules match TLS hostnames. An IP literal here would be a rule
	// that can never match; callers must send a CIDR instead.
	if net.ParseIP(pattern) != nil {
		return fmt.Errorf("domain rule %q is an IP literal; use a CIDR rule", pattern)
	}
	base := pattern
	switch {
	case strings.HasPrefix(base, "**."):
		base = strings.TrimPrefix(base, "**.")
	case strings.HasPrefix(base, "*."):
		base = strings.TrimPrefix(base, "*.")
	}
	if base == "" || base == "*" || strings.Contains(base, "*") {
		return fmt.Errorf("invalid domain rule %q", pattern)
	}
	for _, label := range strings.Split(base, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid domain rule %q", pattern)
		}
		if strings.ContainsAny(label, "[]!?") {
			if !strings.Contains(label, "?") && !strings.Contains(label, "[") {
				return fmt.Errorf("invalid domain rule %q", pattern)
			}
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '?' || r == '[' || r == ']' || r == '!' {
				continue
			}
			return fmt.Errorf("invalid domain rule %q", pattern)
		}
	}
	return nil
}

func networkRuleID(rule sandbox.NetworkRule) string {
	sum := sha256.Sum256([]byte(rule.Protocol + "\x00" + rule.CIDR + "\x00" + rule.Domain + "\x00" + strconv.Itoa(int(rule.Port))))
	return "rul_" + hex.EncodeToString(sum[:8])
}

func networkPolicy(allow, deny []sandbox.NetworkRule) *sandbox.NetworkPolicy {
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return &sandbox.NetworkPolicy{Allow: allow, Deny: deny}
}

func policyAllow(policy *sandbox.NetworkPolicy) []sandbox.NetworkRule {
	if policy == nil {
		return nil
	}
	return policy.Allow
}

func policyDeny(policy *sandbox.NetworkPolicy) []sandbox.NetworkRule {
	if policy == nil {
		return nil
	}
	return policy.Deny
}

func runtimeRules(rules []sandbox.NetworkRule) []runtime.Rule {
	out := make([]runtime.Rule, 0, len(rules))
	for i := range rules {
		out = append(out, runtime.Rule{ID: rules[i].RuleID, Protocol: rules[i].Protocol, CIDR: rules[i].CIDR, Port: rules[i].Port, Domain: rules[i].Domain})
	}
	return out
}

func rulesEqual(a, b []sandbox.NetworkRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func portsEqual(a, b []sandbox.Port) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func workspacesEqual(a, b []sandbox.Workspace) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validSandboxName(name string) bool {
	if name == "" || len(name) > 63 || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func (s *Service) cleanupCreateFailure(ctx context.Context, handle runtime.Handle, createErr error) error {
	if s.backend == nil {
		return createErr
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.backend.Delete(cleanupCtx, handle); err != nil {
		return errors.Join(createErr, fmt.Errorf("cleanup failed after sandbox create: %w", err))
	}
	return createErr
}

func (s *Service) ensureNameAvailable(ctx context.Context, name string) error {
	_, err := s.store.GetByName(ctx, name)
	if err == nil {
		return fmt.Errorf("%w: sandbox name already exists", core.ErrConflict)
	}
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	return err
}

// acquireCreateGates serializes matching names and keys without holding a
// database transaction across runtime I/O. Fixed stripes bound memory use.
func (s *Service) acquireCreateGates(ctx context.Context, name, key string) (func(), error) {
	nameHash := sha256.Sum256([]byte("name:" + name))
	first := int(nameHash[0]) % len(s.createGates)
	second := first
	if key != "" {
		keyHash := sha256.Sum256([]byte("key:" + key))
		second = int(keyHash[0]) % len(s.createGates)
	}
	if first > second {
		first, second = second, first
	}
	acquired := make([]chan struct{}, 0, 2)
	release := func() {
		for i := len(acquired) - 1; i >= 0; i-- {
			<-acquired[i]
		}
	}
	for _, index := range []int{first, second} {
		gate := s.createGates[index]
		if len(acquired) > 0 && gate == acquired[0] {
			continue
		}
		select {
		case gate <- struct{}{}:
			acquired = append(acquired, gate)
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

const (
	maxCreateEnvEntries = 256
	maxCreateEnvEntry   = 64 * 1024
	maxCreateEnvTotal   = 256 * 1024
)

func normalizeCreateEnv(input map[string]string) ([]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if len(input) > maxCreateEnvEntries {
		return nil, fmt.Errorf("%w: too many environment entries", core.ErrConflict)
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	total := 0
	for _, key := range keys {
		value := input[key]
		if !validCreateEnvName(key) {
			return nil, fmt.Errorf("%w: invalid environment name", core.ErrConflict)
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("%w: environment value contains NUL", core.ErrConflict)
		}
		entry := key + "=" + value
		if len(entry) > maxCreateEnvEntry {
			return nil, fmt.Errorf("%w: environment entry is too large", core.ErrConflict)
		}
		total += len(entry)
		if total > maxCreateEnvTotal {
			return nil, fmt.Errorf("%w: environment is too large", core.ErrConflict)
		}
		env = append(env, entry)
	}
	return env, nil
}

func validCreateEnvName(name string) bool {
	if name == "" || len(name) > 255 || !createEnvNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !createEnvNameChar(name[i]) {
			return false
		}
	}
	return true
}

func createEnvNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func createEnvNameChar(c byte) bool {
	return createEnvNameStart(c) || (c >= '0' && c <= '9')
}

const (
	policyProfileSetting  = "policy.profile"
	policyProfileDenyAll  = "deny-all"
	policyProfileBalanced = "balanced"
	policyProfileAllowAll = "allow-all"
	anyIPv4CIDR           = "0.0.0.0/0"
)

func (s *Service) normalizeCreatePolicy(ctx context.Context, req CreateRequest) (string, []sandbox.Port, []sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	ports, allow, deny, err := normalizeCreateNetwork(req)
	if err != nil {
		return "", nil, nil, nil, err
	}
	profile, rules, err := s.resolveCreateProfile(ctx, req.PolicyProfile)
	if err != nil {
		return "", nil, nil, nil, err
	}
	allow, err = normalizeRules(mergePolicyRules(rules, allow))
	if err != nil {
		return "", nil, nil, nil, err
	}
	deny, err = normalizeRules(deny)
	if err != nil {
		return "", nil, nil, nil, err
	}
	return profile, ports, allow, deny, nil
}

// effectivePolicy combines global rules with the sandbox snapshot. Global
// rules are never copied into the stored snapshot, so changing them affects
// only the live gateway and future starts.
func (s *Service) effectivePolicy(ctx context.Context, sb sandbox.Sandbox) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	return s.effectiveRules(ctx, policyAllow(sb.Policy), policyDeny(sb.Policy))
}

func (s *Service) effectiveRules(ctx context.Context, allow, deny []sandbox.NetworkRule) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	globalAllow, globalDeny, err := s.GlobalPolicy(ctx)
	if err != nil {
		return nil, nil, err
	}
	effectiveAllow, err := normalizeRules(mergePolicyRules(globalAllow, allow))
	if err != nil {
		return nil, nil, err
	}
	effectiveDeny, err := normalizeRules(mergePolicyRules(globalDeny, deny))
	if err != nil {
		return nil, nil, err
	}
	return effectiveAllow, effectiveDeny, nil
}

const (
	globalAllowSetting = "policy.global.allow"
	globalDenySetting  = "policy.global.deny"
)

// GlobalPolicy returns the global network rules applied to every new sandbox.
func (s *Service) GlobalPolicy(ctx context.Context) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	allow, err := s.loadGlobalRules(ctx, globalAllowSetting)
	if err != nil {
		return nil, nil, err
	}
	deny, err := s.loadGlobalRules(ctx, globalDenySetting)
	if err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

func (s *Service) loadGlobalRules(ctx context.Context, key string) ([]sandbox.NetworkRule, error) {
	encoded, err := s.store.GetSetting(ctx, key)
	if errors.Is(err, core.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rules []sandbox.NetworkRule
	if err := json.Unmarshal([]byte(encoded), &rules); err != nil {
		return nil, fmt.Errorf("%w: global policy %s is corrupt", core.ErrConflict, key)
	}
	return normalizeRules(rules)
}

// MutateGlobalPolicy changes one global rule. Deny wins at connection time.
func (s *Service) MutateGlobalPolicy(ctx context.Context, action string, rule sandbox.NetworkRule) ([]sandbox.NetworkRule, []sandbox.NetworkRule, error) {
	s.globalPolicyMu.Lock()
	defer s.globalPolicyMu.Unlock()
	allow, deny, err := s.GlobalPolicy(ctx)
	if err != nil {
		return nil, nil, err
	}
	normalized, err := normalizeRules([]sandbox.NetworkRule{rule})
	if err != nil || len(normalized) != 1 {
		return nil, nil, fmt.Errorf("%w: invalid policy rule", core.ErrConflict)
	}
	rule = normalized[0]
	switch action {
	case "allow":
		if slices.Contains(allow, rule) {
			return nil, nil, fmt.Errorf("%w: allow rule already exists", core.ErrConflict)
		}
		allow = append(allow, rule)
	case "deny":
		if slices.Contains(deny, rule) {
			return nil, nil, fmt.Errorf("%w: deny rule already exists", core.ErrConflict)
		}
		deny = append(deny, rule)
	case "rm":
		if !slices.Contains(allow, rule) && !slices.Contains(deny, rule) {
			return nil, nil, fmt.Errorf("%w: policy rule not found", core.ErrConflict)
		}
		allow = slices.DeleteFunc(allow, func(r sandbox.NetworkRule) bool { return r == rule })
		deny = slices.DeleteFunc(deny, func(r sandbox.NetworkRule) bool { return r == rule })
	default:
		return nil, nil, fmt.Errorf("%w: invalid policy action", core.ErrConflict)
	}
	if err := s.storeGlobalRules(ctx, globalAllowSetting, allow); err != nil {
		return nil, nil, err
	}
	if err := s.storeGlobalRules(ctx, globalDenySetting, deny); err != nil {
		return nil, nil, err
	}
	s.globalPolicyMu.Unlock()
	err = s.refreshRunningPolicies(ctx)
	s.globalPolicyMu.Lock()
	if err != nil {
		return allow, deny, err
	}
	return allow, deny, nil
}

// refreshRunningPolicies applies a changed global policy to running sandboxes.
// A failed reload stops that sandbox rather than leaving old rules active.
func (s *Service) refreshRunningPolicies(ctx context.Context) error {
	sandboxes, _, err := s.store.List(ctx, sandbox.ListOptions{PageSize: 1000})
	if err != nil {
		return err
	}
	var failures []error
	for i := range sandboxes {
		sb := sandboxes[i]
		if sb.State != sandbox.Running {
			continue
		}
		if _, err := s.UpdatePolicy(ctx, sb.ID, policyAllow(sb.Policy), policyDeny(sb.Policy)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) storeGlobalRules(ctx context.Context, key string, rules []sandbox.NetworkRule) error {
	encoded, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("encode global policy: %w", err)
	}
	return s.store.SetSetting(ctx, key, string(encoded))
}

// GetPolicyProfile returns the global default profile for new sandboxes.
func (s *Service) GetPolicyProfile(ctx context.Context) (string, error) {
	profile, err := s.store.GetSetting(ctx, policyProfileSetting)
	if errors.Is(err, core.ErrNotFound) {
		if s.DefaultPolicyProfile != "" {
			return s.DefaultPolicyProfile, nil
		}
		return policyProfileDenyAll, nil
	}
	if err != nil {
		return "", err
	}
	if profile == "" {
		if s.DefaultPolicyProfile != "" {
			return s.DefaultPolicyProfile, nil
		}
		return policyProfileDenyAll, nil
	}
	return profile, nil
}

// SetPolicyProfile stores the global default profile for new sandboxes.
func (s *Service) SetPolicyProfile(ctx context.Context, profile string) (string, error) {
	profile, _, err := normalizePolicyProfile(profile)
	if err != nil {
		return "", err
	}
	if err := s.store.SetSetting(ctx, policyProfileSetting, profile); err != nil {
		return "", err
	}
	return profile, nil
}

func (s *Service) resolveCreateProfile(ctx context.Context, requested string) (string, []sandbox.NetworkRule, error) {
	profile := requested
	if profile == "" {
		var err error
		profile, err = s.GetPolicyProfile(ctx)
		if err != nil {
			return "", nil, err
		}
	}
	normalized, rules, err := normalizePolicyProfile(profile)
	if err != nil {
		return "", nil, err
	}
	return normalized, rules, nil
}

func normalizePolicyProfile(profile string) (string, []sandbox.NetworkRule, error) {
	switch profile {
	case "", policyProfileDenyAll:
		return policyProfileDenyAll, nil, nil
	case policyProfileAllowAll, "sbx-compat":
		return policyProfileAllowAll, []sandbox.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR},
			{Protocol: "udp", CIDR: anyIPv4CIDR},
		}, nil
	case policyProfileBalanced:
		return policyProfileBalanced, []sandbox.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 80},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 443},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 53},
			{Protocol: "udp", CIDR: anyIPv4CIDR, Port: 53},
		}, nil
	default:
		return "", nil, fmt.Errorf("%w: unknown policy profile", core.ErrConflict)
	}
}

func mergePolicyRules(profile, explicit []sandbox.NetworkRule) []sandbox.NetworkRule {
	out := append([]sandbox.NetworkRule(nil), profile...)
	seen := make(map[sandbox.NetworkRule]struct{}, len(out))
	for _, rule := range out {
		seen[rule] = struct{}{}
	}
	for _, rule := range explicit {
		if _, exists := seen[rule]; exists {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	return out
}

func (s *Service) setDockerProfile(ctx context.Context, id string, enabled bool) error {
	if !enabled {
		return nil
	}
	return s.store.SetSetting(ctx, dockerSettingKey(id), "true")
}

func (s *Service) startRuntimeSandbox(ctx context.Context, sb sandbox.Sandbox) error {
	allow, deny, err := s.effectivePolicy(ctx, sb)
	if err != nil {
		return err
	}
	if err := s.prepareStoredProxy(ctx, sb); err != nil {
		return err
	}
	handle := s.backend.Handle(sb.Name)
	handle.Ports = runtimePorts(sb.Ports)
	handle.Allow = runtimeRules(allow)
	handle.Deny = runtimeRules(deny)
	if err := s.backend.Start(ctx, handle); err != nil {
		return err
	}
	enabled, err := s.dockerProfileEnabled(ctx, sb.ID)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	return s.startDockerProfile(ctx, handle)
}

func dockerSettingKey(id string) string { return "sandbox.docker." + id }

func (s *Service) dockerProfileEnabled(ctx context.Context, id string) (bool, error) {
	value, err := s.store.GetSetting(ctx, dockerSettingKey(id))
	if errors.Is(err, core.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value == "true", nil
}

func (s *Service) resolveMkfs() string {
	if s.MkfsExt4 != "mkfs.ext4" {
		return s.MkfsExt4
	}
	if resolved, err := exec.LookPath(s.MkfsExt4); err == nil {
		return resolved
	}
	for _, candidate := range []string{
		"/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
		"/usr/local/opt/e2fsprogs/sbin/mkfs.ext4",
		"/sbin/mkfs.ext4",
		"/usr/sbin/mkfs.ext4",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return s.MkfsExt4
}

func (s *Service) removeDockerVolume(id string) error {
	if s.DockerVolumeDir == "" {
		return nil
	}
	err := os.Remove(filepath.Join(s.DockerVolumeDir, id+".ext4"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove docker volume: %w", err)
	}
	return nil
}

func (s *Service) ensureDockerVolume(ctx context.Context, id string) (string, error) {
	if s.DockerVolumeDir == "" {
		return "", errors.New("docker volume directory is not configured")
	}
	if err := os.MkdirAll(s.DockerVolumeDir, 0o700); err != nil {
		return "", fmt.Errorf("create docker volume directory: %w", err)
	}
	path := filepath.Join(s.DockerVolumeDir, id+".ext4")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat docker volume: %w", err)
	}
	size, err := parseVolumeSize(s.DockerVolumeSize)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // path is generated from the trusted state directory and sandbox ID
	if err != nil {
		return "", fmt.Errorf("create docker volume: %w", err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("size docker volume: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close docker volume: %w", err)
	}
	mkfs := s.resolveMkfs()
	command := exec.CommandContext(ctx, mkfs, "-q", "-F", path) // #nosec G204 -- operator-configured binary and generated path
	if output, err := command.CombinedOutput(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("mkfs docker volume: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return path, nil
}

func parseVolumeSize(value string) (int64, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		value = "10g"
	}
	multiplier := int64(1)
	switch value[len(value)-1] {
	case 'g':
		multiplier = 1 << 30
		value = value[:len(value)-1]
	case 'm':
		multiplier = 1 << 20
		value = value[:len(value)-1]
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid docker volume size %q", value)
	}
	size := n * multiplier
	if size < 512<<20 {
		return 0, fmt.Errorf("docker volume size must be at least 512 MiB")
	}
	return size, nil
}

func (s *Service) ensureDockerProfile(ctx context.Context, enabled bool, handle runtime.Handle) error {
	if !enabled {
		return nil
	}
	return s.startDockerProfile(ctx, handle)
}

func (s *Service) startDockerProfile(ctx context.Context, handle runtime.Handle) error {
	native, ok := s.backend.(runtime.NativeExecutor)
	if !ok {
		return errors.New("runtime does not support native docker profile startup")
	}
	script := `mkdir -p /sys/fs/cgroup
mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup
mount -o remount,rw /proc/sys 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
setsid dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &
for i in $(seq 1 50); do docker info >/dev/null 2>&1 && exit 0; sleep 0.2; done
exit 1
`
	if code, err := native.ExecNative(ctx, handle, runtime.ExecRequest{
		Argv: []string{"/bin/sh", "-c", script}, User: "0:0",
	}); err != nil || code != 0 {
		return fmt.Errorf("start dockerd: code=%d err=%w", code, err)
	}
	return nil
}

type createIntent struct {
	name         string
	image        string
	workspace    string
	workspaces   []sandbox.Workspace
	ports        []sandbox.Port
	allow        []sandbox.NetworkRule
	deny         []sandbox.NetworkRule
	agent        string
	detached     bool
	cpus         uint32
	memoryMiB    uint32
	proxyService string
}

func (s *Service) replayCreate(ctx context.Context, key string, intent createIntent) (operation.Operation, error) {
	op, err := s.store.Operations().GetByIdempotencyKey(ctx, key)
	if err != nil {
		return operation.Operation{}, err
	}
	sb, err := s.store.Get(ctx, op.SandboxID)
	if errors.Is(err, core.ErrNotFound) {
		return operation.Operation{}, fmt.Errorf("%w: idempotency key refers to a removed sandbox", core.ErrConflict)
	}
	if err != nil {
		return operation.Operation{}, err
	}
	proxyService, proxyErr := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if errors.Is(proxyErr, core.ErrNotFound) {
		proxyService = ""
	} else if proxyErr != nil {
		return operation.Operation{}, proxyErr
	}
	if op.Kind != operation.KindCreate || !matchesCreateIntent(sb, intent) || proxyService != intent.proxyService {
		return operation.Operation{}, fmt.Errorf("%w: idempotency key was used for a different request", core.ErrConflict)
	}
	return op, nil
}

func matchesCreateIntent(sb sandbox.Sandbox, intent createIntent) bool {
	return sb.Name == intent.name && sb.Image == intent.image && sb.Workspace == intent.workspace &&
		sb.CPUs == intent.cpus && sb.MemoryMiB == intent.memoryMiB &&
		workspacesEqual(sb.Workspaces, intent.workspaces) && portsEqual(sb.Ports, intent.ports) &&
		rulesEqual(policyAllow(sb.Policy), intent.allow) && rulesEqual(policyDeny(sb.Policy), intent.deny) &&
		sandboxAgent(sb) == intent.agent && sandboxDetached(sb) == intent.detached
}

// Reconcile repairs state left behind by an interrupted daemon.
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	now := s.now().UTC()
	changed := 0
	all, err := s.listAll(ctx)
	if err != nil {
		return 0, err
	}
	for i := range all {
		sb := all[i]
		switch sb.State {
		case sandbox.Running, sandbox.Creating, sandbox.Deleting:
			sb.State = sandbox.Unknown
			sb.Error = "daemon restarted; runtime state is unknown"
			sb.UpdatedAt = now
			if err := s.store.Update(ctx, sb); err != nil {
				return changed, err
			}
			changed++
		}
	}
	unfinished, err := s.store.Operations().ListUnfinished(ctx)
	if err != nil {
		return changed, err
	}
	for i := range unfinished {
		op := unfinished[i]
		if err := s.journal.Fail(ctx, op.ID, "daemon restarted"); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// Get returns a sandbox by ID.
func (s *Service) Get(ctx context.Context, id string) (sandbox.Sandbox, error) {
	return s.store.Get(ctx, id)
}

// GetByName returns a sandbox by name.
func (s *Service) GetByName(ctx context.Context, name string) (sandbox.Sandbox, error) {
	return s.store.GetByName(ctx, name)
}

// List returns one page of sandboxes.
func (s *Service) List(ctx context.Context, opts sandbox.ListOptions) ([]sandbox.Sandbox, string, error) {
	return s.store.List(ctx, opts)
}

// Start transitions a sandbox to running.
func (s *Service) Start(ctx context.Context, id string) (operation.Operation, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	defer release()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if sb.State == sandbox.Running {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is already running", core.ErrConflict)
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	if s.backend != nil {
		if err := s.prepareSandboxForStart(ctx, sb); err != nil {
			return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
		}
	}
	op, err := s.apply(ctx, sb, operation.KindStart, sandbox.Running)
	if err != nil && s.backend != nil {
		return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
	}
	return op, err
}

func (s *Service) prepareSandboxForStart(ctx context.Context, sb sandbox.Sandbox) error {
	if err := s.stopUnknownProxySandbox(ctx, sb); err != nil {
		return err
	}
	return s.startRuntimeSandbox(ctx, sb)
}

func (s *Service) stopUnknownProxySandbox(ctx context.Context, sb sandbox.Sandbox) error {
	if sb.State != sandbox.Unknown {
		return nil
	}
	proxyConfigured, err := s.hasStoredProxy(ctx, sb)
	if err != nil || !proxyConfigured {
		return err
	}
	if err := s.backend.Stop(ctx, s.backend.Handle(sb.Name), 5*time.Second); err != nil {
		return fmt.Errorf("stop unknown proxy sandbox before restart: %w", err)
	}
	return nil
}

// UpdatePorts replaces the stored and live published ports.
func (s *Service) UpdatePorts(ctx context.Context, id string, ports []sandbox.Port) (sandbox.Sandbox, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	defer release()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	normalized, err := normalizePorts(ports)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	existing := make(map[string]struct{}, len(sb.Ports))
	for _, port := range sb.Ports {
		existing[portConflictKey(port)] = struct{}{}
	}
	for _, port := range normalized {
		if _, ok := existing[portConflictKey(port)]; ok {
			continue
		}
		if err := checkHostPorts([]sandbox.Port{port}); err != nil {
			return sandbox.Sandbox{}, err
		}
	}
	if sb.State == sandbox.Running {
		updater, ok := s.backend.(runtime.PortUpdater)
		if !ok {
			return sandbox.Sandbox{}, fmt.Errorf("%w: runtime does not support live port updates", core.ErrConflict)
		}
		handle := s.backend.Handle(sb.Name)
		handle.Ports = runtimePorts(normalized)
		if err := updater.UpdatePorts(ctx, handle, runtimePorts(normalized)); err != nil {
			return sandbox.Sandbox{}, s.markRuntimeUnknown(ctx, sb, err)
		}
	} else if sb.State != sandbox.Stopped {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is not ready for a port update", core.ErrConflict)
	}
	sb.Ports = normalized
	sb.UpdatedAt = s.now().UTC()
	if err := s.store.Update(ctx, sb); err != nil {
		return sandbox.Sandbox{}, err
	}
	return sb, nil
}

// MutatePolicy applies one rule while holding the sandbox lifecycle gate.
func (s *Service) MutatePolicy(ctx context.Context, id, action string, rule sandbox.NetworkRule) (sandbox.Sandbox, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	defer release()
	normalized, err := normalizeRules([]sandbox.NetworkRule{rule})
	if err != nil || len(normalized) != 1 {
		return sandbox.Sandbox{}, fmt.Errorf("%w: invalid policy rule", core.ErrConflict)
	}
	rule = normalized[0]
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	allow := append([]sandbox.NetworkRule(nil), policyAllow(sb.Policy)...)
	deny := append([]sandbox.NetworkRule(nil), policyDeny(sb.Policy)...)
	switch action {
	case "allow":
		if slices.Contains(allow, rule) {
			return sandbox.Sandbox{}, fmt.Errorf("%w: allow rule already exists", core.ErrConflict)
		}
		allow = append(allow, rule)
	case "deny":
		if slices.Contains(deny, rule) {
			return sandbox.Sandbox{}, fmt.Errorf("%w: deny rule already exists", core.ErrConflict)
		}
		deny = append(deny, rule)
	case "rm":
		if !slices.Contains(allow, rule) && !slices.Contains(deny, rule) {
			return sandbox.Sandbox{}, fmt.Errorf("%w: policy rule not found", core.ErrConflict)
		}
		allow = slices.DeleteFunc(allow, func(r sandbox.NetworkRule) bool { return r == rule })
		deny = slices.DeleteFunc(deny, func(r sandbox.NetworkRule) bool { return r == rule })
	default:
		return sandbox.Sandbox{}, fmt.Errorf("%w: invalid policy action", core.ErrConflict)
	}
	return s.updatePolicyLocked(ctx, id, allow, deny)
}

// UpdatePolicy replaces the stored and live egress policy for internal callers.
func (s *Service) UpdatePolicy(ctx context.Context, id string, allow, deny []sandbox.NetworkRule) (sandbox.Sandbox, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	defer release()
	return s.updatePolicyLocked(ctx, id, allow, deny)
}

func (s *Service) updatePolicyLocked(ctx context.Context, id string, allow, deny []sandbox.NetworkRule) (sandbox.Sandbox, error) {
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	normalizedAllow, err := normalizeRules(allow)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	normalizedDeny, err := normalizeRules(deny)
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	revision := int(s.now().UnixNano())
	if revision <= 1 {
		revision = 2
	}
	if sb.State != sandbox.Running && sb.State != sandbox.Stopped {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is not ready for a policy update", core.ErrConflict)
	}
	//nolint:nestif // live update persists uncertain state before touching the runtime.
	if sb.State == sandbox.Running {
		updater, ok := s.backend.(runtime.PolicyUpdater)
		if !ok {
			return sandbox.Sandbox{}, fmt.Errorf("%w: runtime does not support live policy updates", core.ErrConflict)
		}
		// Persist the intended policy and an uncertain runtime state before any
		// live change. A crash or a failed reload must never restore old rules.
		previousPolicy := sb.Policy
		sb.Policy = networkPolicy(normalizedAllow, normalizedDeny)
		sb.State = sandbox.Unknown
		sb.Error = "policy update in progress; runtime state is unknown"
		sb.UpdatedAt = s.now().UTC()
		if err := s.store.Update(ctx, sb); err != nil {
			return sandbox.Sandbox{}, err
		}
		allow, deny, policyErr := s.effectivePolicy(ctx, sb)
		if policyErr != nil {
			sb.Policy = previousPolicy
			return sandbox.Sandbox{}, policyErr
		}
		handle := s.backend.Handle(sb.Name)
		handle.Ports = runtimePorts(sb.Ports)
		if err := updater.UpdatePolicy(ctx, handle, runtimeRules(allow), runtimeRules(deny), revision); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			stopErr := s.backend.Stop(cleanupCtx, handle, 5*time.Second)
			cancel()
			return sandbox.Sandbox{}, s.markRuntimeUnknown(ctx, sb, errors.Join(err, stopErr))
		}
		sb.State = sandbox.Running
		sb.Error = ""
	}
	sb.Policy = networkPolicy(normalizedAllow, normalizedDeny)
	sb.UpdatedAt = s.now().UTC()
	if err := s.store.Update(ctx, sb); err != nil {
		return sandbox.Sandbox{}, err
	}
	return sb, nil
}

// Stop transitions a sandbox to stopped.
// StopSandboxByName stops a sandbox identified by its user-visible name. It is
// used when an external component, such as the sandbox gateway, is lost and
// the sandbox can no longer be trusted to have working network isolation.
func (s *Service) StopSandboxByName(ctx context.Context, name string) error {
	sb, err := s.store.GetByName(ctx, name)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil
		}
		return err
	}
	if sb.State != sandbox.Running && sb.State != sandbox.Unknown && sb.State != sandbox.Stopping {
		return nil
	}
	_, err = s.StopWithGrace(ctx, sb.ID, 2*time.Second)
	return err
}

func (s *Service) Stop(ctx context.Context, id string) (operation.Operation, error) {
	return s.StopWithGrace(ctx, id, 0)
}

// StopWithGrace transitions a sandbox to stopped using the requested grace period.
// Zero selects the default of five seconds.
func (s *Service) StopWithGrace(ctx context.Context, id string, grace time.Duration) (operation.Operation, error) {
	if grace < 0 || grace > time.Hour {
		return operation.Operation{}, fmt.Errorf("%w: invalid stop grace period", core.ErrConflict)
	}
	if grace == 0 {
		grace = 5 * time.Second
	}
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	defer release()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	if err := s.cancelExecSessions(ctx, id); err != nil {
		return operation.Operation{}, err
	}
	if s.backend != nil {
		if err := s.backend.Stop(ctx, s.backend.Handle(sb.Name), grace); err != nil {
			return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
		}
	}
	if err := s.stopProxyChannel(sb.Name, sb.ID, true); err != nil {
		return operation.Operation{}, err
	}
	op, err := s.apply(ctx, sb, operation.KindStop, sandbox.Stopped)
	if err != nil && s.backend != nil {
		return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
	}
	return op, err
}

// Delete removes a sandbox.
//
//nolint:gocyclo,cyclop // Delete orchestrates runtime teardown, persistence and volume cleanup.
func (s *Service) Delete(ctx context.Context, id string, force bool) (operation.Operation, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	defer release()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if !force && (sb.State == sandbox.Running || sb.State == sandbox.Unknown || sb.State == sandbox.Creating || sb.State == sandbox.Stopping) {
		return operation.Operation{}, fmt.Errorf("%w: sandbox may be running; force is required", core.ErrConflict)
	}
	if err := s.cancelExecSessions(ctx, id); err != nil {
		return operation.Operation{}, err
	}
	if s.backend != nil {
		if err := s.backend.Delete(ctx, s.backend.Handle(sb.Name)); err != nil {
			return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
		}
	}
	if err := s.stopProxyChannel(sb.Name, sb.ID, false); err != nil {
		return operation.Operation{}, err
	}
	now := s.now().UTC()
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	op := operation.Operation{
		ID:         opID,
		SandboxID:  id,
		Kind:       operation.KindDelete,
		State:      operation.Done,
		Generation: sb.Generation + 1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.DeleteSandboxWithOperation(ctx, id, op); err != nil {
		if s.backend != nil {
			return operation.Operation{}, s.markRuntimeUnknown(ctx, sb, err)
		}
		return operation.Operation{}, err
	}
	if err := s.store.DeleteSetting(ctx, proxyServiceSettingKey(id)); err != nil {
		return op, err
	}
	if err := s.stopProxyChannel(sb.Name, sb.ID, true); err != nil {
		return op, err
	}
	if err := s.cleanupSandboxServiceSecrets(ctx, sb.Name); err != nil {
		return op, err
	}
	if err := s.cleanupSandboxRegistryCredentials(ctx, sb.Name); err != nil {
		return op, err
	}
	if err := s.removeDockerVolume(id); err != nil {
		return op, err
	}
	return op, nil
}

func (s *Service) markRuntimeUnknown(ctx context.Context, sb sandbox.Sandbox, cause error) error {
	sb.State = sandbox.Unknown
	sb.Error = "runtime operation failed; actual state is unknown"
	sb.Generation++
	sb.UpdatedAt = s.now().UTC()
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.store.Update(cleanupCtx, sb); err != nil {
		return errors.Join(cause, fmt.Errorf("record unknown runtime state: %w", err))
	}
	return cause
}

func (s *Service) acquireLifecycle(ctx context.Context, id string) (func(), error) {
	sum := sha256.Sum256([]byte(id))
	gate := s.lifecycleGates[int(sum[0])%len(s.lifecycleGates)]
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetOperation returns an operation by ID.
func (s *Service) GetOperation(ctx context.Context, id string) (operation.Operation, error) {
	return s.store.Operations().Get(ctx, id)
}

// WaitOperation waits until an operation reaches a terminal state.
func (s *Service) WaitOperation(ctx context.Context, id string) (operation.Operation, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := s.GetOperation(ctx, id)
		if err != nil {
			return operation.Operation{}, err
		}
		if op.State == operation.Done || op.State == operation.Failed {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return operation.Operation{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) apply(ctx context.Context, sb sandbox.Sandbox, kind operation.Kind, state sandbox.State) (operation.Operation, error) {
	now := s.now().UTC()
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	sb.State = state
	switch state {
	case sandbox.Stopped:
		sb.StoppedAt = now
	case sandbox.Running:
		sb.StoppedAt = time.Time{}
	}
	if sb.Meta == nil {
		sb.Meta = &sandbox.Meta{}
	}
	if state == sandbox.Running {
		sb.Meta.LastUsedAt = now
	}
	sb.Generation++
	sb.UpdatedAt = now
	op := operation.Operation{
		ID:         opID,
		SandboxID:  sb.ID,
		Kind:       kind,
		State:      operation.Done,
		Generation: sb.Generation,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.ApplySandboxOperation(ctx, sb, op); err != nil {
		return operation.Operation{}, err
	}
	return op, nil
}

func (s *Service) listAll(ctx context.Context) ([]sandbox.Sandbox, error) {
	var out []sandbox.Sandbox
	token := ""
	for {
		items, next, err := s.store.List(ctx, sandbox.ListOptions{PageSize: 200, PageToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		token = next
	}
}

func newID(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
