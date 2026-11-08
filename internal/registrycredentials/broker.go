package registrycredentials

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

// PullRequest contains host-authorized inputs for a single registry pull. The
// sandbox identity, registry authority, realm and service must be selected by
// trusted host code after authenticating the caller and enforcing its policy.
type PullRequest struct {
	Registry    string
	Authority   string
	Scope       Scope
	SandboxName string
	Method      string
	URL         *url.URL
	Challenge   string
	Realms      []registryauth.Realm
	Service     string
}

// ExchangePullToken derives the repository scope from the actual pull request
// before reading credentials. The returned bearer token is a secret and must
// remain on the host. This is not a proxy or authorization gate.
func (s *Store) ExchangePullToken(ctx context.Context, transport http.RoundTripper, request PullRequest) (string, error) {
	if transport == nil {
		return "", errors.New("registry token transport is required")
	}
	registry, err := canonicalRegistry(request.Registry)
	if err != nil {
		return "", err
	}
	authority := request.Authority
	if authority == "" {
		authority = registry
	}
	scope, err := registryauth.PullScope(request.Method, request.URL, authority)
	if err != nil {
		return "", err
	}
	return s.exchangeToken(ctx, transport, registry, request.Scope, request.SandboxName, request.Challenge, request.Realms, request.Service, scope)
}

// ExchangeScopedToken obtains a bearer for a previously parsed, least-privilege
// repository scope. The caller must select the exact configured realm from the
// authenticated request's host/path and bind it to the sandbox before invoking
// this method.
func (s *Store) ExchangeScopedToken(ctx context.Context, transport http.RoundTripper, registry string, scope Scope, sandboxName, service, repositoryScope string, realm registryauth.Realm, realms []registryauth.Realm) (string, error) {
	if transport == nil || service == "" || len(realms) == 0 || !validRepositoryScope(repositoryScope) {
		return "", errors.New("invalid registry token scope")
	}
	registry, err := canonicalRegistry(registry)
	if err != nil {
		return "", err
	}
	if scope != ScopeSandbox && scope != ScopeAllSandboxes {
		return "", errors.New("registry scope is not authorized for guest access")
	}
	if scope == ScopeAllSandboxes {
		sandboxName = ""
	} else if _, _, err := validateScope(scope, sandboxName); err != nil {
		return "", err
	}
	realmURL := (&url.URL{Scheme: registryHTTPScheme, Host: realm.Host, Path: realm.Path}).String()
	header := fmt.Sprintf(`Bearer realm=%q,service=%q,scope=%q`, realmURL, service, repositoryScope)
	if _, err := registryauth.ParseBearerChallenge(header, realms); err != nil {
		return "", errors.New("registry token realm is not configured")
	}
	return s.exchangeToken(ctx, transport, registry, scope, sandboxName, header, realms, service, repositoryScope)
}

func validRepositoryScope(value string) bool {
	separator := strings.LastIndex(value, ":")
	if separator <= 0 || separator == len(value)-1 {
		return false
	}
	resource, actions := value[:separator], value[separator+1:]
	if !strings.HasPrefix(resource, "repository:") {
		return false
	}
	name := strings.TrimPrefix(resource, "repository:")
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "?#%\\\x00\r\n") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || !validRepoComponent(component) {
			return false
		}
	}
	if actions == "" {
		return false
	}
	seen := make(map[string]struct{}, 2)
	for _, action := range strings.Split(actions, ",") {
		if action != registryActionPull && action != registryActionPush {
			return false
		}
		if _, exists := seen[action]; exists {
			return false
		}
		seen[action] = struct{}{}
	}
	return true
}

func validRepoComponent(value string) bool {
	if value == "" || len(value) > 255 || !lowerAlphaNumeric(value[0]) || !lowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for i := range value {
		char := value[i]
		if !lowerAlphaNumeric(char) && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// exchangeToken obtains a token using the exact credential scope selected by a
// trusted host caller. The returned bearer token is a secret and must remain on
// the host; the caller must not disclose it to a guest.
func (s *Store) exchangeToken(ctx context.Context, transport http.RoundTripper, registry string, scope Scope, sandboxName, challenge string, realms []registryauth.Realm, service, repositoryScope string) (string, error) {
	parsed, err := registryauth.ParseBearerChallenge(challenge, realms)
	if err != nil {
		return "", err
	}
	if service == "" || repositoryScope == "" || parsed.Service != service || parsed.Scope != repositoryScope || transport == nil {
		return "", errors.New("registry challenge does not match authorized request")
	}
	credential, err := s.Load(ctx, registry, scope, sandboxName)
	if err != nil {
		return "", err
	}
	defer clear(credential.Password)
	return registryauth.Exchange(ctx, transport, challenge, realms, service, repositoryScope, credential.Username, string(credential.Password))
}
