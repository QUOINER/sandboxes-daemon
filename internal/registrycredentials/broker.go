package registrycredentials

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/KLORQ/sandboxes-gateway/registryauth"
)

// PullRequest contains host-authorized inputs for a single registry pull. The
// sandbox identity, registry authority, realm and service must be selected by
// trusted host code after authenticating the caller and enforcing its policy.
type PullRequest struct {
	Registry    string
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
func (s *Store) ExchangePullToken(ctx context.Context, transport *registryauth.TokenTransport, request PullRequest) (string, error) {
	if transport == nil {
		return "", errors.New("registry token transport is required")
	}
	registry, err := canonicalRegistry(request.Registry)
	if err != nil {
		return "", err
	}
	scope, err := registryauth.PullScope(request.Method, request.URL, registry)
	if err != nil {
		return "", err
	}
	return s.exchangeToken(ctx, transport, registry, request.Scope, request.SandboxName, request.Challenge, request.Realms, request.Service, scope)
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
