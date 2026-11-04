package registrycredentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

// PullProxy is a host-side, read-only registry handler bound to an identity
// selected by trusted host code. It must not be exposed until the listener is
// securely bound to that sandbox and its network policy is enforced.
type PullProxy struct {
	store             *Store
	registry          string
	authority         string
	sandboxName       string
	credentialScope   Scope
	service           string
	realms            []registryauth.Realm
	registryTransport *registryauth.RegistryTransport
	tokenTransport    *registryauth.TokenTransport
	transportFactory  PullProxyTransportFactory
	maxBytes          int64
	inflight          chan struct{}
}

// PullProxyTransportFactory creates host-only HTTPS transports for the
// configured registry and a realm already accepted by the trusted allowlist.
type PullProxyTransportFactory interface {
	Registry(context.Context, string) (*registryauth.RegistryTransport, error)
	Token(context.Context, registryauth.Realm) (*registryauth.TokenTransport, error)
	Redirect(context.Context, string) (http.RoundTripper, error)
}

const maxPullResponseBytes = 16 << 30

// PullProxyConfig is trusted host configuration, never a guest request.
type PullProxyConfig struct {
	Registry          string
	Authority         string
	SandboxName       string
	CredentialScope   Scope
	Service           string
	Realms            []registryauth.Realm
	RegistryTransport *registryauth.RegistryTransport
	TokenTransport    *registryauth.TokenTransport
	TransportFactory  PullProxyTransportFactory
	MaxBytes          int64
}

// NewPullProxy requires a sandbox-scoped or all-sandboxes credential; host-only
// credentials cannot be used for guest traffic.
func NewPullProxy(store *Store, cfg PullProxyConfig) (*PullProxy, error) {
	registry, err := canonicalRegistry(cfg.Registry)
	if err != nil {
		return nil, err
	}
	authority := cfg.Authority
	if authority == "" {
		authority = registry
	}
	parsedAuthority, authorityErr := url.Parse("https://" + authority)
	if authorityErr != nil || parsedAuthority.Host != authority || parsedAuthority.Hostname() == "" || parsedAuthority.User != nil ||
		parsedAuthority.Path != "" || parsedAuthority.RawQuery != "" || parsedAuthority.Fragment != "" {
		return nil, errors.New("invalid pull proxy authority")
	}
	if !validPullProxyConfig(store, cfg) {
		return nil, errors.New("invalid pull proxy configuration")
	}
	if _, _, err := validateScope(ScopeSandbox, cfg.SandboxName); err != nil {
		return nil, errors.New("invalid pull proxy sandbox identity")
	}
	return &PullProxy{store: store, registry: registry, authority: authority, sandboxName: cfg.SandboxName, credentialScope: cfg.CredentialScope,
		service: cfg.Service, realms: append([]registryauth.Realm(nil), cfg.Realms...), registryTransport: cfg.RegistryTransport,
		tokenTransport: cfg.TokenTransport, transportFactory: cfg.TransportFactory,
		maxBytes: cfg.MaxBytes, inflight: make(chan struct{}, 4)}, nil
}

func validPullProxyConfig(store *Store, cfg PullProxyConfig) bool {
	return store != nil && cfg.SandboxName != "" && cfg.Service != "" && len(cfg.Realms) != 0 &&
		(cfg.TransportFactory != nil || (cfg.RegistryTransport != nil && cfg.TokenTransport != nil)) &&
		cfg.MaxBytes > 0 && cfg.MaxBytes <= maxPullResponseBytes &&
		(cfg.CredentialScope == ScopeSandbox || cfg.CredentialScope == ScopeAllSandboxes)
}

// ServeHTTP accepts only read-only registry pull requests and does not forward
// guest-provided authorization headers. It never returns the upstream token.
func (p *PullProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	endpoint := &url.URL{Scheme: "https", Host: p.authority, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	probe := endpoint.Path == "/v2/" && endpoint.RawPath == "" && endpoint.RawQuery == "" && !endpoint.ForceQuery && r.URL.Fragment == "" && r.URL.Opaque == "" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead)
	if _, err := registryauth.PullScope(r.Method, endpoint, p.authority); err != nil && !probe {
		http.Error(w, "unsupported registry request", http.StatusForbidden)
		return
	}
	p.serveAllowed(w, r, endpoint, probe)
}

func (p *PullProxy) serveAllowed(w http.ResponseWriter, r *http.Request, endpoint *url.URL, probe bool) {
	select {
	case p.inflight <- struct{}{}:
		defer func() { <-p.inflight }()
	case <-r.Context().Done():
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if probe {
		if err := p.probe(ctx, r, endpoint); err != nil {
			http.Error(w, "registry request failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	resp, err := p.pull(ctx, r, endpoint)
	if err != nil {
		http.Error(w, "registry request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if err := p.writeResponse(w, r.Method, resp); err != nil {
		return
	}
}

func (p *PullProxy) probe(ctx context.Context, incoming *http.Request, endpoint *url.URL) error {
	transport, err := p.registryTransportFor(ctx)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := p.registryRequest(ctx, client, incoming, endpoint, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	challenges := resp.Header.Values("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || len(challenges) != 1 {
		return errors.New("registry probe failed")
	}
	challenge, err := registryauth.ParseBearerChallenge(challenges[0], p.realms)
	if err != nil || challenge.Service != p.service {
		return errors.New("registry probe returned an untrusted challenge")
	}
	return nil
}

func (p *PullProxy) writeResponse(w http.ResponseWriter, method string, resp *http.Response) error {
	if !allowedPullStatus(resp.StatusCode) {
		http.Error(w, "registry request failed", http.StatusBadGateway)
		return errors.New("registry returned an unsupported status")
	}
	if method != http.MethodHead && resp.StatusCode != http.StatusNotModified && (resp.ContentLength < 0 || resp.ContentLength > p.maxBytes) {
		http.Error(w, "registry response exceeds supported limits", http.StatusBadGateway)
		return errors.New("registry response length is unknown or exceeds the configured limit")
	}
	copyPullResponseHeaders(w.Header(), resp.Header)
	if resp.ContentLength >= 0 && (method == http.MethodHead || resp.StatusCode != http.StatusNotModified) {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	if method == http.MethodHead || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	written, err := io.CopyN(w, resp.Body, resp.ContentLength)
	if err != nil {
		return fmt.Errorf("stream registry response: %w", err)
	}
	if written != resp.ContentLength {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func allowedPullStatus(code int) bool {
	return code == http.StatusOK || code == http.StatusPartialContent || code == http.StatusNotModified
}

func (p *PullProxy) pull(ctx context.Context, incoming *http.Request, endpoint *url.URL) (*http.Response, error) {
	registryTransport, err := p.registryTransportFor(ctx)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: registryTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := p.registryRequest(ctx, client, incoming, endpoint, "")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenges := resp.Header.Values("WWW-Authenticate")
	_ = resp.Body.Close()
	if len(challenges) != 1 {
		return nil, errors.New("registry returned an invalid challenge")
	}
	challenge, err := registryauth.ParseBearerChallenge(challenges[0], p.realms)
	if err != nil || challenge.Service != p.service {
		return nil, errors.New("registry returned an untrusted challenge")
	}
	tokenTransport, err := p.tokenTransportFor(ctx, registryauth.Realm{Host: challenge.Realm.Host, Path: challenge.Realm.EscapedPath()})
	if err != nil {
		return nil, err
	}
	name := ""
	if p.credentialScope == ScopeSandbox {
		name = p.sandboxName
	}
	token, err := p.store.ExchangePullToken(ctx, tokenTransport, PullRequest{Registry: p.registry, Authority: p.authority, Scope: p.credentialScope,
		SandboxName: name, Method: incoming.Method, URL: endpoint, Challenge: challenges[0], Realms: p.realms, Service: p.service})
	if err != nil {
		return nil, err
	}
	return p.followPullRedirects(ctx, client, incoming, endpoint, token)
}

func (p *PullProxy) followPullRedirects(ctx context.Context, registryClient *http.Client, incoming *http.Request, endpoint *url.URL, token string) (*http.Response, error) {
	current := endpoint
	for redirects := 0; ; redirects++ {
		client, requestToken, err := p.redirectClient(ctx, registryClient, current, token, redirects)
		if err != nil {
			return nil, err
		}
		resp, err := p.registryRequest(ctx, client, incoming, current, requestToken)
		if err != nil || !isPullRedirectStatus(resp.StatusCode) {
			return resp, err
		}
		if redirects >= 5 {
			_ = resp.Body.Close()
			return nil, errors.New("too many registry redirects")
		}
		location := resp.Header.Get("Location")
		_ = resp.Body.Close()
		current, err = validatePullRedirect(current, location, p.authority)
		if err != nil {
			return nil, err
		}
	}
}

func isPullRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (p *PullProxy) redirectClient(ctx context.Context, registryClient *http.Client, current *url.URL, token string, redirects int) (*http.Client, string, error) {
	if strings.EqualFold(current.Host, p.authority) {
		return registryClient, token, nil
	}
	if redirects == 0 || p.transportFactory == nil || redirects > 5 {
		return nil, "", errors.New("registry redirect is not supported")
	}
	transport, err := p.transportFactory.Redirect(ctx, current.Host)
	if err != nil {
		return nil, "", err
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, "", nil
}

func validatePullRedirect(current *url.URL, location, registryAuthority string) (*url.URL, error) {
	if strings.TrimSpace(location) == "" {
		return nil, errors.New("registry redirect location is empty")
	}
	next, err := current.Parse(location)
	if err != nil || next.Scheme != "https" || next.User != nil || next.Fragment != "" || next.Opaque != "" || next.Hostname() == "" {
		return nil, errors.New("invalid registry redirect")
	}
	if !strings.EqualFold(next.Host, registryAuthority) && !trustedPullRedirectHost(next.Host) {
		return nil, errors.New("untrusted registry redirect authority")
	}
	return next, nil
}

func trustedPullRedirectHost(host string) bool {
	return strings.EqualFold(host, "production.cloudfront.docker.com")
}

func (p *PullProxy) registryTransportFor(ctx context.Context) (*registryauth.RegistryTransport, error) {
	if p.transportFactory == nil {
		return p.registryTransport, nil
	}
	return p.transportFactory.Registry(ctx, p.authority)
}

func (p *PullProxy) tokenTransportFor(ctx context.Context, realm registryauth.Realm) (*registryauth.TokenTransport, error) {
	if p.transportFactory == nil {
		return p.tokenTransport, nil
	}
	return p.transportFactory.Token(ctx, realm)
}

func (p *PullProxy) registryRequest(ctx context.Context, client *http.Client, incoming *http.Request, endpoint *url.URL, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, incoming.Method, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build registry request: %w", err)
	}
	for _, key := range []string{"Accept", "Range", "If-None-Match", "If-Modified-Since"} {
		for _, value := range incoming.Header.Values(key) {
			req.Header.Add(key, value)
		}
	}
	// Prevent net/http's implicit gzip negotiation and decompression from
	// hiding the upstream wire length from the bounded streaming path.
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		if strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("invalid registry token")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req) // #nosec G704 -- client uses RegistryTransport restricted to a configured HTTPS authority and IP prefixes
}

func copyPullResponseHeaders(dst, src http.Header) {
	for _, key := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Content-Range", "Docker-Content-Digest", "Docker-Distribution-Api-Version", "ETag", "Last-Modified"} {
		for _, value := range src.Values(key) {
			dst.Add(key, value)
		}
	}
}
