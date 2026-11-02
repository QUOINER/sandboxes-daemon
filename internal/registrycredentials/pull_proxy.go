package registrycredentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KLORQ/sandboxes-gateway/registryauth"
)

// PullProxy is a host-side, read-only registry handler bound to an identity
// selected by trusted host code. It must not be exposed until the listener is
// securely bound to that sandbox and its network policy is enforced.
type PullProxy struct {
	store             *Store
	registry          string
	sandboxName       string
	credentialScope   Scope
	service           string
	realms            []registryauth.Realm
	registryTransport *registryauth.RegistryTransport
	tokenTransport    *registryauth.TokenTransport
	maxBytes          int64
	inflight          chan struct{}
}

const maxBufferedPullBytes = 32 << 20

// PullProxyConfig is trusted host configuration, never a guest request.
type PullProxyConfig struct {
	Registry          string
	SandboxName       string
	CredentialScope   Scope
	Service           string
	Realms            []registryauth.Realm
	RegistryTransport *registryauth.RegistryTransport
	TokenTransport    *registryauth.TokenTransport
	MaxBytes          int64
}

// NewPullProxy requires a sandbox-scoped or all-sandboxes credential; host-only
// credentials cannot be used for guest traffic.
func NewPullProxy(store *Store, cfg PullProxyConfig) (*PullProxy, error) {
	registry, err := canonicalRegistry(cfg.Registry)
	if err != nil {
		return nil, err
	}
	if store == nil || cfg.SandboxName == "" || cfg.Service == "" || len(cfg.Realms) == 0 ||
		cfg.RegistryTransport == nil || cfg.TokenTransport == nil || cfg.MaxBytes <= 0 || cfg.MaxBytes > maxBufferedPullBytes ||
		(cfg.CredentialScope != ScopeSandbox && cfg.CredentialScope != ScopeAllSandboxes) {
		return nil, errors.New("invalid pull proxy configuration")
	}
	if _, _, err := validateScope(ScopeSandbox, cfg.SandboxName); err != nil {
		return nil, errors.New("invalid pull proxy sandbox identity")
	}
	return &PullProxy{store: store, registry: registry, sandboxName: cfg.SandboxName, credentialScope: cfg.CredentialScope,
		service: cfg.Service, realms: append([]registryauth.Realm(nil), cfg.Realms...), registryTransport: cfg.RegistryTransport,
		tokenTransport: cfg.TokenTransport, maxBytes: cfg.MaxBytes, inflight: make(chan struct{}, 4)}, nil
}

// ServeHTTP accepts only read-only registry pull requests and does not forward
// guest-provided authorization headers. It never returns the upstream token.
func (p *PullProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	endpoint := &url.URL{Scheme: "https", Host: p.registry, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	probe := endpoint.Path == "/v2/" && endpoint.RawPath == "" && endpoint.RawQuery == "" && !endpoint.ForceQuery && r.URL.Fragment == "" && r.URL.Opaque == "" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead)
	if _, err := registryauth.PullScope(r.Method, endpoint, p.registry); err != nil && !probe {
		http.Error(w, "unsupported registry request", http.StatusForbidden)
		return
	}
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
	p.writeResponse(w, r.Method, resp)
}

func (p *PullProxy) probe(ctx context.Context, incoming *http.Request, endpoint *url.URL) error {
	client := &http.Client{Transport: p.registryTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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

func (p *PullProxy) writeResponse(w http.ResponseWriter, method string, resp *http.Response) {
	if !allowedPullStatus(resp.StatusCode) {
		http.Error(w, "registry request failed", http.StatusBadGateway)
		return
	}
	if method != http.MethodHead && resp.StatusCode != http.StatusNotModified && (resp.ContentLength < 0 || resp.ContentLength > p.maxBytes) {
		http.Error(w, "registry response exceeds supported limits", http.StatusBadGateway)
		return
	}
	var body []byte
	if method != http.MethodHead && resp.StatusCode != http.StatusNotModified {
		var err error
		body, err = io.ReadAll(io.LimitReader(resp.Body, p.maxBytes+1))
		if err != nil || int64(len(body)) != resp.ContentLength || int64(len(body)) > p.maxBytes {
			clear(body)
			http.Error(w, "invalid registry response", http.StatusBadGateway)
			return
		}
		defer clear(body)
	}
	copyPullResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if len(body) != 0 {
		_, _ = w.Write(body)
	}
}

func allowedPullStatus(code int) bool {
	return code == http.StatusOK || code == http.StatusPartialContent || code == http.StatusNotModified
}

func (p *PullProxy) pull(ctx context.Context, incoming *http.Request, endpoint *url.URL) (*http.Response, error) {
	client := &http.Client{Transport: p.registryTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := p.registryRequest(ctx, client, incoming, endpoint, "")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenges := resp.Header.Values("WWW-Authenticate")
	_ = resp.Body.Close()
	if len(challenges) != 1 {
		return nil, errors.New("registry returned an invalid challenge")
	}
	name := ""
	if p.credentialScope == ScopeSandbox {
		name = p.sandboxName
	}
	token, err := p.store.ExchangePullToken(ctx, p.tokenTransport, PullRequest{Registry: p.registry, Scope: p.credentialScope,
		SandboxName: name, Method: incoming.Method, URL: endpoint, Challenge: challenges[0], Realms: p.realms, Service: p.service})
	if err != nil {
		return nil, err
	}
	return p.registryRequest(ctx, client, incoming, endpoint, token)
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
	if token != "" {
		if strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("invalid registry token")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req) // #nosec G704 -- client uses RegistryTransport restricted to a configured HTTPS authority and IP prefixes
}

func copyPullResponseHeaders(dst, src http.Header) {
	for _, key := range []string{"Content-Type", "Content-Length", "Content-Range", "Docker-Content-Digest", "Docker-Distribution-Api-Version", "ETag", "Last-Modified"} {
		for _, value := range src.Values(key) {
			dst.Add(key, value)
		}
	}
}
