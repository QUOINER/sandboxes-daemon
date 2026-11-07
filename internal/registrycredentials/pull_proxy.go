package registrycredentials

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

// PullProxy is a host-side registry handler bound to an identity
// selected by trusted host code. Its forward path supports scoped pull and push
// through TLS interception; it must only be exposed to its bound sandbox.
type PullProxy struct {
	store             *Store
	registry          string
	authority         string
	sandboxName       string
	credentialScope   Scope
	service           string
	realms            []registryauth.Realm
	registryTransport http.RoundTripper
	tokenTransport    http.RoundTripper
	transportFactory  PullProxyTransportFactory
	limiter           *PullLimiter
	maxBytes          int64
	inflight          chan struct{}
	tlsAuthority      *ProxyAuthority
	tunnelSlots       chan struct{}
	stateMu           sync.Mutex
	tokens            map[string]tokenGrant
	uploads           map[string]uploadSession
	blobRedirects     map[string]blobRedirectSession
	redirectHosts     map[string]struct{}
}

type tokenGrant struct {
	repository string
	actions    map[string]struct{}
	expiresAt  time.Time
}

type uploadSession struct {
	registryHost string
	repository   string
	id           string
	location     *url.URL
	expiresAt    time.Time
}

// blobRedirectSession binds guest CDN requests to a URL returned by the
// trusted registry. A small use budget permits Docker range retries while
// preventing the CDN endpoint from becoming a general-purpose proxy.
type blobRedirectSession struct {
	usesLeft  int
	expiresAt time.Time
}

// PullProxyTransportFactory creates host-only HTTPS transports for the
// configured registry and a realm already accepted by the trusted allowlist.
type PullProxyTransportFactory interface {
	Registry(context.Context, string) (http.RoundTripper, error)
	Token(context.Context, registryauth.Realm) (http.RoundTripper, error)
	Redirect(context.Context, string) (http.RoundTripper, error)
}

const maxPullResponseBytes = 16 << 30
const maxPullErrorResponseBytes = 64 << 10

// PullProxyConfig is trusted host configuration, never a guest request.
type PullProxyConfig struct {
	Registry          string
	Authority         string
	SandboxName       string
	CredentialScope   Scope
	Service           string
	Realms            []registryauth.Realm
	RegistryTransport http.RoundTripper
	TokenTransport    http.RoundTripper
	TransportFactory  PullProxyTransportFactory
	Limiter           *PullLimiter
	MaxBytes          int64
	TLSAuthority      *ProxyAuthority
	// RedirectAuthorities are the exact hostnames allowed to serve registry
	// blob redirects. Empty uses the Docker Hub CDN default only for Docker Hub.
	RedirectAuthorities []string
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
	redirectAuthorities := cfg.RedirectAuthorities
	if len(redirectAuthorities) == 0 && strings.EqualFold(authority, "registry-1.docker.io") {
		redirectAuthorities = []string{dockerHubBlobAuthority}
	}
	return &PullProxy{store: store, registry: registry, authority: authority, sandboxName: cfg.SandboxName, credentialScope: cfg.CredentialScope,
		service: cfg.Service, realms: append([]registryauth.Realm(nil), cfg.Realms...), registryTransport: cfg.RegistryTransport,
		tokenTransport: cfg.TokenTransport, transportFactory: cfg.TransportFactory, limiter: cfg.Limiter,
		maxBytes: cfg.MaxBytes, inflight: make(chan struct{}, 4), tlsAuthority: cfg.TLSAuthority,
		tunnelSlots: make(chan struct{}, 8), tokens: make(map[string]tokenGrant), uploads: make(map[string]uploadSession),
		blobRedirects: make(map[string]blobRedirectSession), redirectHosts: redirectHostSet(redirectAuthorities)}, nil
}

func validPullProxyConfig(store *Store, cfg PullProxyConfig) bool {
	return store != nil && cfg.SandboxName != "" && cfg.Service != "" && len(cfg.Realms) != 0 &&
		(cfg.TransportFactory != nil || (cfg.RegistryTransport != nil && cfg.TokenTransport != nil)) &&
		cfg.Limiter != nil &&
		cfg.MaxBytes > 0 && cfg.MaxBytes <= maxPullResponseBytes &&
		(cfg.CredentialScope == ScopeSandbox || cfg.CredentialScope == ScopeAllSandboxes)
}

// ServeHTTP accepts unauthenticated loopback-mirror pulls or requests inside a
// verified registry TLS tunnel. It never returns a host bearer.
func (p *PullProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	if r.TLS != nil {
		p.serveForwardRequest(w, r)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "registry pull request body is unsupported", http.StatusBadRequest)
		return
	}
	endpoint := &url.URL{Scheme: registryHTTPScheme, Host: p.authority, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	probe := endpoint.Path == registryV2Path && endpoint.RawPath == "" && endpoint.RawQuery == "" && !endpoint.ForceQuery && r.URL.Fragment == "" && r.URL.Opaque == "" &&
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
	default:
		writeRegistryBusy(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if !p.limiter.acquire(ctx) {
		if r.Context().Err() != nil {
			return
		}
		writeRegistryBusy(w)
		return
	}
	defer p.limiter.release()
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

func writeRegistryBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "registry proxy is busy", http.StatusServiceUnavailable)
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
	maxBytes := p.maxBytes
	if resp.StatusCode == http.StatusNotFound && maxBytes > maxPullErrorResponseBytes {
		maxBytes = maxPullErrorResponseBytes
	}
	if method != http.MethodHead && resp.StatusCode != http.StatusNotModified && (resp.ContentLength < 0 || resp.ContentLength > maxBytes) {
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
	return code == http.StatusOK || code == http.StatusPartialContent || code == http.StatusNotModified || code == http.StatusNotFound
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
		current, err = p.validatePullRedirect(current, location)
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

func (p *PullProxy) validatePullRedirect(current *url.URL, location string) (*url.URL, error) {
	return validatePullRedirectWithAllowlist(current, location, p.authority, p.isRedirectHost)
}

func validatePullRedirect(current *url.URL, location, registryAuthority string) (*url.URL, error) {
	return validatePullRedirectWithAllowlist(current, location, registryAuthority, trustedPullRedirectHost)
}

func validatePullRedirectWithAllowlist(current *url.URL, location, registryAuthority string, redirectAllowed func(string) bool) (*url.URL, error) {
	if current == nil || redirectAllowed == nil {
		return nil, errors.New("registry redirect validator is unavailable")
	}
	if strings.TrimSpace(location) == "" {
		return nil, errors.New("registry redirect location is empty")
	}
	next, err := current.Parse(location)
	if err != nil || next.Scheme != registryHTTPScheme || next.User != nil || next.Fragment != "" || next.Opaque != "" {
		return nil, errors.New("invalid registry redirect")
	}
	redirectHost, ok := normalizedRedirectHost(next.Host)
	registryHost, registryOK := normalizedRedirectHost(registryAuthority)
	if !ok || !registryOK || (!strings.EqualFold(redirectHost, registryHost) && !redirectAllowed(redirectHost)) {
		return nil, errors.New("untrusted registry redirect authority")
	}
	next.Host = redirectHost
	return next, nil
}

func normalizedRedirectHost(authority string) (string, bool) {
	parsed, err := url.Parse("https://" + authority)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", false
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}
	return host, true
}

func trustedPullRedirectHost(host string) bool {
	return strings.EqualFold(host, "production.cloudfront.docker.com")
}

func (p *PullProxy) registryTransportFor(ctx context.Context) (http.RoundTripper, error) {
	if p.transportFactory == nil {
		return p.registryTransport, nil
	}
	return p.transportFactory.Registry(ctx, p.authority)
}

func (p *PullProxy) tokenTransportFor(ctx context.Context, realm registryauth.Realm) (http.RoundTripper, error) {
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

func (p *PullProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, valid := p.connectHost(r)
	if !valid {
		http.Error(w, "registry CONNECT is unsupported", http.StatusForbidden)
		return
	}
	select {
	case p.tunnelSlots <- struct{}{}:
		defer func() { <-p.tunnelSlots }()
	case <-r.Context().Done():
		return
	default:
		writeRegistryBusy(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "registry CONNECT is unavailable", http.StatusInternalServerError)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	p.serveTLSConnection(ctx, conn, host)
}

func (p *PullProxy) connectHost(r *http.Request) (string, bool) {
	if p.tlsAuthority == nil || r == nil || r.URL == nil ||
		(r.URL.Opaque != "" && r.URL.Opaque != r.Host) || (r.URL.Host != "" && r.URL.Host != r.Host) ||
		r.URL.Path != "" || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return "", false
	}
	host, port, err := net.SplitHostPort(r.Host)
	return host, err == nil && port == "443" && p.allowedConnectHost(host)
}

func (p *PullProxy) serveTLSConnection(ctx context.Context, conn net.Conn, host string) {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	serverTLS := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("registry TLS SNI does not match CONNECT target")
			}
			certificate, err := p.tlsAuthority.Leaf(host, time.Now())
			return &certificate, err
		},
	})
	if err := serverTLS.HandshakeContext(ctx); err != nil {
		return
	}
	_ = serverTLS.SetDeadline(time.Time{})
	listener := newSingleConnListener(serverTLS)
	server := &http.Server{
		Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return ctx },
	}
	_ = server.Serve(listener)
}

func (p *PullProxy) allowedConnectHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.EqualFold(host, p.authority) {
		return true
	}
	if _, ok := p.authRealm(host); ok {
		return true
	}
	_, ok := p.redirectHosts[host]
	return ok
}

func (p *PullProxy) isRedirectHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	_, ok := p.redirectHosts[host]
	return ok
}

func redirectHostSet(hosts []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host != "" {
			set[host] = struct{}{}
		}
	}
	return set
}

func (p *PullProxy) realmForPath(host, path string) (registryauth.Realm, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, realm := range p.realms {
		if strings.EqualFold(realm.Host, host) && realm.Path == path {
			return realm, true
		}
	}
	return registryauth.Realm{}, false
}

func (p *PullProxy) authRealm(host string) (registryauth.Realm, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, realm := range p.realms {
		if strings.EqualFold(realm.Host, host) {
			return realm, true
		}
	}
	return registryauth.Realm{}, false
}

type singleConnListener struct {
	conn      net.Conn
	once      bool
	done      chan struct{}
	closeOnce sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.once {
		l.once = true
		return &singleListenerConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.signal()
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (l *singleConnListener) signal() { l.closeOnce.Do(func() { close(l.done) }) }

type singleListenerConn struct {
	net.Conn
	listener *singleConnListener
}

func (c *singleListenerConn) ConnectionState() tls.ConnectionState {
	stateful, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return tls.ConnectionState{}
	}
	return stateful.ConnectionState()
}

func (c *singleListenerConn) Close() error {
	c.listener.signal()
	return c.Conn.Close()
}
