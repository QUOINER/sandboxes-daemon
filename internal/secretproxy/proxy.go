// Package secretproxy provides per-sandbox loopback HTTP proxies that inject a
// service credential on the host. Secret values never enter the guest.
package secretproxy

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service describes one supported upstream and its auth header.
type Service struct {
	Upstream        string
	Header          string
	Prefix          string
	CredentialScope string
	Authorize       func(context.Context) error
}

const (
	authHeader      = "Authorization"
	bearerPrefix    = "Bearer "
	tokenPath       = "/__rheic/proxy/token" //nolint:gosec // internal route path, not a credential
	tokenPathPrefix = tokenPath + "/"
	// ServiceHeader identifies a host-configured route on the private proxy channel.
	ServiceHeader   = "X-Rheic-Proxy-Service"
	maxRequestBody  = 64 << 20
	maxResponseBody = 64 << 20
)

var errResponseTooLarge = errors.New("proxy response exceeds configured limit")

type boundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *boundedResponseBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining > 0 {
		if int64(len(p)) > b.remaining {
			p = p[:b.remaining]
		}
		n, err := b.body.Read(p)
		b.remaining -= int64(n)
		return n, err
	}
	var extra [1]byte
	n, err := b.body.Read(extra[:])
	if n > 0 {
		return 0, errResponseTooLarge
	}
	return 0, err
}

func (b *boundedResponseBody) Close() error { return b.body.Close() }

var services = map[string]Service{
	"openai":     {Upstream: "https://api.openai.com", Header: authHeader, Prefix: bearerPrefix},
	"anthropic":  {Upstream: "https://api.anthropic.com", Header: "x-api-key"},
	"groq":       {Upstream: "https://api.groq.com", Header: authHeader, Prefix: bearerPrefix},
	"mistral":    {Upstream: "https://api.mistral.ai", Header: authHeader, Prefix: bearerPrefix},
	"openrouter": {Upstream: "https://openrouter.ai", Header: authHeader, Prefix: bearerPrefix},
	"xai":        {Upstream: "https://api.x.ai", Header: authHeader, Prefix: bearerPrefix},
}

// Lookup returns the fixed upstream configuration for a service.
func Lookup(service string) (Service, bool) {
	cfg, ok := services[strings.ToLower(service)]
	return cfg, ok
}

type proxy struct {
	server   *http.Server
	listener net.Listener
	url      string
	mu       sync.RWMutex
	path     string
	routes   map[string]*proxyRoute
}

type proxyRoute struct {
	upstream string
	service  Service
	secret   []byte
	token    []byte
	reverse  *httputil.ReverseProxy
	ctx      context.Context
	cancel   context.CancelFunc
}

type proxySnapshot struct {
	service Service
	secret  []byte
	token   []byte
	reverse *httputil.ReverseProxy
	ctx     context.Context
}

// RouteConfig binds one fixed host service to credentials and an unguessable
// per-sandbox helper token. Secret values remain host-side.
type RouteConfig struct {
	Service Service
	Secret  []byte
	Token   string
}

// TokenHeader carries the per-VM bearer sent by the guest proxy helper. It is
// only meaningful on the unix-socket transport, where the socket path is
// already scoped to one sandbox.
const TokenHeader = "X-Rheic-Proxy-Token" //nolint:gosec // HTTP header name, not a credential.

// Manager owns proxies keyed by sandbox and service.
type Manager struct {
	mu          sync.Mutex
	proxies     map[string]*proxy
	dialContext func(context.Context, string, string) (net.Conn, error)
}

// New creates a manager.
func New() *Manager { return &Manager{proxies: make(map[string]*proxy)} }

// Has reports whether an in-process broker is active for the sandbox/service.
func (m *Manager) Has(sandbox, service string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proxies[sandbox+"/"+service] != nil
}

// StartUnix starts a per-sandbox proxy on a unix socket. Every request must
// carry the per-VM token; the socket is private (0600) and owned by the run
// directory, so the token is defense in depth rather than the only control.
func (m *Manager) StartUnix(ctx context.Context, sandbox, service string, cfg Service, secret []byte, socketPath, token string) (string, error) {
	return m.StartUnixRoutes(ctx, sandbox, map[string]RouteConfig{service: {Service: cfg, Secret: secret, Token: token}}, socketPath)
}

// StartUnixRoutes starts one per-sandbox channel with fixed upstream routes.
// Each route has an independent secret and token; request metadata can select
// only a route that the host configured for this sandbox.
func (m *Manager) StartUnixRoutes(ctx context.Context, sandbox string, routes map[string]RouteConfig, socketPath string) (string, error) {
	if err := validateRouteConfigs(ctx, sandbox, routes, socketPath); err != nil {
		return "", err
	}
	preparedRoutes := make(map[string]*proxyRoute, len(routes))
	for name, route := range routes {
		upstream, err := parseUpstream(route.Service.Upstream)
		if err != nil {
			clearPreparedRoutes(preparedRoutes)
			return "", err
		}
		reverse := httputil.NewSingleHostReverseProxy(upstream)
		reverse.Transport = outboundTransport(upstream.Scheme == "https", m.dialContext)
		reverse.ModifyResponse = enforceResponseLimit
		reverse.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "proxy upstream unavailable", http.StatusBadGateway)
		}
		routeCtx, cancel := context.WithCancel(context.Background())
		preparedRoutes[name] = &proxyRoute{upstream: upstream.String(), service: route.Service,
			secret: append([]byte(nil), route.Secret...), token: []byte(route.Token), reverse: reverse, ctx: routeCtx, cancel: cancel}
	}
	key := sandbox + "/" + firstRouteName(preparedRoutes)
	m.mu.Lock()
	existing := m.proxies[key]
	m.mu.Unlock()
	if existing != nil {
		return existing.updateRoutes(socketPath, preparedRoutes)
	}
	listener, err := listenPrivateUnix(socketPath)
	if err != nil {
		m.mu.Lock()
		existing = m.proxies[key]
		m.mu.Unlock()
		if existing != nil {
			return existing.updateRoutes(socketPath, preparedRoutes)
		}
		clearPreparedRoutes(preparedRoutes)
		return "", err
	}
	p := &proxy{path: socketPath, routes: preparedRoutes, url: "unix:" + socketPath}
	srv := &http.Server{Handler: proxyHandler(p), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10}
	p.server, p.listener = srv, listener
	m.mu.Lock()
	if existing = m.proxies[key]; existing != nil {
		m.mu.Unlock()
		_ = listener.Close()
		clearPreparedRoutes(preparedRoutes)
		return existing.updateRoutes(socketPath, preparedRoutes)
	}
	for name := range preparedRoutes {
		m.proxies[sandbox+"/"+name] = p
	}
	m.mu.Unlock()
	go func() { _ = srv.Serve(listener) }()
	return p.url, nil
}

func enforceResponseLimit(response *http.Response) error {
	if response.ContentLength > maxResponseBody {
		return errResponseTooLarge
	}
	if response.Body != nil {
		response.Body = &boundedResponseBody{body: response.Body, remaining: maxResponseBody}
	}
	return nil
}

func proxyHandler(p *proxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath || strings.HasPrefix(r.URL.Path, tokenPathPrefix) {
			serveProxyToken(w, r, p)
			return
		}
		serveProxyRequest(w, r, p)
	})
}

func serveProxyToken(w http.ResponseWriter, r *http.Request, p *proxy) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid proxy bootstrap request", http.StatusBadRequest)
		return
	}
	service := strings.TrimPrefix(r.URL.Path, tokenPathPrefix)
	if service == r.URL.Path {
		service = p.onlyRoute()
	}
	token, ok := p.tokenSnapshot(service)
	if !ok {
		http.Error(w, "proxy bootstrap denied", http.StatusForbidden)
		return
	}
	defer clear(token)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(token)
}

func serveProxyRequest(w http.ResponseWriter, r *http.Request, p *proxy) {
	service := r.Header.Get(ServiceHeader)
	if service == "" {
		service = p.onlyRoute()
	}
	snapshot, ok := p.snapshot(service)
	defer clear(snapshot.secret)
	defer clear(snapshot.token)
	if !ok || !validProxyToken(r.Header.Get(TokenHeader), snapshot.token) {
		http.Error(w, "proxy channel unauthorized", http.StatusForbidden)
		return
	}
	requestCtx, cancel := context.WithCancel(r.Context())
	stopRouteWatch := context.AfterFunc(snapshot.ctx, cancel)
	defer func() {
		stopRouteWatch()
		cancel()
	}()
	r = r.WithContext(requestCtx)
	if snapshot.service.Authorize != nil {
		if err := snapshot.service.Authorize(r.Context()); err != nil {
			http.Error(w, "proxy request denied by sandbox policy", http.StatusForbidden)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	r.Header.Del(TokenHeader)
	r.Header.Del(ServiceHeader)
	r.Header.Del("Authorization")
	r.Header.Del("X-Api-Key")
	if snapshot.service.Header != "" {
		r.Header.Set(snapshot.service.Header, snapshot.service.Prefix+string(snapshot.secret))
	}
	r.Header.Set("X-Rheic-Secret-Proxy", service)
	snapshot.reverse.ServeHTTP(w, r)
}

func validProxyToken(received string, expected []byte) bool {
	return len(received) == len(expected) && subtle.ConstantTimeCompare([]byte(received), expected) == 1
}

func (p *proxy) onlyRoute() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.routes) != 1 {
		return ""
	}
	for service := range p.routes {
		return service
	}
	return ""
}

func (p *proxy) snapshot(name string) (proxySnapshot, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	route := p.routes[name]
	if route == nil {
		return proxySnapshot{}, false
	}
	return proxySnapshot{service: route.service, secret: append([]byte(nil), route.secret...),
		token: append([]byte(nil), route.token...), reverse: route.reverse, ctx: route.ctx}, true
}

func (p *proxy) tokenSnapshot(name string) ([]byte, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	route := p.routes[name]
	if route == nil {
		return nil, false
	}
	return append([]byte(nil), route.token...), true
}

func (p *proxy) updateRoutes(socketPath string, routes map[string]*proxyRoute) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path != socketPath || len(p.routes) != len(routes) {
		clearPreparedRoutes(routes)
		return "", errors.New("proxy channel configuration changed; sandbox restart is required")
	}
	for name, next := range routes {
		current := p.routes[name]
		if current == nil || current.upstream != next.upstream {
			clearPreparedRoutes(routes)
			return "", errors.New("proxy channel configuration changed; sandbox restart is required")
		}
	}
	for name, next := range routes {
		current := p.routes[name]
		clear(current.secret)
		clear(current.token)
		current.service = next.service
		current.secret = next.secret
		current.token = next.token
		next.secret, next.token = nil, nil
	}
	return p.url, nil
}

func (p *proxy) refreshSecret(service string, secret []byte) {
	p.mu.Lock()
	if route := p.routes[service]; route != nil {
		clear(route.secret)
		route.secret = append([]byte(nil), secret...)
	}
	p.mu.Unlock()
}

func (p *proxy) clearRoute(service string) {
	p.mu.Lock()
	if route := p.routes[service]; route != nil {
		route.cancel()
		clear(route.secret)
		clear(route.token)
		route.secret, route.token = nil, nil
		route.service.Authorize = nil
		delete(p.routes, service)
	}
	p.mu.Unlock()
}

func (p *proxy) clearCredentials() {
	p.mu.Lock()
	for _, route := range p.routes {
		route.cancel()
		clear(route.secret)
		clear(route.token)
		route.secret, route.token = nil, nil
		route.service.Authorize = nil
	}
	p.routes = make(map[string]*proxyRoute)
	p.mu.Unlock()
}

func (p *proxy) routeScope(service string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	route := p.routes[service]
	if route == nil {
		return "", false
	}
	return route.service.CredentialScope, true
}

func (p *proxy) routeCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.routes)
}

func validateRouteConfigs(ctx context.Context, sandbox string, routes map[string]RouteConfig, socketPath string) error {
	if sandbox == "" || len(routes) == 0 || len(routes) > 32 {
		return errors.New("sandbox and one to 32 service routes are required")
	}
	for name, route := range routes {
		if !validRouteName(name) || route.Secret == nil {
			return errors.New("invalid proxy service route")
		}
		if err := validUnixStart(ctx, sandbox, name, route.Secret, socketPath, route.Token); err != nil {
			return err
		}
		if _, err := parseUpstream(route.Service.Upstream); err != nil {
			return err
		}
	}
	return nil
}

func validRouteName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func firstRouteName(routes map[string]*proxyRoute) string {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}

func clearPreparedRoutes(routes map[string]*proxyRoute) {
	for _, route := range routes {
		route.cancel()
		clear(route.secret)
		clear(route.token)
		route.secret, route.token = nil, nil
	}
}

// RefreshSecret replaces the in-memory secret for active channels whose
// service/scope matches. It never persists the value.
func (m *Manager) RefreshSecret(service, sandboxName, scope string, secret []byte) {
	m.mu.Lock()
	selected := make(map[*proxy]struct{})
	for key, current := range m.proxies {
		if sandboxName != "" && key != sandboxName+"/"+service {
			continue
		}
		if sandboxName == "" && !strings.HasSuffix(key, "/"+service) {
			continue
		}
		currentScope, exists := current.routeScope(service)
		if exists && (sandboxName != "" || currentScope == scope) {
			selected[current] = struct{}{}
		}
	}
	m.mu.Unlock()
	for current := range selected {
		current.refreshSecret(service, secret)
	}
}

// RevokeSecret closes active channels backed by the removed secret scope.
func (m *Manager) RevokeSecret(service, sandboxName, scope string) error {
	m.mu.Lock()
	type routeRef struct {
		proxy   *proxy
		service string
	}
	selected := make([]routeRef, 0)
	for key, current := range m.proxies {
		if sandboxName != "" && key != sandboxName+"/"+service {
			continue
		}
		if sandboxName == "" && !strings.HasSuffix(key, "/"+service) {
			continue
		}
		currentScope, exists := current.routeScope(service)
		if exists && currentScope == scope {
			selected = append(selected, routeRef{proxy: current, service: service})
			delete(m.proxies, key)
		}
	}
	m.mu.Unlock()
	var failures []error
	closed := make(map[*proxy]struct{})
	for _, selectedRoute := range selected {
		current := selectedRoute.proxy
		current.clearRoute(selectedRoute.service)
		if current.routeCount() == 0 {
			if _, alreadyClosed := closed[current]; alreadyClosed {
				continue
			}
			closed[current] = struct{}{}
			if err := closeProxy(current); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func outboundTransport(requirePublicIP bool, dialOverride func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       16,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialOverride != nil {
				return dialOverride(ctx, network, address)
			}
			if !requirePublicIP {
				return dialer.DialContext(ctx, network, address)
			}
			return dialPublicUnicast(ctx, network, address, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
		},
	}
	return transport
}

func dialPublicUnicast(
	ctx context.Context,
	network, address string,
	lookup func(context.Context, string) ([]net.IPAddr, error),
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid proxy upstream address")
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("proxy upstream DNS resolution failed")
	}
	for _, answer := range ips {
		if !isPublicUnicast(answer.IP) {
			return nil, errors.New("proxy upstream resolved to a non-public address")
		}
	}
	return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

var (
	publicIPv6Unicast = netip.MustParsePrefix("2000::/3")
	nonPublicPrefixes = [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

func isPublicUnicast(ip net.IP) bool {
	if ip == nil {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	if address.Is6() && !publicIPv6Unicast.Contains(address) {
		return false
	}
	for _, prefix := range &nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validUnixStart(ctx context.Context, sandbox, service string, secret []byte, socketPath, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sandbox == "" || service == "" || len(secret) == 0 || socketPath == "" || len(token) != 64 {
		return errors.New("sandbox, service, secret, socket path and a 32-byte hex token are required")
	}
	decoded := make([]byte, hex.DecodedLen(len(token)))
	if _, err := hex.Decode(decoded, []byte(token)); err != nil {
		return errors.New("proxy token must be 32-byte hex")
	}
	clear(decoded)
	return nil
}

func parseUpstream(raw string) (*url.URL, error) {
	upstream, err := url.Parse(raw)
	if err != nil || upstream.Host == "" || (upstream.Scheme != "https" && (upstream.Scheme != "http" || !isLoopbackURL(upstream))) {
		return nil, errors.New("invalid upstream")
	}
	return upstream, nil
}

func isLoopbackURL(upstream *url.URL) bool {
	host := upstream.Hostname()
	ip := net.ParseIP(host)
	return upstream.Scheme == "http" && ip != nil && ip.IsLoopback()
}

func listenPrivateUnix(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || len(path) >= 104 {
		return nil, errors.New("proxy socket path must be absolute and shorter than 104 bytes")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect proxy socket directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(parentInfo) {
		return nil, errors.New("proxy socket directory must be a real private directory owned by the daemon user")
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("proxy socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect proxy socket path: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen for proxy channel: %w", err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("proxy channel listener is not a Unix socket")
	}
	unixListener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("protect proxy channel socket: %w", err)
	}
	return listener, nil
}

// EnsurePrivateDir creates path once and verifies that it is a real directory
// owned by the daemon user with no group/other permissions. Existing paths are
// never removed or repaired automatically.
func EnsurePrivateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("proxy directory path must be absolute")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create proxy directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect proxy directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("proxy directory must be a real private directory owned by the daemon user")
	}
	return nil
}

// RemovePrivateDir removes an empty directory only when it still belongs to
// this user and retains private permissions. It never recursively removes data.
func RemovePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("refusing to remove a proxy directory not owned by the daemon user")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RemoveStaleSocket removes a socket owned by this daemon user when no process
// is listening on it. It is intended for daemon restart recovery inside a
// private directory allocated to the sandbox.
func RemoveStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) {
		return errors.New("refusing to remove a proxy path not owned by the daemon")
	}
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("proxy socket is already active")
	}
	return os.Remove(path)
}

// ownedByCurrentUser checks the Unix owner without making the package depend
// on OS-specific syscall structs. Platforms without a UID field fail closed.
func ownedByCurrentUser(info os.FileInfo) bool {
	if os.Geteuid() < 0 {
		return false
	}
	stat := reflect.ValueOf(info.Sys())
	if !stat.IsValid() {
		return false
	}
	if stat.Kind() == reflect.Pointer {
		stat = stat.Elem()
	}
	if !stat.IsValid() || stat.Kind() != reflect.Struct {
		return false
	}
	uid := stat.FieldByName("Uid")
	if !uid.IsValid() {
		return false
	}
	switch uid.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uid.Uint() == uint64(os.Geteuid()) //nolint:gosec // euid is checked non-negative above
	default:
		return false
	}
}

// StopSandbox closes every proxy owned by a sandbox.
func (m *Manager) StopSandbox(sandbox string) error {
	m.mu.Lock()
	selected := make(map[*proxy]struct{})
	for key, p := range m.proxies {
		if strings.HasPrefix(key, sandbox+"/") {
			selected[p] = struct{}{}
			delete(m.proxies, key)
		}
	}
	m.mu.Unlock()
	var failures []error
	for p := range selected {
		p.clearCredentials()
		if err := closeProxy(p); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Close closes every proxy.
func (m *Manager) Close() error {
	m.mu.Lock()
	unique := make(map[*proxy]struct{}, len(m.proxies))
	for key, p := range m.proxies {
		unique[p] = struct{}{}
		delete(m.proxies, key)
	}
	m.mu.Unlock()
	var failures []error
	for p := range unique {
		p.clearCredentials()
		if err := closeProxy(p); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func closeProxy(p *proxy) error {
	closeErr := p.server.Close()
	if err := removeOwnedSocket(p.path); err != nil {
		return errors.Join(closeErr, err)
	}
	return closeErr
}

func removeOwnedSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) {
		return errors.New("refusing to remove a proxy path not owned by the daemon")
	}
	return os.Remove(path)
}
