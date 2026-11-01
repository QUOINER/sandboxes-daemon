// Package secretproxy provides per-sandbox loopback HTTP proxies that inject a
// service credential on the host. Secret values never enter the guest.
package secretproxy

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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
	authHeader     = "Authorization"
	bearerPrefix   = "Bearer "
	tokenPath      = "/__klorq/proxy/token" //nolint:gosec // internal route path, not a credential
	maxRequestBody = 64 << 20
)

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
	upstream string
	service  Service
	secret   []byte
	token    []byte
}

// TokenHeader carries the per-VM bearer sent by the guest proxy helper. It is
// only meaningful on the unix-socket transport, where the socket path is
// already scoped to one sandbox.
const TokenHeader = "X-Klorq-Proxy-Token" //nolint:gosec // HTTP header name, not a credential.

// Manager owns proxies keyed by sandbox and service.
type Manager struct {
	mu      sync.Mutex
	proxies map[string]*proxy
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
	if err := validUnixStart(ctx, sandbox, service, secret, socketPath, token); err != nil {
		return "", err
	}
	upstream, err := parseUpstream(cfg.Upstream)
	if err != nil {
		return "", err
	}
	key := sandbox + "/" + service
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		return existing.update(socketPath, upstream.String(), cfg, secret, token)
	}
	m.mu.Unlock()
	listener, err := listenPrivateUnix(socketPath)
	if err != nil {
		m.mu.Lock()
		existing := m.proxies[key]
		m.mu.Unlock()
		if existing != nil {
			return existing.update(socketPath, upstream.String(), cfg, secret, token)
		}
		return "", err
	}
	reverse := httputil.NewSingleHostReverseProxy(upstream)
	reverse.Transport = outboundTransport(upstream.Scheme == "https")
	reverse.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "proxy upstream unavailable", http.StatusBadGateway)
	}
	p := &proxy{path: socketPath, upstream: upstream.String(), service: cfg, secret: append([]byte(nil), secret...), token: []byte(token), url: "unix:" + socketPath}
	srv := &http.Server{Handler: proxyHandler(service, p, reverse), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10}
	p.server, p.listener = srv, listener
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		_ = listener.Close()
		return existing.update(socketPath, upstream.String(), cfg, secret, token)
	}
	m.proxies[key] = p
	m.mu.Unlock()
	go func() { _ = srv.Serve(listener) }()
	return p.url, nil
}

func proxyHandler(service string, p *proxy, reverse *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				http.Error(w, "invalid proxy bootstrap request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.currentToken()))
			return
		}
		got := r.Header.Get(TokenHeader)
		cfg, secret, token := p.snapshot()
		defer clear(secret)
		defer clear(token)
		if len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), token) != 1 {
			http.Error(w, "proxy channel unauthorized", http.StatusForbidden)
			return
		}
		if cfg.Authorize != nil {
			if err := cfg.Authorize(r.Context()); err != nil {
				http.Error(w, "proxy request denied by sandbox policy", http.StatusForbidden)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		r.Header.Del(TokenHeader)
		r.Header.Del("Authorization")
		r.Header.Del("X-Api-Key")
		if cfg.Header != "" {
			r.Header.Set(cfg.Header, cfg.Prefix+string(secret))
		}
		r.Header.Set("X-Klorq-Secret-Proxy", service)
		reverse.ServeHTTP(w, r)
	})
}

func (p *proxy) currentToken() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return string(p.token)
}

func (p *proxy) snapshot() (Service, []byte, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.service, append([]byte(nil), p.secret...), append([]byte(nil), p.token...)
}

func (p *proxy) update(socketPath, upstream string, cfg Service, secret []byte, token string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path != socketPath || p.upstream != upstream {
		return "", errors.New("proxy channel configuration changed; sandbox restart is required")
	}
	clear(p.secret)
	clear(p.token)
	p.service, p.secret, p.token = cfg, append([]byte(nil), secret...), []byte(token)
	return p.url, nil
}

func (p *proxy) refreshSecret(secret []byte) {
	p.mu.Lock()
	clear(p.secret)
	p.secret = append([]byte(nil), secret...)
	p.mu.Unlock()
}

func (p *proxy) clearCredentials() {
	p.mu.Lock()
	clear(p.secret)
	clear(p.token)
	p.secret, p.token = nil, nil
	p.service.Authorize = nil
	p.mu.Unlock()
}

// RefreshSecret replaces the in-memory secret for active channels whose
// service/scope matches. It never persists the value.
func (m *Manager) RefreshSecret(service, sandboxName, scope string, secret []byte) {
	m.mu.Lock()
	selected := make([]*proxy, 0)
	for key, current := range m.proxies {
		if sandboxName != "" && key != sandboxName+"/"+service {
			continue
		}
		if sandboxName == "" && !strings.HasSuffix(key, "/"+service) {
			continue
		}
		cfg, _, _ := current.snapshot()
		if sandboxName != "" || cfg.CredentialScope == scope {
			selected = append(selected, current)
		}
	}
	m.mu.Unlock()
	for _, current := range selected {
		current.refreshSecret(secret)
	}
}

// RevokeSecret closes active channels backed by the removed secret scope.
func (m *Manager) RevokeSecret(service, sandboxName, scope string) error {
	m.mu.Lock()
	selected := make([]*proxy, 0)
	for key, current := range m.proxies {
		if sandboxName != "" && key != sandboxName+"/"+service {
			continue
		}
		if sandboxName == "" && !strings.HasSuffix(key, "/"+service) {
			continue
		}
		cfg, _, _ := current.snapshot()
		if cfg.CredentialScope == scope {
			selected = append(selected, current)
			delete(m.proxies, key)
		}
	}
	m.mu.Unlock()
	var failures []error
	for _, current := range selected {
		current.clearCredentials()
		if err := closeProxy(current); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func outboundTransport(requirePublicIP bool) *http.Transport {
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
			if !requirePublicIP {
				return dialer.DialContext(ctx, network, address)
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("invalid proxy upstream address")
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("proxy upstream DNS resolution failed")
			}
			for _, answer := range ips {
				if !isPublicUnicast(answer.IP) {
					return nil, errors.New("proxy upstream resolved to a non-public address")
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	return transport
}

func isPublicUnicast(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	blocked := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48",
		"100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
	}
	for _, cidr := range blocked {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
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
	return os.Remove(path)
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
	var selected []*proxy
	for key, p := range m.proxies {
		if strings.HasPrefix(key, sandbox+"/") {
			selected = append(selected, p)
			delete(m.proxies, key)
		}
	}
	m.mu.Unlock()
	var failures []error
	for _, p := range selected {
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
	all := make([]*proxy, 0, len(m.proxies))
	for key, p := range m.proxies {
		all = append(all, p)
		delete(m.proxies, key)
	}
	m.mu.Unlock()
	var failures []error
	for _, p := range all {
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
