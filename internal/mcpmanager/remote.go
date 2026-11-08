package mcpmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/version"
)

// transportRemote selects the streamable HTTP MCP transport.
const transportRemote = "remote"

// SetRemoteAllowlist installs the exact host names the daemon may connect to
// for remote MCP servers. An empty allowlist disables remote transports
// (fail closed). Entries are matched case-insensitively without wildcards.
func (m *Manager) SetRemoteAllowlist(hosts []string) {
	normalized := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			normalized[host] = struct{}{}
		}
	}
	m.mu.Lock()
	m.remoteHosts = normalized
	m.mu.Unlock()
}

func (m *Manager) remoteHostAllowed(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.remoteHosts) == 0 {
		return false
	}
	_, ok := m.remoteHosts[strings.ToLower(host)]
	return ok
}

// SetRemoteTLSConfig overrides the TLS root store for remote MCP dials. A nil
// config selects the system trust store. This exists for controlled tests;
// production callers must not weaken verification.
func (m *Manager) SetRemoteTLSConfig(cfg *tls.Config) {
	m.mu.Lock()
	m.remoteTLSConfig = cfg
	m.mu.Unlock()
}

func (m *Manager) remoteTLS() *tls.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.remoteTLSConfig
}

func (m *Manager) remoteDialers() (func(context.Context, string, string) ([]netip.Addr, error), func(context.Context, string, string) (net.Conn, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lookup, dial := m.remoteLookup, m.remoteDial
	if lookup == nil {
		lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, network, host)
		}
	}
	return lookup, dial
}

func pinnedRemoteDialContext(ctx context.Context, dialer *net.Dialer, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error), networkName, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid remote MCP dial address")
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		if !network.IsPublicUnicast(parsed) {
			return nil, errors.New("remote MCP destination is not public unicast")
		}
		return dialRemoteIP(ctx, dialer, dial, networkName, net.JoinHostPort(parsed.String(), port))
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("remote MCP DNS lookup failed")
	}
	for _, address := range addresses {
		if !network.IsPublicUnicast(address) {
			return nil, errors.New("remote MCP DNS resolved to a non-public address")
		}
	}
	var lastErr error
	for _, address := range addresses {
		conn, err := dialRemoteIP(ctx, dialer, dial, networkName, net.JoinHostPort(address.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("remote MCP pinned dial failed: " + lastErr.Error())
}

func dialRemoteIP(ctx context.Context, dialer *net.Dialer, override func(context.Context, string, string) (net.Conn, error), networkName, address string) (net.Conn, error) {
	if override != nil {
		return override(ctx, networkName, address)
	}
	return dialer.DialContext(ctx, networkName, address)
}

// RegisterRemote queues a remote (streamable HTTP) MCP server for trusted
// host approval. The URL must satisfy the fail-closed remote policy before a
// challenge is created.
func (m *Manager) RegisterRemote(ctx context.Context, name, rawURL string, headers, secretHeaders map[string]string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	server, err := prepareRemoteServer(name, rawURL, headers, secretHeaders, m.remoteHostAllowed)
	if err != nil {
		return "", err
	}
	return m.registerPrepared(ctx, server)
}

// prepareRemoteServer validates a remote MCP server registration against the
// host allowlist. Anything but an exact, allowlisted https host fails closed.
func prepareRemoteServer(name, rawURL string, headers, secretHeaders map[string]string, allowed func(string) bool) (Server, error) {
	if !namePattern.MatchString(name) {
		return Server{}, errors.New("invalid MCP server name")
	}
	_, cleanURL, err := validateRemoteURL(rawURL, allowed)
	if err != nil {
		return Server{}, err
	}
	copied, copiedSecrets, err := copiedRemoteHeaders(headers, secretHeaders)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name, Transport: transportRemote, URL: cleanURL, Headers: copied, SecretHeaders: copiedSecrets}, nil
}

// validateRemoteURL enforces the remote transport policy and returns the
// normalized endpoint with its policy-checked host.
func validateRemoteURL(rawURL string, allowed func(string) bool) (host, cleanURL string, err error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", errors.New("invalid MCP server URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", "", errors.New("remote MCP servers require an https URL")
	}
	if parsed.User != nil {
		return "", "", errors.New("remote MCP server URL must not embed credentials")
	}
	host = parsed.Hostname()
	if host == "" {
		return "", "", errors.New("remote MCP server URL requires a host")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", "", errors.New("remote MCP server URL must use a host name, not an IP literal")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return "", "", errors.New("remote MCP server URL must use the default https port")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("remote MCP server URL must not contain a query or fragment")
	}
	if !allowed(host) {
		return "", "", errors.New("remote MCP host is not allowed by local policy")
	}
	clean := *parsed
	clean.Scheme = "https"
	if clean.Port() == "" {
		clean.Host = net.JoinHostPort(strings.ToLower(host), "443")
	} else {
		clean.Host = strings.ToLower(clean.Host)
	}
	return strings.ToLower(host), clean.String(), nil
}

// copiedRemoteHeaders validates static headers and non-secret ${name}
// references. Secret material itself must never enter registration state.
func copiedRemoteHeaders(headers, secretHeaders map[string]string) (map[string]string, map[string]string, error) {
	copied := make(map[string]string, len(headers))
	copiedSecrets := make(map[string]string, len(secretHeaders))
	headerNames := make(map[string]struct{}, len(headers)+len(secretHeaders))
	for key, value := range headers {
		trimmed, refs, err := validateMCPHeader(key, value, headerNames)
		if err != nil {
			return nil, nil, err
		}
		if sensitiveMCPHeaderName(trimmed) {
			return nil, nil, errors.New("credential-bearing MCP headers must use secret_headers with a host-vault ${placeholder}")
		}
		if len(refs) > 0 {
			return nil, nil, errors.New("MCP header placeholders must use secret_headers")
		}
		copied[trimmed] = value
	}
	if len(copied) > 16 {
		return nil, nil, errors.New("remote MCP server allows at most 16 headers")
	}
	for key, value := range secretHeaders {
		trimmed, refs, err := validateMCPHeader(key, value, headerNames)
		if err != nil {
			return nil, nil, err
		}
		if len(refs) == 0 {
			return nil, nil, errors.New("secret MCP header templates must contain valid host-vault ${placeholder} references")
		}
		copiedSecrets[trimmed] = value
	}
	if len(headerNames) > 16 {
		return nil, nil, errors.New("remote MCP server allows at most 16 headers")
	}
	return copied, copiedSecrets, nil
}

func validateMCPHeader(key, value string, names map[string]struct{}) (string, []string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n:\x00") {
		return "", nil, errors.New("invalid remote MCP header name")
	}
	canonicalName := strings.ToLower(trimmed)
	if _, exists := names[canonicalName]; exists {
		return "", nil, errors.New("remote MCP header names must be unique, ignoring case")
	}
	names[canonicalName] = struct{}{}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", nil, errors.New("invalid remote MCP header value")
	}
	refs, err := parseMCPHeaderReferences(value)
	if err != nil {
		return "", nil, err
	}
	return trimmed, refs, nil
}

func sensitiveMCPHeaderName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, marker := range []string{"auth", "cookie", "token", "secret", "credential", "password", "-key", "_key", "apikey"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return strings.HasSuffix(name, "key")
}

func parseMCPHeaderReferences(value string) ([]string, error) {
	var names []string
	for offset := 0; ; {
		start := strings.Index(value[offset:], "${")
		if start < 0 {
			if strings.Contains(value[offset:], "}") {
				return nil, errors.New("invalid MCP header placeholder")
			}
			return names, nil
		}
		start += offset
		if strings.Contains(value[offset:start], "}") {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end += start + 2
		name := value[start+2 : end]
		if !validMCPPlaceholderName(name) {
			return nil, errors.New("invalid MCP header placeholder")
		}
		names = append(names, name)
		offset = end + 1
	}
}

func validMCPPlaceholderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for index, char := range name {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-'
		if !valid || index == 0 && (char == '_' || char == '-') {
			return false
		}
	}
	return true
}

// verifyRemoteServer re-checks policy at use time so a registration made
// under an older allowlist cannot outlive a policy revocation.
func (m *Manager) verifyRemoteServer(s Server) error {
	if s.Transport != transportRemote {
		return errors.New("remote MCP server registration is invalid")
	}
	host, err := remoteServerHost(s.URL)
	if err != nil {
		return err
	}
	if !m.remoteHostAllowed(host) {
		return errors.New("remote MCP host is no longer allowed by local policy")
	}
	return nil
}

func remoteServerHost(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid remote MCP server URL: %w", err)
	}
	return parsed.Hostname(), nil
}

// headerTransport injects the registered static, non-secret headers.
type headerTransport struct {
	base          http.RoundTripper
	headers       map[string]string
	secretHeaders map[string]string
	server        string
	host          string
	resolve       RemoteSecretResolver
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") || !strings.EqualFold(req.URL.Hostname(), t.host) {
		return nil, errors.New("remote MCP request escaped its approved origin")
	}
	cloned := req.Clone(req.Context())
	for key, value := range t.headers {
		if err := t.applyHeader(req.Context(), cloned, key, value, false); err != nil {
			return nil, err
		}
	}
	for key, value := range t.secretHeaders {
		if err := t.applyHeader(req.Context(), cloned, key, value, true); err != nil {
			return nil, err
		}
	}
	return t.base.RoundTrip(cloned)
}

func (t headerTransport) applyHeader(ctx context.Context, req *http.Request, key, value string, requireReference bool) error {
	refs, err := parseMCPHeaderReferences(value)
	if err != nil || requireReference && len(refs) == 0 {
		return errors.New("remote MCP header configuration is invalid")
	}
	if len(refs) == 0 {
		req.Header.Set(key, value)
		return nil
	}
	var resolved strings.Builder
	resolved.Grow(len(value))
	cursor := 0
	for _, name := range refs {
		placeholder := "${" + name + "}"
		relativeStart := strings.Index(value[cursor:], placeholder)
		if relativeStart < 0 {
			return errors.New("remote MCP header configuration is invalid")
		}
		start := cursor + relativeStart
		resolved.WriteString(value[cursor:start])
		if t.resolve == nil {
			return errors.New("remote MCP host-vault secret is unavailable")
		}
		secret, err := t.resolve(ctx, t.server, name)
		if err != nil || len(secret) == 0 || strings.ContainsAny(string(secret), "\r\n\x00") {
			clear(secret)
			return errors.New("remote MCP host-vault secret is unavailable")
		}
		resolved.Write(secret)
		clear(secret)
		cursor = start + len(placeholder)
	}
	resolved.WriteString(value[cursor:])
	req.Header.Set(key, resolved.String())
	return nil
}

// startRemoteSession connects to a streamable HTTP MCP endpoint with a
// pinned transport: no proxy environment, verified TLS, no standalone SSE
// stream, bounded event size.
func (m *Manager) startRemoteSession(ctx context.Context, server Server) (*managedSession, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	lookup, dial := m.remoteDialers()
	tlsConfig := m.remoteTLS()
	m.mu.Lock()
	secretResolver := m.remoteSecrets
	m.mu.Unlock()
	serverHost, err := remoteServerHost(server.URL)
	if err != nil {
		return nil, errors.New("remote MCP server configuration is invalid")
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext: func(ctx context.Context, networkName, address string) (net.Conn, error) {
			return pinnedRemoteDialContext(ctx, dialer, lookup, dial, networkName, address)
		},
		TLSClientConfig: tlsConfig,
	}
	var roundTripper http.RoundTripper = transport
	if len(server.Headers)+len(server.SecretHeaders) > 0 {
		roundTripper = headerTransport{base: transport, headers: server.Headers, secretHeaders: server.SecretHeaders, server: server.Name, host: serverHost, resolve: secretResolver}
	}
	client := &http.Client{Transport: roundTripper, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	stream := &mcp.StreamableClientTransport{
		Endpoint:             server.URL,
		HTTPClient:           client,
		MaxRetries:           0,
		DisableStandaloneSSE: true,
		MaxEventSize:         5 << 20,
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "rheic-daemon", Version: version.Version}, nil)
	session, err := mcpClient.Connect(ctx, stream, nil)
	if err != nil {
		return nil, errors.New("remote MCP server connection failed")
	}
	return &managedSession{session: session}, nil
}
