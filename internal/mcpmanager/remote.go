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

// RegisterRemote queues a remote (streamable HTTP) MCP server for trusted
// host approval. The URL must satisfy the fail-closed remote policy before a
// challenge is created.
func (m *Manager) RegisterRemote(ctx context.Context, name, rawURL string, headers map[string]string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	server, err := prepareRemoteServer(name, rawURL, headers, m.remoteHostAllowed)
	if err != nil {
		return "", err
	}
	return m.registerPrepared(ctx, server)
}

// prepareRemoteServer validates a remote MCP server registration against the
// host allowlist. Anything but an exact, allowlisted https host fails closed.
func prepareRemoteServer(name, rawURL string, headers map[string]string, allowed func(string) bool) (Server, error) {
	if !namePattern.MatchString(name) {
		return Server{}, errors.New("invalid MCP server name")
	}
	_, cleanURL, err := validateRemoteURL(rawURL, allowed)
	if err != nil {
		return Server{}, err
	}
	copied, err := copiedRemoteHeaders(headers)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name, Transport: transportRemote, URL: cleanURL, Headers: copied}, nil
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

// copiedRemoteHeaders validates and copies static, non-secret headers.
// Authorization material must come from the host vault, never registration.
func copiedRemoteHeaders(headers map[string]string) (map[string]string, error) {
	copied := make(map[string]string, len(headers))
	for key, value := range headers {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" || strings.ContainsAny(trimmed, "\r\n:\x00") {
			return nil, errors.New("invalid remote MCP header name")
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid remote MCP header value")
		}
		if strings.EqualFold(trimmed, "authorization") || strings.EqualFold(trimmed, "proxy-authorization") {
			return nil, errors.New("secret MCP headers must come from the host vault, not registration")
		}
		copied[trimmed] = value
	}
	if len(copied) > 16 {
		return nil, errors.New("remote MCP server allows at most 16 headers")
	}
	return copied, nil
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
	base    http.RoundTripper
	headers map[string]string
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	for key, value := range t.headers {
		cloned.Header.Set(key, value)
	}
	return t.base.RoundTrip(cloned)
}

// startRemoteSession connects to a streamable HTTP MCP endpoint with a
// pinned transport: no proxy environment, verified TLS, no standalone SSE
// stream, bounded event size.
func (m *Manager) startRemoteSession(ctx context.Context, server Server) (*managedSession, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tlsConfig := m.remoteTLS()
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
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
	}
	var roundTripper http.RoundTripper = transport
	if len(server.Headers) > 0 {
		roundTripper = headerTransport{base: transport, headers: server.Headers}
	}
	client := &http.Client{Transport: roundTripper}
	stream := &mcp.StreamableClientTransport{
		Endpoint:             server.URL,
		HTTPClient:           client,
		MaxRetries:           0,
		DisableStandaloneSSE: true,
		MaxEventSize:         5 << 20,
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "rheic-daemon", Version: "0.0.36"}, nil)
	session, err := mcpClient.Connect(ctx, stream, nil)
	if err != nil {
		return nil, errors.New("remote MCP server connection failed")
	}
	return &managedSession{session: session}, nil
}
