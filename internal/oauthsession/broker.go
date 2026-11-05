package oauthsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBrokerRequestBody = 1 << 20

// TokenStore is the host-only store used by one sandbox OAuth credential.
type TokenStore interface {
	Save(context.Context, Tokens) error
	Load(context.Context) (Tokens, time.Time, error)
	Delete(context.Context) error
}

// BrokerConfig is immutable kit metadata validated by trusted host code.
type BrokerConfig struct {
	TokenEndpointHost string
	TokenEndpointPath string
	ResourceHosts     []string
	Sentinels         Sentinels
	ResponseFields    ResponseFields
}

// Broker intercepts one exact OAuth token endpoint and injects host-held bearer
// tokens only into the configured resource hosts.
type Broker struct {
	config            BrokerConfig
	store             TokenStore
	tokenTransport    http.RoundTripper
	resourceTransport func(context.Context, string) (http.RoundTripper, error)
	gate              chan struct{}
}

// NewBroker validates an immutable host/path allowlist. Transports must enforce
// HTTPS certificate verification, destination pinning, policy and no redirects.
func NewBroker(config BrokerConfig, store TokenStore, tokenTransport http.RoundTripper,
	resourceTransport func(context.Context, string) (http.RoundTripper, error),
) (*Broker, error) {
	config.TokenEndpointHost = canonicalOAuthHost(config.TokenEndpointHost)
	if !validOAuthHost(config.TokenEndpointHost) || !validOAuthPath(config.TokenEndpointPath) || store == nil || tokenTransport == nil || resourceTransport == nil ||
		config.Sentinels.AccessToken == "" || config.Sentinels.RefreshToken == "" || config.Sentinels.AccessToken == config.Sentinels.RefreshToken {
		return nil, errors.New("invalid OAuth broker configuration")
	}
	if !validResponseFields(normalizedResponseFields(config.ResponseFields)) {
		return nil, errors.New("invalid OAuth broker response fields")
	}
	seen := map[string]struct{}{config.TokenEndpointHost: {}}
	for i, host := range config.ResourceHosts {
		host = canonicalOAuthHost(host)
		if !validOAuthHost(host) {
			return nil, errors.New("invalid OAuth resource host")
		}
		if _, duplicate := seen[host]; duplicate {
			return nil, errors.New("duplicate OAuth broker host")
		}
		seen[host] = struct{}{}
		config.ResourceHosts[i] = host
	}
	config.ResponseFields = normalizedResponseFields(config.ResponseFields)
	return &Broker{config: config, store: store, tokenTransport: tokenTransport, resourceTransport: resourceTransport, gate: make(chan struct{}, 1)}, nil
}

// ServeHTTP is used inside a host-terminated TLS tunnel. CONNECT target, TLS
// SNI, Host header, and the configured exact host must all agree.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b == nil || r == nil || r.URL == nil || r.TLS == nil || r.TLS.ServerName == "" || !brokerHostMatchesTLS(r) {
		http.Error(w, "OAuth proxy host mismatch", http.StatusMisdirectedRequest)
		return
	}
	host := canonicalOAuthHost(r.TLS.ServerName)
	if host == b.config.TokenEndpointHost {
		b.serveTokenEndpoint(w, r)
		return
	}
	for _, resourceHost := range b.config.ResourceHosts {
		if host == resourceHost {
			b.serveResourceRequest(w, r, host)
			return
		}
	}
	http.Error(w, "OAuth proxy host is not authorized", http.StatusForbidden)
}

func brokerHostMatchesTLS(r *http.Request) bool {
	host := canonicalOAuthHost(r.Host)
	if parsedHost, port, err := net.SplitHostPort(host); err == nil {
		if port != "443" {
			return false
		}
		host = canonicalOAuthHost(parsedHost)
	}
	return host == canonicalOAuthHost(r.TLS.ServerName)
}

func (b *Broker) serveTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if !validIncomingTokenRequest(r, b.config.TokenEndpointPath) {
		http.Error(w, "OAuth token request is unsupported", http.StatusForbidden)
		return
	}
	if !b.acquire(r.Context()) {
		return
	}
	defer b.release()
	body, err := readBrokerBody(r.Body, maxBrokerRequestBody)
	if err != nil {
		http.Error(w, "OAuth token request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	defer clear(body)
	upstreamBody, err := b.prepareTokenRequest(r.Context(), body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNoTokens) {
			status = http.StatusBadGateway
		}
		http.Error(w, "OAuth token request is invalid or unavailable", status)
		return
	}
	defer clear(upstreamBody)
	response, err := b.roundTripToken(r, upstreamBody)
	if err != nil {
		http.Error(w, "OAuth token endpoint is unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		b.writeOAuthProviderError(w, r, response)
		return
	}
	responseBody, err := readBrokerBody(response.Body, maxInterceptedTokenResponse)
	if err != nil {
		http.Error(w, "OAuth token response is invalid", http.StatusBadGateway)
		return
	}
	defer clear(responseBody)
	filtered, tokens, err := InterceptTokenResponse(responseBody, b.config.ResponseFields, b.config.Sentinels)
	if err != nil {
		http.Error(w, "OAuth token response is invalid", http.StatusBadGateway)
		return
	}
	defer clear(filtered)
	if err := b.saveTokens(r.Context(), tokens); err != nil {
		http.Error(w, "OAuth token storage failed", http.StatusBadGateway)
		return
	}
	writeSanitizedTokenResponse(w, response.StatusCode, filtered)
}

func validIncomingTokenRequest(r *http.Request, tokenPath string) bool {
	return r.Method == http.MethodPost && r.URL != nil && r.URL.Path == tokenPath && r.URL.RawPath == "" && r.URL.RawQuery == "" && r.URL.Fragment == "" &&
		r.ContentLength <= maxBrokerRequestBody && len(r.TransferEncoding) <= 1
}

func readBrokerBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("OAuth body exceeds limit")
	}
	return data, nil
}

func (b *Broker) prepareTokenRequest(ctx context.Context, body []byte) ([]byte, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values["grant_type"]) != 1 {
		return nil, errors.New("invalid OAuth grant")
	}
	switch values.Get("grant_type") {
	case "authorization_code":
		if len(values["code"]) != 1 || len(values["code_verifier"]) > 1 || len(values["refresh_token"]) != 0 {
			return nil, errors.New("invalid OAuth authorization grant")
		}
		return append([]byte(nil), body...), nil
	case refreshGrant:
		return b.restoreRefreshGrant(ctx, values, body)
	default:
		return nil, errors.New("unsupported OAuth grant")
	}
}

func (b *Broker) restoreRefreshGrant(ctx context.Context, values url.Values, body []byte) ([]byte, error) {
	if len(values[refreshGrant]) != 1 || values.Get(refreshGrant) != b.config.Sentinels.RefreshToken {
		return nil, errors.New("invalid OAuth refresh sentinel")
	}
	stored, _, err := b.store.Load(ctx)
	if err != nil || stored.RefreshToken == "" {
		return nil, ErrNoTokens
	}
	restored, _, err := RestoreRefreshToken(body, b.config.Sentinels.RefreshToken, stored.RefreshToken)
	return restored, err
}

func (b *Broker) saveTokens(ctx context.Context, tokens Tokens) error {
	if tokens.RefreshToken == "" {
		previous, _, err := b.store.Load(ctx)
		if err != nil || previous.RefreshToken == "" {
			return ErrNoTokens
		}
		tokens.RefreshToken = previous.RefreshToken
	}
	return b.store.Save(ctx, tokens)
}

func writeSanitizedTokenResponse(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (b *Broker) writeOAuthProviderError(w http.ResponseWriter, r *http.Request, response *http.Response) {
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized {
		body, err := readBrokerBody(response.Body, 8<<10)
		if err == nil && errors.Is(classifyTokenError(bytes.NewReader(body)), ErrOAuthReauthRequired) {
			clear(body)
			if deleteErr := b.store.Delete(r.Context()); deleteErr != nil {
				http.Error(w, "OAuth credential state is unavailable", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		clear(body)
	}
	http.Error(w, "OAuth token endpoint rejected request", http.StatusBadGateway)
}

func (b *Broker) roundTripToken(incoming *http.Request, body []byte) (*http.Response, error) {
	endpoint := &url.URL{Scheme: httpsScheme, Host: b.config.TokenEndpointHost, Path: b.config.TokenEndpointPath}
	request, err := http.NewRequestWithContext(incoming.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid OAuth upstream request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	client := http.Client{Transport: b.tokenTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("OAuth token upstream request failed")
	}
	return response, nil
}

func (b *Broker) serveResourceRequest(w http.ResponseWriter, incoming *http.Request, host string) {
	tokens, expiry, err := b.store.Load(incoming.Context())
	if err != nil || expiry.IsZero() || !expiry.After(time.Now()) || tokens.AccessToken == "" {
		http.Error(w, "OAuth resource credential is unavailable", http.StatusBadGateway)
		return
	}
	transport, err := b.resourceTransport(incoming.Context(), host)
	if err != nil || transport == nil {
		http.Error(w, "OAuth resource host is unavailable", http.StatusBadGateway)
		return
	}
	request := incoming.Clone(incoming.Context())
	request.RequestURI = ""
	request.URL = &url.URL{Scheme: "https", Host: host, Path: incoming.URL.Path, RawPath: incoming.URL.RawPath, RawQuery: incoming.URL.RawQuery, ForceQuery: incoming.URL.ForceQuery}
	request.Host = host
	request.Header = incoming.Header.Clone()
	for _, header := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token", "X-Api-Token", "Proxy-Connection"} {
		request.Header.Del(header)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err := transport.RoundTrip(request)
	if err != nil || response == nil {
		http.Error(w, "OAuth resource request failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		http.Error(w, "OAuth resource redirect is not supported", http.StatusBadGateway)
		return
	}
	for _, header := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Cache-Control", "ETag", "Last-Modified", "Retry-After"} {
		for _, value := range response.Header.Values(header) {
			w.Header().Add(header, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 64<<20))
}

func (b *Broker) acquire(ctx context.Context) bool {
	select {
	case b.gate <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *Broker) release() { <-b.gate }

func canonicalOAuthHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func validOAuthHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, ":/@?#\\\x00\r\n") || net.ParseIP(host) != nil {
		return false
	}
	parsed := &url.URL{Scheme: httpsScheme, Host: host}
	if parsed.Hostname() != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !validOAuthLabel(label) {
			return false
		}
	}
	return true
}

func validOAuthLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range label {
		if !validOAuthHostRune(label[i]) {
			return false
		}
	}
	return true
}

func validOAuthHostRune(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' }

func validOAuthPath(path string) bool {
	return path != "" && strings.HasPrefix(path, "/") && !strings.ContainsAny(path, "?#\\\x00\r\n") &&
		!strings.Contains(path, "//") && !strings.Contains(path, "/../") && !strings.HasSuffix(path, "/..")
}
