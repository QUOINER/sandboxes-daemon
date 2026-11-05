package oauthsession

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrOAuthReauthRequired means the provider rejected the stored refresh token
// permanently (OAuth invalid_grant); local credentials must be removed.
var ErrOAuthReauthRequired = errors.New("OAuth credentials require sign-in")

// Tokens contain sensitive material; never log or expose them to guests.
type Tokens struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	IDToken      string   `json:"id_token,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
}

// String and GoString prevent accidental formatting of credentials in logs.
func (Tokens) String() string   { return "[redacted OAuth tokens]" }
func (Tokens) GoString() string { return "[redacted OAuth tokens]" }

// Exchange redeems a code using the transaction's PKCE verifier. The caller
// must supply an endpoint and TLS-verifying transport from trusted host config.
func (s *Session) Exchange(ctx context.Context, transport http.RoundTripper, endpoint, clientID, redirect, code string) (Tokens, error) {
	if s == nil || s.verifier == "" || code == "" || clientID == "" || !validRedirect(redirect) {
		return Tokens{}, errors.New("invalid OAuth code exchange")
	}
	s.mu.Lock()
	if !s.used || s.exchanged || s.code != code || s.redirect != redirect || s.clientID != clientID || s.tokenEndpoint == "" || s.tokenEndpoint != endpoint {
		s.mu.Unlock()
		return Tokens{}, errors.New("OAuth code is not bound to this transaction")
	}
	s.exchanged = true
	s.code = ""
	s.mu.Unlock()
	return tokenRequest(ctx, transport, endpoint, url.Values{
		grantTypeKey: {"authorization_code"}, "code": {code}, clientIDKey: {clientID},
		"redirect_uri": {redirect}, "code_verifier": {s.verifier},
	})
}

func (s *Session) bindTokenEndpoint(endpoint string) error {
	if !validEndpointString(endpoint) {
		return errors.New("invalid OAuth token endpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenEndpoint != "" || s.used {
		return errors.New("OAuth token endpoint already bound")
	}
	s.tokenEndpoint = endpoint
	return nil
}

// Refresh renews an access token without allowing endpoint redirects.
func Refresh(ctx context.Context, transport http.RoundTripper, endpoint, clientID, refreshToken string) (Tokens, error) {
	if clientID == "" || refreshToken == "" {
		return Tokens{}, errors.New("invalid OAuth refresh request")
	}
	return tokenRequest(ctx, transport, endpoint, url.Values{
		grantTypeKey: {refreshGrant}, refreshGrant: {refreshToken}, clientIDKey: {clientID},
	})
}

// Revoke removes a refresh token upstream. Local keychain deletion should occur
// first so a network failure cannot leave the session usable on this host.
func Revoke(ctx context.Context, transport http.RoundTripper, endpoint, clientID, refreshToken string) error {
	if clientID == "" || refreshToken == "" || !validEndpointString(endpoint) || transport == nil {
		return errors.New("invalid OAuth revocation configuration")
	}
	u, _ := url.Parse(endpoint)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(url.Values{
		clientIDKey: {clientID}, "token": {refreshToken},
	}.Encode()))
	if err != nil {
		return errors.New("invalid OAuth revocation request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("OAuth token revocation failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return errors.New("OAuth token revocation was rejected")
	}
	return nil
}

func tokenRequest(ctx context.Context, transport http.RoundTripper, endpoint string, form url.Values) (Tokens, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !validAuthorizationEndpoint(u) || transport == nil {
		return Tokens{}, errors.New("invalid OAuth token endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, errors.New("invalid OAuth token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return Tokens{}, errors.New("OAuth token request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	const maxTokenResponse = 64 << 10
	if resp.StatusCode != http.StatusOK {
		return Tokens{}, classifyTokenError(resp.Body)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil || len(body) > maxTokenResponse {
		return Tokens{}, errors.New("invalid OAuth token response")
	}
	defer clear(body)
	var tokens Tokens
	if json.Unmarshal(body, &tokens) != nil || tokens.AccessToken == "" || !strings.EqualFold(tokens.TokenType, "bearer") || tokens.ExpiresIn < 0 {
		return Tokens{}, errors.New("invalid OAuth token response")
	}
	return tokens, nil
}

func classifyTokenError(body io.Reader) error {
	const maxTokenErrorResponse = 8 << 10
	data, err := io.ReadAll(io.LimitReader(body, maxTokenErrorResponse+1))
	if err != nil || len(data) > maxTokenErrorResponse {
		clear(data)
		return errors.New("OAuth token endpoint rejected request")
	}
	defer clear(data)
	var providerError struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &providerError) == nil && providerError.Error == "invalid_grant" {
		return ErrOAuthReauthRequired
	}
	return errors.New("OAuth token endpoint rejected request")
}

func validEndpointString(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && validAuthorizationEndpoint(u)
}
