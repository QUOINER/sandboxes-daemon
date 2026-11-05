package oauthsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	OpenAIIssuer        = "https://auth.openai.com"
	OpenAICodexClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	OpenAITokenURL      = OpenAIIssuer + "/oauth/token"
	OpenAIRevokeURL     = OpenAIIssuer + "/oauth/revoke"
)

// NewOpenAICodexProvider returns the fixed public PKCE client configuration
// used by the Codex CLI. It accepts no endpoint or client configuration from
// the caller beyond an HTTPS-verifying transport.
func NewOpenAICodexProvider(transport http.RoundTripper) (Provider, error) {
	if transport == nil {
		return Provider{}, errors.New("OpenAI OAuth transport is required")
	}
	return Provider{
		AuthorizationEndpoint: OpenAIIssuer + "/oauth/authorize",
		TokenEndpoint:         OpenAITokenURL,
		ClientID:              OpenAICodexClientID,
		Scopes:                []string{"openid", "profile", "email", "offline_access", "api.connectors.read", "api.connectors.invoke"},
		AuthorizationParams: map[string]string{
			"id_token_add_organizations": "true",
			"codex_cli_simplified_flow":  "true",
			"originator":                 "rsbx",
		},
		CallbackPorts: []uint16{1455, 1457},
		CallbackPath:  "/auth/callback",
		Transport:     transport,
	}, nil
}

// RevokeOpenAI revokes a host-held refresh token using the Codex-compatible
// JSON request. It never follows redirects and bounds response consumption.
func RevokeOpenAI(ctx context.Context, transport http.RoundTripper, refreshToken string) error {
	if transport == nil || refreshToken == "" {
		return errors.New("invalid OpenAI OAuth revocation request")
	}
	body, err := json.Marshal(struct {
		Token         string `json:"token"`
		TokenTypeHint string `json:"token_type_hint"`
		ClientID      string `json:"client_id"`
	}{Token: refreshToken, TokenTypeHint: refreshGrant, ClientID: OpenAICodexClientID})
	if err != nil {
		return errors.New("encode OpenAI OAuth revocation request")
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OpenAIRevokeURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("build OpenAI OAuth revocation request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("OpenAI OAuth revocation failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("OpenAI OAuth revocation was rejected")
	}
	return nil
}
