package oauthsession

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type openAIRoundTripper func(*http.Request) (*http.Response, error)

func (f openAIRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOpenAICodexProviderUsesFixedPKCEContract(t *testing.T) {
	provider, err := NewOpenAICodexProvider(http.DefaultTransport)
	if err != nil {
		t.Fatal(err)
	}
	if provider.AuthorizationEndpoint != OpenAIIssuer+"/oauth/authorize" || provider.TokenEndpoint != OpenAITokenURL ||
		provider.ClientID != OpenAICodexClientID || provider.CallbackPath != "/auth/callback" ||
		len(provider.CallbackPorts) != 2 || provider.CallbackPorts[0] != 1455 || provider.CallbackPorts[1] != 1457 {
		t.Fatalf("unexpected OpenAI provider config: %#v", provider)
	}
	session, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range provider.AuthorizationParams {
		if !validAuthorizationExtra(key, value) {
			t.Fatalf("invalid provider param %q=%q", key, value)
		}
	}
	authorizationURL, err := session.AuthorizationURLWithParams(provider.AuthorizationEndpoint, provider.ClientID,
		"http://127.0.0.1:1455/auth/callback", provider.Scopes, provider.AuthorizationParams)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("scope") != strings.Join(provider.Scopes, " ") || query.Get("codex_cli_simplified_flow") != "true" ||
		query.Get("id_token_add_organizations") != "true" || query.Get("originator") != "rsbx" ||
		query.Get("redirect_uri") != "http://127.0.0.1:1455/auth/callback" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("OpenAI authorization request differs from trusted configuration: %s", authorizationURL)
	}
}

func TestFixedOAuthCallbackFallsBackOnlyToConfiguredLoopbackPort(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	occupiedPort := uint16(occupied.Addr().(*net.TCPAddr).Port)
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := uint16(free.Addr().(*net.TCPAddr).Port)
	_ = free.Close()

	session, err := New()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := listenOnPorts(session, []uint16{occupiedPort, freePort}, "/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = callback.Close() }()
	want := "http://127.0.0.1:" + strconv.Itoa(int(freePort)) + "/auth/callback"
	if got := callback.RedirectURI(); got != want {
		t.Fatalf("redirect URI=%q want=%q", got, want)
	}
}

func TestRevokeOpenAIUsesBoundedJSONAndDoesNotFollowRedirect(t *testing.T) {
	var calls int
	transport := openAIRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != OpenAIRevokeURL || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected revoke request: %s %s", request.Method, request.URL)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		defer clear(body)
		for _, value := range []string{`"token":"synthetic-refresh"`, `"token_type_hint":"refresh_token"`, `"client_id":"` + OpenAICodexClientID + `"`} {
			if !strings.Contains(string(body), value) {
				t.Errorf("revoke body missing %s", value)
			}
		}
		return &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := RevokeOpenAI(ctx, transport, "synthetic-refresh")
	if err == nil || calls != 1 {
		t.Fatalf("revoke error/calls=%v/%d", err, calls)
	}
}
