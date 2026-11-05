package oauthsession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeSyntheticProvider(t *testing.T) {
	challenge := ""
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "synthetic-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			t.Error("token exchange did not match authorization")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`)
	}))
	defer provider.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "synthetic-provider")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func(_ context.Context, raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		challenge = q.Get("code_challenge")
		redirect := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}}.Encode()
		resp, err := (&http.Client{Timeout: time.Second}).Get(redirect)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("callback returned %d", resp.StatusCode)
		}
		return nil
	}
	err = Authorize(ctx, Provider{AuthorizationEndpoint: provider.URL + "/authorize", TokenEndpoint: provider.URL + "/token", ClientID: "synthetic-client", Transport: provider.Client().Transport}, open, sink)
	if err != nil {
		t.Fatal(err)
	}
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.AccessToken != "synthetic-access" || tokens.RefreshToken != "synthetic-refresh" {
		t.Fatal("tokens were not passed to sink")
	}
}

func TestAuthorizeUsesProviderRegisteredLoopbackCallback(t *testing.T) {
	challenge := ""
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "registered-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge ||
			r.Form.Get("redirect_uri") == "" || !strings.HasSuffix(r.Form.Get("redirect_uri"), "/auth/callback") {
			t.Error("token exchange was not bound to registered callback and PKCE transaction")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"synthetic-id","token_type":"Bearer","expires_in":60}`)
	}))
	defer tokenServer.Close()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()

	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "openai")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func(_ context.Context, raw string) error {
		authorizeURL, err := url.Parse(raw)
		if err != nil {
			return err
		}
		challenge = authorizeURL.Query().Get("code_challenge")
		redirect := authorizeURL.Query().Get("redirect_uri") + "?" + url.Values{
			"state": {authorizeURL.Query().Get("state")}, "code": {"registered-code"},
		}.Encode()
		response, err := (&http.Client{Timeout: time.Second}).Get(redirect)
		if err != nil {
			return err
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("callback returned %d", response.StatusCode)
		}
		return nil
	}
	provider := Provider{
		AuthorizationEndpoint: tokenServer.URL + "/authorize",
		TokenEndpoint:         tokenServer.URL + "/token",
		ClientID:              "synthetic-client",
		CallbackPorts:         []uint16{port},
		CallbackPath:          "/auth/callback",
		Transport:             tokenServer.Client().Transport,
	}
	if err := Authorize(ctx, provider, open, sink); err != nil {
		t.Fatal(err)
	}
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.IDToken != "synthetic-id" {
		t.Fatalf("ID token was not retained on host: err=%v", err)
	}
}
