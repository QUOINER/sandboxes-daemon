package oauthsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceAuthorizationAndPolling(t *testing.T) {
	approved := false
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/device":
			if r.Form.Get("client_id") != "fixture-client" || r.Form.Get("audience") != "fixture-audience" || r.Form.Get("scope") != "openid offline_access" {
				t.Error("device grant did not use the trusted configuration")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"synthetic-device-secret","user_code":"ABCD-EFGH","verification_uri_complete":"` + server.URL + `/activate?user_code=ABCD-EFGH","expires_in":120,"interval":1}`))
		case "/token":
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "synthetic-device-secret" {
				t.Error("token polling did not use the issued device code")
			}
			w.Header().Set("Content-Type", "application/json")
			if !approved {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- local synthetic TLS fixture
	defer transport.CloseIdleConnections()
	provider := DeviceProvider{DeviceEndpoint: server.URL + "/device", TokenEndpoint: server.URL + "/token", ClientID: "fixture-client", Audience: "fixture-audience", Scopes: []string{"openid", "offline_access"}, Transport: transport}
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "fixture-device")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	err = AuthorizeDevice(ctx, provider, func(_ context.Context, code, rawURL string) error {
		if code != "ABCD-EFGH" || !strings.Contains(rawURL, "user_code=ABCD-EFGH") {
			t.Error("unexpected user device instructions")
		}
		approved = true
		return nil
	}, sink)
	if err != nil {
		t.Fatal(err)
	}
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.AccessToken != "synthetic-access" || tokens.RefreshToken != "synthetic-refresh" {
		t.Fatal("device tokens were not saved to the host vault")
	}
}

func TestNewDockerHubProviderUsesDockerDeviceClient(t *testing.T) {
	provider, err := NewDockerHubProvider(http.DefaultTransport)
	if err != nil {
		t.Fatal(err)
	}
	if provider.ClientID != "L4v0dmlNBpYUjGGab0C2JtgTgXr1Qz4d" ||
		provider.DeviceEndpoint != DockerOAuthDeviceURL ||
		provider.TokenEndpoint != DockerOAuthTokenURL ||
		provider.PATEndpoint != DockerHubPATEndpoint ||
		provider.Audience != DockerOAuthAudience {
		t.Fatalf("Docker provider does not match the supported Docker login flow: %#v", provider)
	}
}

func TestDeviceAuthorizationCompletesURLWhenProviderOmitsCompleteURI(t *testing.T) {
	got, err := validateVerificationURI(deviceAuthorizationResponse{
		UserCode: "SYNTHETIC-CODE", VerificationURI: "https://login.example/activate?source=cli",
	}, "https://login.example/oauth/device/code")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://login.example/activate?source=cli&user_code=SYNTHETIC-CODE" {
		t.Fatalf("verification URL = %q", got)
	}
}

func TestDeviceAuthorizationRejectsTerminalControlInUserCode(t *testing.T) {
	for _, code := range []string{"ABCD\x1b[31m", "ABCD\nEFGH", strings.Repeat("A", 65)} {
		body := []byte(`{"device_code":"synthetic-device","user_code":"` + code + `","verification_uri":"https://login.example/device","expires_in":60}`)
		if _, err := parseDeviceAuthorization(body, "https://login.example/oauth/device"); err == nil {
			t.Fatalf("unsafe user code accepted: %q", code)
		}
	}
}

func TestDeviceAuthorizationRejectsRedirectAndLeaksNoDeviceCode(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.invalid/device", http.StatusFound)
	}))
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- local synthetic TLS fixture
	defer transport.CloseIdleConnections()
	_, err := BeginDeviceAuthorization(context.Background(), DeviceProvider{DeviceEndpoint: server.URL, TokenEndpoint: server.URL, ClientID: "fixture", Audience: "fixture", Transport: transport})
	if err == nil || strings.Contains(err.Error(), "synthetic-device-secret") {
		t.Fatalf("unexpected device authorization error: %v", err)
	}
	authorization := DeviceAuthorization{deviceCode: "synthetic-device-secret", UserCode: "ABCD", VerificationURI: "https://login.example"}
	if strings.Contains(fmt.Sprintf("%+v %#v", authorization, authorization), "synthetic-device-secret") {
		t.Fatal("device code leaked through formatting")
	}
}

func TestDeviceDenialAndExpiry(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want error
	}{{"denial", `{"error":"access_denied"}`, ErrDeviceDenied}, {"expiry", `{"error":"expired_token"}`, ErrDeviceExpired}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- local synthetic TLS fixture
			defer transport.CloseIdleConnections()
			_, err := WaitForDeviceToken(context.Background(), DeviceProvider{DeviceEndpoint: server.URL, TokenEndpoint: server.URL, ClientID: "fixture", Audience: "fixture", Transport: transport}, DeviceAuthorization{
				deviceCode: "synthetic", interval: time.Millisecond, expiresAt: time.Now().Add(time.Second),
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}
