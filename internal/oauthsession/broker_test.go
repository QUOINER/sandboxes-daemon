package oauthsession

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type brokerRoundTripper func(*http.Request) (*http.Response, error)

func (f brokerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type brokerMemoryStore struct {
	tokens Tokens
	expiry time.Time
}

func (s *brokerMemoryStore) Save(_ context.Context, tokens Tokens) error {
	s.tokens = tokens
	if tokens.ExpiresIn > 0 {
		s.expiry = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	return nil
}

func (s *brokerMemoryStore) Load(context.Context) (Tokens, time.Time, error) {
	if s.tokens.AccessToken == "" {
		return Tokens{}, time.Time{}, ErrNoTokens
	}
	return s.tokens, s.expiry, nil
}

func (s *brokerMemoryStore) Delete(context.Context) error {
	s.tokens = Tokens{}
	s.expiry = time.Time{}
	return nil
}

func TestBrokerInterceptsTokenAndInjectsOnlyConfiguredResourceHost(t *testing.T) {
	store := &brokerMemoryStore{}
	var upstreamToken string
	tokenTransport := brokerRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://auth.example.test/oauth/token" {
			t.Fatalf("token endpoint escaped configured authority: %s", request.URL)
		}
		requestBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(requestBody)
		if !strings.Contains(string(requestBody), "grant_type=authorization_code") {
			t.Fatalf("unexpected upstream token request body: %q", requestBody)
		}
		body := `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"synthetic-id","expires_in":300,"token_type":"Bearer"}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	resourceTransport := func(_ context.Context, host string) (http.RoundTripper, error) {
		if host != "api.example.test" {
			t.Fatalf("unconfigured resource host selected: %s", host)
		}
		return brokerRoundTripper(func(request *http.Request) (*http.Response, error) {
			upstreamToken = request.Header.Get("Authorization")
			if request.URL.Host != host {
				t.Fatalf("resource request escaped configured host: %s", request.URL)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: request}, nil
		}), nil
	}
	broker, err := NewBroker(BrokerConfig{
		TokenEndpointHost: "auth.example.test", TokenEndpointPath: "/oauth/token",
		ResourceHosts: []string{"api.example.test"}, Sentinels: Sentinels{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"},
	}, store, tokenTransport, resourceTransport)
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest := brokerRequest("auth.example.test", "/oauth/token", "grant_type=authorization_code&code=synthetic-code")
	tokenRecorder := httptest.NewRecorder()
	broker.ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusOK {
		t.Fatalf("token interception status=%d body=%s", tokenRecorder.Code, tokenRecorder.Body.String())
	}
	for _, secret := range []string{"synthetic-access", "synthetic-refresh", "synthetic-id"} {
		if strings.Contains(tokenRecorder.Body.String(), secret) {
			t.Fatalf("token response leaked %s: %s", secret, tokenRecorder.Body.String())
		}
	}
	if !strings.Contains(tokenRecorder.Body.String(), "access-sentinel") || !strings.Contains(tokenRecorder.Body.String(), "refresh-sentinel") {
		t.Fatalf("guest did not receive sentinels: %s", tokenRecorder.Body.String())
	}

	resourceRequest := brokerRequest("api.example.test", "/v1/models", "")
	resourceRequest.Header.Set("Authorization", "Bearer guest-value")
	resourceRequest.Header.Set("Proxy-Authorization", "Basic guest-value")
	resourceRecorder := httptest.NewRecorder()
	broker.ServeHTTP(resourceRecorder, resourceRequest)
	if resourceRecorder.Code != http.StatusOK || upstreamToken != "Bearer synthetic-access" {
		t.Fatalf("resource response status=%d upstream auth=%q body=%q", resourceRecorder.Code, upstreamToken, resourceRecorder.Body.String())
	}
}

func TestBrokerRestoresRefreshSentinelAndFailsClosedOnWrongHostOrPath(t *testing.T) {
	store := &brokerMemoryStore{}
	if err := store.Save(context.Background(), Tokens{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer", ExpiresIn: 300}); err != nil {
		t.Fatal(err)
	}
	var forwarded string
	transport := brokerRoundTripper(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		forwarded = string(body)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"new-access","expires_in":300,"token_type":"Bearer"}`)), Request: request}, nil
	})
	broker, err := NewBroker(BrokerConfig{TokenEndpointHost: "auth.example.test", TokenEndpointPath: "/oauth/token",
		ResourceHosts: []string{"api.example.test"}, Sentinels: Sentinels{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"}}, store, transport,
		func(context.Context, string) (http.RoundTripper, error) { return transport, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := brokerRequest("auth.example.test", "/oauth/token", "grant_type=refresh_token&refresh_token=refresh-sentinel&client_id=client")
	recorder := httptest.NewRecorder()
	broker.ServeHTTP(recorder, request)
	form, parseErr := url.ParseQuery(forwarded)
	if recorder.Code != http.StatusOK || parseErr != nil || form.Get("refresh_token") != "old-refresh" {
		t.Fatalf("refresh status=%d forwarded=%q err=%v", recorder.Code, forwarded, parseErr)
	}
	for _, wrong := range []*http.Request{
		brokerRequest("evil.example.test", "/oauth/token", "grant_type=authorization_code&code=x"),
		brokerRequest("auth.example.test", "/oauth/other", "grant_type=authorization_code&code=x"),
	} {
		bad := httptest.NewRecorder()
		broker.ServeHTTP(bad, wrong)
		if bad.Code < 400 {
			t.Errorf("accepted wrong OAuth endpoint host/path: %s%s", wrong.Host, wrong.URL.Path)
		}
	}
}

func brokerRequest(host, path, body string) *http.Request {
	request, _ := http.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(body))
	request.Host = host
	request.TLS = &tls.ConnectionState{ServerName: host}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func TestBrokerInvalidGrantDeletesHostCredentialWithoutEchoingProviderBody(t *testing.T) {
	store := &brokerMemoryStore{tokens: Tokens{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", TokenType: "Bearer"}, expiry: time.Now().Add(time.Hour)}
	broker, err := NewBroker(BrokerConfig{
		TokenEndpointHost: "auth.example.test", TokenEndpointPath: "/oauth/token",
		ResourceHosts: []string{"api.example.test"},
		Sentinels:     Sentinels{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"},
	}, store, brokerRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant","detail":"synthetic-refresh"}`)), Request: request}, nil
	}), func(context.Context, string) (http.RoundTripper, error) { return brokerRoundTripper(nil), nil })
	if err != nil {
		t.Fatal(err)
	}
	req := brokerRequest("auth.example.test", "/oauth/token", "grant_type=refresh_token&refresh_token=refresh-sentinel")
	response := httptest.NewRecorder()
	broker.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "synthetic") || strings.Contains(response.Body.String(), "temporarily_unavailable") {
		t.Fatalf("invalid_grant response code=%d body=%q", response.Code, response.Body.String())
	}
	if store.tokens.AccessToken != "" || store.tokens.RefreshToken != "" || !store.expiry.IsZero() {
		t.Fatalf("invalid_grant did not clear credentials: %+v", store.tokens)
	}
}
