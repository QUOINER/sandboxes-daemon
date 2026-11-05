package registrycredentials

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

type contractTransportFactory struct {
	registry http.RoundTripper
	token    http.RoundTripper
}

func (f contractTransportFactory) Registry(context.Context, string) (http.RoundTripper, error) {
	return f.registry, nil
}

func (f contractTransportFactory) Token(context.Context, registryauth.Realm) (http.RoundTripper, error) {
	return f.token, nil
}

func (contractTransportFactory) Redirect(context.Context, string) (http.RoundTripper, error) {
	return nil, fmt.Errorf("redirect is not used by this fixture")
}

func TestDockerHubForwardContractPullsAndPushesWithoutGuestBearerLeak(t *testing.T) {
	const (
		registryHost = "registry-1.docker.io"
		authHost     = "auth.docker.io"
		service      = "registry.docker.io"
		upstream     = "fixture-upstream-bearer"
	)
	var upstreamRequests []string
	registryTransport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != registryHost || request.Header.Get("Authorization") != "Bearer "+upstream {
			t.Errorf("upstream request authority/auth=%q/%q", request.URL.Host, request.Header.Get("Authorization"))
		}
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Error("guest proxy authorization reached registry")
		}
		if strings.Contains(request.Header.Get("Authorization"), "rheic-") {
			t.Error("guest sentinel leaked to registry")
		}
		upstreamRequests = append(upstreamRequests, request.Method+" "+request.URL.RequestURI())
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v2/team/image/manifests/latest":
			return contractResponse(http.StatusOK, `{"manifest":true}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/v2/team/image/blobs/uploads/":
			if request.URL.RawQuery != "" || request.Body != http.NoBody {
				t.Errorf("upload init query/body was not normalized: query=%q body=%T", request.URL.RawQuery, request.Body)
			}
			return contractResponse(http.StatusAccepted, "", http.Header{"Location": []string{"/v2/team/image/blobs/uploads/session-12345678?state=initial"}}), nil
		case request.Method == http.MethodPatch && strings.HasSuffix(request.URL.Path, "/session-12345678"):
			body, _ := io.ReadAll(request.Body)
			if string(body) != "layer-chunk" {
				t.Errorf("upload PATCH body=%q", body)
			}
			return contractResponse(http.StatusAccepted, "", http.Header{"Location": []string{"/v2/team/image/blobs/uploads/session-12345678?state=rotated"}}), nil
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/session-12345678"):
			body, _ := io.ReadAll(request.Body)
			if string(body) != "layer-final" || request.URL.Query().Get("digest") != "sha256:"+strings.Repeat("a", 64) {
				t.Errorf("upload completion body/digest=%q/%q", body, request.URL.Query().Get("digest"))
			}
			return contractResponse(http.StatusCreated, "", nil), nil
		case request.Method == http.MethodDelete && strings.HasSuffix(request.URL.Path, "/session-12345678"):
			return contractResponse(http.StatusAccepted, "", nil), nil
		case request.Method == http.MethodPut && request.URL.Path == "/v2/team/image/manifests/latest":
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"manifest":true}` {
				t.Errorf("manifest PUT body=%q", body)
			}
			return contractResponse(http.StatusCreated, "", nil), nil
		default:
			return contractResponse(http.StatusNotFound, `{"error":"unexpected fixture request"}`, nil), nil
		}
	})
	tokenTransport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "fixture-user" || password != "fixture-password" {
			t.Errorf("token endpoint received unexpected host credentials: %q", username)
		}
		if request.URL.Host != authHost || request.URL.Path != "/token" || request.Method != http.MethodGet {
			t.Errorf("token request endpoint/method=%s %s", request.Method, request.URL)
		}
		if scope := request.URL.Query().Get("scope"); scope != "repository:team/image:pull" && scope != "repository:team/image:pull,push" {
			t.Errorf("token exchange requested an unsupported scope: %q", scope)
		}
		return contractResponse(http.StatusOK, `{"token":"`+upstream+`"}`, nil), nil
	})
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(t.Context(), Credential{
		Registry: "docker.io", Username: "fixture-user", Password: []byte("fixture-password"),
		Scope: ScopeSandbox, SandboxName: "contract-sandbox",
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewPullProxy(store, PullProxyConfig{
		Registry: "docker.io", Authority: registryHost, SandboxName: "contract-sandbox", CredentialScope: ScopeSandbox,
		Service: service, Realms: []registryauth.Realm{{Host: authHost, Path: "/token"}},
		TransportFactory: contractTransportFactory{registry: registryTransport, token: tokenTransport},
		Limiter:          NewPullLimiter(), MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, host, path, body, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{ServerName: host}
		r.Host = host
		r.Header.Set("Proxy-Authorization", "Basic fixture-guest-proxy")
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, r)
		return recorder
	}
	getChallengeScope := func(response *httptest.ResponseRecorder, action string) string {
		t.Helper()
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected registry challenge, got %d: %s", response.Code, response.Body.String())
		}
		challenge, err := registryauth.ParseBearerChallenge(response.Header().Get("WWW-Authenticate"), []registryauth.Realm{{Host: authHost, Path: "/token"}})
		if err != nil {
			t.Fatal(err)
		}
		want := "repository:team/image:" + action
		if action == registryActionPush {
			want = "repository:team/image:pull,push"
		}
		if challenge.Scope != want {
			t.Fatalf("challenge scope=%q want=%q", challenge.Scope, want)
		}
		return challenge.Scope
	}
	getSentinel := func(scope string) string {
		t.Helper()
		values := url.Values{"service": []string{service}, "scope": []string{scope}}
		response := request(http.MethodGet, authHost, "/token?"+values.Encode(), "", "")
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("token response status/cache=%d/%q: %s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Token == "" || body.Token == upstream {
			t.Fatalf("unexpected guest token response: token=%q err=%v", body.Token, err)
		}
		return body.Token
	}

	pullChallenge := getChallengeScope(request(http.MethodGet, registryHost, "/v2/team/image/manifests/latest", "", ""), registryActionPull)
	pullToken := getSentinel(pullChallenge)
	pulled := request(http.MethodGet, registryHost, "/v2/team/image/manifests/latest", "", "Bearer "+pullToken)
	if pulled.Code != http.StatusOK || pulled.Body.String() != `{"manifest":true}` {
		t.Fatalf("manifest pull status/body=%d/%q", pulled.Code, pulled.Body.String())
	}

	pushScope := getChallengeScope(request(http.MethodPost, registryHost, "/v2/team/image/blobs/uploads/", "", ""), registryActionPush)
	pushToken := getSentinel(pushScope)
	initURL := "/v2/team/image/blobs/uploads/?mount=sha256%3A" + strings.Repeat("b", 64) + "&from=other/image"
	started := request(http.MethodPost, registryHost, initURL, "", "Bearer "+pushToken)
	if started.Code != http.StatusAccepted || started.Header().Get("Location") != "/v2/team/image/blobs/uploads/session-12345678?state=initial" {
		t.Fatalf("upload init status/location=%d/%q", started.Code, started.Header().Get("Location"))
	}
	patched := request(http.MethodPatch, registryHost, "/v2/team/image/blobs/uploads/session-12345678?state=initial", "layer-chunk", "Bearer "+pushToken)
	if patched.Code != http.StatusAccepted || !strings.Contains(patched.Header().Get("Location"), "state=rotated") {
		t.Fatalf("upload PATCH status/location=%d/%q", patched.Code, patched.Header().Get("Location"))
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	completed := request(http.MethodPut, registryHost, "/v2/team/image/blobs/uploads/session-12345678?state=rotated&digest="+url.QueryEscape(digest), "layer-final", "Bearer "+pushToken)
	if completed.Code != http.StatusCreated {
		t.Fatalf("upload completion status/body=%d/%q", completed.Code, completed.Body.String())
	}
	if _, exists := proxy.uploads["team/image/session-12345678"]; exists {
		t.Fatal("completed upload session remained authorized")
	}

	manifestPut := request(http.MethodPut, registryHost, "/v2/team/image/manifests/latest", `{"manifest":true}`, "Bearer "+pushToken)
	if manifestPut.Code != http.StatusCreated {
		t.Fatalf("manifest PUT status/body=%d/%q", manifestPut.Code, manifestPut.Body.String())
	}
	startedAgain := request(http.MethodPost, registryHost, "/v2/team/image/blobs/uploads/", "", "Bearer "+pushToken)
	if startedAgain.Code != http.StatusAccepted {
		t.Fatalf("second upload init status=%d", startedAgain.Code)
	}
	canceled := request(http.MethodDelete, registryHost, "/v2/team/image/blobs/uploads/session-12345678?state=initial", "", "Bearer "+pushToken)
	if canceled.Code != http.StatusAccepted {
		t.Fatalf("owned upload cancellation status=%d", canceled.Code)
	}
	if _, exists := proxy.uploads["team/image/session-12345678"]; exists {
		t.Fatal("canceled upload session remained authorized")
	}
	beforeDenied := len(upstreamRequests)
	for _, forbidden := range []struct{ method, path string }{
		{http.MethodDelete, "/v2/team/image/manifests/latest"},
		{http.MethodDelete, "/v2/team/image/blobs/sha256:" + strings.Repeat("a", 64)},
		{http.MethodPatch, "/v2/team/image/blobs/uploads/unknown-12345678"},
	} {
		response := request(forbidden.method, registryHost, forbidden.path, "", "Bearer "+pushToken)
		if response.Code != http.StatusForbidden {
			t.Errorf("forbidden request %s %s status=%d", forbidden.method, forbidden.path, response.Code)
		}
	}
	forbiddenMethods := []struct {
		method, host, path, token string
	}{
		{http.MethodPost, registryHost, "/v2/team/image/blobs/uploads/", pullToken},
		{http.MethodGet, registryHost, "/v2/other/image/manifests/latest", pushToken},
		{http.MethodGet, "evil.example", "/token?service=registry.docker.io&scope=repository:team/image:pull", ""},
	}
	for _, forbidden := range forbiddenMethods {
		response := request(forbidden.method, forbidden.host, forbidden.path, "", "Bearer "+forbidden.token)
		if response.Code != http.StatusForbidden {
			t.Errorf("unauthorized request %s %s status=%d", forbidden.method, forbidden.path, response.Code)
		}
	}
	if len(upstreamRequests) != beforeDenied {
		t.Fatal("forbidden operation reached the controlled registry")
	}
}

func contractResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	if body != "" {
		headers.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func TestUploadResponseRejectsUntrustedLocationBeforeForwarding(t *testing.T) {
	proxy := &PullProxy{authority: "registry-1.docker.io", uploads: make(map[string]uploadSession)}
	endpoint := &url.URL{Scheme: registryHTTPScheme, Host: proxy.authority, Path: "/v2/team/image/blobs/uploads/"}
	operation := registryOperation{repository: "team/image", action: registryActionPush, kind: registryUploadInitKind}
	for _, location := range []string{
		"https://attacker.example/v2/team/image/blobs/uploads/session-12345678",
		"https://registry-1.docker.io/v2/other/image/blobs/uploads/session-12345678",
		"https://registry-1.docker.io/v2/team/image/manifests/latest",
		"https://registry-1.docker.io/v2/team/image/blobs/uploads/session-12345678#fragment",
	} {
		recorder := httptest.NewRecorder()
		response := contractResponse(http.StatusAccepted, "", http.Header{"Location": []string{location}})
		proxy.finishRegistryResponse(recorder, http.MethodPost, endpoint, operation, response)
		if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Location") != "" {
			t.Errorf("untrusted upload location %q was forwarded: status=%d location=%q", location, recorder.Code, recorder.Header().Get("Location"))
		}
	}
	if len(proxy.uploads) != 0 {
		t.Fatal("untrusted upload location created an authorized session")
	}
}
