package registrycredentials

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/KLORQ/sandboxes-gateway/registryauth"
)

func TestPullProxyUsesHostCredentialsAndIsolatesSandboxes(t *testing.T) {
	tokenRequests, registryRequests := 0, 0
	challengeRealm := ""
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		username, password, ok := r.BasicAuth()
		if !ok || username != "fixture-user" || password != "fixture-password" || r.URL.Query().Get("scope") != "repository:demo:pull" {
			t.Error("unexpected token request")
		}
		_, _ = fmt.Fprint(w, `{"token":"fixture-bearer"}`)
	}))
	defer tokenServer.Close()
	tokenURL, err := url.Parse(tokenServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	registryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryRequests++
		if r.URL.Path == "/v2/truncated/manifests/latest" {
			w.Header().Set("Content-Length", "100")
			_, _ = fmt.Fprint(w, "short")
			return
		}
		if r.URL.Path == "/v2/redirect/manifests/latest" {
			w.Header().Set("Location", "https://redirect.invalid/synthetic")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/v2/public/manifests/latest" {
			_, _ = fmt.Fprint(w, `{"public":true}`)
			return
		}
		if strings.Contains(r.Header.Get("Authorization"), "guest-secret") {
			t.Error("guest authorization reached upstream")
		}
		if r.Header.Get("Authorization") != "Bearer fixture-bearer" {
			realmURL := tokenServer.URL
			if challengeRealm != "" {
				realmURL = challengeRealm
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry.fixture",scope="repository:demo:pull"`, realmURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/demo/blobs/sha256:abc" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = fmt.Fprint(w, "fixture-layer")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = fmt.Fprint(w, `{"fixture":true}`)
	}))
	defer registryServer.Close()
	registryURL, err := url.Parse(registryServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tokenServer.Certificate())
	roots.AddCert(registryServer.Certificate())
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	realm := registryauth.Realm{Host: tokenURL.Host, Path: "/token"}
	tokenTransport, err := registryauth.NewTokenTransport(realm, allowed, roots)
	if err != nil {
		t.Fatal(err)
	}
	registryTransport, err := registryauth.NewRegistryTransport(registryURL.Host, allowed, roots)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(NativeVault{backend: &fakeKeyringBackend{items: make(map[string]string)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Save(context.Background(), Credential{Registry: registryURL.Host, Username: "fixture-user", Password: []byte("fixture-password"), Scope: ScopeSandbox, SandboxName: "one"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := PullProxyConfig{Registry: registryURL.Host, SandboxName: "one", CredentialScope: ScopeSandbox, Service: "registry.fixture", Realms: []registryauth.Realm{realm}, RegistryTransport: registryTransport, TokenTransport: tokenTransport, MaxBytes: 1024}
	proxy, err := NewPullProxy(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody)
	request.Header.Set("Authorization", "Bearer guest-secret")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"fixture":true}` || tokenRequests != 1 || registryRequests != 2 {
		t.Fatalf("pull failed: status=%d body=%q token=%d registry=%d", response.Code, response.Body.String(), tokenRequests, registryRequests)
	}
	if strings.Contains(response.Body.String(), "fixture-bearer") || strings.Contains(fmt.Sprint(response.Header()), "fixture-bearer") {
		t.Fatal("host bearer token reached guest")
	}
	layer := httptest.NewRecorder()
	proxy.ServeHTTP(layer, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/blobs/sha256:abc", http.NoBody))
	if layer.Code != http.StatusOK || layer.Body.String() != "fixture-layer" || tokenRequests != 2 {
		t.Fatal("private blob pull failed")
	}
	public := httptest.NewRecorder()
	proxy.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "http://guest/v2/public/manifests/latest", http.NoBody))
	if public.Code != http.StatusOK || public.Body.String() != `{"public":true}` || tokenRequests != 2 {
		t.Fatal("public pull did not succeed without a token exchange")
	}
	probe := httptest.NewRecorder()
	proxy.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "http://guest/v2/", http.NoBody))
	if probe.Code != http.StatusOK || tokenRequests != 2 {
		t.Fatal("registry probe failed or accessed credentials")
	}
	before := registryRequests
	write := httptest.NewRecorder()
	proxy.ServeHTTP(write, httptest.NewRequest(http.MethodPut, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if write.Code != http.StatusForbidden || registryRequests != before {
		t.Fatal("write request reached registry")
	}
	challengeRealm = "https://untrusted.example"
	wrongRealm := httptest.NewRecorder()
	proxy.ServeHTTP(wrongRealm, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if wrongRealm.Code != http.StatusBadGateway || tokenRequests != 2 {
		t.Fatal("untrusted realm reached token endpoint")
	}
	wrongProbe := httptest.NewRecorder()
	proxy.ServeHTTP(wrongProbe, httptest.NewRequest(http.MethodGet, "http://guest/v2/", http.NoBody))
	if wrongProbe.Code != http.StatusBadGateway || tokenRequests != 2 {
		t.Fatal("registry probe accepted an untrusted challenge")
	}
	challengeRealm = ""
	wrongScope := httptest.NewRecorder()
	proxy.ServeHTTP(wrongScope, httptest.NewRequest(http.MethodGet, "http://guest/v2/other/manifests/latest", http.NoBody))
	if wrongScope.Code != http.StatusBadGateway || tokenRequests != 2 {
		t.Fatal("unrelated repository challenge reached token endpoint")
	}
	redirect := httptest.NewRecorder()
	proxy.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "http://guest/v2/redirect/manifests/latest", http.NoBody))
	if redirect.Code != http.StatusBadGateway || redirect.Header().Get("Location") != "" {
		t.Fatal("upstream redirect was forwarded to guest")
	}
	limitedCfg := cfg
	limitedCfg.MaxBytes = 4
	limited, err := NewPullProxy(store, limitedCfg)
	if err != nil {
		t.Fatal(err)
	}
	large := httptest.NewRecorder()
	limited.ServeHTTP(large, httptest.NewRequest(http.MethodGet, "http://guest/v2/public/manifests/latest", http.NoBody))
	if large.Code != http.StatusBadGateway || strings.Contains(large.Body.String(), "public") {
		t.Fatal("oversized response reached guest")
	}
	truncated := httptest.NewRecorder()
	proxy.ServeHTTP(truncated, httptest.NewRequest(http.MethodGet, "http://guest/v2/truncated/manifests/latest", http.NoBody))
	if truncated.Code != http.StatusBadGateway || strings.Contains(truncated.Body.String(), "short") {
		t.Fatal("truncated upstream response was reported as success")
	}
	hostCfg := cfg
	hostCfg.CredentialScope = ScopeHostOnly
	if _, err := NewPullProxy(store, hostCfg); err == nil {
		t.Fatal("host-only credential was enabled for guest pull")
	}
	cfg.SandboxName = "other"
	other, err := NewPullProxy(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	other.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if denied.Code != http.StatusBadGateway || tokenRequests != 2 {
		t.Fatal("other sandbox obtained credentials")
	}
	removed, err := store.Delete(context.Background(), registryURL.Host, ScopeSandbox, "one")
	if err != nil || !removed {
		t.Fatal("failed to remove fixture credential")
	}
	afterLogout := httptest.NewRecorder()
	proxy.ServeHTTP(afterLogout, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if afterLogout.Code != http.StatusBadGateway || tokenRequests != 2 {
		t.Fatal("pull obtained new token after logout")
	}
}
