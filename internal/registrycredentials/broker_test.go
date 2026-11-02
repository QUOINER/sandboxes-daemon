package registrycredentials

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/KLORQ/sandboxes-gateway/registryauth"
)

func TestExchangeTokenUsesSelectedCredential(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		username, password, ok := r.BasicAuth()
		if !ok || username != "synthetic-user" || password != "synthetic-password" {
			t.Error("incorrect credential")
		}
		_, _ = fmt.Fprint(w, `{"token":"synthetic-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Save(context.Background(), Credential{Registry: "registry.example", Username: "synthetic-user", Password: []byte("synthetic-password"), Scope: ScopeSandbox, SandboxName: "one"})
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:demo:pull"`, server.URL)
	realms := []registryauth.Realm{{Host: endpoint.Host, Path: "/token"}}
	if _, err := store.exchangeToken(context.Background(), server.Client().Transport, "registry.example", ScopeSandbox, "one", header, nil, "registry.example", "repository:demo:pull"); err == nil || vault.reads != 0 {
		t.Fatal("untrusted realm accessed the credential store")
	}
	call := func(sandbox string) (string, error) {
		return store.exchangeToken(context.Background(), server.Client().Transport, "registry.example", ScopeSandbox, sandbox, header, realms, "registry.example", "repository:demo:pull")
	}
	if token, err := call("one"); err != nil || token != "synthetic-token" {
		t.Fatalf("exchange failed: %v", err)
	}
	if _, err := call("other"); err == nil || requests != 1 {
		t.Fatal("another sandbox accessed the credential")
	}
}

func TestExchangePullTokenDerivesScopeBeforeReadingCredential(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		username, password, ok := r.BasicAuth()
		if !ok || username != "synthetic-user" || password != "synthetic-password" || r.URL.Query().Get("scope") != "repository:team/app:pull" {
			t.Error("unexpected token request")
		}
		_, _ = fmt.Fprint(w, `{"token":"synthetic-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, err := registryauth.NewTokenTransport(registryauth.Realm{Host: endpoint.Host, Path: "/token"}, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Save(context.Background(), Credential{Registry: "registry.example", Username: "synthetic-user", Password: []byte("synthetic-password"), Scope: ScopeSandbox, SandboxName: "one"})
	if err != nil {
		t.Fatal(err)
	}
	pullURL, err := url.Parse("https://registry.example/v2/team/app/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	req := PullRequest{
		Registry: "registry.example", Scope: ScopeSandbox, SandboxName: "one", Method: http.MethodGet, URL: pullURL,
		Challenge: fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:team/app:pull"`, server.URL),
		Realms:    []registryauth.Realm{{Host: endpoint.Host, Path: "/token"}}, Service: "registry.example",
	}
	if _, err := store.ExchangePullToken(context.Background(), nil, req); err == nil || vault.reads != 0 {
		t.Fatal("missing transport accessed credentials")
	}
	token, err := store.ExchangePullToken(context.Background(), transport, req)
	if err != nil || token != "synthetic-token" || requests != 1 {
		t.Fatalf("authorized pull failed: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*PullRequest)
	}{
		{"push method", func(r *PullRequest) { r.Method = http.MethodPut }},
		{"wrong registry", func(r *PullRequest) { r.Registry = "other.example" }},
		{"wrong repository scope", func(r *PullRequest) {
			r.Challenge = fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:other:pull"`, server.URL)
		}},
		{"untrusted realm", func(r *PullRequest) { r.Realms = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := req
			tc.edit(&candidate)
			before := vault.reads
			if _, err := store.ExchangePullToken(context.Background(), transport, candidate); err == nil {
				t.Fatal("unauthorized pull was accepted")
			}
			if vault.reads != before || requests != 1 {
				t.Fatal("rejected request accessed credentials or token endpoint")
			}
		})
	}
	other := req
	other.SandboxName = "other"
	if _, err := store.ExchangePullToken(context.Background(), transport, other); err == nil || requests != 1 {
		t.Fatal("another sandbox accessed the credential")
	}
}

func TestExchangePullTokenStopsAfterLogout(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = fmt.Fprint(w, `{"token":"synthetic-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, err := registryauth.NewTokenTransport(registryauth.Realm{Host: endpoint.Host, Path: "/token"}, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	vault := NativeVault{backend: &fakeKeyringBackend{items: make(map[string]string)}}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = store.Save(ctx, Credential{Registry: "registry.example", Username: "synthetic-user", Password: []byte("synthetic-password"), Scope: ScopeSandbox, SandboxName: "one"})
	if err != nil {
		t.Fatal(err)
	}
	pullURL, err := url.Parse("https://registry.example/v2/demo/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	req := PullRequest{
		Registry: "registry.example", Scope: ScopeSandbox, SandboxName: "one", Method: http.MethodGet, URL: pullURL,
		Challenge: fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:demo:pull"`, server.URL),
		Realms:    []registryauth.Realm{{Host: endpoint.Host, Path: "/token"}}, Service: "registry.example",
	}
	if _, err := store.ExchangePullToken(ctx, transport, req); err != nil {
		t.Fatalf("exchange before logout: %v", err)
	}
	if removed, err := store.Delete(ctx, req.Registry, req.Scope, req.SandboxName); err != nil || !removed {
		t.Fatalf("logout: removed=%v err=%v", removed, err)
	}
	if _, err := store.ExchangePullToken(ctx, transport, req); err == nil || requests != 1 {
		t.Fatal("credential remained usable after logout")
	}
}
