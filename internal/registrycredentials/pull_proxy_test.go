package registrycredentials

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

type pullRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f pullRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type pullRedirectFactory struct {
	redirect  http.RoundTripper
	authority string
}

func (pullRedirectFactory) Registry(context.Context, string) (http.RoundTripper, error) {
	return nil, errors.New("unused")
}

func TestNewPullProxyRedirectDefaultsAreRegistryScoped(t *testing.T) {
	tests := []struct {
		name      string
		registry  string
		authority string
		realms    []registryauth.Realm
		redirects []string
		wantCDN   bool
	}{
		{name: "Docker Hub default", registry: "docker.io", authority: "registry-1.docker.io", realms: []registryauth.Realm{{Host: "auth.docker.io", Path: "/token"}}, wantCDN: true},
		{name: "private registry default denies", registry: "registry.private.test", authority: "registry.private.test", realms: []registryauth.Realm{{Host: "auth.private.test", Path: "/token"}}},
		{name: "private registry explicit allow", registry: "registry.private.test", authority: "registry.private.test", realms: []registryauth.Realm{{Host: "auth.private.test", Path: "/token"}}, redirects: []string{"cdn.private.test"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := NewPullProxy(&Store{}, PullProxyConfig{
				Registry: test.registry, Authority: test.authority, SandboxName: "synthetic-sandbox",
				CredentialScope: ScopeSandbox, Service: "registry.fixture", Realms: test.realms,
				RedirectAuthorities: test.redirects, TransportFactory: pullRedirectFactory{},
				Limiter: NewPullLimiter(), MaxBytes: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}
			gotCDN := proxy.isRedirectHost(dockerHubBlobAuthority)
			if gotCDN != test.wantCDN {
				t.Fatalf("Docker Hub CDN allowed = %v, want %v", gotCDN, test.wantCDN)
			}
			if len(test.redirects) != 0 && !proxy.isRedirectHost(test.redirects[0]) {
				t.Fatal("explicit private redirect allowlist was not applied")
			}
		})
	}
}

func TestForwardProxyConnectTerminatesTLSForBoundHostOnly(t *testing.T) {
	authority, err := generateProxyAuthority()
	if err != nil {
		t.Fatal(err)
	}
	proxy := &PullProxy{authority: "registry-1.docker.io", redirectHosts: redirectHostSet([]string{dockerHubBlobAuthority}), tlsAuthority: authority, tunnelSlots: make(chan struct{}, 8)}
	server := httptest.NewServer(proxy)
	defer server.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.Certificate()) {
		t.Fatal("failed to load test proxy CA")
	}

	connect := func(serverName string) (net.Conn, error) {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(conn, "CONNECT registry-1.docker.io:443 HTTP/1.1\r\nHost: registry-1.docker.io:443\r\n\r\n"); err != nil {
			_ = conn.Close()
			return nil, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("CONNECT status %d", response.StatusCode)
		}
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName})
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	conn, err := connect("registry-1.docker.io")
	if err != nil {
		t.Fatalf("trusted CONNECT failed: %v", err)
	}
	if _, err := fmt.Fprint(conn, "GET /v2/ HTTP/1.1\r\nHost: registry-1.docker.io\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = conn.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("registry probe status=%d body=%q headers=%v", response.StatusCode, body, response.Header)
	}

	mismatchedHost, err := connect("registry-1.docker.io")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(mismatchedHost, "GET /token?service=registry.docker.io&scope=repository:team/image:pull HTTP/1.1\r\nHost: auth.docker.io\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	mismatchResponse, err := http.ReadResponse(bufio.NewReader(mismatchedHost), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = mismatchResponse.Body.Close()
	_ = mismatchedHost.Close()
	if mismatchResponse.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("mismatched CONNECT/SNI/Host status=%d", mismatchResponse.StatusCode)
	}

	wrongSNI, err := connect("auth.docker.io")
	if err == nil {
		_ = wrongSNI.Close()
		t.Fatal("CONNECT target accepted a mismatched TLS SNI")
	}
}
func (pullRedirectFactory) Token(context.Context, registryauth.Realm) (http.RoundTripper, error) {
	return nil, errors.New("unused")
}
func (f pullRedirectFactory) Redirect(_ context.Context, authority string) (http.RoundTripper, error) {
	want := f.authority
	if want == "" {
		want = "production.cloudfront.docker.com"
	}
	if authority != want {
		return nil, errors.New("unexpected redirect authority")
	}
	return f.redirect, nil
}

func TestPullProxyRedirectDropsBearerAndRejectsUntrustedAuthority(t *testing.T) {
	registryRequests, blobRequests := 0, 0
	registryTransport := pullRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		registryRequests++
		if got := r.Header.Get("Authorization"); got != "Bearer registry-token" {
			t.Fatalf("registry authorization = %q", got)
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://production.cloudfront.docker.com/blob?sig=synthetic"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	blobTransport := pullRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		blobRequests++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("registry bearer crossed origin: %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Length": []string{"4"}}, Body: io.NopCloser(strings.NewReader("blob")), ContentLength: 4}, nil
	})
	p := &PullProxy{authority: "registry-1.docker.io", redirectHosts: redirectHostSet([]string{dockerHubBlobAuthority}), transportFactory: pullRedirectFactory{redirect: blobTransport}, maxBytes: 8}
	client := &http.Client{Transport: registryTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint, _ := url.Parse("https://registry-1.docker.io/v2/library/test/blobs/sha256:abcd")
	resp, err := p.followPullRedirects(context.Background(), client, httptest.NewRequest(http.MethodGet, "http://guest/v2/library/test/blobs/sha256:abcd", http.NoBody), endpoint, "registry-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "blob" || registryRequests != 1 || blobRequests != 1 {
		t.Fatalf("redirect result body=%q err=%v registry=%d blob=%d", body, err, registryRequests, blobRequests)
	}
	if trustedPullRedirectHost("attacker.example") || trustedPullRedirectHost("production.cloudfront.docker.com:444") {
		t.Fatal("untrusted pull redirect host accepted")
	}
}

func TestPullProxyUsesConfiguredPrivateRedirectAndDropsBearer(t *testing.T) {
	registryRequests, redirectRequests := 0, 0
	registryTransport := pullRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		registryRequests++
		if got := r.Header.Get("Authorization"); got != "Bearer registry-token" {
			t.Fatalf("registry authorization = %q", got)
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://cdn.private.test/blob?sig=synthetic"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	redirectTransport := pullRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		redirectRequests++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("registry bearer crossed to configured redirect host: %q", got)
		}
		if r.URL.Host != "cdn.private.test" || r.URL.Query().Get("sig") != "synthetic" {
			t.Fatalf("unexpected redirect request: %s", r.URL.Redacted())
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Length": []string{"4"}}, Body: io.NopCloser(strings.NewReader("blob")), ContentLength: 4}, nil
	})
	p := &PullProxy{
		authority: "registry.private.test", maxBytes: 8,
		redirectHosts:    map[string]struct{}{"cdn.private.test": {}},
		transportFactory: pullRedirectFactory{redirect: redirectTransport, authority: "cdn.private.test"},
	}
	client := &http.Client{Transport: registryTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint, _ := url.Parse("https://registry.private.test/v2/team/image/blobs/sha256:abcd")
	resp, err := p.followPullRedirects(context.Background(), client, httptest.NewRequest(http.MethodGet, "http://guest/v2/team/image/blobs/sha256:abcd", http.NoBody), endpoint, "registry-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "blob" || registryRequests != 1 || redirectRequests != 1 {
		t.Fatalf("configured redirect result body=%q err=%v registry=%d redirect=%d", body, err, registryRequests, redirectRequests)
	}

	for _, location := range []string{
		"https://attacker.private.test/blob",
		"https://cdn.private.test:444/blob",
		"http://cdn.private.test/blob",
	} {
		if _, err := p.validatePullRedirect(endpoint, location); err == nil {
			t.Errorf("accepted unsafe configured redirect %q", location)
		}
	}
	if _, err := (&PullProxy{authority: "registry.private.test"}).validatePullRedirect(endpoint, "https://cdn.private.test/blob"); err == nil {
		t.Fatal("unconfigured private redirect host was accepted")
	}
}

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
		if r.URL.Path == "/v2/missing/manifests/latest" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`)
			return
		}
		if r.URL.Path == "/v2/public-gzip/manifests/latest" {
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf("upstream Accept-Encoding = %q, want identity", r.Header.Get("Accept-Encoding"))
			}
			var encoded bytes.Buffer
			compressor := gzip.NewWriter(&encoded)
			if _, err := compressor.Write([]byte(`{"compressed":true}`)); err != nil {
				t.Errorf("compress fixture: %v", err)
				return
			}
			if err := compressor.Close(); err != nil {
				t.Errorf("close compressed fixture: %v", err)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(encoded.Len()))
			_, _ = w.Write(encoded.Bytes())
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
	cfg := PullProxyConfig{Registry: registryURL.Host, SandboxName: "one", CredentialScope: ScopeSandbox, Service: "registry.fixture", Realms: []registryauth.Realm{realm}, RegistryTransport: registryTransport, TokenTransport: tokenTransport, Limiter: NewPullLimiter(), MaxBytes: 1024}
	proxy, err := NewPullProxy(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bodyRequest := httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", strings.NewReader("synthetic request body"))
	bodyResponse := httptest.NewRecorder()
	proxy.ServeHTTP(bodyResponse, bodyRequest)
	if bodyResponse.Code != http.StatusBadRequest || registryRequests != 0 {
		t.Fatalf("registry pull body status=%d upstream_requests=%d", bodyResponse.Code, registryRequests)
	}
	for range cap(proxy.inflight) {
		proxy.inflight <- struct{}{}
	}
	perSandboxOverload := httptest.NewRecorder()
	proxy.ServeHTTP(perSandboxOverload, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if perSandboxOverload.Code != http.StatusServiceUnavailable || perSandboxOverload.Header().Get("Retry-After") != "1" {
		t.Fatalf("per-sandbox overload status=%d headers=%v", perSandboxOverload.Code, perSandboxOverload.Header())
	}
	for range cap(proxy.inflight) {
		<-proxy.inflight
	}
	for range maxQueuedRegistryPulls {
		proxy.limiter.queued <- struct{}{}
	}
	overloaded := httptest.NewRecorder()
	proxy.ServeHTTP(overloaded, httptest.NewRequest(http.MethodGet, "http://guest/v2/demo/manifests/latest", http.NoBody))
	if overloaded.Code != http.StatusServiceUnavailable || overloaded.Header().Get("Retry-After") != "1" {
		t.Fatalf("overloaded registry request status=%d headers=%v", overloaded.Code, overloaded.Header())
	}
	for range maxQueuedRegistryPulls {
		<-proxy.limiter.queued
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
	missing := httptest.NewRecorder()
	proxy.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "http://guest/v2/missing/manifests/latest", http.NoBody))
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), "MANIFEST_UNKNOWN") || tokenRequests != 2 {
		t.Fatalf("missing manifest response status=%d body=%q tokens=%d", missing.Code, missing.Body.String(), tokenRequests)
	}
	compressed := httptest.NewRecorder()
	proxy.ServeHTTP(compressed, httptest.NewRequest(http.MethodGet, "http://guest/v2/public-gzip/manifests/latest", http.NoBody))
	if compressed.Code != http.StatusOK || compressed.Header().Get("Content-Encoding") != "gzip" || compressed.Header().Get("Content-Length") == "" {
		t.Fatalf("compressed manifest metadata was not preserved: status=%d headers=%v", compressed.Code, compressed.Header())
	}
	decoder, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(decoder)
	_ = decoder.Close()
	if err != nil || string(decoded) != `{"compressed":true}` {
		t.Fatalf("compressed manifest body = %q, error = %v", decoded, err)
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
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	truncated, err := proxyServer.Client().Get(proxyServer.URL + "/v2/truncated/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(truncated.Body)
	_ = truncated.Body.Close()
	if truncated.StatusCode != http.StatusOK || !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated upstream response status=%d read_err=%v", truncated.StatusCode, readErr)
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

func TestPullProxyPreservesNotModifiedResponse(t *testing.T) {
	transport := pullRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("ETag", "\"fixture\"")
		return &http.Response{StatusCode: http.StatusNotModified, Header: header, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	proxy := &PullProxy{authority: "registry-1.docker.io"}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint, _ := url.Parse("https://registry-1.docker.io/v2/library/test/manifests/latest")
	response, err := proxy.followPullRedirects(context.Background(), client, httptest.NewRequest(http.MethodGet, "http://guest/v2/library/test/manifests/latest", http.NoBody), endpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotModified || response.Header.Get("ETag") != "\"fixture\"" {
		t.Fatalf("not-modified response = status %d, ETag %q", response.StatusCode, response.Header.Get("ETag"))
	}
}

func TestValidatePullRedirectRejectsUnsafeTargets(t *testing.T) {
	current, _ := url.Parse("https://registry-1.docker.io/v2/library/test/blobs/sha256:abcd")
	for _, location := range []string{
		"",
		"http://production.cloudfront.docker.com/blob",
		"https://user@production.cloudfront.docker.com/blob",
		"https://production.cloudfront.docker.com:444/blob",
		"https://registry-1.docker.io.attacker.example/blob",
		"https://attacker.example/blob",
	} {
		if _, err := validatePullRedirect(current, location, "registry-1.docker.io"); err == nil {
			t.Errorf("accepted unsafe redirect target %q", location)
		}
	}
	got, err := validatePullRedirect(current, "https://production.cloudfront.docker.com/blob?sig=synthetic", "registry-1.docker.io")
	if err != nil || got.Host != "production.cloudfront.docker.com" {
		t.Fatalf("rejected trusted blob redirect: target=%v err=%v", got, err)
	}
}

type countingPullResponseWriter struct {
	header   http.Header
	status   int
	written  int64
	maxWrite int
	sample   []byte
}

func (w *countingPullResponseWriter) Header() http.Header { return w.header }

func (w *countingPullResponseWriter) WriteHeader(status int) { w.status = status }

func (w *countingPullResponseWriter) Write(data []byte) (int, error) {
	if len(data) > w.maxWrite {
		w.maxWrite = len(data)
	}
	w.written += int64(len(data))
	if len(w.sample) < 128 {
		remaining := 128 - len(w.sample)
		if len(data) < remaining {
			remaining = len(data)
		}
		w.sample = append(w.sample, data[:remaining]...)
	}
	return len(data), nil
}

type repeatedPullResponseReader struct{ remaining int64 }

func (r *repeatedPullResponseReader) Read(data []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(data))
	if n > r.remaining {
		n = r.remaining
	}
	clear(data[:int(n)])
	r.remaining -= n
	return int(n), nil
}

func TestPullProxyStreamsLargeResponseWithBoundedWrites(t *testing.T) {
	const responseSize = (32 << 20) + 1
	proxy := &PullProxy{maxBytes: responseSize}
	response := &http.Response{
		StatusCode: http.StatusOK, ContentLength: responseSize,
		Header: make(http.Header), Body: io.NopCloser(&repeatedPullResponseReader{remaining: responseSize}),
	}
	writer := &countingPullResponseWriter{header: make(http.Header)}
	if err := proxy.writeResponse(writer, http.MethodGet, response); err != nil {
		t.Fatal(err)
	}
	if writer.status != http.StatusOK || writer.written != responseSize || writer.maxWrite > 32<<10 ||
		writer.header.Get("Content-Length") != fmt.Sprint(responseSize) {
		t.Fatalf("stream result status=%d bytes=%d max_write=%d content_length=%q", writer.status, writer.written, writer.maxWrite, writer.header.Get("Content-Length"))
	}
}

func TestPullProxyRejectsUnknownOrOversizedLengthBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		contentLength int64
		maxBytes      int64
	}{
		{name: "unknown", contentLength: -1, maxBytes: 1024},
		{name: "oversized", contentLength: 1025, maxBytes: 1024},
		{name: "oversized error", status: http.StatusNotFound, contentLength: maxPullErrorResponseBytes + 1, maxBytes: maxPullResponseBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := &PullProxy{maxBytes: tc.maxBytes}
			status := tc.status
			if status == 0 {
				status = http.StatusOK
			}
			response := &http.Response{
				StatusCode: status, ContentLength: tc.contentLength,
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic")),
			}
			writer := &countingPullResponseWriter{header: make(http.Header)}
			if err := proxy.writeResponse(writer, http.MethodGet, response); err == nil {
				t.Fatal("writeResponse() accepted an unknown or oversized body")
			}
			if writer.status != http.StatusBadGateway || strings.Contains(string(writer.sample), "synthetic") {
				t.Fatalf("rejected response status=%d bytes=%d", writer.status, writer.written)
			}
		})
	}
}

func TestConfiguredRegistryConnectAndRealmAllowlist(t *testing.T) {
	authority, err := generateProxyAuthority()
	if err != nil {
		t.Fatal(err)
	}
	authority.AllowHosts("registry.private.test", "auth.private.test", "cdn.private.test")
	proxy := &PullProxy{
		authority:     "registry.private.test",
		realms:        []registryauth.Realm{{Host: "auth.private.test", Path: "/token"}},
		redirectHosts: map[string]struct{}{"cdn.private.test": {}},
		tlsAuthority:  authority,
		tunnelSlots:   make(chan struct{}, 8),
	}
	for _, host := range []string{"registry.private.test", "auth.private.test", "cdn.private.test"} {
		if !proxy.allowedConnectHost(host) {
			t.Fatalf("configured host %q was rejected", host)
		}
	}
	if proxy.allowedConnectHost("attacker.example") {
		t.Fatal("unconfigured host was allowed")
	}
	if realm, ok := proxy.authRealm("AUTH.private.test."); !ok || realm.Path != "/token" {
		t.Fatalf("realm lookup = %+v, %v", realm, ok)
	}
	if _, err := authority.Leaf("registry.private.test", time.Now()); err != nil {
		t.Fatalf("configured host leaf: %v", err)
	}
	if _, err := authority.Leaf("attacker.example", time.Now()); err == nil {
		t.Fatal("authority signed an unconfigured host")
	}
}

func TestRealmPathWinsOnSharedRegistryHost(t *testing.T) {
	proxy := &PullProxy{
		authority: "registry.example.test",
		realms:    []registryauth.Realm{{Host: "registry.example.test", Path: "/token"}},
	}
	if realm, ok := proxy.realmForPath("REGISTRY.example.test.", "/token"); !ok || realm.Path != "/token" {
		t.Fatalf("realm dispatch = %+v, %v", realm, ok)
	}
	if _, ok := proxy.realmForPath("registry.example.test", "/v2/repo/manifests/v1"); ok {
		t.Fatal("manifest path treated as a token request")
	}
}
