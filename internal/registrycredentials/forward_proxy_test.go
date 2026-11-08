package registrycredentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-gateway/registryauth"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

type realmRoutingFactory struct {
	transports map[registryauth.Realm]http.RoundTripper
	selected   []registryauth.Realm
}

func (f *realmRoutingFactory) Registry(context.Context, string) (http.RoundTripper, error) {
	return nil, errors.New("unexpected registry transport request")
}

func (f *realmRoutingFactory) Token(_ context.Context, realm registryauth.Realm) (http.RoundTripper, error) {
	f.selected = append(f.selected, realm)
	transport, ok := f.transports[realm]
	if !ok {
		return nil, errors.New("unexpected token realm")
	}
	return transport, nil
}

func (f *realmRoutingFactory) Redirect(context.Context, string) (http.RoundTripper, error) {
	return nil, errors.New("unexpected redirect transport request")
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestForwardRegistryTransportRestrictsAuthorityAndOperationKinds(t *testing.T) {
	transport, err := NewForwardRegistryTransport("registry-1.docker.io", []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pinned := transport.(*forwardRegistryTransport)
	var requests int
	pinned.transport = pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return contractResponse(http.StatusOK, "", nil), nil
	})
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/v2/team/image/manifests/latest"},
		{http.MethodPut, "/v2/team/image/manifests/latest"},
		{http.MethodPost, "/v2/team/image/blobs/uploads/"},
		{http.MethodPatch, "/v2/team/image/blobs/uploads/session-12345678"},
		{http.MethodPut, "/v2/team/image/blobs/uploads/session-12345678?digest=sha256:" + strings.Repeat("a", 64)},
		{http.MethodDelete, "/v2/team/image/blobs/uploads/session-12345678"},
	} {
		request, err := http.NewRequest(test.method, "https://registry-1.docker.io"+test.path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		response, err := pinned.RoundTrip(request)
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			t.Errorf("supported operation %s %s failed: response=%v err=%v", test.method, test.path, response, err)
		}
		if response != nil {
			_ = response.Body.Close()
		}
	}
	for _, test := range []struct{ method, target string }{
		{http.MethodDelete, "https://registry-1.docker.io/v2/team/image/manifests/latest"},
		{http.MethodPost, "https://registry-1.docker.io/v2/team/image/blobs/uploads/session-12345678"},
		{http.MethodPut, "https://attacker.example/v2/team/image/manifests/latest"},
	} {
		request, err := http.NewRequest(test.method, test.target, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pinned.RoundTrip(request); err == nil {
			t.Errorf("unsupported operation was accepted: %s %s", test.method, test.target)
		}
	}
	if requests != 6 {
		t.Fatalf("upstream called %d times; invalid operations must stop before dialing", requests)
	}
	if _, err := NewForwardRegistryTransport("registry-1.docker.io", []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}, nil); err == nil {
		t.Fatal("accepted a non-host-sized pin prefix")
	}
}

func TestDockerHubForwardScopeAndOperationBoundaries(t *testing.T) {
	for _, scope := range []string{
		"repository:team/image:pull", "repository:team/image:push", "repository:team/image:pull,push",
	} {
		if _, _, ok := parseRepositoryScope(scope); !ok {
			t.Errorf("expected valid scope %q", scope)
		}
	}
	for _, scope := range []string{
		"repository:team/image:delete", "repository:team/image:pull,delete", "repository:team/image:pull,pull",
		"repository:../image:push", "repository:Team/image:push", "repository:team/image:push:delete",
	} {
		if _, _, ok := parseRepositoryScope(scope); ok {
			t.Errorf("accepted invalid scope %q", scope)
		}
	}

	allowed := []struct{ method, path, action string }{
		{"GET", "/v2/team/image/manifests/latest", "pull"},
		{"PUT", "/v2/team/image/manifests/latest", "push"},
		{"POST", "/v2/team/image/blobs/uploads/", "push"},
		{"PATCH", "/v2/team/image/blobs/uploads/abc12345", "push"},
		{"PUT", "/v2/team/image/blobs/uploads/abc12345", "push"},
		{"DELETE", "/v2/team/image/blobs/uploads/abc12345", "push"},
	}
	for _, tc := range allowed {
		endpoint := &url.URL{Scheme: "https", Host: "registry-1.docker.io", Path: tc.path}
		operation, err := parseRegistryOperation(tc.method, endpoint, "registry-1.docker.io")
		if err != nil || operation.action != tc.action {
			t.Errorf("%s %s rejected: op=%#v err=%v", tc.method, tc.path, operation, err)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"DELETE", "/v2/team/image/manifests/latest"},
		{"DELETE", "/v2/team/image/blobs/sha256:abcdef"},
		{"POST", "/v2/team/image/blobs/uploads/abc12345"},
	} {
		endpoint := &url.URL{Scheme: "https", Host: "registry-1.docker.io", Path: tc.path}
		if _, err := parseRegistryOperation(tc.method, endpoint, "registry-1.docker.io"); err == nil {
			t.Errorf("accepted forbidden operation %s %s", tc.method, tc.path)
		}
	}
}

func TestUploadSessionBindsExactIssuedLocation(t *testing.T) {
	proxy := &PullProxy{uploads: make(map[string]uploadSession)}
	issued, err := url.Parse("https://registry-1.docker.io/v2/team/image/blobs/uploads/abc12345?_state=opaque")
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.storeUpload("team/image", "abc12345", issued); err != nil {
		t.Fatal(err)
	}
	allowed := &url.URL{Scheme: "https", Host: issued.Host, Path: issued.Path, RawQuery: "_state=opaque"}
	operation := registryOperation{repository: "team/image", action: "push", kind: "upload", uploadID: "abc12345"}
	if !proxy.authorizeUploadRequest(allowed, operation, "PATCH") {
		t.Fatal("issued upload URL was denied")
	}
	for _, query := range []string{"_state=attacker", "_state=opaque&admin=true"} {
		candidate := *allowed
		candidate.RawQuery = query
		if proxy.authorizeUploadRequest(&candidate, operation, "PATCH") {
			t.Errorf("accepted modified upload query %q", query)
		}
	}
	putURL := *allowed
	putURL.RawQuery += "&digest=sha256:" + strings.Repeat("a", 64)
	if !proxy.authorizeUploadRequest(&putURL, operation, "PUT") {
		t.Fatal("valid final upload digest was denied")
	}
	putURL.RawQuery = "_state=opaque&digest=sha256:bad"
	if proxy.authorizeUploadRequest(&putURL, operation, "PUT") {
		t.Fatal("invalid final upload digest was accepted")
	}
	otherHost := *allowed
	otherHost.Host = "attacker.example"
	if proxy.authorizeUploadRequest(&otherHost, operation, "PATCH") {
		t.Fatal("accepted upload URL from another host")
	}
}

func TestBlobRedirectRequiresExactRegistryIssuedURL(t *testing.T) {
	proxy := &PullProxy{redirectHosts: redirectHostSet([]string{dockerHubBlobAuthority})}
	issued, err := url.Parse("https://production.cloudfront.docker.com/v2/blobs/sha256:abc?sig=synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.recordBlobRedirect(issued); err != nil {
		t.Fatal(err)
	}
	allowed := *issued
	if !proxy.consumeBlobRedirect(&allowed) {
		t.Fatal("registry-issued blob URL was denied")
	}
	for _, mutate := range []func(*url.URL){
		func(candidate *url.URL) { candidate.Path = "/arbitrary/object" },
		func(candidate *url.URL) { candidate.RawQuery = "sig=attacker" },
		func(candidate *url.URL) { candidate.Host = "attacker.example" },
	} {
		candidate := *issued
		mutate(&candidate)
		if proxy.consumeBlobRedirect(&candidate) {
			t.Errorf("accepted an unissued redirect URL: %v", candidate)
		}
	}
	for use := 1; use < blobRedirectUses; use++ {
		if !proxy.consumeBlobRedirect(issued) {
			t.Fatalf("registry-issued URL denied on use %d", use+1)
		}
	}
	if proxy.consumeBlobRedirect(issued) {
		t.Fatal("accepted a redirect URL beyond its bounded use count")
	}
}

func TestBlobRedirectPreservesEmptyQueryMarker(t *testing.T) {
	const host = "cdn.private.test"
	transport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if !request.URL.ForceQuery || !strings.HasSuffix(request.URL.String(), "?") {
			t.Fatalf("outbound blob request lost empty query marker: %q", request.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, ContentLength: 0}, nil
	})
	proxy := &PullProxy{
		redirectHosts:    redirectHostSet([]string{host}),
		transportFactory: pullRedirectFactory{redirect: transport, authority: host},
		limiter:          NewPullLimiter(), maxBytes: 8, blobRedirects: make(map[string]blobRedirectSession),
	}
	issued, err := url.Parse("https://" + host + "/blob?")
	if err != nil || !issued.ForceQuery {
		t.Fatalf("parse issued empty-query redirect: url=%v err=%v", issued, err)
	}
	if err := proxy.recordBlobRedirect(issued); err != nil {
		t.Fatal(err)
	}
	withoutMarker := httptest.NewRequest(http.MethodGet, "https://"+host+"/blob", http.NoBody)
	denied := httptest.NewRecorder()
	proxy.serveBlobRedirectRequest(denied, withoutMarker, host)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("URL without issued empty-query marker returned %d", denied.Code)
	}
	withMarker := httptest.NewRequest(http.MethodGet, "https://"+host+"/blob?", http.NoBody)
	if !withMarker.URL.ForceQuery {
		t.Fatal("test request did not preserve the empty query marker")
	}
	allowed := httptest.NewRecorder()
	proxy.serveBlobRedirectRequest(allowed, withMarker, host)
	if allowed.Code != http.StatusOK {
		t.Fatalf("registry-issued empty-query redirect returned %d: %s", allowed.Code, allowed.Body.String())
	}
}

func TestBlobRedirectCapsNotFoundResponseBody(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		bodyLength     int64
		wantStatus     int
	}{
		{name: "within error limit", responseStatus: http.StatusNotFound, bodyLength: maxPullErrorResponseBytes, wantStatus: http.StatusNotFound},
		{name: "over error limit", responseStatus: http.StatusNotFound, bodyLength: maxPullErrorResponseBytes + 1, wantStatus: http.StatusBadGateway},
		{name: "successful blob exceeds error limit", responseStatus: http.StatusOK, bodyLength: maxPullErrorResponseBytes + 1, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := strings.Repeat("x", int(test.bodyLength))
			response := &http.Response{
				StatusCode: test.responseStatus, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(body)), ContentLength: test.bodyLength,
			}
			proxy := &PullProxy{maxBytes: maxPullResponseBytes}
			recorder := httptest.NewRecorder()
			proxy.writeBlobRedirect(recorder, http.MethodGet, response)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			if (test.wantStatus == http.StatusNotFound || test.wantStatus == http.StatusOK) && int64(recorder.Body.Len()) != test.bodyLength {
				t.Fatalf("body length = %d, want %d", recorder.Body.Len(), test.bodyLength)
			}
		})
	}
}

func TestBlobRedirectRejectsExpiredAndUntrustedSessions(t *testing.T) {
	proxy := &PullProxy{blobRedirects: make(map[string]blobRedirectSession), redirectHosts: redirectHostSet([]string{dockerHubBlobAuthority})}
	expired, err := url.Parse("https://production.cloudfront.docker.com/blob?sig=expired")
	if err != nil {
		t.Fatal(err)
	}
	proxy.blobRedirects[expired.String()] = blobRedirectSession{usesLeft: 1, expiresAt: time.Now().Add(-time.Second)}
	if proxy.consumeBlobRedirect(expired) {
		t.Fatal("accepted an expired registry redirect")
	}
	untrusted, err := url.Parse("https://attacker.example/blob?sig=synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.recordBlobRedirect(untrusted); err == nil {
		t.Fatal("recorded a redirect to an untrusted host")
	}
}

func TestConfiguredPrivateBlobRedirectTraversesForwardTLSPath(t *testing.T) {
	const location = "https://CDN.private.test.:443/v2/team%2Fimage/blobs/sha256:abcd?sig=synthetic"
	redirectTransport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "cdn.private.test" || request.URL.EscapedPath() != "/v2/team%2Fimage/blobs/sha256:abcd" ||
			request.URL.Query().Get("sig") != "synthetic" {
			t.Fatalf("unexpected blob redirect request: %s", request.URL.Redacted())
		}
		if got := request.Header.Get("Authorization"); got != "" {
			t.Fatalf("registry bearer crossed to blob host: %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("blob")), ContentLength: 4}, nil
	})
	proxy := &PullProxy{
		authority: "registry.private.test", redirectHosts: redirectHostSet([]string{"CDN.private.test."}),
		privateRegistry: true, maxBytes: 64, limiter: NewPullLimiter(),
		transportFactory: pullRedirectFactory{redirect: redirectTransport, authority: "cdn.private.test"},
		blobRedirects:    make(map[string]blobRedirectSession),
	}
	endpoint, err := url.Parse("https://registry.private.test/v2/team/image/blobs/sha256:abcd")
	if err != nil {
		t.Fatal(err)
	}
	redirectBody := &closeTrackingBody{Reader: strings.NewReader("")}
	registryResponse := &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{location}}, Body: redirectBody}
	registryWriter := httptest.NewRecorder()
	proxy.finishRegistryRedirect(t.Context(), registryWriter, httptest.NewRequest(http.MethodGet, endpoint.String(), http.NoBody), http.MethodGet, endpoint, registryResponse)
	if !redirectBody.closed {
		t.Fatal("registry redirect response body was not closed")
	}
	if registryWriter.Code != http.StatusOK || registryWriter.Body.String() != "blob" || registryWriter.Header().Get("Location") != "" {
		t.Fatalf("configured registry redirect status=%d body=%q location=%q", registryWriter.Code, registryWriter.Body.String(), registryWriter.Header().Get("Location"))
	}

	request := httptest.NewRequest(http.MethodGet, location, http.NoBody)
	request.TLS = &tls.ConnectionState{ServerName: "cdn.private.test"}
	request.Header.Set("Authorization", "Bearer guest-token")
	blobWriter := httptest.NewRecorder()
	proxy.serveForwardRequest(blobWriter, request)
	if blobWriter.Code != http.StatusForbidden {
		t.Fatalf("unrecorded TLS redirect status=%d body=%q", blobWriter.Code, blobWriter.Body.String())
	}
}

func TestForwardTLSPathRejectsUnconfiguredPrivateRedirect(t *testing.T) {
	proxy := &PullProxy{authority: "registry.private.test", redirectHosts: redirectHostSet(nil), privateRegistry: true}
	endpoint, err := url.Parse("https://registry.private.test/v2/team/image/blobs/sha256:abcd")
	if err != nil {
		t.Fatal(err)
	}
	registryWriter := httptest.NewRecorder()
	proxy.finishRegistryRedirect(t.Context(), registryWriter, httptest.NewRequest(http.MethodGet, endpoint.String(), http.NoBody), http.MethodGet, endpoint, &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"https://cdn.private.test/blob?sig=synthetic"}},
		Body:       http.NoBody,
	})
	if registryWriter.Code != http.StatusBadGateway {
		t.Fatalf("unconfigured registry redirect status=%d", registryWriter.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "https://cdn.private.test/blob?sig=synthetic", http.NoBody)
	request.TLS = &tls.ConnectionState{ServerName: "cdn.private.test"}
	blobWriter := httptest.NewRecorder()
	proxy.serveForwardRequest(blobWriter, request)
	if blobWriter.Code != http.StatusForbidden {
		t.Fatalf("unconfigured TLS redirect status=%d", blobWriter.Code)
	}
}

func TestProxyAuthorityPersistsAndMintsHostBoundLeaf(t *testing.T) {
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ProxyCA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ProxyCA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate()) != string(second.Certificate()) {
		t.Fatal("proxy CA changed between reads")
	}
	leaf, err := first.Leaf("registry-1.docker.io", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(first.Certificate()) {
		t.Fatal("root certificate could not be parsed")
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "registry-1.docker.io", Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf certificate did not verify: %v", err)
	}
	if _, err := first.Leaf("auth.docker.io", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Leaf("attacker.example", time.Now()); err == nil {
		t.Fatal("minted a leaf for an untrusted registry host")
	}
}

func TestTokenRequestAcceptsRepeatedScopes(t *testing.T) {
	query := "service=fixture&scope=repository:rheic/acceptance:pull&scope=repository:rheic/acceptance:pull%2Cpush"
	repository, actions, ok, valid := parseTokenRequestScope(query, "fixture")
	if !valid || !ok || repository != "rheic/acceptance" {
		t.Fatalf("scope = %q %v %v %v", repository, actions, ok, valid)
	}
	if _, hasPull := actions[registryActionPull]; !hasPull {
		t.Fatal("pull action missing")
	}
	if _, hasPush := actions[registryActionPush]; !hasPush {
		t.Fatal("push action missing")
	}
	other := "service=fixture&scope=repository:one:pull&scope=repository:two:pull"
	if _, _, ok, valid := parseTokenRequestScope(other, "fixture"); !valid || ok {
		t.Fatal("multi-repository token request accepted")
	}
}

func TestAuthenticatedForwardProxyDispatchesExactRealmAndPath(t *testing.T) {
	const (
		service = "registry.fixture"
		sandbox = "realm-routing-sandbox"
	)
	realms := []registryauth.Realm{
		{Host: "auth.private.test", Path: "/token"},
		{Host: "auth-alt.private.test", Path: "/oauth/token"},
	}
	upstreamTokens := []string{"realm-one-upstream-token", "realm-two-upstream-token"}
	transportCalls := make(map[registryauth.Realm]int, len(realms))
	transports := make(map[registryauth.Realm]http.RoundTripper, len(realms))
	transportForRealm := func(expected registryauth.Realm, upstreamToken string) http.RoundTripper {
		return pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			transportCalls[expected]++
			if request.Method != http.MethodGet || request.URL.Host != expected.Host || request.URL.Path != expected.Path {
				t.Errorf("realm %v received token exchange for %s %s; realm selection must bind host and path", expected, request.Method, request.URL)
			}
			if username, password, ok := request.BasicAuth(); !ok || username != "synthetic-user" || password != "synthetic-password" {
				t.Errorf("realm %v received unexpected synthetic credentials: %q", expected, username)
			}
			if request.URL.Query().Get("service") != service || request.URL.Query().Get("scope") != "repository:team/image:pull" {
				t.Errorf("realm %v received unexpected credential exchange query: %q", expected, request.URL.RawQuery)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"token":"` + upstreamToken + `"}`)),
			}, nil
		})
	}
	for index, realm := range realms {
		transports[realm] = transportForRealm(realm, upstreamTokens[index])
	}
	factory := &realmRoutingFactory{transports: transports}
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(t.Context(), Credential{
		Registry: "registry.private.test", Username: "synthetic-user", Password: []byte("synthetic-password"),
		Scope: ScopeSandbox, SandboxName: sandbox,
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewPullProxy(store, PullProxyConfig{
		Registry: "registry.private.test", SandboxName: sandbox, CredentialScope: ScopeSandbox,
		Service: service, Realms: realms, TransportFactory: factory, PrivateRegistry: true, Limiter: NewPullLimiter(), MaxBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(realm registryauth.Realm, path string) *httptest.ResponseRecorder {
		t.Helper()
		query := url.Values{"service": []string{service}, "scope": []string{"repository:team/image:pull"}}
		r := httptest.NewRequest(http.MethodGet, "https://"+realm.Host+path+"?"+query.Encode(), http.NoBody)
		r.TLS = &tls.ConnectionState{ServerName: realm.Host}
		r.Host = realm.Host
		// The PullProxy is bound to this sandbox; its registry credential is
		// loaded from the host vault and never supplied in this guest request.
		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, r)
		return response
	}

	mismatched := request(realms[1], realms[0].Path)
	if mismatched.Code != http.StatusForbidden {
		t.Fatalf("mismatched realm path returned %d: %s", mismatched.Code, mismatched.Body.String())
	}
	if len(factory.selected) != 0 || transportCalls[realms[0]] != 0 || transportCalls[realms[1]] != 0 {
		t.Fatalf("mismatched realm path invoked token exchange: selected=%v calls=%v", factory.selected, transportCalls)
	}

	for index, realm := range realms {
		otherRealm := realms[1-index]
		otherRealmCalls := transportCalls[otherRealm]
		response := request(realm, realm.Path)
		if response.Code != http.StatusOK {
			t.Fatalf("realm %v request returned %d: %s", realm, response.Code, response.Body.String())
		}
		for _, token := range upstreamTokens {
			if strings.Contains(response.Body.String(), token) {
				t.Fatal("upstream registry token was exposed to the guest")
			}
		}
		if got := factory.selected[index]; got != realm {
			t.Fatalf("request for realm %v selected token transport for %v", realm, got)
		}
		if transportCalls[realm] != 1 {
			t.Fatalf("request for realm %v called its token transport %d times", realm, transportCalls[realm])
		}
		if transportCalls[otherRealm] != otherRealmCalls {
			t.Fatalf("request for realm %v also invoked realm %v transport", realm, otherRealm)
		}
	}
	if len(factory.selected) != len(realms) {
		t.Fatalf("selected %d token transports for %d realm requests", len(factory.selected), len(realms))
	}
}

type challengeRealmFactory struct {
	registry   http.RoundTripper
	tokens     map[registryauth.Realm]http.RoundTripper
	selected   []registryauth.Realm
	registries int
}

func (f *challengeRealmFactory) Registry(context.Context, string) (http.RoundTripper, error) {
	f.registries++
	return f.registry, nil
}

func (f *challengeRealmFactory) Token(_ context.Context, realm registryauth.Realm) (http.RoundTripper, error) {
	f.selected = append(f.selected, realm)
	transport, ok := f.tokens[realm]
	if !ok {
		return nil, errors.New("unexpected private token realm")
	}
	return transport, nil
}

func (f *challengeRealmFactory) Redirect(context.Context, string) (http.RoundTripper, error) {
	return nil, errors.New("unexpected redirect transport")
}

func TestPrivateForwardUsesUpstreamChallengeRealmAndLocalTokenEndpoint(t *testing.T) {
	const service = "fixture"
	const sandbox = "private-realm-sandbox"
	realms := []registryauth.Realm{
		{Host: "realm1.private.test", Path: "/token"},
		{Host: "realm2.private.test", Path: "/token"},
	}
	var registryCalls int
	registryTransport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		registryCalls++
		switch request.Header.Get("Authorization") {
		case "":
			header := make(http.Header)
			header.Set("WWW-Authenticate", `Bearer realm="https://realm2.private.test/token",service="fixture",scope="repository:team/image:pull"`)
			return contractResponse(http.StatusUnauthorized, "", header), nil
		case "Bearer upstream-token":
			return contractResponse(http.StatusOK, "manifest", nil), nil
		default:
			t.Fatalf("registry received unexpected authorization %q", request.Header.Get("Authorization"))
			return nil, errors.New("unreachable")
		}
	})
	tokenTransport := pullRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "realm2.private.test" || request.URL.Path != "/token" {
			t.Fatalf("token exchange reached unexpected realm %s", request.URL.Redacted())
		}
		if request.URL.Query().Get("service") != service || request.URL.Query().Get("scope") != "repository:team/image:pull" {
			t.Fatalf("token exchange query = %q", request.URL.RawQuery)
		}
		if username, password, ok := request.BasicAuth(); !ok || username != "synthetic-user" || password != "synthetic-password" {
			t.Fatalf("token exchange did not use the host credential: %q", username)
		}
		return contractResponse(http.StatusOK, `{"token":"upstream-token"}`, nil), nil
	})
	factory := &challengeRealmFactory{
		registry: registryTransport,
		tokens: map[registryauth.Realm]http.RoundTripper{
			realms[0]: pullRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("first configured realm must not be contacted")
				return nil, errors.New("unreachable")
			}),
			realms[1]: tokenTransport,
		},
	}
	store, err := NewStore(&fakeVault{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(t.Context(), Credential{
		Registry: "registry.private.test", Username: "synthetic-user", Password: []byte("synthetic-password"),
		Scope: ScopeSandbox, SandboxName: sandbox,
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewPullProxy(store, PullProxyConfig{
		Registry: "registry.private.test", SandboxName: sandbox, CredentialScope: ScopeSandbox,
		Service: service, Realms: realms, TransportFactory: factory, PrivateRegistry: true, Limiter: NewPullLimiter(), MaxBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestURL := "https://registry.private.test/v2/team/image/manifests/latest"
	forward := func(authorization string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, manifestURL, http.NoBody)
		request.TLS = &tls.ConnectionState{ServerName: "registry.private.test"}
		request.Host = "registry.private.test"
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		return recorder
	}

	challenge := forward("")
	if challenge.Code != http.StatusUnauthorized {
		t.Fatalf("first request status=%d body=%q", challenge.Code, challenge.Body.String())
	}
	wantRealm := "https://registry.private.test" + brokerTokenPath
	if got := challenge.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="`+wantRealm+`"`) {
		t.Fatalf("guest challenge = %q, want synthetic realm %q", got, wantRealm)
	}
	if strings.Contains(challenge.Header().Get("WWW-Authenticate"), "realm2.private.test") {
		t.Fatal("guest challenge exposed the real token realm")
	}

	query := url.Values{"service": []string{service}, "scope": []string{"repository:team/image:pull"}}
	tokenRequest := httptest.NewRequest(http.MethodGet, "https://registry.private.test"+brokerTokenPath+"?"+query.Encode(), http.NoBody)
	tokenRequest.TLS = &tls.ConnectionState{ServerName: "registry.private.test"}
	tokenRequest.Host = "registry.private.test"
	tokenResponse := httptest.NewRecorder()
	proxy.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("private token endpoint status=%d body=%q", tokenResponse.Code, tokenResponse.Body.String())
	}
	if strings.Contains(tokenResponse.Body.String(), "upstream-token") {
		t.Fatal("upstream registry token was exposed to the guest")
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode sentinel token: %v", err)
	}
	if !strings.HasPrefix(issued.Token, "rheic-") {
		t.Fatalf("guest token %q is not a broker sentinel", issued.Token)
	}

	forwarded := forward("Bearer " + issued.Token)
	if forwarded.Code != http.StatusOK || forwarded.Body.String() != "manifest" {
		t.Fatalf("authenticated forward status=%d body=%q", forwarded.Code, forwarded.Body.String())
	}
	if len(factory.selected) != 2 || factory.selected[0] != realms[1] || factory.selected[1] != realms[1] {
		t.Fatalf("token transports = %v, want only %v", factory.selected, realms[1])
	}
	if registryCalls != 2 {
		t.Fatalf("registry calls = %d, want probe and forward", registryCalls)
	}
}

func TestPrivateForwardRejectsChallengeRealmOutsideAllowlist(t *testing.T) {
	const service = "fixture"
	const sandbox = "private-realm-evil-sandbox"
	realms := []registryauth.Realm{{Host: "realm2.private.test", Path: "/token"}}
	registryTransport := pullRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("WWW-Authenticate", `Bearer realm="https://evil.private.test/token",service="fixture",scope="repository:team/image:pull"`)
		return contractResponse(http.StatusUnauthorized, "", header), nil
	})
	factory := &challengeRealmFactory{
		registry: registryTransport,
		tokens: map[registryauth.Realm]http.RoundTripper{
			realms[0]: pullRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("allowlisted realm must not be contacted for an untrusted challenge")
				return nil, errors.New("unreachable")
			}),
		},
	}
	store, err := NewStore(&fakeVault{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(t.Context(), Credential{
		Registry: "registry.private.test", Username: "synthetic-user", Password: []byte("synthetic-password"),
		Scope: ScopeSandbox, SandboxName: sandbox,
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewPullProxy(store, PullProxyConfig{
		Registry: "registry.private.test", SandboxName: sandbox, CredentialScope: ScopeSandbox,
		Service: service, Realms: realms, TransportFactory: factory, PrivateRegistry: true, Limiter: NewPullLimiter(), MaxBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://registry.private.test/v2/team/image/manifests/latest", http.NoBody)
	request.TLS = &tls.ConnectionState{ServerName: "registry.private.test"}
	request.Host = "registry.private.test"
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("untrusted challenge status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(factory.selected) != 0 {
		t.Fatalf("untrusted challenge selected a token transport: %v", factory.selected)
	}
}
