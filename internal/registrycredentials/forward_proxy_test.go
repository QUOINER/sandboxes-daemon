package registrycredentials

import (
	"crypto/x509"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
	proxy := &PullProxy{}
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

func TestBlobRedirectRejectsExpiredAndUntrustedSessions(t *testing.T) {
	proxy := &PullProxy{blobRedirects: make(map[string]blobRedirectSession)}
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
