package secretproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixProxyChannelInjectsSecretAndRequiresToken(t *testing.T) {
	var gotAuth, gotGuestAuth, gotMethod, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotGuestAuth = r.Header.Get("X-Guest-Auth")
		gotMethod = r.Method
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("streamed-body"))
	}))
	defer upstream.Close()

	m := New()
	defer func() { _ = m.Close() }()
	dir, err := os.MkdirTemp("/tmp", "kqproxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := m.StartUnix(context.Background(), "dev", "openai", Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, "s3cret", socket, token); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	bootstrap, _ := http.NewRequest(http.MethodGet, "http://broker"+tokenPath, nil)
	bootstrapResponse, err := client.Do(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken, readErr := io.ReadAll(bootstrapResponse.Body)
	_ = bootstrapResponse.Body.Close()
	if readErr != nil || bootstrapResponse.StatusCode != http.StatusOK || string(bootstrapToken) != token || bootstrapResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("bootstrap response status=%d token_matches=%t cache=%q err=%v", bootstrapResponse.StatusCode, string(bootstrapToken) == token, bootstrapResponse.Header.Get("Cache-Control"), readErr)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://upstream.test/v1/chat?q=1", strings.NewReader("payload"))
	req.Header.Set(TokenHeader, token)
	req.Header.Set("X-Guest-Auth", "guest-value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "streamed-body" {
		t.Fatalf("body = %q", body)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("upstream authorization = %q", gotAuth)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/chat" {
		t.Fatalf("upstream request = %s %s", gotMethod, gotPath)
	}

	unauthorized, _ := http.NewRequest(http.MethodGet, "http://upstream.test/v1/chat", nil)
	unauthorized.Header.Set(TokenHeader, strings.Repeat("f", 64))
	resp, err = client.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token status = %d", resp.StatusCode)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatal("unauthorized request reached upstream")
	}
	_ = gotGuestAuth
}

func TestUnixProxyRefusesToReplaceExistingSocketPath(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-path")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "proxy.sock")
	want := []byte("owned by another process")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = listenPrivateUnix(path)
	if err == nil {
		t.Fatal("listenPrivateUnix accepted an existing path")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("existing path was removed or changed: %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("existing path contents = %q, want %q", got, want)
	}
}

func TestUnixProxyRequiresPrivateParentDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-mode")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700); _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := listenPrivateUnix(filepath.Join(dir, "proxy.sock")); err == nil {
		t.Fatal("listenPrivateUnix accepted a shared parent directory")
	}
}

func TestUnixProxyPolicyDenialDoesNotReachUpstream(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	dir, err := os.MkdirTemp("/tmp", "kqproxy-policy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := strings.Repeat("a", 64)
	manager := New()
	defer func() { _ = manager.Close() }()
	service := Service{
		Upstream: upstream.URL,
		Header:   "Authorization",
		Prefix:   "Bearer ",
		Authorize: func(context.Context) error {
			return errors.New("default deny")
		},
	}
	if _, err := manager.StartUnix(context.Background(), "policy-test", "openai", service, "synthetic-secret", socket, token); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	request, _ := http.NewRequest(http.MethodGet, "http://upstream.test/v1/models", nil)
	request.Header.Set(TokenHeader, token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || calls != 0 {
		t.Fatalf("status=%d upstream_calls=%d", response.StatusCode, calls)
	}
}

func TestUnixProxySecretRefreshRotatesTokenAndRevokesChannel(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	dir, err := os.MkdirTemp("/tmp", "kqproxy-refresh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	firstToken, secondToken := strings.Repeat("a", 64), strings.Repeat("b", 64)
	manager := New()
	defer func() { _ = manager.Close() }()
	cfg := Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", CredentialScope: "global"}
	if _, err := manager.StartUnix(context.Background(), "refresh-test", "openai", cfg, "old-secret", socket, firstToken); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartUnix(context.Background(), "refresh-test", "openai", cfg, "new-secret", socket, secondToken); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	request, _ := http.NewRequest(http.MethodGet, "http://upstream.test/v1/models", nil)
	request.Header.Set(TokenHeader, firstToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("old token status=%d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodGet, "http://upstream.test/v1/models", nil)
	request.Header.Set(TokenHeader, secondToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || gotAuth != "Bearer new-secret" {
		t.Fatalf("refreshed request status=%d auth=%q", response.StatusCode, gotAuth)
	}
	if err := manager.RevokeSecret("openai", "", "global"); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodGet, "http://upstream.test/__klorq/proxy/token", nil)
	if _, err := client.Do(request); err == nil {
		t.Fatal("revoked broker still accepts requests")
	}
}

func TestStopSandboxRemovesOwnedSocketForRestart(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-restart")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := New()
	cfg := Service{Upstream: "https://api.openai.com", Header: "Authorization", Prefix: "Bearer "}
	if _, err := manager.StartUnix(context.Background(), "restart-test", "openai", cfg, "synthetic-secret", socket, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := manager.StopSandbox("restart-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after stop: %v", err)
	}
	if _, err := manager.StartUnix(context.Background(), "restart-test", "openai", cfg, "synthetic-secret", socket, strings.Repeat("b", 64)); err != nil {
		t.Fatalf("restarting proxy on same owned path: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveStaleSocketPreservesActiveAndForeignPaths(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-stale")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	active := filepath.Join(dir, "active.sock")
	listener, err := net.Listen("unix", active)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveStaleSocket(active); err == nil {
		t.Fatal("active socket was accepted as stale")
	}
	_ = listener.Close()
	if err := RemoveStaleSocket(active); err != nil {
		t.Fatalf("stale socket was not removed: %v", err)
	}
	foreign := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStaleSocket(foreign); err == nil {
		t.Fatal("non-socket path was removed")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign path disappeared: %v", err)
	}
}

func TestPublicUnicastAddressFilter(t *testing.T) {
	for _, tc := range []struct {
		address string
		allowed bool
	}{
		{address: "8.8.8.8", allowed: true},
		{address: "2001:4860:4860::8888", allowed: true},
		{address: "127.0.0.1"},
		{address: "10.0.0.1"},
		{address: "100.64.0.1"},
		{address: "192.0.2.1"},
		{address: "::1"},
		{address: "2001:db8::1"},
	} {
		ip := net.ParseIP(tc.address)
		if ip == nil {
			t.Fatalf("test address %q is invalid", tc.address)
		}
		if got := isPublicUnicast(ip); got != tc.allowed {
			t.Errorf("isPublicUnicast(%s)=%t, want %t", tc.address, got, tc.allowed)
		}
	}
}

func TestUnixProxyRejectsSymlinkParentDirectory(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "kqproxy-symlink")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(privateDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := listenPrivateUnix(filepath.Join(linkDir, "proxy.sock")); err == nil {
		t.Fatal("listenPrivateUnix accepted a symlink parent directory")
	}
}
