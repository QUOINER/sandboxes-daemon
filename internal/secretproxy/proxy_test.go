//go:build !windows

package secretproxy

import (
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnixProxyChannelInjectsSecretAndRequiresToken(t *testing.T) {
	var gotAuth, gotGuestAPIKey, gotMethod, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotGuestAPIKey = r.Header.Get("X-Api-Key")
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
	if _, err := m.StartUnix(context.Background(), "dev", "openai", Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, []byte("s3cret"), socket, token); err != nil {
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
	req.Header.Set("Authorization", "Bearer guest-controlled")
	req.Header.Set("X-Api-Key", "guest-controlled-api-key")
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
	if gotGuestAPIKey != "" {
		t.Fatal("guest-controlled API key header reached upstream")
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
}

func TestGoogleServiceProxyOverridesGuestKey(t *testing.T) {
	var gotKey, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-goog-api-key")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	service, ok := Lookup("google")
	if !ok || service.Upstream != "https://generativelanguage.googleapis.com" || service.Header != "x-goog-api-key" {
		t.Fatalf("Google service contract=%+v, found=%t", service, ok)
	}
	service.Upstream = upstream.URL
	dir, err := os.MkdirTemp("/tmp", "rheic-google-proxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := strings.Repeat("a", 64)
	manager := New()
	if _, err := manager.StartUnixRoutes(context.Background(), "google-test", map[string]RouteConfig{
		"google": {Service: service, Secret: []byte("synthetic-google-key"), Token: token},
	}, socket); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	request, err := http.NewRequest(http.MethodPost, "http://broker/v1beta/models:testGenerateContent", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, token)
	request.Header.Set(ServiceHeader, "google")
	request.Header.Set("x-goog-api-key", "guest-controlled-key")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || gotKey != "synthetic-google-key" || gotPath != "/v1beta/models:testGenerateContent" {
		t.Fatalf("response=%d upstream key=%q path=%q", response.StatusCode, gotKey, gotPath)
	}
}

func TestFixedAgentServiceAliasesUseExpectedUpstreamAndBearerHeader(t *testing.T) {
	want := map[string]string{
		"github": "https://api.github.com", "github-web": "https://github.com",
		"github-raw": "https://raw.githubusercontent.com", "github-gist": "https://gist.github.com",
		"github-copilot": "https://copilot.github.com", "github-copilot-api": "https://api.githubcopilot.com",
		"cursor": "https://api2.cursor.sh", "cursor-api3": "https://api3.cursor.sh",
		"cursor-repo42": "https://repo42.cursor.sh", "cursor-web": "https://cursor.com",
		"droid": "https://api.factory.ai", "droid-app": "https://app.factory.ai", "droid-relay": "https://relay.factory.ai",
	}
	for name, upstream := range want {
		service, ok := Lookup(name)
		if !ok || service.Upstream != upstream || service.Header != "Authorization" || service.Prefix != "Bearer " {
			t.Errorf("service %q = %+v, found=%t; want upstream %q with fixed bearer injection", name, service, ok, upstream)
		}
	}
}

func TestUnixProxyResolvesOAuthCredentialOnHostAndFailsClosed(t *testing.T) {
	var upstreamCalls atomic.Int32
	var credentialAvailable atomic.Bool
	upstreamAuth := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		upstreamAuth <- r.Header.Get("Authorization")
		if r.Header.Get("X-Api-Key") != "" {
			t.Error("guest API key header reached upstream")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	m := New()
	defer func() { _ = m.Close() }()
	dir, err := os.MkdirTemp("/tmp", "kqoauth-proxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	service := Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", Credential: func(context.Context) ([]byte, error) {
		if !credentialAvailable.Load() {
			return nil, errors.New("OAuth credential unavailable")
		}
		return []byte("synthetic-host-oauth-token"), nil
	}}
	if _, err := m.StartUnixRoutes(context.Background(), "oauth", map[string]RouteConfig{"openai-oauth": {
		Service: service, Token: token,
	}}, socket); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	request := func() *http.Response {
		req, reqErr := http.NewRequest(http.MethodGet, "http://upstream.test/v1/models", nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set(ServiceHeader, "openai-oauth")
		req.Header.Set(TokenHeader, token)
		req.Header.Set("Authorization", "Bearer rheic-proxy-placeholder")
		req.Header.Set("X-Api-Key", "guest-controlled")
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		return resp
	}

	denied := request()
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusBadGateway || upstreamCalls.Load() != 0 {
		t.Fatalf("missing OAuth credential status=%d upstream calls=%d", denied.StatusCode, upstreamCalls.Load())
	}
	credentialAvailable.Store(true)
	allowed := request()
	_ = allowed.Body.Close()
	gotAuth := <-upstreamAuth
	if allowed.StatusCode != http.StatusNoContent || upstreamCalls.Load() != 1 || gotAuth != "Bearer synthetic-host-oauth-token" {
		t.Fatalf("OAuth proxy status=%d calls=%d upstream auth=%q", allowed.StatusCode, upstreamCalls.Load(), gotAuth)
	}
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
	if _, err := manager.StartUnix(context.Background(), "policy-test", "openai", service, []byte("synthetic-secret"), socket, token); err != nil {
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
	if _, err := manager.StartUnix(context.Background(), "refresh-test", "openai", cfg, []byte("old-secret"), socket, firstToken); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartUnix(context.Background(), "refresh-test", "openai", cfg, []byte("new-secret"), socket, secondToken); err != nil {
		t.Fatal(err)
	}
	manager.RefreshSecret("openai", "refresh-test", "sandbox", []byte("sandbox-secret"))
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
	if response.StatusCode != http.StatusOK || gotAuth != "Bearer sandbox-secret" {
		t.Fatalf("refreshed request status=%d auth=%q", response.StatusCode, gotAuth)
	}
	if err := manager.RevokeSecret("openai", "", "global"); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodGet, "http://upstream.test/__rheic/proxy/token", nil)
	if _, err := client.Do(request); err == nil {
		t.Fatal("revoked broker still accepts requests")
	}
}

func TestUnixProxyRevokeCancelsInflightRequestAndClosesChannel(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, canceledOnce sync.Once
	var callsMu sync.Mutex
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		startedOnce.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
			canceledOnce.Do(func() { close(canceled) })
		case <-release:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()
	defer close(release)

	dir, err := os.MkdirTemp("/tmp", "kqproxy-revoke-inflight")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := strings.Repeat("c", 64)
	manager := New()
	if _, err := manager.StartUnix(context.Background(), "revoke-inflight", "openai", Service{
		Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", CredentialScope: "sandbox",
	}, []byte("synthetic-secret"), socket, token); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}

	requestCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://broker/v1/controlled", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, token)
	type requestResult struct {
		status int
		err    error
	}
	requestDone := make(chan requestResult, 1)
	go func() {
		response, err := client.Do(request)
		result := requestResult{err: err}
		if response != nil {
			result.status = response.StatusCode
			_ = response.Body.Close()
		}
		requestDone <- result
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("positive control did not reach controlled upstream")
	}
	if err := manager.RevokeSecret("openai", "revoke-inflight", "sandbox"); err != nil {
		t.Fatalf("revoke scoped secret: %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("secret revoke did not cancel the in-flight upstream request")
	}
	select {
	case result := <-requestDone:
		if result.err == nil && result.status == http.StatusOK {
			t.Fatal("in-flight request unexpectedly succeeded after secret revoke")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("guest-facing request did not finish after secret revoke")
	}

	request, err = http.NewRequest(http.MethodGet, "http://broker/v1/controlled", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, token)
	if response, err := client.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("request connected through the revoked broker")
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("revoked channel sent additional upstream requests (calls=%d)", calls)
	}
}

func TestUnixProxyRevokeCancelsOnlyRevokedRoute(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	var startedOnce, canceledOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			startedOnce.Do(func() { close(started) })
			<-r.Context().Done()
			canceledOnce.Do(func() { close(canceled) })
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer anthropic-secret" {
			http.Error(w, "wrong route credential", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	dir, err := os.MkdirTemp("/tmp", "kqproxy-multi-revoke")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := New()
	route := func(secret, token string) RouteConfig {
		return RouteConfig{Service: Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ", CredentialScope: "sandbox"},
			Secret: []byte(secret), Token: token}
	}
	routes := map[string]RouteConfig{
		"openai":    route("openai-secret", strings.Repeat("a", 64)),
		"anthropic": route("anthropic-secret", strings.Repeat("b", 64)),
	}
	if _, err := manager.StartUnixRoutes(context.Background(), "multi-revoke", routes, socket); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	request, err := http.NewRequest(http.MethodGet, "http://broker/slow", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(ServiceHeader, "openai")
	request.Header.Set(TokenHeader, strings.Repeat("a", 64))
	done := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		done <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("positive control did not reach controlled upstream")
	}
	if err := manager.RevokeSecret("openai", "multi-revoke", "sandbox"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not cancel the active route request")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked route request did not complete")
	}

	request, err = http.NewRequest(http.MethodGet, "http://broker/ok", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(ServiceHeader, "anthropic")
	request.Header.Set(TokenHeader, strings.Repeat("b", 64))
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("unrevoked route stopped with revoked route: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unrevoked route status = %d, want 204", response.StatusCode)
	}
}

func TestUnixProxyCustomHandlerDoesNotRequireSecretBytes(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-custom-handler")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	manager := New()
	_, err = manager.StartUnixRoutes(context.Background(), "custom-handler", map[string]RouteConfig{
		"docker-hub": {
			Service: Service{Upstream: "https://registry-1.docker.io"},
			Token:   strings.Repeat("c", 64),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		},
	}, socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	request, err := http.NewRequest(http.MethodGet, "http://broker/v2/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, strings.Repeat("c", 64))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("custom handler status = %d", response.StatusCode)
	}
}

func TestUnixProxyBrokerProcessDeathCancelsAndRecovers(t *testing.T) {
	const (
		childFlag = "RHEIC_P04_BROKER_CHILD"
		childURL  = "RHEIC_P04_BROKER_UPSTREAM"
	)
	if os.Getenv(childFlag) == "1" {
		dir := filepath.Join(os.TempDir(), fmt.Sprintf("kqproxy-process-death-%d", os.Getppid()))
		manager := New()
		if _, err := manager.StartUnix(context.Background(), "process-death", "openai", Service{
			Upstream: os.Getenv(childURL), Header: "Authorization", Prefix: "Bearer ",
		}, []byte("synthetic-process-death-secret"), filepath.Join(dir, "proxy.sock"), strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {}
	}

	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, canceledOnce sync.Once
	var callsMu sync.Mutex
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		if r.URL.Path == "/slow" {
			startedOnce.Do(func() { close(started) })
			select {
			case <-r.Context().Done():
				canceledOnce.Do(func() { close(canceled) })
			case <-release:
			}
			return
		}
		_, _ = io.WriteString(w, "recovered")
	}))
	defer upstream.Close()
	defer close(release)

	dir := filepath.Join(os.TempDir(), fmt.Sprintf("kqproxy-process-death-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create uniquely owned broker directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove owned broker directory: %v", err)
		}
	})
	socket := filepath.Join(dir, "proxy.sock")
	ready := filepath.Join(dir, "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestUnixProxyBrokerProcessDeathCancelsAndRecovers$", "-test.count=1")
	command.Env = append(os.Environ(), childFlag+"=1", childURL+"="+upstream.URL)
	output := new(strings.Builder)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker subprocess did not become ready: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	clientFor := func(token string) *http.Client {
		return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}}
	}
	client := clientFor(strings.Repeat("d", 64))
	requestCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://broker/slow", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, strings.Repeat("d", 64))
	requestDone := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatalf("positive control did not reach the controlled upstream: %s", output.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill owned broker subprocess: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("broker subprocess exited successfully despite an explicit kill")
	}
	if _, err := os.Lstat(socket); err != nil {
		t.Fatalf("expected stale owned socket after process death: %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("broker process death did not cancel the in-flight upstream request")
	}
	select {
	case <-requestDone:
	case <-time.After(3 * time.Second):
		t.Fatal("guest-facing request did not finish after broker process death")
	}
	if err := RemoveStaleSocket(socket); err != nil {
		t.Fatalf("remove owned stale socket after broker death: %v", err)
	}

	manager := New()
	if _, err := manager.StartUnix(context.Background(), "process-death", "openai", Service{
		Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer ",
	}, []byte("synthetic-process-death-secret"), socket, strings.Repeat("e", 64)); err != nil {
		t.Fatalf("restart broker on recovered socket: %v", err)
	}
	defer func() { _ = manager.Close() }()
	client = clientFor(strings.Repeat("e", 64))
	request, err = http.NewRequest(http.MethodGet, "http://broker/recovered", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(TokenHeader, strings.Repeat("e", 64))
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request after broker recovery: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "recovered" {
		t.Fatalf("recovered response status=%d body=%q read error=%v", response.StatusCode, body, readErr)
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 2 {
		t.Fatalf("unexpected controlled upstream call count after process death/recovery: %d", calls)
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
	if _, err := manager.StartUnix(context.Background(), "restart-test", "openai", cfg, []byte("synthetic-secret"), socket, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := manager.StopSandbox("restart-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after stop: %v", err)
	}
	if _, err := manager.StartUnix(context.Background(), "restart-test", "openai", cfg, []byte("synthetic-secret"), socket, strings.Repeat("b", 64)); err != nil {
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
		{address: "2606:4700:4700::1111", allowed: true},
		{address: "127.0.0.1"},
		{address: "10.0.0.1"},
		{address: "100.64.0.1"},
		{address: "192.0.2.1"},
		{address: "::1"},
		{address: "2001:db8::1"},
		{address: "3fff::1"},
		{address: "5f00::1"},
		{address: "4000::1"},
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

func TestDialPublicUnicastPinsCheckedDNSAnswers(t *testing.T) {
	ctx := context.Background()
	var dialCalls int
	var dialAddress string
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "api.example.test" {
			t.Fatalf("lookup host = %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dialCalls++
		if network != "tcp" {
			t.Fatalf("network = %q", network)
		}
		dialAddress = address
		conn, peer := net.Pipe()
		_ = peer.Close()
		return conn, nil
	}
	conn, err := dialPublicUnicast(ctx, "tcp", "api.example.test:443", lookup, dial)
	if err != nil {
		t.Fatalf("public DNS positive control failed: %v", err)
	}
	_ = conn.Close()
	if dialCalls != 1 || dialAddress != "8.8.8.8:443" {
		t.Fatalf("public answer was not pinned for dialing: calls=%d address=%q", dialCalls, dialAddress)
	}

	for _, tc := range []struct {
		name string
		ips  []net.IPAddr
	}{
		{name: "private answer", ips: []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}},
		{name: "mixed public and private answers", ips: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("10.0.0.1")}}},
		{name: "documentation IPv6 range", ips: []net.IPAddr{{IP: net.ParseIP("3fff::1")}}},
		{name: "reserved IPv6 range", ips: []net.IPAddr{{IP: net.ParseIP("5f00::1")}}},
		{name: "outside IPv6 global unicast allocation", ips: []net.IPAddr{{IP: net.ParseIP("4000::1")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := dialCalls
			resolve := func(context.Context, string) ([]net.IPAddr, error) { return tc.ips, nil }
			if _, err := dialPublicUnicast(ctx, "tcp", "api.example.test:443", resolve, dial); err == nil {
				t.Fatal("non-public DNS answer was accepted")
			}
			if dialCalls != before {
				t.Fatal("dial ran after a non-public DNS answer")
			}
		})
	}
	if _, err := dialPublicUnicast(ctx, "tcp", "api.example.test:443", func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("synthetic resolver failure")
	}, dial); err == nil || dialCalls != 1 {
		t.Fatalf("resolver failure was not denied before dial: calls=%d err=%v", dialCalls, err)
	}
}

func TestDialPublicUnicastEnforcesResolvedAddressPolicy(t *testing.T) {
	ctx := context.Background()
	var dialCalls int
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		conn, peer := net.Pipe()
		_ = peer.Close()
		return conn, nil
	}
	deny := func(_ context.Context, address netip.Addr) (bool, error) {
		if address != netip.MustParseAddr("8.8.8.8") {
			t.Fatalf("policy checked unexpected address %s", address)
		}
		return false, nil
	}
	if _, err := dialPublicUnicastWithPolicy(ctx, "tcp", "api.example.test:443", lookup, dial, deny); err == nil {
		t.Fatal("dial accepted an address denied by sandbox CIDR policy")
	}
	if dialCalls != 0 {
		t.Fatalf("dial ran %d times after policy denial", dialCalls)
	}

	allow := func(context.Context, netip.Addr) (bool, error) { return true, nil }
	conn, err := dialPublicUnicastWithPolicy(ctx, "tcp", "api.example.test:443", lookup, dial, allow)
	if err != nil {
		t.Fatalf("public policy-allowed positive control failed: %v", err)
	}
	_ = conn.Close()
	if dialCalls != 1 {
		t.Fatalf("positive control dial calls = %d, want 1", dialCalls)
	}

	transport := outboundTransportWithPolicy(true, nil, allow)
	defer transport.CloseIdleConnections()
	if !transport.DisableKeepAlives {
		t.Fatal("policy-aware transport may reuse a connection after policy changes")
	}
}

func TestOutboundTransportVerifiesTLSHostname(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	certificate := upstream.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := outboundTransport(true, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
	})
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	if len(certificate.DNSNames) == 0 {
		t.Fatal("TLS fixture certificate has no DNS SAN for positive control")
	}
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("parse TLS fixture listener address: %v", err)
	}
	positiveURL := "https://" + net.JoinHostPort(certificate.DNSNames[0], port)
	response, err := client.Get(positiveURL)
	if err != nil {
		t.Fatalf("trusted matching-host positive control failed: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("positive control status = %d", response.StatusCode)
	}

	negativeURL := "https://wrong-host.example:" + port
	if response, err := client.Get(negativeURL); err == nil {
		_ = response.Body.Close()
		t.Fatal("TLS certificate for a different host was accepted")
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

// TestUnixProxyCAEndpointRequiresChannelToken covers a previously untested
// fail-closed path: host CA trust material must not be served to a guest that
// does not present the per-sandbox channel token.
func TestUnixProxyCAEndpointRequiresChannelToken(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "kqproxy-ca-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := strings.Repeat("c", 64)
	wrongToken := strings.Repeat("d", 64)
	manager := New()
	if _, err := manager.StartUnixRoutes(context.Background(), "ca-token-test", map[string]RouteConfig{
		"openai": {
			Service: Service{Upstream: "https://api.openai.com", Header: "Authorization", Prefix: "Bearer "},
			Token:   token,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
			CACert:  []byte("synthetic-ca-pem"),
		},
	}, socket); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socket)
	}}}

	positive, err := http.NewRequest(http.MethodGet, "http://broker/__rheic/proxy/ca/openai", nil)
	if err != nil {
		t.Fatal(err)
	}
	positive.Header.Set(TokenHeader, token)
	response, err := client.Do(positive)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "synthetic-ca-pem" {
		t.Fatalf("positive CA response status=%d body=%q err=%v", response.StatusCode, body, readErr)
	}

	for _, receivedToken := range []string{"", wrongToken} {
		negative, err := http.NewRequest(http.MethodGet, "http://broker/__rheic/proxy/ca/openai", nil)
		if err != nil {
			t.Fatal(err)
		}
		if receivedToken != "" {
			negative.Header.Set(TokenHeader, receivedToken)
		}
		response, err := client.Do(negative)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("CA response with token %q status=%d, want %d", receivedToken, response.StatusCode, http.StatusForbidden)
		}
	}
}
