//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
)

func TestVsockConnWrapsPollableFile(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	conn := &vsockConn{file: reader, local: vsockAddr{}, remote: vsockAddr{cid: 2, port: 1027}}
	if conn.RemoteAddr().Network() != "vsock" || conn.RemoteAddr().String() != "2:1027" {
		t.Fatalf("remote address = %v", conn.RemoteAddr())
	}
	if _, err := io.WriteString(writer, "connected"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("connected"))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "connected" {
		t.Fatalf("read %q", buffer)
	}
}

func TestVsockConnectWaitHonorsCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := waitForVSockConnect(ctx, int(reader.Fd())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForVSockConnect() error = %v, want deadline exceeded", err)
	}
}

func TestDialVsockRejectsOutOfRangeAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		cid  int
		port int
	}{
		{name: "negative cid", cid: -1, port: 1027},
		{name: "cid overflow", cid: 1 << 32, port: 1027},
		{name: "zero port", cid: 2, port: 0},
		{name: "port overflow", cid: 2, port: 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dialVsock(context.Background(), tc.cid, tc.port); err == nil {
				t.Fatal("dialVsock() accepted an out-of-range address")
			}
		})
	}
}

func TestHelperServerBindsConfiguredLoopbackAddress(t *testing.T) {
	server := newHTTPServer("127.0.0.1:3128", http.NotFoundHandler())
	if server.Addr != "127.0.0.1:3128" {
		t.Fatalf("server listen address = %q", server.Addr)
	}
}

func TestHelperServerStopsOnSIGTERM(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listener, server) }()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve() after cancellation = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy helper server did not stop after cancellation")
	}
}

func TestHelperForwardsWithTokenAndBrokerInjectsSecret(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "answer")
	}))
	defer upstream.Close()

	dir, err := os.MkdirTemp("/tmp", "kqhelper")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "broker.sock")
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	broker := secretproxy.New()
	t.Cleanup(func() { _ = broker.Close() })
	if _, err := broker.StartUnix(context.Background(), "dev", "openai", secretproxy.Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, []byte("s3cret"), socket, token); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	bootstrapped, err := fetchToken(context.Background(), transport)
	if err != nil || bootstrapped != token {
		t.Fatalf("fetchToken() = matching:%t, err=%v", bootstrapped == token, err)
	}
	helper := httptest.NewServer(newHandler("api.example.test", transport))
	defer helper.Close()

	req, _ := http.NewRequest(http.MethodGet, helper.URL+"/v1/answer", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "answer" || gotAuth != "Bearer s3cret" || gotPath != "/v1/answer" {
		t.Fatalf("body=%q auth=%q path=%q", body, gotAuth, gotPath)
	}
}

func TestHelperMultiplexesConfiguredServicesWithoutCredentialMixing(t *testing.T) {
	var gotOpenAI, gotAnthropic string
	var routeHeaderLeaked bool
	openAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOpenAI = r.Header.Get("Authorization")
		routeHeaderLeaked = routeHeaderLeaked || r.Header.Get(secretproxy.ServiceHeader) != ""
		_, _ = io.WriteString(w, "openai")
	}))
	defer openAI.Close()
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAnthropic = r.Header.Get("x-api-key")
		routeHeaderLeaked = routeHeaderLeaked || r.Header.Get(secretproxy.ServiceHeader) != ""
		_, _ = io.WriteString(w, "anthropic")
	}))
	defer anthropic.Close()

	dir, err := os.MkdirTemp("/tmp", "rheic-multiproxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "broker.sock")
	tokenOpenAI := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokenAnthropic := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	broker := secretproxy.New()
	t.Cleanup(func() { _ = broker.Close() })
	routes := map[string]secretproxy.RouteConfig{
		"openai":    {Service: secretproxy.Service{Upstream: openAI.URL, Header: "Authorization", Prefix: "Bearer ", CredentialScope: "sandbox"}, Secret: []byte("openai-secret"), Token: tokenOpenAI},
		"anthropic": {Service: secretproxy.Service{Upstream: anthropic.URL, Header: "x-api-key", CredentialScope: "sandbox"}, Secret: []byte("anthropic-secret"), Token: tokenAnthropic},
	}
	if _, err := broker.StartUnixRoutes(context.Background(), "dev", routes, socket); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	openAIHelper := httptest.NewServer(newRouteHandler("openai", "api.openai.com", transport))
	defer openAIHelper.Close()
	anthropicHelper := httptest.NewServer(newRouteHandler("anthropic", "api.anthropic.com", transport))
	defer anthropicHelper.Close()

	for _, tc := range []struct {
		url    string
		body   string
		client *http.Client
	}{
		{url: openAIHelper.URL + "/v1/models", body: "openai", client: openAIHelper.Client()},
		{url: anthropicHelper.URL + "/v1/models", body: "anthropic", client: anthropicHelper.Client()},
	} {
		response, err := tc.client.Get(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || string(body) != tc.body || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d body=%q err=%v", tc.url, response.StatusCode, body, readErr)
		}
	}
	if gotOpenAI != "Bearer openai-secret" || gotAnthropic != "anthropic-secret" {
		t.Fatalf("service credentials crossed routes: openai=%q anthropic=%q", gotOpenAI, gotAnthropic)
	}
	if routeHeaderLeaked {
		t.Fatal("internal service route metadata reached an upstream provider")
	}
	spoof, err := http.NewRequest(http.MethodGet, openAIHelper.URL+"/v1/models", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	spoof.Header.Set(secretproxy.ServiceHeader, "anthropic")
	spoofResponse, err := openAIHelper.Client().Do(spoof)
	if err != nil {
		t.Fatal(err)
	}
	spoofBody, readErr := io.ReadAll(spoofResponse.Body)
	_ = spoofResponse.Body.Close()
	if readErr != nil || string(spoofBody) != "openai" || gotOpenAI != "Bearer openai-secret" || gotAnthropic != "anthropic-secret" {
		t.Fatalf("guest route spoof changed destination or credential: body=%q openai=%q anthropic=%q err=%v", spoofBody, gotOpenAI, gotAnthropic, readErr)
	}
	broker.RefreshSecret("openai", "dev", "sandbox", []byte("rotated-openai-key"))
	refreshed, err := openAIHelper.Client().Get(openAIHelper.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, refreshed.Body)
	_ = refreshed.Body.Close()
	if gotOpenAI != "Bearer rotated-openai-key" {
		t.Fatalf("OpenAI secret rotation was not isolated: auth=%q", gotOpenAI)
	}
	if err := broker.RevokeSecret("openai", "dev", "sandbox"); err != nil {
		t.Fatal(err)
	}
	denied, err := openAIHelper.Client().Get(openAIHelper.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusBadGateway || broker.Has("dev", "openai") || !broker.Has("dev", "anthropic") {
		t.Fatalf("route revoke status=%d openai_active=%t anthropic_active=%t", denied.StatusCode, broker.Has("dev", "openai"), broker.Has("dev", "anthropic"))
	}
	stillAllowed, err := anthropicHelper.Client().Get(anthropicHelper.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = stillAllowed.Body.Close()
	if stillAllowed.StatusCode != http.StatusOK || gotAnthropic != "anthropic-secret" {
		t.Fatalf("revoking OpenAI affected Anthropic: status=%d auth=%q", stillAllowed.StatusCode, gotAnthropic)
	}
	unknownRequest, err := http.NewRequest(http.MethodGet, "http://broker/__rheic/proxy/token/unknown", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	unknownResponse, err := transport.RoundTrip(unknownRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = unknownResponse.Body.Close()
	if unknownResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown route token status=%d", unknownResponse.StatusCode)
	}
}

func TestParseProxyRoutesRejectsUnsafeConfiguration(t *testing.T) {
	routes, err := parseProxyRoutes([]string{"openai=api.openai.com:3128", "anthropic=api.anthropic.com:3129"})
	if err != nil || len(routes) != 2 {
		t.Fatalf("parseProxyRoutes valid config: routes=%+v err=%v", routes, err)
	}
	for _, input := range [][]string{
		{"openai=api.openai.com:3128", "openai=api.other.com:3129"},
		{"openai=api.openai.com:80"},
		{"openai=api.openai.com;touch:3128"},
		{"openai=api.openai.com:3128:extra"},
		{"OpenAI=api.openai.com:3128"},
	} {
		if _, err := parseProxyRoutes(input); err == nil {
			t.Fatalf("parseProxyRoutes accepted unsafe config %q", input)
		}
	}
}
