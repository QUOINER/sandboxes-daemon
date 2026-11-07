package mcpmanager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	core "github.com/rheic/sandboxes-core"
)

type memoryMCPState struct {
	values map[string]string
}

func (s *memoryMCPState) GetSetting(ctx context.Context, key string) (string, error) {
	if s.values == nil {
		s.values = make(map[string]string)
	}
	value, ok := s.values[key]
	if !ok {
		return "", core.ErrNotFound
	}
	return value, nil
}

func (s *memoryMCPState) SetSetting(ctx context.Context, key, value string) error {
	if s.values == nil {
		s.values = make(map[string]string)
	}
	s.values[key] = value
	return nil
}

func TestPrepareRemoteServerFailsClosed(t *testing.T) {
	allow := func(string) bool { return true }
	cases := []struct {
		name    string
		rawURL  string
		headers map[string]string
		wantErr string
	}{
		{name: "http scheme", rawURL: "http://mcp.example.com/mcp", wantErr: "https"},
		{name: "userinfo", rawURL: "https://user:pass@mcp.example.com/mcp", wantErr: "credentials"},
		{name: "ip literal", rawURL: "https://127.0.0.1/mcp", wantErr: "IP literal"},
		{name: "non-default port", rawURL: "https://mcp.example.com:8443/mcp", wantErr: "port"},
		{name: "query", rawURL: "https://mcp.example.com/mcp?x=1", wantErr: "query"},
		{name: "fragment", rawURL: "https://mcp.example.com/mcp#x", wantErr: "query"},
		{name: "authorization header", rawURL: "https://mcp.example.com/mcp", headers: map[string]string{"Authorization": "Bearer x"}, wantErr: "host vault"},
		{name: "crlf header value", rawURL: "https://mcp.example.com/mcp", headers: map[string]string{"X-Test": "a\r\nb"}, wantErr: "header value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prepareRemoteServer("fixture", tc.rawURL, tc.headers, allow); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if _, err := prepareRemoteServer("fixture", "https://mcp.example.com/mcp", nil, func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("disallowed host err = %v", err)
	}
	server, err := prepareRemoteServer("fixture", "https://MCP.example.com/mcp", map[string]string{"X-Team": "docs"}, allow)
	if err != nil {
		t.Fatal(err)
	}
	if server.Transport != transportRemote || server.URL != "https://mcp.example.com:443/mcp" {
		t.Fatalf("server = %+v", server)
	}
	if server.Headers["X-Team"] != "docs" {
		t.Fatalf("headers = %+v", server.Headers)
	}
}

type approvingProvider struct {
	requests []ApprovalRequest
}

func (a *approvingProvider) Approve(ctx context.Context, req ApprovalRequest) error {
	a.requests = append(a.requests, req)
	return nil
}

func TestRemoteRegistrationApprovalAndPolicyRevocation(t *testing.T) {
	ctx := context.Background()
	state := &memoryMCPState{}
	manager, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	manager.SetRemoteAllowlist([]string{"mcp.example.com"})
	provider := &approvingProvider{}
	manager.SetApprovalProvider(provider)

	id, err := manager.RegisterRemote(ctx, "remote-fixture", "https://mcp.example.com/mcp", map[string]string{"X-Team": "docs"})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := manager.ApproveRegistration(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Name != "remote-fixture" {
		t.Fatalf("summary = %+v", summary)
	}
	if len(provider.requests) != 1 || provider.requests[0].URL != "https://mcp.example.com:443/mcp" {
		t.Fatalf("approval requests = %+v", provider.requests)
	}

	// Policy revocation disables an already-approved remote server.
	manager.SetRemoteAllowlist(nil)
	callID, err := manager.RequestCall("sb-owned", "remote-fixture", "fixture_tool", json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "no longer allowed") {
		t.Fatalf("revoked call err = %v", err)
	}
}

func TestRemoteSessionAgainstStreamableServer(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture-remote", Version: "0.0.1"}, nil)
	server.AddTool(&mcp.Tool{Name: "fixture_tool", Description: "fixture", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture-result"}}}, nil
	})
	streamableHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The SDK rejects a non-loopback Host on its loopback test listener.
		r.Host = "127.0.0.1"
		streamableHandler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	state := &memoryMCPState{}
	manager, err := New(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	host := "mcp.example.test"
	manager.SetRemoteAllowlist([]string{host})
	manager.remoteLookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	serverAddress := strings.TrimPrefix(httpServer.URL, "https://")
	manager.remoteDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "1.1.1.1:443" {
			t.Errorf("dial address = %q, want pinned DNS answer", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	// Pin the test CA; production uses the system trust store.
	manager.SetRemoteTLSConfig(&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- self-signed controlled httptest endpoint.

	registered := Server{Name: "remote-fixture", Transport: transportRemote, URL: "https://mcp.example.test:443"}
	session, err := manager.startRemoteSession(context.Background(), registered)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.close() }()
	if session.process != nil {
		t.Fatal("remote session must not own a host process")
	}
	result, err := session.session.CallTool(context.Background(), &mcp.CallToolParams{Name: "fixture_tool"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("content = %+v", result.Content)
	}
}

func TestPinnedRemoteDialRejectsNonPublicDNSAnswers(t *testing.T) {
	called := false
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	}
	_, err := pinnedRemoteDialContext(context.Background(), &net.Dialer{}, lookup, dial, "tcp", "mcp.example.test:443")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("err = %v, want non-public DNS rejection", err)
	}
	if called {
		t.Fatal("dial was attempted for a mixed public/private DNS answer")
	}
}
