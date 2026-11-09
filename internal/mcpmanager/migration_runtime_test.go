package mcpmanager

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMigratedLegacyHeadersAreNotSentToRemoteEndpoint(t *testing.T) {
	ctx := context.Background()
	legacy := `[{"name":"legacy-runtime","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"Authorization":"Bearer legacy-synthetic-token","Cookie":"session=legacy-synthetic-cookie","X-Custom":"legacy-synthetic-custom"}}]`
	state := &memoryMCPState{values: map[string]string{registrySettingKey: legacy}}
	manager, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	manager.SetRemoteAllowlist([]string{"mcp.example.test"})
	stored, err := state.GetSetting(ctx, registrySettingKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"legacy-synthetic-token", "legacy-synthetic-cookie", "legacy-synthetic-custom"} {
		if strings.Contains(stored, canary) {
			t.Fatalf("migration left a legacy value in storage: %q", canary)
		}
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "fixture-remote", Version: "0.0.1"}, nil)
	server.AddTool(&mcp.Tool{Name: "fixture_tool", Description: "fixture", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture-result"}}}, nil
	})
	streamableHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	var sawRequest atomic.Bool
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest.Store(true)
		for _, name := range []string{"Authorization", "Cookie", "X-Custom"} {
			if value := r.Header.Get(name); value != "" {
				t.Errorf("migrated legacy header %s was sent", name)
			}
		}
		for _, canary := range []string{"legacy-synthetic-token", "legacy-synthetic-cookie", "legacy-synthetic-custom"} {
			for name, values := range r.Header {
				for _, value := range values {
					if strings.Contains(value, canary) {
						t.Errorf("request header %s contained a legacy value", name)
					}
				}
			}
		}
		// The SDK rejects a non-loopback Host on its loopback test listener.
		r.Host = "127.0.0.1"
		streamableHandler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

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
	// Pin no trust store; the fixture uses a controlled self-signed endpoint.
	manager.SetRemoteTLSConfig(&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- controlled httptest endpoint.
	manager.SetApprovalProvider(testApprovalProvider{})

	callID, err := manager.RequestCall("sb-owned", "legacy-runtime", "fixture_tool", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !sawRequest.Load() {
		t.Fatal("fake HTTPS endpoint did not receive the migrated server request")
	}
	if !strings.Contains(string(result), "fixture-result") {
		t.Fatalf("remote result = %s", result)
	}
}
