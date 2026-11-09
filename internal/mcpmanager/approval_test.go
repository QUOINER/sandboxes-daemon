package mcpmanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteApprovalDisclosesDestinationAndHeaderScope(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &memoryMCPState{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	manager.SetRemoteAllowlist([]string{"mcp.example.com"})
	provider := &approvingProvider{}
	manager.SetApprovalProvider(provider)

	id, err := manager.RegisterRemote(ctx, "remote-fixture", "https://MCP.example.com/mcp",
		map[string]string{"X-Team": "synthetic-static-value"},
		map[string]string{
			"Authorization": "Bearer ${token}",
			"X-API-Key":     "${api_key}",
			"X-Composite":   "${suffix}/${token}",
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("registration approval requests = %d", len(provider.requests))
	}
	assertApprovalScope(t, provider.requests[0])

	callID, err := manager.RequestCall("sb-owned", "remote-fixture", "fixture_tool", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(approvalCallback(func(_ context.Context, request ApprovalRequest) error {
		provider.requests = append(provider.requests, request)
		return errors.New("synthetic stop before transport")
	}))
	if _, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("synthetic call approval stop did not fail")
	}
	if len(provider.requests) != 2 {
		t.Fatalf("call approval requests = %d", len(provider.requests))
	}
	assertApprovalScope(t, provider.requests[1])
}

func TestCloneServerDeepCopiesMutableFields(t *testing.T) {
	original := Server{
		Arguments:     []string{"--stdio"},
		Headers:       map[string]string{"X-Team": "docs"},
		SecretHeaders: map[string]string{"Authorization": "Bearer ${token}"},
	}
	cloned := cloneServer(original)
	cloned.Arguments[0] = "changed"
	cloned.Headers["X-Team"] = "changed"
	cloned.SecretHeaders["Authorization"] = "Bearer ${other}"
	if original.Arguments[0] != "--stdio" || original.Headers["X-Team"] != "docs" || original.SecretHeaders["Authorization"] != "Bearer ${token}" {
		t.Fatalf("clone aliased mutable server fields: %+v", original)
	}
}

func assertApprovalScope(t *testing.T, request ApprovalRequest) {
	t.Helper()
	if request.URL != "https://mcp.example.com:443/mcp" {
		t.Fatalf("approval destination = %q", request.URL)
	}
	want := []ApprovalHeader{
		{Name: "Authorization", ValueClass: ApprovalHeaderHostVault, References: []string{"token"}},
		{Name: "X-API-Key", ValueClass: ApprovalHeaderHostVault, References: []string{"api_key"}},
		{Name: "X-Composite", ValueClass: ApprovalHeaderHostVault, References: []string{"suffix", "token"}},
		{Name: "X-Team", ValueClass: ApprovalHeaderStatic},
	}
	if !reflect.DeepEqual(request.Headers, want) {
		t.Fatalf("approval headers = %+v, want %+v", request.Headers, want)
	}
	serialized := fmt.Sprintf("%+v", request)
	for _, canary := range []string{"synthetic-static-value", "Bearer", "synthetic-secret"} {
		if strings.Contains(serialized, canary) {
			t.Fatalf("approval request disclosed header value %q: %s", canary, serialized)
		}
	}
}

func TestApprovalCallRejectsDestinationOrHeaderMutation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Server)
	}{
		{name: "destination", mutate: func(server *Server) { server.URL = "https://other.example.test/mcp" }},
		{name: "static header", mutate: func(server *Server) {
			server.Headers = map[string]string{"X-Team": "changed-static-value"}
		}},
		{name: "static header in place", mutate: func(server *Server) {
			server.Headers["X-Team"] = "changed-in-place-value"
		}},
		{name: "vault header", mutate: func(server *Server) {
			server.SecretHeaders = map[string]string{"Authorization": "Bearer ${other}"}
		}},
		{name: "vault header in place", mutate: func(server *Server) {
			server.SecretHeaders["Authorization"] = "Bearer ${other}"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			manager, err := New(ctx, &memoryMCPState{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = manager.Close() }()
			manager.SetRemoteAllowlist([]string{"mcp.example.test"})
			manager.SetApprovalProvider(testApprovalProvider{})
			id, err := manager.RegisterRemote(ctx, "remote-fixture", "https://mcp.example.test/mcp",
				map[string]string{"X-Team": "docs"},
				map[string]string{"Authorization": "Bearer ${token}"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.ApproveRegistration(ctx, id); err != nil {
				t.Fatal(err)
			}
			resolutions := 0
			manager.SetRemoteSecretResolver(func(context.Context, string, string) ([]byte, error) {
				resolutions++
				return []byte("synthetic-secret"), nil
			})
			dialed := false
			manager.remoteDial = func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("unexpected remote dial")
			}
			callID, err := manager.RequestCall("sb-owned", "remote-fixture", "fixture_tool", []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			manager.SetApprovalProvider(approvalCallback(func(context.Context, ApprovalRequest) error {
				manager.mu.Lock()
				server := manager.servers["remote-fixture"]
				tc.mutate(&server)
				manager.servers["remote-fixture"] = server
				manager.mu.Unlock()
				return nil
			}))
			if _, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "changed after approval") {
				t.Fatalf("mutated approval err = %v", err)
			}
			if dialed {
				t.Fatal("mutated registration reached the remote dialer")
			}
			if resolutions != 0 {
				t.Fatalf("mutated registration resolved %d vault values", resolutions)
			}
		})
	}
}
