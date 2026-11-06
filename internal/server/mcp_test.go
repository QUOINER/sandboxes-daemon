package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/mcpmanager"

	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestMCPRegistrationApprovalAndRemovalRPCs(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	server := NewSandbox(service.New(state, nil))
	server.svc.SetMCPApprovalProvider(mcpTestApprovalProvider{})
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "fixture", Command: command, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.GetApprovalRequired() || pending.GetApprovalId() == "" || pending.GetServer() != nil {
		t.Fatalf("registration response=%+v", pending)
	}
	list, err := server.ListMCPServers(ctx, &localv1.ListMCPServersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetServers()) != 0 {
		t.Fatalf("unapproved registration visible: %+v", list.GetServers())
	}
	approved, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()})
	if err != nil {
		t.Fatal(err)
	}
	if approved.GetServer().GetName() != "fixture" || approved.GetServer().GetTransport() != "stdio" {
		t.Fatalf("summary=%+v", approved.GetServer())
	}
	list, err = server.ListMCPServers(ctx, &localv1.ListMCPServersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetServers()) != 1 || !list.GetServers()[0].GetUsable() {
		t.Fatalf("server list=%+v", list.GetServers())
	}
	removed, err := server.MCPRemoveServer(ctx, &localv1.MCPRemoveServerRequest{Name: "fixture"})
	if err != nil || !removed.GetRemoved() {
		t.Fatalf("remove=%+v err=%v", removed, err)
	}
	if _, err = server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("reused approval status=%s err=%v", status.Code(err), err)
	}
}

type mcpTestApprovalProvider struct{}

func (mcpTestApprovalProvider) Approve(context.Context, mcpmanager.ApprovalRequest) error { return nil }

func TestMCPApprovalFailsClosedWithoutTrustedProvider(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-no-provider.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	server := NewSandbox(service.New(state, nil))
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := server.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{Name: "fixture", Command: command, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: pending.GetApprovalId()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("approval without provider status=%s err=%v", status.Code(err), err)
	}
	list, err := server.ListMCPServers(ctx, &localv1.ListMCPServersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetServers()) != 0 {
		t.Fatalf("server was registered without trusted approval: %+v", list.GetServers())
	}
}

func TestMCPCallRejectsUnknownSandboxBeforeCreatingChallenge(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "mcp-call.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	server := NewSandbox(service.New(state, nil))
	_, err = server.MCPCall(ctx, &localv1.MCPCallRequest{SandboxId: "sb-not-owned", ServerName: "fixture", ToolName: "tool", ArgumentsJson: `{}`})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error status=%s err=%v", status.Code(err), err)
	}
}
