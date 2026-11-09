package mcpmanager

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type memoryState struct{ values map[string]string }

type testApprovalProvider struct{ denied bool }

func (p testApprovalProvider) Approve(context.Context, ApprovalRequest) error {
	if p.denied {
		return errors.New("synthetic user denial")
	}
	return nil
}

type approvalCallback func(context.Context, ApprovalRequest) error

func (callback approvalCallback) Approve(ctx context.Context, request ApprovalRequest) error {
	return callback(ctx, request)
}

func (s *memoryState) GetSetting(_ context.Context, key string) (string, error) {
	return s.values[key], nil
}
func (s *memoryState) SetSetting(_ context.Context, key, value string) error {
	s.values[key] = value
	return nil
}

func TestRegistrationRequiresOneUseApprovalAndPersistsRedactedSummaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	ctx := context.Background()
	state := &memoryState{values: map[string]string{}}
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(testApprovalProvider{denied: true})
	id, err := manager.Register(ctx, "fixture", command, []string{"--stdio"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("pending server appeared in registry")
	}
	if _, err := manager.ApproveRegistration(ctx, id); err == nil {
		t.Fatal("denied registration succeeded")
	}
	if _, err := manager.ApproveRegistration(ctx, id); err == nil {
		t.Fatal("challenge was reusable after denial")
	}
	manager.SetApprovalProvider(testApprovalProvider{})
	id, err = manager.Register(ctx, "fixture", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	list := manager.List()
	if len(list) != 1 || list[0].Name != "fixture" {
		t.Fatalf("summaries=%+v", list)
	}
	if strings.Contains(state.values["mcp_stdio_servers_v1"], "--stdio") {
		t.Fatal("registry persisted an argument not present in the approved entry")
	}
	loaded, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.List(); len(got) != 1 || got[0].Name != "fixture" {
		t.Fatalf("reloaded summaries=%+v", got)
	}
}

func TestApprovalFailsClosedWithoutTrustedProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	ctx := context.Background()
	manager, err := New(ctx, &memoryState{values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\\nexit 0\\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Register(ctx, "fixture", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveRegistration(ctx, id); err == nil || !strings.Contains(err.Error(), "trusted MCP host approval provider is unavailable") {
		t.Fatalf("approval without a trusted provider err=%v", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("registration persisted without trusted approval")
	}
	manager.SetApprovalProvider(testApprovalProvider{})
	id, err = manager.Register(ctx, "fixture", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(nil)
	callID, err := manager.RequestCall("sb-owned", "fixture", "tool", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "trusted MCP host approval provider is unavailable") {
		t.Fatalf("tool call without a trusted provider err=%v", err)
	}
	if got := manager.List(); len(got) != 1 || got[0].Loaded {
		t.Fatalf("host process was started without trusted approval: %+v", got)
	}
}

func TestCallRequiresOneUseApprovalAndRejectsChangedExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	ctx := context.Background()
	state := &memoryState{values: map[string]string{}}
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager, _ := New(ctx, state)
	manager.SetApprovalProvider(testApprovalProvider{})
	id, err := manager.Register(ctx, "fixture", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	callID, err := manager.RequestCall("sb-owned", "fixture", "tool", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(testApprovalProvider{denied: true})
	if _, err = manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("denied call succeeded")
	}
	if _, err = manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("call challenge was reusable")
	}
	manager.SetApprovalProvider(testApprovalProvider{})
	callID, err = manager.RequestCall("sb-owned", "fixture", "tool", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(command, []byte("#!/bin/sh\n# changed\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "changed after approval") {
		t.Fatalf("changed executable error=%v", err)
	}
}

func TestRemovedServerDuringApprovalCannotExecuteCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires the POSIX MCP process fixture")
	}
	ctx := context.Background()
	manager, err := New(ctx, &memoryState{values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	manager.SetApprovalProvider(testApprovalProvider{})
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	registrationID, err := manager.Register(ctx, "fixture", command, []string{"-test.run=^TestMCPProcessFixture$"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveRegistration(ctx, registrationID); err != nil {
		t.Fatal(err)
	}
	callID, err := manager.RequestCall("sb-owned", "fixture", "echo", []byte(`{"value":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	manager.SetApprovalProvider(approvalCallback(func(ctx context.Context, _ ApprovalRequest) error {
		_, err := manager.Remove(ctx, "fixture")
		return err
	}))
	if _, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "registration changed") {
		t.Fatalf("call after concurrent server removal err=%v", err)
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("removed MCP server remained registered: %+v", got)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	ctx := context.Background()
	state := &memoryState{values: map[string]string{}}
	manager, _ := New(ctx, state)
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Register(ctx, "fixture", command, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Now().Add(challengeTTL + time.Second) }
	if _, err = manager.ApproveRegistration(ctx, id); err == nil {
		t.Fatal("expired challenge approved")
	}
}

func TestRegistrationRejectsCredentialArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable fixture")
	}
	command := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := New(context.Background(), &memoryState{values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Register(context.Background(), "fixture", command, []string{"--api-token", "synthetic"}, t.TempDir()); err == nil {
		t.Fatal("credential-bearing command option was accepted for plaintext registry persistence")
	}
}

func TestMCPProcessFixture(t *testing.T) {
	if flag.Lookup("test.run").Value.String() != "^TestMCPProcessFixture$" {
		return
	}
	fixtureCalls := 0
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fixtureCalls++
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("synthetic-result-%d", fixtureCalls)}}}, nil
	})
	if err := server.Run(context.Background(), &mcp.IOTransport{Reader: os.Stdin, Writer: os.Stdout, MaxLineLength: 5 << 20}); err != nil {
		t.Fatal(err)
	}
}

func TestApprovedCallRunsBoundedStdioFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires process execution fixture; Windows Job Object verified by cross-build")
	}
	ctx := context.Background()
	state := &memoryState{values: map[string]string{}}
	manager, _ := New(ctx, state)
	manager.SetApprovalProvider(testApprovalProvider{})
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := manager.Register(ctx, "fixture", command, []string{"-test.run=^TestMCPProcessFixture$"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.ApproveRegistration(ctx, id); err != nil {
		t.Fatal(err)
	}
	callID, err := manager.RequestCall("sb-owned", "fixture", "echo", []byte(`{"value":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "synthetic-result-1") {
		t.Fatalf("MCP result=%s", result)
	}
	if got := manager.List(); len(got) != 1 || !got[0].Loaded {
		t.Fatalf("running stdio session not reported: %+v", got)
	}
	callID, err = manager.RequestCall("sb-owned", "fixture", "echo", []byte(`{"value":"second"}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err = manager.ApproveCall(ctx, callID, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "synthetic-result-2") {
		t.Fatalf("stdio process was not reused across calls: %s", result)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if got := manager.List(); len(got) != 1 || got[0].Loaded {
		t.Fatalf("daemon close left MCP process loaded: %+v", got)
	}
	if _, err = manager.Remove(ctx, "fixture"); err != nil {
		t.Fatal(err)
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("server remained after removal: %+v", got)
	}
}
