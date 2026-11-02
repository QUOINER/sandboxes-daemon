package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
)

func TestSandboxAndOperationLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Unix(100, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-1", Name: "dev", State: sandbox.Stopped, Generation: 1,
		Image: "scratch", CPUs: 4, MemoryMiB: 2048, StoppedAt: now,
		Workspaces: []sandbox.Workspace{{Path: "/work", ReadOnly: false}, {Path: "/docs", ReadOnly: true}},
		Ports:      []sandbox.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
		Meta:       &sandbox.Meta{Agent: "shell", Detached: true, LastUsedAt: now},
		Policy: &sandbox.NetworkPolicy{
			Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}},
			Deny:  []sandbox.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}},
		},
		CreatedAt: now, UpdatedAt: now,
	}
	op := operation.Operation{
		ID: "op-1", SandboxID: "sb-1", Kind: operation.KindCreate,
		State: operation.Done, Generation: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateSandboxWithOperation(ctx, sb, op); err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "dev" || got.CPUs != 4 || got.MemoryMiB != 2048 || !got.StoppedAt.Equal(now) ||
		len(got.Workspaces) != 2 || got.Workspaces[1].Path != "/docs" || !got.Workspaces[1].ReadOnly ||
		got.Meta == nil || got.Meta.Agent != "shell" || !got.Meta.Detached || !got.Meta.LastUsedAt.Equal(now) ||
		len(got.Ports) != 1 || got.Ports[0].Host != 8080 || got.Policy == nil ||
		len(got.Policy.Allow) != 1 || got.Policy.Allow[0].Port != 80 || len(got.Policy.Deny) != 1 || got.Policy.Deny[0].Protocol != "udp" {
		t.Fatalf("sandbox = %+v", got)
	}
	byName, err := st.GetByName(ctx, "dev")
	if err != nil || byName.ID != "sb-1" {
		t.Fatalf("by name: %+v, %v", byName, err)
	}

	opGot, err := st.Operations().Get(ctx, "op-1")
	if err != nil || opGot.State != operation.Done {
		t.Fatalf("operation: %+v, %v", opGot, err)
	}

	items, next, err := st.List(ctx, sandbox.ListOptions{PageSize: 10})
	if err != nil || len(items) != 1 || next != "" {
		t.Fatalf("list: %+v %q %v", items, next, err)
	}

	sb.State = sandbox.Running
	sb.Generation = 2
	sb.UpdatedAt = now.Add(time.Second)
	op2 := operation.Operation{
		ID: "op-2", SandboxID: "sb-1", Kind: operation.KindStart,
		State: operation.Done, Generation: 2, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.ApplySandboxOperation(ctx, sb, op2); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get(ctx, "sb-1")
	if err != nil || got.State != sandbox.Running || got.Generation != 2 {
		t.Fatalf("updated: %+v, %v", got, err)
	}

	op3 := operation.Operation{
		ID: "op-3", SandboxID: "sb-1", Kind: operation.KindDelete,
		State: operation.Done, Generation: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.DeleteSandboxWithOperation(ctx, "sb-1", op3); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "sb-1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Unix(100, 0).UTC()
	for i, id := range []string{"sb-1", "sb-2", "sb-3"} {
		sb := sandbox.Sandbox{
			ID: id, Name: id, State: sandbox.Stopped, Generation: 1,
			CreatedAt: now.Add(time.Duration(i) * time.Second), UpdatedAt: now,
		}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	first, next, err := st.List(ctx, sandbox.ListOptions{PageSize: 2})
	if err != nil || len(first) != 2 || next == "" {
		t.Fatalf("first page: %+v %q %v", first, next, err)
	}
	second, next2, err := st.List(ctx, sandbox.ListOptions{PageSize: 2, PageToken: next})
	if err != nil || len(second) != 1 || next2 != "" {
		t.Fatalf("second page: %+v %q %v", second, next2, err)
	}
}

func TestOpenMigratesLegacySandboxResourceColumns(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE sandboxes (
			id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
			generation INTEGER NOT NULL, image TEXT NOT NULL, workspace TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
		)`,
		`INSERT INTO sandboxes (id, name, state, generation, image, workspace, error, created_at, updated_at)
			VALUES ('sb-old', 'legacy', 'stopped', 1, 'scratch', '/legacy', '', 100, 100)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sb, err := st.Get(ctx, "sb-old")
	if err != nil {
		t.Fatal(err)
	}
	if sb.CPUs != 2 || sb.MemoryMiB != 1024 || !sb.StoppedAt.IsZero() ||
		len(sb.Workspaces) != 1 || sb.Workspaces[0].Path != "/legacy" {
		t.Fatalf("legacy defaults = %+v", sb)
	}
	if err := st.Create(ctx, sandbox.Sandbox{ID: "sb-new", Name: "new", State: sandbox.Stopped, CPUs: 3, MemoryMiB: 3072}); err != nil {
		t.Fatal(err)
	}
	created, err := st.Get(ctx, "sb-new")
	if err != nil || created.CPUs != 3 || created.MemoryMiB != 3072 {
		t.Fatalf("new sandbox = %+v, %v", created, err)
	}
}

func TestRegistryCredentialIndexLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	entry := RegistryCredentialIndex{Registry: "ghcr.io", Username: "alice", Scope: "sandbox", SandboxName: "dev"}
	if err := st.UpsertRegistryCredentialIndex(ctx, entry); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListRegistryCredentialIndex(ctx)
	if err != nil || len(items) != 1 || items[0] != entry {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if err := st.DeleteRegistryCredentialIndex(ctx, entry.Registry, entry.Scope, entry.SandboxName); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListRegistryCredentialIndex(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("items after delete=%+v err=%v", items, err)
	}
}

func TestDeleteSetting(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.SetSetting(ctx, "sandbox.proxy-service.sb-test", "openai"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSetting(ctx, "sandbox.proxy-service.sb-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSetting(ctx, "sandbox.proxy-service.sb-test"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("setting after delete error = %v", err)
	}
	if err := st.DeleteSetting(ctx, "sandbox.proxy-service.missing"); err != nil {
		t.Fatalf("delete missing setting: %v", err)
	}
}
