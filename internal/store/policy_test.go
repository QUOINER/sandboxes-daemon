//go:build !windows

package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testBundle(revision uint64, now time.Time) StoredPolicyBundle {
	return StoredPolicyBundle{
		OrgID: "org-a", Revision: revision, Payload: []byte(`{"schemaVersion":1}`),
		Signature: "c2lnbmF0dXJl", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), SyncedAt: now,
	}
}

func TestPolicyBundleStoreRoundTripAndRollbackRefusal(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

	if _, found, err := state.GetPolicyBundle(ctx, "org-a"); err != nil || found {
		t.Fatalf("empty store found=%v err=%v", found, err)
	}
	if err := state.SavePolicyBundle(ctx, testBundle(1, now)); err != nil {
		t.Fatal(err)
	}
	stored, found, err := state.GetPolicyBundle(ctx, "org-a")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if stored.Revision != 1 || !stored.ExpiresAt.Equal(now.Add(time.Hour)) || !stored.IssuedAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("stored=%+v", stored)
	}
	if err := state.SavePolicyBundle(ctx, testBundle(2, now)); err != nil {
		t.Fatal(err)
	}
	if err := state.SavePolicyBundle(ctx, testBundle(1, now)); !errors.Is(err, ErrPolicyRevisionNotNewer) {
		t.Fatalf("rollback error=%v, want ErrPolicyRevisionNotNewer", err)
	}
	if err := state.SavePolicyBundle(ctx, testBundle(2, now)); !errors.Is(err, ErrPolicyRevisionNotNewer) {
		t.Fatalf("equal revision error=%v, want ErrPolicyRevisionNotNewer", err)
	}
	stored, found, err = state.GetPolicyBundle(ctx, "org-a")
	if err != nil || !found || stored.Revision != 2 {
		t.Fatalf("stored revision=%d found=%v err=%v", stored.Revision, found, err)
	}
}

func TestPolicyBundleStoreRejectsInvalidBundles(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	cases := map[string]StoredPolicyBundle{
		"missing org":       {Revision: 1, Payload: []byte("x"), Signature: "s", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"zero revision":     {OrgID: "org-a", Payload: []byte("x"), Signature: "s", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"empty payload":     {OrgID: "org-a", Revision: 1, Signature: "s", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"empty signature":   {OrgID: "org-a", Revision: 1, Payload: []byte("x"), IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"invalid lifetime":  {OrgID: "org-a", Revision: 1, Payload: []byte("x"), Signature: "s", IssuedAt: now, ExpiresAt: now},
		"missing timestamp": {OrgID: "org-a", Revision: 1, Payload: []byte("x"), Signature: "s"},
	}
	for name, bundle := range cases {
		t.Run(name, func(t *testing.T) {
			if err := state.SavePolicyBundle(ctx, bundle); err == nil {
				t.Fatal("invalid bundle was stored")
			}
		})
	}
}

func TestPolicyBundleSchemaMigratesFromV1WithBackup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TABLE legacy_marker(value TEXT); INSERT INTO legacy_marker(value) VALUES('v1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	matches, err := filepath.Glob(path + ".pre-v1-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups=%v err=%v", matches, err)
	}
	if info, err := os.Stat(matches[0]); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup info=%v err=%v", info, err)
	}
	if err := state.SavePolicyBundle(ctx, testBundle(1, time.Now().UTC())); err != nil {
		t.Fatalf("save after v1 migration: %v", err)
	}
	if _, found, err := state.GetPolicyBundle(ctx, "org-a"); err != nil || !found {
		t.Fatalf("read after v1 migration found=%v err=%v", found, err)
	}
}
