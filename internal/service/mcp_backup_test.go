package service

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/mcpmanager"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

const backupMigrationRegistry = `[
 {"name":"legacy-auth","transport":"remote","url":"https://mcp.example.test/auth","headers":{"Authorization":"Bearer legacy-synthetic-token"}},
 {"name":"legacy-headerless","transport":"remote","url":"https://mcp.example.test/plain"},
 {"name":"legacy-vault","transport":"remote","url":"https://mcp.example.test/vault","secret_headers":{"Authorization":"Bearer ${token}"}}
]`

func TestInitializeMCPRegistryScrubsBackupsAndPreservesUnrelatedData(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "sandboxes.db")
	createLegacyMCPDatabase(t, path, backupMigrationRegistry)
	unrelated := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	if err := svc.InitializeMCPRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	current, err := st.GetSetting(ctx, mcpmanager.RegistrySettingKey)
	if err != nil {
		t.Fatal(err)
	}
	assertRegistrySanitized(t, current)
	backups, err := filepath.Glob(path + ".pre-v0-*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v err=%v", backups, err)
	}
	backupValue, updatedAt := readSettingsValue(t, backups[0], mcpmanager.RegistrySettingKey)
	assertRegistrySanitized(t, backupValue)
	if updatedAt != 222 {
		t.Fatalf("backup updated_at changed: %d", updatedAt)
	}
	if got := readSettingsValueOnly(t, backups[0], "unrelated_key"); got != "keep-me" {
		t.Fatalf("unrelated backup setting changed: %q", got)
	}
	if got := readMarker(t, backups[0]); got != "pre-upgrade" {
		t.Fatalf("unrelated backup row changed: %q", got)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "unchanged" {
		t.Fatalf("unrelated file changed: %q err=%v", data, err)
	}

	// Retrying after the current database was already sanitized is safe.
	if err := svc.InitializeMCPRegistry(ctx); err != nil {
		t.Fatal(err)
	}
	retried, err := st.GetSetting(ctx, mcpmanager.RegistrySettingKey)
	if err != nil || retried != current {
		t.Fatalf("retry changed current registry: %q err=%v", retried, err)
	}
	retriedBackup, retriedUpdatedAt := readSettingsValue(t, backups[0], mcpmanager.RegistrySettingKey)
	if retriedBackup != backupValue || retriedUpdatedAt != updatedAt {
		t.Fatalf("retry changed backup: before=%q/%d after=%q/%d", backupValue, updatedAt, retriedBackup, retriedUpdatedAt)
	}
}

func assertRegistrySanitized(t *testing.T, value string) {
	t.Helper()
	for _, canary := range []string{"legacy-synthetic-token"} {
		if strings.Contains(value, canary) {
			t.Fatalf("registry retained legacy value %q", canary)
		}
	}
	for _, marker := range []string{`"legacy-auth"`, `"legacy-headerless"`, `"legacy-vault"`, `${token}`} {
		if !strings.Contains(value, marker) {
			t.Fatalf("registry lost %q: %s", marker, value)
		}
	}
}

func createLegacyMCPDatabase(t *testing.T, path, registry string) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, statement := range []string{
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
		`CREATE TABLE marker (value TEXT NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES (?,?,?)`, mcpmanager.RegistrySettingKey, registry, 222); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES (?,?,?)`, "unrelated_key", "keep-me", 111); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO marker(value) VALUES (?)`, "pre-upgrade"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
}

func readSettingsValue(t *testing.T, path, key string) (string, int64) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var value string
	var updatedAt int64
	if err := db.QueryRowContext(context.Background(), `SELECT value, updated_at FROM settings WHERE key=?`, key).Scan(&value, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return value, updatedAt
}

func readSettingsValueOnly(t *testing.T, path, key string) string {
	t.Helper()
	value, _ := readSettingsValue(t, path, key)
	return value
}

func readMarker(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var value string
	if err := db.QueryRowContext(context.Background(), `SELECT value FROM marker`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
