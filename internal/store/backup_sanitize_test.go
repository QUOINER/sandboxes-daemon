package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeBackupSettingScrubsOnlyTargetAndPreservesOthers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	active := filepath.Join(dir, "sandboxes.db")
	backupOne := active + ".pre-v1-20240102T030405Z.bak"
	backupTwo := active + ".pre-v1-20240101T000000Z-1.bak"
	legacySchemaBackup := active + ".pre-v0-20231231T000000Z.bak"
	createBackupSettingsFixture(t, backupOne, `[{"name":"legacy","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"Authorization":"synthetic-secret"}}]`)
	createBackupSettingsFixture(t, backupTwo, `[{"name":"clean","transport":"remote","url":"https://mcp.example.test/mcp"}]`)
	createBackupWithoutSettings(t, legacySchemaBackup)

	unrelatedBackup := filepath.Join(dir, "other.db.pre-v1-20240101T000000Z.bak")
	unrelatedFile := filepath.Join(dir, "sandboxes.db.pre-v1-not-a-timestamp.bak")
	for path, content := range map[string]string{unrelatedBackup: "unrelated-backup", unrelatedFile: "unrelated-file"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	clean := func(raw string) (string, error) {
		if !strings.Contains(raw, "synthetic-secret") {
			return raw, nil
		}
		return strings.ReplaceAll(raw, "synthetic-secret", ""), nil
	}
	st := &Store{path: active}
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", clean); err != nil {
		t.Fatal(err)
	}

	target, updatedAt := readBackupSetting(t, backupOne, "mcp_stdio_servers_v1")
	if strings.Contains(target, "synthetic-secret") {
		t.Fatalf("backup retained target value: %q", target)
	}
	if updatedAt != 222 {
		t.Fatalf("target updated_at changed: %d", updatedAt)
	}
	if got := readBackupSettingValue(t, backupOne, "unrelated_key"); got != "keep-me" {
		t.Fatalf("unrelated setting changed: %q", got)
	}
	if got := readBackupMarker(t, backupOne); got != "pre-upgrade" {
		t.Fatalf("unrelated backup row changed: %q", got)
	}
	if got, _ := readBackupSetting(t, backupTwo, "mcp_stdio_servers_v1"); !strings.Contains(got, `"clean"`) {
		t.Fatalf("already-clean backup changed: %q", got)
	}
	if got := readBackupMarker(t, legacySchemaBackup); got != "legacy-schema" {
		t.Fatalf("backup without settings table changed: %q", got)
	}
	for path, want := range map[string]string{unrelatedBackup: "unrelated-backup", unrelatedFile: "unrelated-file"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("unrelated file %s changed: %q err=%v", filepath.Base(path), data, err)
		}
	}

	before, _ := readBackupSetting(t, backupOne, "mcp_stdio_servers_v1")
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", clean); err != nil {
		t.Fatal(err)
	}
	after, updatedAtAgain := readBackupSetting(t, backupOne, "mcp_stdio_servers_v1")
	if before != after || updatedAtAgain != updatedAt {
		t.Fatalf("retry changed backup: before=%q after=%q updated=%d/%d", before, after, updatedAt, updatedAtAgain)
	}
}

func TestSanitizeBackupSettingErasesLegacyValueBytes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	active := filepath.Join(dir, "sandboxes.db")
	backup := active + ".pre-v1-20240102T030405Z.bak"
	canary := "legacy-header-secret-" + strings.Repeat("x", 256)
	registry := `[{"name":"legacy","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"X-API-Key":"` + canary + `"}}]`
	createBackupSettingsFixture(t, backup, registry)

	before, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), canary) {
		t.Fatal("fixture does not contain the synthetic legacy value")
	}

	st := &Store{path: active}
	sanitize := func(raw string) (string, error) {
		return strings.ReplaceAll(raw, canary, ""), nil
	}
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", sanitize); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), canary) {
		t.Fatal("backup file still contains the removed legacy value bytes")
	}
	if _, err := os.Lstat(backup + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed sanitizer left a rollback journal: %v", err)
	}
}

func createBackupSettingsFixture(t *testing.T, path, registry string) {
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
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES (?,?,?)`, "mcp_stdio_servers_v1", registry, 222); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES (?,?,?)`, "unrelated_key", "keep-me", 111); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO marker(value) VALUES (?)`, "pre-upgrade"); err != nil {
		t.Fatal(err)
	}
}

func createBackupWithoutSettings(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE TABLE marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO marker(value) VALUES (?)`, "legacy-schema"); err != nil {
		t.Fatal(err)
	}
}

func readBackupSetting(t *testing.T, path, key string) (string, int64) {
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

func readBackupSettingValue(t *testing.T, path, key string) string {
	t.Helper()
	value, _ := readBackupSetting(t, path, key)
	return value
}

func readBackupMarker(t *testing.T, path string) string {
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
