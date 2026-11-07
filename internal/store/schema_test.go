package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenMigratesLegacySchemaWithBackup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `INSERT INTO legacy_marker(value) VALUES ('pre-upgrade')`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	matches, err := filepath.Glob(path + ".pre-v0-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups = %v, %v", matches, err)
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v", info.Mode().Perm())
	}

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d", version)
	}

	backup, err := sql.Open("sqlite", "file:"+matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backup.Close() }()
	var value string
	if err := backup.QueryRowContext(ctx, `SELECT value FROM legacy_marker`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "pre-upgrade" {
		t.Fatalf("backup value = %q", value)
	}
	var backupVersion int
	if err := backup.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&backupVersion); err != nil {
		t.Fatal(err)
	}
	if backupVersion != 0 {
		t.Fatalf("backup schema version = %d", backupVersion)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("Open error = %v, want ErrSchemaNewer", err)
	}
}

func TestBackupRestoresPreUpgradeDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxes.db")
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `INSERT INTO legacy_marker(value) VALUES ('rollback')`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(path + ".pre-v0-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups = %v, %v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || !strings.HasPrefix(string(data), "SQLite format 3") {
		t.Fatal("backup is not a SQLite database")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rolledBack.Close() }()
	var value string
	if err := rolledBack.QueryRowContext(ctx, `SELECT value FROM legacy_marker`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "rollback" {
		t.Fatalf("restored value = %q", value)
	}
}
