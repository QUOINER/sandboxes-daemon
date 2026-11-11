//go:build !windows

package daemon

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const daemonBackupRegistry = `[{"name":"legacy","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"Authorization":"Bearer legacy-synthetic-token"}}]`

func TestRunAbortsWhenBackupSanitizationFailsThenRetries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	dir, err := os.MkdirTemp("/tmp", "rsbx-backup-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup test directory: %v", err)
		}
	})
	path := filepath.Join(dir, "sandboxes.db")
	createLegacyDaemonDatabase(t, path)
	backup := path + ".pre-v1-20990101T000000Z.bak"
	createLegacyDaemonDatabase(t, backup)
	if err := os.Chmod(backup, 0o400); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "sandboxesd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = Run(ctx, Config{SocketPath: socket, StateDir: dir})
	if err == nil {
		t.Fatal("daemon startup succeeded with an unsanitized backup")
	}
	if !strings.Contains(err.Error(), "initialize MCP registry") {
		t.Fatalf("startup error = %v", err)
	}
	if _, statErr := os.Lstat(socket); !os.IsNotExist(statErr) {
		t.Fatalf("daemon listened before backup sanitization: %v", statErr)
	}

	if err := os.Chmod(backup, 0o600); err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, Config{SocketPath: socket, StateDir: dir}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, statErr := os.Lstat(socket); statErr == nil {
			break
		}
		select {
		case err := <-done:
			runCancel()
			t.Fatalf("daemon retry failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			runCancel()
			t.Fatal("daemon did not start after backup write recovery")
		}
		time.Sleep(20 * time.Millisecond)
	}
	runCancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if value := daemonBackupSetting(t, backup); strings.Contains(value, "legacy-synthetic-token") {
		t.Fatalf("retry did not scrub backup: %q", value)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "unchanged" {
		t.Fatalf("unrelated file changed: %q err=%v", data, err)
	}
}

func createLegacyDaemonDatabase(t *testing.T, path string) {
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
	if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES (?,?,?)`, "mcp_stdio_servers_v1", daemonBackupRegistry, 222); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO marker(value) VALUES (?)`, "pre-upgrade"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
}

func daemonBackupSetting(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var value string
	if err := db.QueryRowContext(context.Background(), `SELECT value FROM settings WHERE key=?`, "mcp_stdio_servers_v1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
