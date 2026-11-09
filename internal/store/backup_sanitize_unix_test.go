//go:build !windows

package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeBackupSettingFailsThenRetriesAfterWriteRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	ctx := context.Background()
	dir := t.TempDir()
	active := filepath.Join(dir, "sandboxes.db")
	backup := active + ".pre-v1-20240102T030405Z.bak"
	createBackupSettingsFixture(t, backup, `[{"name":"legacy","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"Authorization":"synthetic-secret"}}]`)
	if err := os.Chmod(backup, 0o400); err != nil {
		t.Fatal(err)
	}
	clean := func(raw string) (string, error) {
		if !strings.Contains(raw, "synthetic-secret") {
			return raw, nil
		}
		return strings.ReplaceAll(raw, "synthetic-secret", ""), nil
	}
	st := &Store{path: active}
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", clean); err == nil {
		t.Fatal("sanitizer succeeded on a read-only backup")
	}
	if err := os.Chmod(backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", clean); err != nil {
		t.Fatalf("retry failed after write recovery: %v", err)
	}
	if got, _ := readBackupSetting(t, backup, "mcp_stdio_servers_v1"); strings.Contains(got, "synthetic-secret") {
		t.Fatalf("retry did not scrub backup: %q", got)
	}
}

func TestSanitizeBackupSettingRejectsSymlinkedBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	active := filepath.Join(dir, "sandboxes.db")
	target := filepath.Join(dir, "target.db")
	createBackupSettingsFixture(t, target, `[{"name":"legacy","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"Authorization":"synthetic-secret"}}]`)
	link := active + ".pre-v1-20240102T030405Z.bak"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	st := &Store{path: active}
	if err := st.SanitizeBackupSetting(ctx, "mcp_stdio_servers_v1", func(raw string) (string, error) {
		return strings.ReplaceAll(raw, "synthetic-secret", ""), nil
	}); err == nil {
		t.Fatal("sanitizer followed a symlinked backup")
	}
	if got, _ := readBackupSetting(t, target, "mcp_stdio_servers_v1"); !strings.Contains(got, "synthetic-secret") {
		t.Fatalf("symlink target changed: %q", got)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
}
