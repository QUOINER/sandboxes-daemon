//go:build darwin || linux

package mcpprocess

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCloseTerminatesDescendantProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "orphan-wrote-this")
	cmd := exec.Command("/bin/sh", "-c", "(sleep 0.3; printf orphan > \"$1\") & wait", "mcp-fixture", marker)
	process, err := StartProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant survived process-tree cleanup; marker stat error=%v", err)
	}
}
