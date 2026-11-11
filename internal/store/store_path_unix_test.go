//go:build !windows

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSupportsURICharactersInFilename(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state #1 [work].db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open database at URI-like path: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("database was not created at requested path: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("database path is not a regular file: %v", info.Mode())
	}
}
