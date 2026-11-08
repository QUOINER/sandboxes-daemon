//go:build !windows

package policysync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTokenFile(t *testing.T) {
	dir := t.TempDir()
	const token = "synthetic-policy-sync-token-000000000000000000000000000000"
	path := writeTestFile(t, dir, "token", []byte(token+"\n"), 0o600)
	loaded, err := LoadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != token {
		t.Fatalf("token = %q", loaded)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("group-readable token error = %v", err)
	}
}

func TestLoadTokenFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	linkTarget := writeTestFile(t, dir, "token-target", []byte("synthetic-token-0000000000000000000000000000"), 0o600)
	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	oversize := writeTestFile(t, dir, "token-oversize", []byte(strings.Repeat("a", MaxTokenFileBytes+1)), 0o600)
	empty := writeTestFile(t, dir, "token-empty", []byte("\n"), 0o600)

	for name, path := range map[string]string{
		"symlink":    link,
		"oversize":   oversize,
		"empty":      empty,
		"directory":  dir,
		"missing":    filepath.Join(dir, "missing"),
		"empty path": "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadTokenFile(path); err == nil {
				t.Fatal("unsafe token file was accepted")
			}
		})
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	dir := t.TempDir()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(publicKey)
	path := writeTestFile(t, dir, "policy.public", []byte(encoded+"\n"), 0o644)
	loaded, err := LoadPublicKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(publicKey) {
		t.Fatal("loaded public key does not match")
	}
}

func TestLoadPublicKeyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := writeTestFile(t, dir, "policy.public", []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o600)
	link := filepath.Join(dir, "policy-link.public")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"invalid base64": "not base64!",
		"wrong length":   base64.StdEncoding.EncodeToString([]byte("short")),
		"empty":          "",
		"oversized":      strings.Repeat("A", MaxPublicKeyFileBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestFile(t, dir, strings.ReplaceAll(name, " ", "-"), []byte(content), 0o600)
			if _, err := LoadPublicKeyFile(path); err == nil {
				t.Fatal("invalid public key file was accepted")
			}
		})
	}
	if _, err := LoadPublicKeyFile(link); err == nil {
		t.Fatal("symlinked public key file was accepted")
	}
}
