//go:build !windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProtectedTestFile(t *testing.T, dir, name string, content []byte, mode os.FileMode) string {
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

func policySyncTestOptions(t *testing.T) (*options, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := writeProtectedTestFile(t, dir, "policy.public", []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o644)
	tokenPath := writeProtectedTestFile(t, dir, "policy.token", []byte("synthetic-policy-sync-token-000000000000000000000000000000\n"), 0o600)
	return &options{
		policySyncURL:       "https://control.example.test",
		policySyncOrg:       "acme",
		policySyncPublicKey: publicPath,
		policySyncTokenFile: tokenPath,
		policySyncInterval:  90 * time.Second,
	}, publicKey
}

func TestLoadPolicySyncDisabled(t *testing.T) {
	cfg, err := loadPolicySync(&options{})
	if err != nil || cfg != nil {
		t.Fatalf("disabled policy sync = %+v, %v", cfg, err)
	}
}

func TestLoadPolicySyncReadsProtectedFiles(t *testing.T) {
	opts, publicKey := policySyncTestOptions(t)
	cfg, err := loadPolicySync(opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.Client == nil || cfg.Client.OrgID() != "acme" || cfg.Interval != 90*time.Second {
		t.Fatalf("policy sync config = %+v", cfg)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("test public key has the wrong size")
	}
}

func TestLoadPolicySyncRejectsUnsafeFiles(t *testing.T) {
	opts, _ := policySyncTestOptions(t)
	if err := os.Chmod(opts.policySyncTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicySync(opts); err == nil {
		t.Fatal("group-readable token file was accepted")
	}

	opts, _ = policySyncTestOptions(t)
	link := filepath.Join(filepath.Dir(opts.policySyncPublicKey), "policy-link.public")
	if err := os.Symlink(opts.policySyncPublicKey, link); err != nil {
		t.Fatal(err)
	}
	opts.policySyncPublicKey = link
	if _, err := loadPolicySync(opts); err == nil {
		t.Fatal("symlinked public key file was accepted")
	}

	opts, _ = policySyncTestOptions(t)
	opts.policySyncURL = "http://control.example.test"
	if _, err := loadPolicySync(opts); err == nil {
		t.Fatal("non-HTTPS policy sync URL was accepted")
	}
}
