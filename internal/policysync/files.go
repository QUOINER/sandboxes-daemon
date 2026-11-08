package policysync

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// MaxPublicKeyFileBytes bounds the pinned public key file.
	MaxPublicKeyFileBytes = 4096
	// MaxTokenFileBytes bounds the bearer token file.
	MaxTokenFileBytes = 4096
)

// LoadTokenFile reads a bearer token from a protected file. The file must be a
// regular file, not a symlink, owned-only (0600 on Unix) and at most
// MaxTokenFileBytes. The value is never logged by this package.
func LoadTokenFile(path string) (string, error) {
	raw, err := readRegularFile(path, MaxTokenFileBytes, true)
	if err != nil {
		return "", fmt.Errorf("read policy sync token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("policy sync token file is empty")
	}
	return token, nil
}

// LoadPublicKeyFile reads the pinned base64 Ed25519 public key. The public key
// is not secret, but the file is still validated as a bounded regular file
// that is not a symlink.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	raw, err := readRegularFile(path, MaxPublicKeyFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read policy sync public key file: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("policy sync public key file must contain a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

// readRegularFile opens path after an lstat check and verifies that the opened
// descriptor still refers to the same file. This rejects symlinks and special
// files, and avoids a path-swap race between validation and reading.
func readRegularFile(path string, limit int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("must be a regular file, not a symlink or special file")
	}
	if private {
		if err := checkPrivateFileMode(info.Mode()); err != nil {
			return nil, err
		}
	}
	//nolint:gosec // The operator supplies this protected host path in settings.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errors.New("file changed while opening")
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return content, nil
}
