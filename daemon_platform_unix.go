//go:build !windows

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func prepareDaemonStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect daemon state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("daemon state path must be a directory, not a symlink")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict daemon state directory permissions: %w", err)
	}
	return nil
}

func listenDaemon(ctx context.Context, path string) (net.Listener, error) {
	if err := ensureSocketAvailable(path); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("chmod daemon socket: %w", err)
	}
	return lis, nil
}

// lockStateDirectory prevents cooperative daemon instances from sharing one
// SQLite store and runtime resources. The lock file is retained after shutdown.
func lockStateDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- state directory is configured by the operator; symlinks are rejected
	if err != nil {
		return nil, fmt.Errorf("open daemon state lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state lock must be a regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state directory is already in use: %w", err)
	}
	return file, nil
}

func ensureSocketAvailable(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect daemon socket: %w", err)
	}
	return fmt.Errorf("daemon socket path already exists")
}
