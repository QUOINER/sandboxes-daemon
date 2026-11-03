//go:build !windows

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/lickren/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestRunRequiresConfig(t *testing.T) {
	if err := Run(context.Background(), Config{}); err == nil {
		t.Fatal("expected config error")
	}
}

func TestRunStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "sandboxesd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{SocketPath: socket, StateDir: dir})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket was not created")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(socket); !os.IsNotExist(err) {
			t.Fatalf("owned socket not removed after shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestRunShutdownClosesActiveWatch(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lsbx-watch-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup test directory: %v", err)
		}
	})
	socket := filepath.Join(dir, "daemon.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		done <- Run(ctx, Config{SocketPath: socket, StateDir: dir})
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("test daemon cleanup timed out")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix:"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := localv1.NewSandboxServiceClient(conn)
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer requestCancel()
	if _, err := client.Create(requestCtx, &localv1.CreateRequest{Name: "fixture"}); err != nil {
		t.Fatal(err)
	}
	watch, err := client.Watch(requestCtx, &localv1.WatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Recv(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("daemon shutdown blocked on active watch")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("daemon socket remains: %v", err)
	}
}

func TestRunReportsCleanupErrorBeforeReleasingStateLock(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lsbx-cleanup-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup test directory: %v", err)
		}
	})
	socket := filepath.Join(dir, "daemon.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sentinel := errors.New("synthetic gateway cleanup failure")
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		done <- Run(ctx, Config{SocketPath: socket, StateDir: dir, Cleanup: func() error {
			lock, err := lockStateDirectory(dir)
			if err == nil {
				_ = lock.Close()
				return errors.New("state lock was released before cleanup")
			}
			return sentinel
		}})
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("test daemon cleanup timed out")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatalf("cleanup failure was not returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
	lock, err := lockStateDirectory(dir)
	if err != nil {
		t.Fatalf("state lock was not released: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSocketAvailablePreservesExistingObjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.sock")
	if err := ensureSocketAvailable(path); err != nil {
		t.Fatalf("unused path rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("existing file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketAvailable(path); err == nil {
		t.Fatal("existing regular file accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing file" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
}

func TestEnsureSocketAvailablePreservesSocketAndSymlink(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lsbx-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup test directory: %v", err)
		}
	})
	path := filepath.Join(dir, "daemon.sock")
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	if err := ensureSocketAvailable(path); err == nil {
		t.Fatal("existing socket accepted")
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("existing listener was disturbed: %v", err)
	}
	_ = conn.Close()
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketAvailable(link); err == nil {
		t.Fatal("dangling symlink accepted")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("existing symlink removed: %v", err)
	}
}

func TestStateDirectoryLockExcludesSecondDaemon(t *testing.T) {
	dir := t.TempDir()
	first, err := lockStateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockStateDirectory(dir); err == nil {
		_ = second.Close()
		_ = first.Close()
		t.Fatal("second state lock unexpectedly succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := lockStateDirectory(dir)
	if err != nil {
		t.Fatalf("lock not released on close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateDirectoryLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "daemon.lock")); err != nil {
		t.Fatal(err)
	}
	if lock, err := lockStateDirectory(dir); err == nil {
		_ = lock.Close()
		t.Fatal("symlink lock accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("symlink target changed: %q, %v", data, err)
	}
}
