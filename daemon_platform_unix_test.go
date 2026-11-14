//go:build !windows

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDaemonSocketGenerationCrashHarness(t *testing.T) {
	path := os.Getenv("RSBX_TEST_DAEMON_SOCKET_CHILD")
	if path == "" {
		return
	}
	listener, err := listenDaemon(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	select {}
}

func TestPrepareDaemonStateDirectoryEnforcesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareDaemonStateDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %04o, want 0700", got)
	}
}

func TestPrepareDaemonStateDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := prepareDaemonStateDirectory(link); err == nil {
		t.Fatal("accepted symlink as daemon state directory")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("symlink target mode changed to %04o", got)
	}
}

func TestDaemonSocketGenerationRecoversAfterSIGKILL(t *testing.T) {
	path := newShortDaemonSocketPath(t)
	child := exec.Command(os.Args[0], "-test.run=^TestDaemonSocketGenerationCrashHarness$")
	cleanupDaemonSocketTestArtifacts(t, path)
	child.Env = append(os.Environ(), "RSBX_TEST_DAEMON_SOCKET_CHILD="+path)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childWaited := false
	var restarted net.Listener
	var stalePath string
	t.Cleanup(func() {
		if child.Process != nil && !childWaited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		if restarted != nil {
			_ = restarted.Close()
		}
	})
	waitForDaemonSocket(t, path, 5*time.Second)
	var err error
	stalePath, err = os.Readlink(path)
	if err != nil {
		t.Fatalf("read child daemon socket alias: %v", err)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL owned daemon socket child: %v", err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("child exited successfully after SIGKILL")
	}
	childWaited = true
	if info, err := os.Lstat(stalePath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("SIGKILL did not leave the old generation socket node: info=%v err=%v", info, err)
	}
	restarted, err = listenDaemon(context.Background(), path)
	if err != nil {
		t.Fatalf("restart daemon on the configured socket after SIGKILL: %v", err)
	}
	newPath, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("read restarted daemon socket alias: %v", err)
	}
	if newPath == stalePath || !strings.HasPrefix(filepath.Base(newPath), "g-") {
		t.Fatalf("socket generation did not rotate: old=%q new=%q", stalePath, newPath)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("configured daemon socket alias does not accept connections after restart: %v", err)
	}
	_ = conn.Close()
	if err := restarted.Close(); err != nil {
		t.Fatalf("close restarted daemon listener: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("graceful close retained daemon socket alias: %v", err)
	}
	if info, err := os.Lstat(stalePath); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("restart modified previous generation socket: info=%v err=%v", info, err)
	}
}

func TestValidateDaemonSocketAliasPathEnforcesUnixPathLimit(t *testing.T) {
	maxPathBytes := len(syscall.RawSockaddrUnix{}.Path) - 1
	if err := validateDaemonSocketAliasPath(strings.Repeat("a", maxPathBytes)); err != nil {
		t.Fatalf("accepted maximum-length Unix socket path: %v", err)
	}
	if err := validateDaemonSocketAliasPath(strings.Repeat("a", maxPathBytes+1)); err == nil {
		t.Fatal("accepted overlong Unix socket path")
	}
}

func TestValidateDaemonSocketParentRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-parent")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "parent-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateDaemonSocketParent(filepath.Join(link, "nested")); err == nil {
		t.Fatal("accepted an intermediate symlink in daemon socket parent")
	}
}

func TestValidateDaemonSocketParentRejectsWritableAncestorWithoutStickyBit(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(shared, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateDaemonSocketParent(private); err == nil {
		t.Fatal("accepted a private socket directory under a writable non-sticky ancestor")
	}
}

func TestValidateDaemonSocketACLListing(t *testing.T) {
	tests := []struct {
		name    string
		listing string
		wantErr bool
	}{
		{name: "no acl", listing: "drwx------ 2 user staff 64 dir\n"},
		{name: "empty listing", listing: "", wantErr: true},
		{name: "invalid header", listing: "unexpected output\n", wantErr: true},
		{name: "deny mutation", listing: "drwx------@ 2 user staff 64 dir\n 0: group:everyone deny delete_child\n"},
		{name: "allow read", listing: "drwx------@ 2 user staff 64 dir\n 0: group:everyone allow list,search,readattr\n"},
		{name: "allow delete child", listing: "drwx------@ 2 user staff 64 dir\n 0: group:everyone allow delete_child\n", wantErr: true},
		{name: "allow add file", listing: "drwx------@ 2 user staff 64 dir\n 0: user:other allow add_file\n", wantErr: true},
		{name: "unknown ACL entry", listing: "drwx------@ 2 user staff 64 dir\n 0: user:other audit delete_child\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDaemonSocketACLListing(test.listing)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateDaemonSocketACLListing() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestValidateDaemonSocketRejectsDarwinACLMutation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin ACL test")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/chmod", "+a", "everyone allow delete_child,add_file,add_subdirectory", dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("filesystem does not support macOS ACL test: %v: %s", err, output)
	}
	defer func() {
		cleanup := exec.Command("/bin/chmod", "-N", dir)
		if output, err := cleanup.CombinedOutput(); err != nil {
			t.Errorf("remove test-only ACL: %v: %s", err, output)
		}
	}()
	if err := validateDaemonSocketACL(dir); err == nil {
		t.Fatal("accepted a directory ACL that grants mutation rights")
	}
}

func TestValidateDaemonSocketAncestorIdentity(t *testing.T) {
	foreignUID := uint32(os.Getuid() + 1)
	if err := validateDaemonSocketAncestorIdentity(foreignUID, 0o755); err == nil {
		t.Fatal("accepted foreign-owned ancestor")
	}
	if err := validateDaemonSocketAncestorIdentity(0, os.ModeDir|os.ModeSticky|0o1777); err != nil {
		t.Fatalf("rejected root-owned sticky ancestor: %v", err)
	}
	if err := validateDaemonSocketAncestorIdentity(uint32(os.Getuid()), 0o755); err != nil {
		t.Fatalf("rejected current-user-owned non-writable ancestor: %v", err)
	}
	if err := validateDaemonSocketAncestorIdentity(uint32(os.Getuid()), 0o775); err == nil {
		t.Fatal("accepted group-writable current-user-owned ancestor")
	}
}

func TestManagedDaemonSocketNameRequiresLowercaseHexNonce(t *testing.T) {
	valid := "g-0123456789abcdef-0123456789abcdef.sock"
	if !managedDaemonSocketName(valid, "0123456789abcdef") {
		t.Fatal("rejected valid managed generation name")
	}
	for _, name := range []string{
		"g-0123456789abcdef-0123456789abcdeG.sock",
		"g-0123456789abcdef-0123456789ABCDEf.sock",
		"g-0123456789abcdef-not-a-nonce!.sock",
	} {
		if managedDaemonSocketName(name, "0123456789abcdef") {
			t.Errorf("accepted malformed generation name %q", name)
		}
	}
}

func TestListenDaemonRejectsForeignAndActiveEndpoints(t *testing.T) {
	t.Run("regular file is preserved", func(t *testing.T) {
		path := newShortDaemonSocketPath(t)
		cleanupDaemonSocketTestArtifacts(t, path)
		if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if listener, err := listenDaemon(context.Background(), path); err == nil {
			_ = listener.Close()
			t.Fatal("replaced a foreign regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "foreign" {
			t.Fatalf("foreign file changed: %q err=%v", data, err)
		}
	})

	t.Run("foreign symlink is preserved", func(t *testing.T) {
		path := newShortDaemonSocketPath(t)
		foreign := path + ".foreign"
		if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		cleanupDaemonSocketTestArtifacts(t, path)
		if err := os.Symlink(foreign, path); err != nil {
			t.Fatal(err)
		}
		if listener, err := listenDaemon(context.Background(), path); err == nil {
			_ = listener.Close()
			t.Fatal("replaced a foreign symlink")
		}
		target, err := os.Readlink(path)
		if err != nil || target != foreign {
			t.Fatalf("foreign symlink changed: target=%q err=%v", target, err)
		}
	})

	t.Run("active managed endpoint is preserved", func(t *testing.T) {
		path := newShortDaemonSocketPath(t)
		cleanupDaemonSocketTestArtifacts(t, path)
		listener, err := listenDaemon(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		if other, err := listenDaemon(context.Background(), path); err == nil {
			_ = other.Close()
			t.Fatal("accepted a second listener for an active endpoint")
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatalf("active endpoint was disturbed: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("active foreign socket is preserved", func(t *testing.T) {
		path := newShortDaemonSocketPath(t)
		cleanupDaemonSocketTestArtifacts(t, path)
		foreign, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = foreign.Close() }()
		if listener, err := listenDaemon(context.Background(), path); err == nil {
			_ = listener.Close()
			t.Fatal("replaced an active foreign socket")
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatalf("active foreign listener was disturbed: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("legacy stale socket is preserved", func(t *testing.T) {
		path := newShortDaemonSocketPath(t)
		cleanupDaemonSocketTestArtifacts(t, path)
		stale, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		unixListener, ok := stale.(*net.UnixListener)
		if !ok {
			_ = stale.Close()
			t.Fatal("listener is not a Unix listener")
		}
		unixListener.SetUnlinkOnClose(false)
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}
		if listener, err := listenDaemon(context.Background(), path); err == nil {
			_ = listener.Close()
			t.Fatal("replaced a legacy stale direct socket")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("legacy stale socket was modified: info=%v err=%v", info, err)
		}
		removeOwnedDaemonSocket(t, path)
	})
}

func newShortDaemonSocketPath(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "rsbx-socket-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned daemon socket test directory: %v", err)
		}
	})
	return filepath.Join(root, "daemon.sock")
}

func waitForDaemonSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("daemon socket did not become ready: %s", path)
}

func daemonSocketTestPaths(path string) (string, string) {
	hash := sha256.Sum256([]byte(filepath.Clean(path)))
	endpointHash := hex.EncodeToString(hash[:8])
	endpointDir := filepath.Join("/tmp", ".rsbx-daemon-"+strconv.Itoa(os.Getuid()))
	return endpointDir, filepath.Join(endpointDir, "l-"+endpointHash+".lock")
}

func cleanupDaemonSocketTestArtifacts(t *testing.T, path string) {
	t.Helper()
	endpointDir, lockPath := daemonSocketTestPaths(path)
	hash := filepath.Base(lockPath)
	hash = strings.TrimPrefix(strings.TrimSuffix(hash, ".lock"), "l-")
	t.Cleanup(func() {
		removeOwnedDaemonSocketLock(t, lockPath)
		entries, err := os.ReadDir(endpointDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("list test daemon socket directory: %v", err)
			return
		}
		prefix := "g-" + hash + "-"
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".sock") || strings.HasSuffix(name, ".sock.ttrpc") {
				continue
			}
			removeOwnedDaemonSocket(t, filepath.Join(endpointDir, name))
		}
		_ = os.Remove(endpointDir)
	})
}

func removeOwnedDaemonSocketLock(t *testing.T, lockPath string) {
	t.Helper()
	info, err := os.Lstat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Errorf("inspect test-owned daemon endpoint lock: %v", err)
		return
	}
	if !info.Mode().IsRegular() || !daemonPathOwnedByCurrentUser(info) {
		t.Errorf("refusing to remove unexpected daemon lock path %s", lockPath)
		return
	}
	if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove test-owned daemon endpoint lock: %v", err)
	}
}

func removeOwnedDaemonSocket(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Errorf("inspect test-owned stale socket: %v", err)
		return
	}
	if info.Mode()&os.ModeSocket == 0 || !daemonPathOwnedByCurrentUser(info) {
		t.Errorf("refusing to remove non-owned socket path %s", path)
		return
	}
	if err := os.Remove(path); err != nil {
		t.Errorf("remove test-owned stale socket: %v", err)
	}
}
