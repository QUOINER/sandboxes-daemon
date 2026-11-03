//go:build windows

package daemon

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	localv1 "github.com/quoiner/sandboxes-api/gen/go/sandboxes/local/v1"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestWindowsDaemonPipePathIsPerUserAndStable(t *testing.T) {
	address := filepath.Join(t.TempDir(), "sandboxesd.sock")
	first, _, err := daemonPipePath(address)
	if err != nil {
		t.Fatal(err)
	}
	stable, _, err := daemonPipePath(address)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := daemonPipePath(filepath.Join(t.TempDir(), "other.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.ToLower(first), strings.ToLower(daemonPipePrefix)) || first == second || first != stable {
		t.Fatalf("unexpected named-pipe identities: first=%q second=%q", first, second)
	}
	explicit := `\\.\pipe\quoiner-explicit-test`
	got, _, err := daemonPipePath(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if got != explicit {
		t.Fatalf("explicit named pipe changed: got %q, want %q", got, explicit)
	}
}

func TestWindowsStateDirectoryIsPrivateAndLockIsExclusive(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "private-state")
	if err := prepareDaemonStateDirectory(stateDir); err != nil {
		t.Fatal(err)
	}
	first, err := lockStateDirectory(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if second, err := lockStateDirectory(stateDir); err == nil {
		_ = second.Close()
		t.Fatal("second daemon acquired an already-held state lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := lockStateDirectory(stateDir)
	if err != nil {
		t.Fatalf("state lock was not released on close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsStateDirectoryRejectsInheritedBroadACL(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "inherited-state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareDaemonStateDirectory(stateDir); err == nil {
		t.Fatal("state directory with inherited permissions was accepted")
	}
}

func TestWindowsStateDirectoryRejectsJunctionTraversal(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("create owned junction: %v: %s", err, output)
	}
	defer func() { _ = os.Remove(junction) }()
	if err := prepareDaemonStateDirectory(filepath.Join(junction, "new-state")); err == nil {
		t.Fatal("state directory setup followed a junction")
	}
}

func TestWindowsDACLRejectsWorldAccessAndExtraEntries(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExpectedDACL(valid, sid) {
		t.Fatal("expected current-user and SYSTEM ACL was rejected")
	}
	for _, dacl := range []string{
		"D:P(A;;GA;;;WD)",
		"D:P(A;;FA;;;" + sid + ")(A;;FA;;;WD)",
		"D:(A;;FA;;;" + sid + ")(A;;FA;;;SY)",
	} {
		unsafeDescriptor, err := windows.SecurityDescriptorFromString(dacl)
		if err != nil {
			t.Fatal(err)
		}
		if hasExpectedDACL(unsafeDescriptor, sid) {
			t.Errorf("unsafe DACL was accepted: %s", dacl)
		}
	}
}

func TestWindowsDaemonNamedPipeServesGRPC(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	address := filepath.Join(root, "sandboxesd.sock")
	pipe, _, err := daemonPipePath(address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{SocketPath: address, StateDir: stateDir}) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		timeout := 100 * time.Millisecond
		conn, dialErr := winio.DialPipe(pipe, &timeout)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			select {
			case runErr := <-done:
				t.Fatalf("daemon failed to start: %v (pipe dial: %v)", runErr, dialErr)
			case <-time.After(3 * time.Second):
				t.Fatalf("daemon did not create named pipe: %v", dialErr)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, pipe)
	}
	clientConn, err := grpc.NewClient("passthrough:///daemon", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer requestCancel()
	if _, err := localv1.NewSandboxServiceClient(clientConn).List(requestCtx, &localv1.ListRequest{}); err != nil {
		_ = clientConn.Close()
		t.Fatalf("gRPC over named pipe failed: %v", err)
	}
	_ = clientConn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop after cancellation")
	}
}
