//go:build linux

package containerdsvc

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

func TestKeeperHarness(t *testing.T) {
	if os.Getenv("RSBX_KEEPER_TEST_MODE") != "keeper" {
		return
	}
	_ = os.Setenv("RSBX_KEEPER_TEST_MODE", "child")
	os.Exit(RunLauncher([]string{os.Getenv("RSBX_KEEPER_SERVICE"), os.Args[0], "-test.run=^TestKeeperChild$"}))
}

func TestContainerdSmokeHarness(t *testing.T) {
	if os.Getenv("RSBX_REAL_CONTAINERD_MODE") != "keeper" {
		return
	}
	serviceDir := os.Getenv("RSBX_REAL_CONTAINERD_SERVICE")
	binary := os.Getenv("RSBX_TEST_CONTAINERD")
	args := []string{serviceDir, binary, containerdConfigFlag, filepath.Join(serviceDir, "config.toml"), "--log-level", "info"}
	os.Exit(RunLauncher(args))
}

func TestKeeperChild(t *testing.T) {
	if os.Getenv("RSBX_KEEPER_TEST_MODE") != "child" {
		return
	}
	path := os.Getenv("RSBX_KEEPER_CHILD_PIDS")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(31)
	}
	_, _ = fmt.Fprintln(f, os.Getpid())
	_ = f.Close()
	if os.Getenv("RSBX_KEEPER_CRASH") == "1" {
		os.Exit(42)
	}
	if os.Getenv("RSBX_KEEPER_CREATE_SHIM") == "1" {
		shim := exec.Command(os.Args[0], "-test.run=^TestKeeperShim$")
		shim.Env = append(os.Environ(), "RSBX_KEEPER_TEST_MODE=shim")
		if err := shim.Start(); err != nil {
			os.Exit(32)
		}
		_ = os.WriteFile(os.Getenv("RSBX_KEEPER_SHIM_PID"), []byte(strconv.Itoa(shim.Process.Pid)), 0o600)
	}
	select {}
}

func TestKeeperShim(t *testing.T) {
	if os.Getenv("RSBX_KEEPER_TEST_MODE") == "shim" {
		select {}
	}
}

func TestPropagationHarness(t *testing.T) {
	if os.Getenv("RSBX_PROPAGATION_TEST_MODE") != "keeper" {
		return
	}
	runtime.LockOSThread()
	if err := makeRootPrivate(); err != nil {
		os.Exit(41)
	}
	childTarget := os.Getenv("RSBX_PROPAGATION_CHILD_TARGET")
	if err := unix.Mount("tmpfs", childTarget, "tmpfs", 0, "size=16k"); err != nil {
		os.Exit(42)
	}
	var ns syscall.Stat_t
	_ = syscall.Stat("/proc/self/ns/mnt", &ns)
	_ = os.WriteFile(os.Getenv("RSBX_PROPAGATION_READY"), []byte(strconv.FormatUint(ns.Ino, 10)), 0o600)
	for {
		if _, err := os.Stat(os.Getenv("RSBX_PROPAGATION_TRIGGER")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(os.Getenv("RSBX_PROPAGATION_HOST_TARGET")))
	if err != nil {
		os.Exit(43)
	}
	result := "not-visible"
	if len(mounts) != 0 {
		result = "visible"
	}
	_ = os.WriteFile(os.Getenv("RSBX_PROPAGATION_RESULT"), []byte(result), 0o600)
	select {}
}

func TestPrivateNamespaceBlocksMountPropagationBothWays(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", base, "tmpfs", 0, "size=64k"); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("mount capability unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { unmountTestTmpfs(t, base) })
	if err := unix.Mount("", base, "", unix.MS_SHARED, ""); err != nil {
		t.Skipf("shared propagation setup unavailable: %v", err)
	}
	childTarget := filepath.Join(base, "keeper-only")
	hostTarget := filepath.Join(base, "host-only")
	trigger := filepath.Join(base, "trigger")
	ready := filepath.Join(base, "ready")
	result := filepath.Join(base, "result")
	for _, path := range []string{childTarget, hostTarget} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPropagationHarness$")
	cmd.Env = append(os.Environ(), "RSBX_PROPAGATION_TEST_MODE=keeper", "RSBX_PROPAGATION_CHILD_TARGET="+childTarget,
		"RSBX_PROPAGATION_HOST_TARGET="+hostTarget, "RSBX_PROPAGATION_TRIGGER="+trigger,
		"RSBX_PROPAGATION_READY="+ready, "RSBX_PROPAGATION_RESULT="+result)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setsid: true}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("mount namespace creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitForFileLinux(t, ready)
	childNS, err := os.ReadFile(ready)
	if err != nil {
		t.Fatal(err)
	}
	childInode, err := strconv.ParseUint(string(childNS), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if childInode == namespaceInode(t, os.Getpid()) {
		t.Fatal("propagation helper shares host mount namespace")
	}
	if err := unix.Mount("tmpfs", hostTarget, "tmpfs", 0, "size=16k"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(trigger, []byte("check"), 0o600)
	waitForFileLinux(t, result)
	got, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "not-visible" {
		t.Fatalf("host mount propagated into private keeper: %q", got)
	}
	hostMounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(childTarget))
	if err != nil {
		t.Fatal(err)
	}
	if len(hostMounts) != 0 {
		t.Fatalf("keeper-only mount propagated to host: %+v", hostMounts)
	}
	unmountTestTmpfs(t, hostTarget)
}

func waitForFileLinux(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func cleanupSocketGenerations(plan Plan) error {
	stateID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(plan.Socket), "h-"), ".sock")
	prefix := "g-" + stateID + "-"
	entries, err := os.ReadDir(plan.SocketDir)
	if err != nil {
		return fmt.Errorf("read managed socket directory: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || (!strings.HasSuffix(entry.Name(), ".sock") && !strings.HasSuffix(entry.Name(), ".sock.ttrpc")) {
			continue
		}
		path := filepath.Join(plan.SocketDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect owned socket generation: %w", err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("owned socket generation has unexpected type; refusing removal")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stopped socket generation: %w", err)
		}
	}
	info, err := os.Lstat(plan.Socket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stable socket alias: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("stable socket alias has unexpected type; refusing removal")
	}
	target, err := os.Readlink(plan.Socket)
	if err != nil || filepath.Base(target) != target || !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, ".sock") {
		return fmt.Errorf("stable socket alias target is not an owned generation; refusing removal")
	}
	if err := os.Remove(plan.Socket); err != nil {
		return fmt.Errorf("remove stable socket alias: %w", err)
	}
	return nil
}

func TestCleanupSocketGenerationsRemovesGRPCAndTTRPCNodes(t *testing.T) {
	plan := keeperPlan(filepath.Join(t.TempDir(), "containerd"))
	if err := ensurePrivateDir(plan.SocketDir); err != nil {
		t.Fatal(err)
	}
	stateID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(plan.Socket), "h-"), ".sock")
	grpcPath := filepath.Join(plan.SocketDir, "g-"+stateID+"-deadbeef.sock")
	ttrpcPath := grpcPath + ".ttrpc"
	for _, path := range []string{grpcPath, ttrpcPath} {
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(grpcPath), plan.Socket); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSocketGenerations(plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{grpcPath, ttrpcPath, plan.Socket} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("owned socket path %q remains after cleanup: %v", path, err)
		}
	}
}

func unmountTestTmpfs(t *testing.T, path string) {
	t.Helper()
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(path))
	if err != nil {
		t.Errorf("inspect test mount %s: %v", path, err)
		return
	}
	for _, mount := range mounts {
		if mount.Mountpoint != path {
			continue
		}
		if mount.FSType != "tmpfs" {
			t.Errorf("refusing to unmount unexpected test mount type %s at %s", mount.FSType, path)
			return
		}
		if err := unix.Unmount(path, 0); err != nil {
			t.Errorf("unmount owned tmpfs %s: %v", path, err)
		}
		return
	}
}

func TestKeeperSurvivesDaemonRestartAndRestartsContainerdInSameNamespace(t *testing.T) {
	serviceDir := t.TempDir()
	cmd := startTestKeeper(t, serviceDir, false, false)
	firstPID := waitForKeeperChild(t, filepath.Join(serviceDir, "child-pids"), 1)
	plan := keeperPlan(serviceDir)
	reused, err := existingKeeper(plan)
	if err != nil || !reused {
		t.Fatalf("reattach after daemon restart: reused=%t err=%v", reused, err)
	}
	keeperNS := namespaceInode(t, cmd.Process.Pid)
	if hostNS := namespaceInode(t, os.Getpid()); keeperNS == hostNS {
		t.Fatalf("keeper shares test/host mount namespace inode %d", hostNS)
	}
	if err := syscall.Kill(firstPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	secondPID := waitForKeeperChild(t, filepath.Join(serviceDir, "child-pids"), 2)
	if secondPID == firstPID {
		t.Fatalf("keeper did not restart child: PID remains %d", firstPID)
	}
	if got := namespaceInode(t, secondPID); got != keeperNS {
		t.Fatalf("restarted child namespace inode=%d, keeper inode=%d", got, keeperNS)
	}
	stopTestKeeper(t, cmd)
}

func TestDeadKeeperWithSurvivingChildFailsClosed(t *testing.T) {
	serviceDir := t.TempDir()
	cmd := startTestKeeper(t, serviceDir, true, false)
	childPID := waitForKeeperChild(t, filepath.Join(serviceDir, "child-pids"), 1)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	shimBytes, err := os.ReadFile(filepath.Join(serviceDir, "shim-pid"))
	if err != nil {
		t.Fatal(err)
	}
	shimPID, err := strconv.Atoi(string(shimBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(shimPID, 0); err != nil {
		t.Fatalf("fixture shim did not survive keeper death: %v", err)
	}
	if reused, err := existingKeeper(keeperPlan(serviceDir)); err == nil || reused {
		t.Fatalf("dead keeper unexpectedly permitted a fresh namespace: reused=%t err=%v", reused, err)
	}
	_ = syscall.Kill(childPID, syscall.SIGKILL)
	_ = syscall.Kill(shimPID, syscall.SIGKILL)
}

func TestExistingKeeperClearsPriorBootMarker(t *testing.T) {
	dir := t.TempDir()
	plan := keeperPlan(dir)
	if err := os.WriteFile(plan.KeeperMarker, []byte("1234 5678 9012 prior-boot-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reused, err := existingKeeper(plan)
	if err != nil || reused {
		t.Fatalf("prior-boot marker should permit a fresh namespace: reused=%t err=%v", reused, err)
	}
	if _, err := os.Lstat(plan.KeeperMarker); !os.IsNotExist(err) {
		t.Fatalf("prior-boot marker remains: %v", err)
	}
}

func TestPublishSocketAliasRefusesActiveAndStaleSocketPaths(t *testing.T) {
	activeDir := t.TempDir()
	if err := os.Chmod(activeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(activeDir, "h-0000000000000000.sock")
	listener, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := publishSocketAlias(activePath, filepath.Join(activeDir, "g-0000000000000000-1111111111111111.sock"), activeDir, "g-0000000000000000-1111111111111111"); err == nil {
		t.Fatal("active socket alias was replaced")
	}
	conn, err := net.Dial("unix", activePath)
	if err != nil {
		t.Fatalf("active listener was modified: %v", err)
	}
	_ = conn.Close()

	staleDir := t.TempDir()
	if err := os.Chmod(staleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(staleDir, "h-0000000000000000.sock")
	stale, err := net.Listen("unix", stalePath)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if err := publishSocketAlias(stalePath, filepath.Join(staleDir, "g-0000000000000000-1111111111111111.sock"), staleDir, "g-0000000000000000-1111111111111111"); err == nil {
		t.Fatal("stale socket alias was replaced")
	}
	if _, err := os.Lstat(stalePath); err != nil {
		t.Fatalf("stale socket path was modified: %v", err)
	}
}

func TestPublishSocketAliasRotatesOnlyManagedGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldSocket := filepath.Join(dir, "g-0000000000000000-1111111111111111.sock")
	newSocket := filepath.Join(dir, "g-0000000000000000-2222222222222222.sock")
	for _, path := range []string{oldSocket, newSocket} {
		if err := os.WriteFile(path, []byte("owned generation fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "h-0000000000000000.sock")
	if err := os.Symlink(filepath.Base(oldSocket), alias); err != nil {
		t.Fatal(err)
	}
	if err := publishSocketAlias(alias, newSocket, dir, "g-0000000000000000-2222222222222222"); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(alias)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Base(newSocket) {
		t.Fatalf("active socket alias = %q, want %q", target, filepath.Base(newSocket))
	}
	for _, path := range []string{oldSocket, newSocket} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("generation path %q was modified: %v", path, err)
		}
	}
}

func TestPublishSocketAliasRefusesUnmanagedPaths(t *testing.T) {
	t.Run("filesystem socket", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(dir, "h-0000000000000000.sock")
		listener, err := net.Listen("unix", alias)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		if err := publishSocketAlias(alias, filepath.Join(dir, "g-0000000000000000-2222222222222222.sock"), dir, "g-0000000000000000-2222222222222222"); err == nil {
			t.Fatal("filesystem socket alias was replaced")
		}
	})
	t.Run("foreign symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(dir, "h-0000000000000000.sock")
		if err := os.Symlink("../foreign.sock", alias); err != nil {
			t.Fatal(err)
		}
		if err := publishSocketAlias(alias, filepath.Join(dir, "g-0000000000000000-2222222222222222.sock"), dir, "g-0000000000000000-2222222222222222"); err == nil {
			t.Fatal("foreign symlink target was replaced")
		}
	})
}

func TestManagedSocketPathsFitUnixLimitForLongStatePath(t *testing.T) {
	serviceDir := filepath.Join("/var/lib/rheic", strings.Repeat("long-state-component-", 8), "containerd")
	socketDir, socket := managedSocketPaths(serviceDir)
	if filepath.Dir(socket) != socketDir {
		t.Fatalf("socket %q is outside socket directory %q", socket, socketDir)
	}
	if len(socket+".ttrpc") > 100 {
		t.Fatalf("containerd TTRPC socket path exceeds Linux Unix path limit: %d bytes", len(socket+".ttrpc"))
	}
	if socketDir == serviceDir {
		t.Fatal("long state path was reused for the Unix socket directory")
	}
}

func TestKeeperCrashLoopIsBoundedAndFailsClosed(t *testing.T) {
	serviceDir := t.TempDir()
	cmd := startTestKeeper(t, serviceDir, false, true)
	waitForKeeperChild(t, filepath.Join(serviceDir, "child-pids"), 6)
	err := cmd.Wait()
	if err == nil {
		t.Fatal("keeper returned success after repeated child failures")
	}
	if reused, err := existingKeeper(keeperPlan(serviceDir)); err == nil || reused {
		t.Fatalf("crash-loop keeper should leave stale marker and fail closed: reused=%t err=%v", reused, err)
	}
}

func TestPinnedContainerdKeeperSmoke(t *testing.T) {
	binary := os.Getenv("RSBX_TEST_CONTAINERD")
	ctr := os.Getenv("RSBX_TEST_CTR")
	if binary == "" || ctr == "" {
		t.Skip("set RSBX_TEST_CONTAINERD and RSBX_TEST_CTR to run pinned containerd smoke")
	}
	if err := checkExecutable("containerd", binary); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable("ctr", ctr); err != nil {
		t.Fatal(err)
	}
	serviceDir := t.TempDir()
	if err := os.Chmod(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := environment("/usr/local/bin", "/usr/lib", serviceDir)
	if err := verifyBinaryVersion(binary, "containerd", env); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinaryVersion(ctr, "ctr", env); err != nil {
		t.Fatal(err)
	}
	plan := keeperPlan(serviceDir)
	launcher := exec.Command(os.Args[0], "-test.run=^TestContainerdSmokeHarness$")
	launcher.Env = append(os.Environ(), env...)
	launcher.Env = append(launcher.Env, "RSBX_REAL_CONTAINERD_MODE=keeper", "RSBX_REAL_CONTAINERD_SERVICE="+serviceDir,
		"RSBX_TEST_CONTAINERD="+binary)
	launcher.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setsid: true}
	log, err := os.Create(filepath.Join(serviceDir, "containerd-smoke.log"))
	if err != nil {
		t.Fatal(err)
	}
	launcher.Stdout, launcher.Stderr = log, log
	if err := launcher.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = log.Close()
		_ = launcher.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- launcher.Wait() }()
		select {
		case <-done:
		case <-time.After(shutdownTimeout + 2*time.Second):
			_ = launcher.Process.Kill()
			<-done
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ready bool
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, err := runCommand(ctx, ctr, []string{"--address", plan.Socket, "--namespace", Namespace, "version"}, env)
		if err == nil {
			ready = true
			break
		}
		if err := ctx.Err(); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		logData, _ := os.ReadFile(filepath.Join(serviceDir, "containerd-smoke.log"))
		t.Fatalf("containerd readiness timed out: %v; log: %s", ctx.Err(), strings.TrimSpace(string(logData)))
	}
	firstTarget, err := os.Readlink(plan.Socket)
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := managedContainerdChildPID(launcher.Process.Pid, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(childPID, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL owned containerd child: %v", err)
	}
	restarted := false
	restartDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(restartDeadline) {
		activeTarget, readErr := os.Readlink(plan.Socket)
		if readErr == nil && activeTarget != firstTarget {
			if _, runErr := runCommand(ctx, ctr, []string{"--address", plan.Socket, "--namespace", Namespace, "version"}, env); runErr == nil {
				restarted = true
				break
			}
		}
		if err := ctx.Err(); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !restarted {
		logData, _ := os.ReadFile(filepath.Join(serviceDir, "containerd-smoke.log"))
		t.Fatalf("containerd did not recover on a new socket generation after SIGKILL; log: %s", strings.TrimSpace(string(logData)))
	}
	if _, err := os.Lstat(filepath.Join(plan.SocketDir, firstTarget)); err != nil {
		t.Fatalf("previous generation socket was not retained: %v", err)
	}
	if err := launcher.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- launcher.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("keeper shutdown: %v", err)
		}
	case <-time.After(12 * time.Second):
		_ = launcher.Process.Kill()
		t.Fatal("keeper did not stop")
	}
	if _, err := os.Lstat(plan.KeeperMarker); !os.IsNotExist(err) {
		t.Fatalf("keeper marker remains after stop: %v", err)
	}
	if err := cleanupSocketGenerations(plan); err != nil {
		t.Fatalf("clean owned socket generations: %v", err)
	}
}

func TestPinnedContainerdServiceGuestSurvivesDetachAndReattach(t *testing.T) {
	values := map[string]string{}
	for _, key := range []string{"RSBX_TEST_CONTAINERD", "RSBX_TEST_CTR", "RSBX_TEST_SHIM", "RSBX_TEST_ASSETS", "RSBX_TEST_LAUNCHER"} {
		values[key] = os.Getenv(key)
		if values[key] == "" {
			t.Skipf("set %s to run managed guest detach/reattach acceptance", key)
		}
	}
	for _, key := range []string{"RSBX_TEST_CONTAINERD", "RSBX_TEST_CTR", "RSBX_TEST_SHIM", "RSBX_TEST_ASSETS", "RSBX_TEST_LAUNCHER"} {
		if !filepath.IsAbs(values[key]) {
			t.Fatalf("%s must be absolute", key)
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shim, err := os.ReadFile(values["RSBX_TEST_SHIM"])
	if err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(runtimeDir, "containerd-shim-nerdbox-v1")
	if err := os.WriteFile(shimPath, shim, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDir, 0o555); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Binary: values["RSBX_TEST_CONTAINERD"], CTR: values["RSBX_TEST_CTR"],
		RuntimeDir: runtimeDir, RuntimeAssets: values["RSBX_TEST_ASSETS"], StateDir: stateDir,
	}
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stopOwnedKeeper := func() error {
		reused, keeperErr := existingKeeper(plan)
		if keeperErr != nil {
			return keeperErr
		}
		if !reused {
			return nil
		}
		fields, keeperErr := keeperMarkerFields(plan.KeeperMarker)
		if keeperErr != nil {
			return fmt.Errorf("read owned keeper identity: %w", keeperErr)
		}
		if len(fields) != 4 {
			return fmt.Errorf("owned keeper marker has %d fields, want 4", len(fields))
		}
		pid, keeperErr := strconv.Atoi(fields[0])
		if keeperErr != nil {
			return fmt.Errorf("parse owned keeper PID: %w", keeperErr)
		}
		if keeperErr := syscall.Kill(pid, syscall.SIGTERM); keeperErr != nil && !errors.Is(keeperErr, os.ErrProcessDone) {
			return fmt.Errorf("stop owned keeper PID %d: %w", pid, keeperErr)
		}
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			if _, statErr := os.Lstat(plan.KeeperMarker); os.IsNotExist(statErr) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("owned keeper PID %d did not remove its marker", pid)
	}
	var first, second *Service
	ownedTask := ""
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if ownedTask != "" {
			cleanupOwnedAcceptanceTask(t, cleanupCtx, cfg, runtimeDir, values["RSBX_TEST_ASSETS"], plan, ownedTask)
		}
		if first != nil {
			if closeErr := first.Close(); closeErr != nil {
				t.Errorf("detach first acceptance service during cleanup: %v", closeErr)
			}
		}
		if second != nil {
			if closeErr := second.Close(); closeErr != nil {
				t.Errorf("detach second acceptance service during cleanup: %v", closeErr)
			}
		}
		if cleanupErr := stopOwnedKeeper(); cleanupErr != nil {
			t.Errorf("stop uniquely owned acceptance keeper: %v", cleanupErr)
		} else if cleanupErr := cleanupSocketGenerations(plan); cleanupErr != nil {
			t.Errorf("clean uniquely owned socket generations: %v", cleanupErr)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	first, err = Start(ctx, cfg, values["RSBX_TEST_LAUNCHER"])
	if err != nil {
		containerdLog, _ := os.ReadFile(plan.LogFile)
		if len(containerdLog) > 4096 {
			containerdLog = containerdLog[len(containerdLog)-4096:]
		}
		keeperMarker, _ := os.ReadFile(plan.KeeperMarker)
		t.Fatalf("start managed containerd service: %v; containerd log=%q keeper marker=%q", err, containerdLog, keeperMarker)
	}
	env := environment(runtimeDir, values["RSBX_TEST_ASSETS"], plan.ServiceDir)
	runCtr := func(args ...string) (string, error) {
		output, commandErr := runCommand(ctx, cfg.CTR, append([]string{"--address", plan.Socket, "--namespace", Namespace}, args...), env)
		if commandErr != nil {
			return string(output), fmt.Errorf("ctr %v: %w", args, commandErr)
		}
		return strings.TrimSpace(string(output)), nil
	}
	image := os.Getenv("RSBX_TEST_GUEST_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"
	}
	if _, err := runCtr("images", "pull", "--platform", "linux/arm64", image); err != nil {
		t.Fatalf("pull pinned synthetic acceptance image: %v", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	task := "rheic-managed-reattach-" + hex.EncodeToString(nonce[:])
	ownedTask = task
	if _, err := runCtr("run", "--runtime", "io.containerd.nerdbox.v1", "--snapshotter", "overlayfs", "--detach", image, task, "/bin/sh", "-c", "exec sleep 600"); err != nil {
		t.Fatalf("start owned nerdbox guest task: %v", err)
	}
	marker, err := runCtr("tasks", "exec", "--exec-id", "before-detach", task, "/bin/sh", "-c", "echo RHEIC_GUEST_BEFORE_DETACH")
	if err != nil || marker != "RHEIC_GUEST_BEFORE_DETACH" {
		t.Fatalf("guest exec before detach: output=%q err=%v", marker, err)
	}
	firstIdentity, err := keeperMarkerFields(plan.KeeperMarker)
	if err != nil {
		t.Fatal(err)
	}
	keeperPID, err := strconv.Atoi(firstIdentity[0])
	if err != nil {
		t.Fatalf("owned keeper marker has an invalid PID %q: %v", firstIdentity[0], err)
	}
	containerdPID, err := managedContainerdChildPID(keeperPID, cfg.Binary)
	if err != nil {
		t.Fatalf("locate the uniquely owned managed containerd child: %v", err)
	}
	if err := syscall.Kill(containerdPID, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL only the owned managed containerd child PID %d: %v", containerdPID, err)
	}
	restartCtx, restartCancel := context.WithTimeout(ctx, 30*time.Second)
	defer restartCancel()
	recovered := false
	for restartCtx.Err() == nil {
		restartedPID, findErr := managedContainerdChildPID(keeperPID, cfg.Binary)
		if findErr == nil && restartedPID != containerdPID {
			probeCtx, probeCancel := context.WithTimeout(restartCtx, 2*time.Second)
			_, readyErr := runCommand(probeCtx, cfg.CTR, []string{"--address", plan.Socket, "--namespace", Namespace, "version"}, env)
			probeCancel()
			if readyErr == nil {
				recovered = true
				break
			}
		}
		time.Sleep(probeInterval)
	}
	if !recovered {
		containerdLog, _ := os.ReadFile(plan.LogFile)
		if len(containerdLog) > 4096 {
			containerdLog = containerdLog[len(containerdLog)-4096:]
		}
		t.Fatalf("keeper did not restart the SIGKILLed managed containerd child PID %d on a new child with ctr readiness within 30s: %v; containerd log: %s", containerdPID, restartCtx.Err(), strings.TrimSpace(string(containerdLog)))
	}
	status, err := runCtr("tasks", "ls")
	if err != nil || !strings.Contains(status, task+" ") || !strings.Contains(status, "RUNNING") {
		t.Fatalf("owned guest task did not remain running after managed containerd SIGKILL and keeper restart: output=%q err=%v", status, err)
	}
	marker, err = runCtr("tasks", "exec", "--exec-id", "after-containerd-kill", task, "/bin/sh", "-c", "echo RHEIC_GUEST_AFTER_CONTAINERD_KILL")
	if err != nil || marker != "RHEIC_GUEST_AFTER_CONTAINERD_KILL" {
		t.Fatalf("guest exec after managed containerd restart: output=%q err=%v", marker, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("detach first daemon service: %v", err)
	}
	second, err = Start(ctx, cfg, values["RSBX_TEST_LAUNCHER"])
	if err != nil {
		t.Fatalf("reattach managed containerd service: %v", err)
	}
	secondIdentity, err := keeperMarkerFields(plan.KeeperMarker)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstIdentity) != 4 || len(secondIdentity) != 4 || firstIdentity[0] != secondIdentity[0] || firstIdentity[1] != secondIdentity[1] {
		t.Fatalf("keeper identity changed across daemon detach/reattach: before=%v after=%v", firstIdentity, secondIdentity)
	}
	status, err = runCtr("tasks", "ls")
	if err != nil || !strings.Contains(status, task+" ") || !strings.Contains(status, "RUNNING") {
		t.Fatalf("guest task did not remain running after reattach: output=%q err=%v", status, err)
	}
	marker, err = runCtr("tasks", "exec", "--exec-id", "after-reattach", task, "/bin/sh", "-c", "echo RHEIC_GUEST_AFTER_REATTACH")
	if err != nil || marker != "RHEIC_GUEST_AFTER_REATTACH" {
		t.Fatalf("guest exec after reattach: output=%q err=%v", marker, err)
	}
}

func cleanupOwnedAcceptanceTask(t *testing.T, ctx context.Context, cfg Config, runtimeDir, assets string, plan Plan, taskID string) {
	t.Helper()
	cleanupEnv := environment(runtimeDir, assets, plan.ServiceDir)
	ctr := func(args ...string) (string, error) {
		base := []string{"--address", plan.Socket, "--namespace", Namespace}
		output, commandErr := runCommand(ctx, cfg.CTR, append(base, args...), cleanupEnv)
		return strings.TrimSpace(string(output)), commandErr
	}
	taskList, listErr := ctr("tasks", "ls")
	if listErr != nil {
		t.Errorf("list tasks before acceptance cleanup: %v", listErr)
	} else {
		cleanupAcceptanceTaskEntry(t, ctx, ctr, taskList, taskID)
	}
	if output, removeErr := ctr("containers", "rm", taskID); removeErr != nil {
		t.Errorf("remove owned acceptance container %q: %v: %s", taskID, removeErr, output)
	}
	verifyAcceptanceInventories(t, ctr, taskID)
}

func cleanupAcceptanceTaskEntry(t *testing.T, ctx context.Context, ctr func(...string) (string, error), taskList, taskID string) {
	t.Helper()
	status, found := acceptanceTaskStatus(taskList, taskID)
	if !found {
		return
	}
	if status == "RUNNING" {
		if output, killErr := ctr("tasks", "kill", "--signal", "SIGKILL", taskID); killErr != nil {
			t.Errorf("kill owned acceptance task %q: %v: %s", taskID, killErr, output)
		}
	}
	if waitErr := waitAcceptanceTaskStopped(ctx, ctr, taskID); waitErr != nil {
		t.Errorf("wait for owned acceptance task %q to stop: %v", taskID, waitErr)
	}
	if output, removeErr := ctr("tasks", "rm", taskID); removeErr != nil {
		t.Errorf("remove owned acceptance task %q: %v: %s", taskID, removeErr, output)
	}
}

func verifyAcceptanceInventories(t *testing.T, ctr func(...string) (string, error), taskID string) {
	t.Helper()
	for _, inventory := range [][]string{{"tasks", "ls"}, {"containers", "ls"}} {
		output, inventoryErr := ctr(inventory...)
		if inventoryErr != nil {
			t.Errorf("verify owned acceptance %s cleanup: %v", inventory[0], inventoryErr)
		} else if _, found := acceptanceTaskStatus(output, taskID); found {
			t.Errorf("owned acceptance ID %q remains in %s inventory: %s", taskID, inventory[0], output)
		}
	}
}

func managedContainerdChildPID(keeperPID int, binary string) (int, error) {
	childrenPath := filepath.Join("/proc", strconv.Itoa(keeperPID), "task", strconv.Itoa(keeperPID), "children")
	data, err := os.ReadFile(childrenPath)
	if err != nil {
		return 0, fmt.Errorf("read keeper child list: %w", err)
	}
	for _, field := range strings.Fields(string(data)) {
		pid, parseErr := strconv.Atoi(field)
		if parseErr != nil {
			continue
		}
		cmdline, readErr := os.ReadFile(filepath.Join("/proc", field, "cmdline"))
		if readErr != nil {
			continue
		}
		if strings.HasPrefix(string(cmdline), binary+"\x00") {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("managed containerd child was not found under keeper PID %d", keeperPID)
}

func acceptanceTaskStatus(output, taskID string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != taskID {
			continue
		}
		if len(fields) >= 3 {
			return fields[2], true
		}
		return "", true
	}
	return "", false
}

func waitAcceptanceTaskStopped(ctx context.Context, ctr func(...string) (string, error), taskID string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		output, err := ctr("tasks", "ls")
		if err != nil {
			return fmt.Errorf("list tasks: %w", err)
		}
		status, found := acceptanceTaskStatus(output, taskID)
		if !found || status == "STOPPED" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("task still has status %q: %w", status, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestAcceptanceTaskStatus(t *testing.T) {
	const ownedTask = "rheic-managed-reattach-owned"
	tests := []struct {
		name   string
		output string
		want   string
		found  bool
	}{
		{name: "running", output: "TASK PID STATUS\n" + ownedTask + " 220 RUNNING\n", want: "RUNNING", found: true},
		{name: "stopped", output: "TASK PID STATUS\n" + ownedTask + " 220 STOPPED\n", want: "STOPPED", found: true},
		{name: "status with padding", output: "TASK PID STATUS\n" + ownedTask + "\t220\tSTOPPED\n", want: "STOPPED", found: true},
		{name: "substring is not a match", output: "TASK PID STATUS\nrheic-managed-reattach-owned-extra 221 RUNNING\n", found: false},
		{name: "header only", output: "TASK PID STATUS\n", found: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, found := acceptanceTaskStatus(test.output, ownedTask)
			if got != test.want || found != test.found {
				t.Fatalf("acceptanceTaskStatus() = (%q, %t), want (%q, %t)", got, found, test.want, test.found)
			}
		})
	}
}

func startTestKeeper(t *testing.T, serviceDir string, withShim, crash bool) *exec.Cmd {
	t.Helper()
	if err := os.Chmod(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	serviceInfo, err := os.Lstat(serviceDir)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByCurrentUser(serviceInfo) {
		t.Fatalf("test service directory is not owned by uid %d", currentUID())
	}
	pidFile := filepath.Join(serviceDir, "child-pids")
	cmd := exec.Command(os.Args[0], "-test.run=^TestKeeperHarness$")
	cmd.Env = append(os.Environ(), "RSBX_KEEPER_TEST_MODE=keeper", "RSBX_KEEPER_SERVICE="+serviceDir,
		"RSBX_KEEPER_CHILD_PIDS="+pidFile, "RSBX_KEEPER_SHIM_PID="+filepath.Join(serviceDir, "shim-pid"))
	if withShim {
		cmd.Env = append(cmd.Env, "RSBX_KEEPER_CREATE_SHIM=1")
	}
	if crash {
		cmd.Env = append(cmd.Env, "RSBX_KEEPER_CRASH=1")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setsid: true}
	log, err := os.Create(filepath.Join(serviceDir, "keeper-test.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		if errors.Is(err, syscall.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("mount namespace creation is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = log.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return cmd
}

func stopTestKeeper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(12 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("keeper did not stop")
	}
}

func waitForKeeperChild(t *testing.T, path string, count int) int {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		file, err := os.Open(path)
		if err == nil {
			var pids []int
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				pid, parseErr := strconv.Atoi(strings.TrimSpace(scanner.Text()))
				if parseErr == nil {
					pids = append(pids, pid)
				}
			}
			_ = file.Close()
			if len(pids) >= count {
				return pids[count-1]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if log, err := os.ReadFile(filepath.Join(filepath.Dir(path), "keeper-test.log")); err == nil && strings.Contains(strings.ToLower(string(log)), "operation not permitted") {
		t.Skipf("mount namespace setup is unavailable: %s", strings.TrimSpace(string(log)))
	}
	log, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "keeper-test.log"))
	t.Fatalf("timed out waiting for child start %d; keeper log: %s", count, strings.TrimSpace(string(log)))
	return 0
}

func namespaceInode(t *testing.T, pid int) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}
