//go:build linux

package containerdsvc

import (
	"bufio"
	"context"
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
	args := []string{serviceDir, binary, "--config", filepath.Join(serviceDir, "config.toml"), "--log-level", "info"}
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

func TestRemoveStaleSocketRefusesActiveAndStaleSocketPaths(t *testing.T) {
	activePath := filepath.Join(t.TempDir(), "active.sock")
	listener, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := removeStaleSocket(activePath); err == nil {
		t.Fatal("active socket was not refused")
	}
	conn, err := net.Dial("unix", activePath)
	if err != nil {
		t.Fatalf("active listener was modified: %v", err)
	}
	_ = conn.Close()

	stalePath := filepath.Join(t.TempDir(), "stale.sock")
	stale, err := net.Listen("unix", stalePath)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(stalePath); err == nil {
		t.Fatal("stale socket pathname was unlinked")
	}
	if _, err := os.Lstat(stalePath); err != nil {
		t.Fatalf("stale socket path was modified: %v", err)
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
