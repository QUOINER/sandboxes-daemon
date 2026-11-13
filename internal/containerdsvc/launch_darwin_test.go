//go:build darwin

package containerdsvc

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinLauncherStopsContainerdWhenDaemonParentExits(t *testing.T) {
	switch os.Getenv("RSBX_LAUNCH_TEST_MODE") {
	case "daemon":
		cmd := exec.Command(os.Args[0], "-test.run=^TestDarwinLauncherStopsContainerdWhenDaemonParentExits$")
		cmd.Env = append(os.Environ(), "RSBX_LAUNCH_TEST_MODE=launcher")
		guardian, _, err := configureParentDeath(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			_ = guardian.Close()
			closeParentDeathReader(cmd)
			t.Fatal(err)
		}
		closeParentDeathReader(cmd)
		if err := os.WriteFile(os.Getenv("RSBX_LAUNCHER_PID"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		waitForFile(t, os.Getenv("RSBX_READY"))
		// The guardian writer closes when this helper exits, simulating daemon death.
		defer guardian.Close()
		return
	case "launcher":
		_ = os.Setenv("RSBX_LAUNCH_TEST_MODE", "containerd")
		RunLauncher([]string{os.Getenv("RSBX_SERVICE_DIR"), os.Args[0], "-test.run=^TestDarwinLauncherStopsContainerdWhenDaemonParentExits$"})
		return
	case "containerd":
		if len(os.Args) > 1 && os.Args[1] == os.Args[0] {
			t.Fatal("launcher passed the binary path as an extra argument")
		}
		_ = os.WriteFile(os.Getenv("RSBX_ARGS"), []byte(strings.Join(os.Args[1:], "\n")), 0o600)
		stopped := make(chan os.Signal, 1)
		signal.Notify(stopped, syscall.SIGTERM)
		_ = os.WriteFile(os.Getenv("RSBX_READY"), []byte("ready"), 0o600)
		<-stopped
		_ = os.WriteFile(os.Getenv("RSBX_STOPPED"), []byte("stopped"), 0o600)
		os.Exit(0)
	}

	dir := t.TempDir()
	ready, stopped := filepath.Join(dir, "ready"), filepath.Join(dir, "stopped")
	pidFile := filepath.Join(dir, "launcher.pid")
	daemon := exec.Command(os.Args[0], "-test.run=^TestDarwinLauncherStopsContainerdWhenDaemonParentExits$")
	argsFile := filepath.Join(dir, "args")
	daemon.Env = append(os.Environ(), "RSBX_LAUNCH_TEST_MODE=daemon", "RSBX_SERVICE_DIR="+dir,
		"RSBX_READY="+ready, "RSBX_STOPPED="+stopped, "RSBX_LAUNCHER_PID="+pidFile, "RSBX_ARGS="+argsFile)
	if err := daemon.Run(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ready)
	argv, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(argv); got != "-test.run=^TestDarwinLauncherStopsContainerdWhenDaemonParentExits$" {
		t.Fatalf("containerd argv = %q", got)
	}
	contents, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, stopped)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("launcher process %d remained after daemon parent exit", pid)
}

func waitForFile(t *testing.T, path string) {
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
