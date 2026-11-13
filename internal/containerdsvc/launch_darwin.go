//go:build darwin

package containerdsvc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const LauncherArgument = "--internal-containerd-launcher"

func newCommand(launcher string, plan Plan) (*exec.Cmd, error) {
	if !filepath.IsAbs(launcher) {
		return nil, fmt.Errorf("daemon launcher path must be absolute")
	}
	args := append([]string{LauncherArgument, plan.ServiceDir, plan.Binary}, plan.Args...)
	cmd := makeCommand(launcher, args, append([]string(nil), plan.Environment...))
	return cmd, nil
}

func configureParentDeath(cmd *exec.Cmd) (*os.File, bool, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, false, fmt.Errorf("create containerd parent-death pipe: %w", err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, reader)
	cmd.Env = append(cmd.Env, "RSBX_PARENT_DEATH_FD="+strconv.Itoa(3+len(cmd.ExtraFiles)-1))
	return writer, true, nil
}

func closeParentDeathReader(cmd *exec.Cmd) {
	for _, file := range cmd.ExtraFiles {
		_ = file.Close()
	}
}

func persistentKeeper() bool            { return false }
func precheckStateMounts(Plan) error    { return nil }
func existingKeeper(Plan) (bool, error) { return false, nil }
func RunLauncher(args []string) int {
	if len(args) < 2 || !filepath.IsAbs(args[0]) || !filepath.IsAbs(args[1]) {
		return launcherError(fmt.Errorf("internal containerd launcher requires absolute service and binary paths"))
	}
	fd, err := strconv.Atoi(os.Getenv("RSBX_PARENT_DEATH_FD"))
	if err != nil || fd < 3 {
		return launcherError(fmt.Errorf("invalid parent-death pipe descriptor"))
	}
	parentDeath := os.NewFile(uintptr(fd), "daemon-parent-death")
	if parentDeath == nil {
		return launcherError(fmt.Errorf("open parent-death pipe"))
	}
	syscall.CloseOnExec(fd)
	child := makeCommand(args[1], args[2:], os.Environ())
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return launcherError(fmt.Errorf("start containerd: %w", err))
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	parentGone := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = parentDeath.Read(one[:])
		close(parentGone)
		_ = parentDeath.Close()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	for {
		select {
		case err := <-done:
			if err != nil {
				return launcherError(fmt.Errorf("containerd exited: %w", err))
			}
			return 0
		case <-signals:
			stopContainerd(child, done)
			return 0
		case <-parentGone:
			stopContainerd(child, done)
			return 0
		}
	}
}

func stopContainerd(child *exec.Cmd, done <-chan error) {
	if child.Process == nil {
		return
	}
	_ = child.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "containerd shutdown:", err)
		}
	case <-timer.C:
		if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			_, _ = fmt.Fprintln(os.Stderr, "kill containerd:", err)
		}
		if err := <-done; err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "containerd shutdown:", err)
		}
	}
}

func launcherError(err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "containerd launcher:", err)
	return 1
}

func systemPath() string {
	return "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
}

func libraryPathName() string { return "DYLD_LIBRARY_PATH" }
