//go:build linux

package containerdsvc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

const LauncherArgument = "--internal-containerd-launcher"

func newCommand(launcher string, plan Plan) (*exec.Cmd, error) {
	if !filepathIsAbs(launcher) {
		return nil, fmt.Errorf("daemon launcher path must be absolute")
	}
	args := append([]string{LauncherArgument, plan.ServiceDir, plan.Binary}, plan.Args...)
	cmd := makeCommand(launcher, args, append([]string(nil), plan.Environment...))
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Setsid: true}
	return cmd, nil
}

func configureParentDeath(*exec.Cmd) (*os.File, error) { return nil, nil }
func closeParentDeathReader(*exec.Cmd)                 {}
func persistentKeeper() bool                           { return true }
func stopKeeper(plan Plan) (bool, error) {
	fields, err := keeperMarkerFields(plan.KeeperMarker)
	if err != nil {
		return false, err
	}
	pid, _ := strconv.Atoi(fields[0])
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false, fmt.Errorf("open keeper process handle: %w", err)
	}
	defer unix.Close(fd)
	reused, err := existingKeeper(plan)
	if err != nil || !reused {
		if err == nil {
			err = fmt.Errorf("keeper disappeared before shutdown")
		}
		return false, err
	}
	if err := unix.PidfdSendSignal(fd, syscall.SIGTERM, nil, 0); err != nil {
		return false, fmt.Errorf("signal empty namespace keeper: %w", err)
	}
	deadline := time.Now().Add(shutdownTimeout + time.Second)
	for time.Now().Before(deadline) {
		alive, err := existingKeeper(plan)
		if err != nil {
			return false, err
		}
		if !alive {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			remaining := int(time.Until(deadline).Milliseconds())
			if remaining < 0 {
				remaining = 0
			}
			if _, err := unix.Poll(fds, remaining); err != nil {
				return false, err
			}
			if fds[0].Revents&unix.POLLIN != 0 {
				return true, nil
			}
			return false, fmt.Errorf("keeper marker cleared before process exit")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, fmt.Errorf("empty namespace keeper did not stop")
}

func precheckStateMounts(plan Plan) error {
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(plan.ServiceDir))
	if err != nil {
		return fmt.Errorf("precheck managed containerd mount tree: %w", err)
	}
	if len(mounts) != 0 {
		return fmt.Errorf("managed containerd state already has mountpoint %q (%s)", mounts[0].Mountpoint, mounts[0].FSType)
	}
	return nil
}

// RunLauncher is called only by the daemon's internal launcher mode. It exits
// on every setup error so no Go code can continue in a partially changed ns.
func RunLauncher(args []string) int {
	if len(args) < 3 || !filepathIsAbs(args[0]) || !filepathIsAbs(args[1]) {
		return launcherError(fmt.Errorf("internal containerd launcher requires absolute service and binary paths"))
	}
	if args[2] == "--config" && (len(args) < 4 || !filepathIsAbs(args[3])) {
		return launcherError(fmt.Errorf("containerd config path must be absolute"))
	}
	runtime.LockOSThread()
	if err := makeRootPrivate(); err != nil {
		return launcherError(fmt.Errorf("make mount namespace recursively private: %w", err))
	}
	if err := checkNoMountsUnder(args[0]); err != nil {
		return launcherError(err)
	}
	plan := keeperPlan(args[0])
	if err := writeConfig(plan, currentUID(), currentGID()); err != nil {
		return launcherError(fmt.Errorf("prepare containerd state in private namespace: %w", err))
	}
	log, err := os.OpenFile(plan.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return launcherError(fmt.Errorf("open containerd log: %w", err))
	}
	if err := writeKeeperMarker(args[0]); err != nil {
		return launcherError(err)
	}
	backoff := 100 * time.Millisecond
	restartWindow := time.Now()
	restarts := 0
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	for {
		if err := removeStaleSocket(filepath.Join(args[0], "containerd.sock")); err != nil {
			return launcherError(err)
		}
		child := makeCommand(args[1], args[2:], os.Environ())
		child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		child.Stdout, child.Stderr = log, log
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "containerd keeper: start failed: %v\n", err)
			if !keeperRestartAllowed(&restartWindow, &restarts, time.Now()) {
				return launcherError(fmt.Errorf("containerd failed to start repeatedly; keeper is stopping in place"))
			}
			timer := time.NewTimer(backoff)
			select {
			case <-signals:
				timer.Stop()
				if err := os.Remove(plan.KeeperMarker); err != nil {
					return launcherError(fmt.Errorf("remove keeper marker: %w", err))
				}
				return 0
			case <-timer.C:
			}
		} else {
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			select {
			case <-done:
				if !keeperRestartAllowed(&restartWindow, &restarts, time.Now()) {
					return launcherError(fmt.Errorf("containerd exited repeatedly; keeper is stopping in place"))
				}
			case <-signals:
				_ = child.Process.Signal(syscall.SIGTERM)
				timer := time.NewTimer(10 * time.Second)
				select {
				case <-done:
					timer.Stop()
				case <-timer.C:
					_ = child.Process.Kill()
					<-done
				}
				if err := os.Remove(plan.KeeperMarker); err != nil {
					return launcherError(fmt.Errorf("remove keeper marker: %w", err))
				}
				return 0
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-signals:
			timer.Stop()
			if err := os.Remove(plan.KeeperMarker); err != nil {
				return launcherError(fmt.Errorf("remove keeper marker: %w", err))
			}
			return 0
		case <-timer.C:
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func makeRootPrivate() error {
	return unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
}

func keeperRestartAllowed(window *time.Time, failures *int, now time.Time) bool {
	if now.Sub(*window) > time.Minute {
		*window = now
		*failures = 0
	}
	*failures++
	return *failures <= 5
}

func keeperPlan(serviceDir string) Plan {
	return Plan{
		ServiceDir:   serviceDir,
		Root:         filepath.Join(serviceDir, "root"),
		State:        filepath.Join(serviceDir, "state"),
		Socket:       filepath.Join(serviceDir, "containerd.sock"),
		ConfigFile:   filepath.Join(serviceDir, "config.toml"),
		LogFile:      filepath.Join(serviceDir, "containerd.log"),
		KeeperMarker: filepath.Join(serviceDir, "keeper.pid"),
	}
}

func writeKeeperMarker(serviceDir string) error {
	var ns syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/mnt", &ns); err != nil {
		return fmt.Errorf("inspect keeper mount namespace: %w", err)
	}
	start, err := processStartTime(os.Getpid())
	if err != nil {
		return fmt.Errorf("inspect keeper process identity: %w", err)
	}
	path := filepath.Join(serviceDir, "keeper.pid")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create keeper marker: %w", err)
	}
	bootID, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("read Linux boot identity: %w", bootErr)
	}
	_, writeErr := fmt.Fprintf(f, "%d %d %d %s\n", os.Getpid(), ns.Ino, start, strings.TrimSpace(string(bootID)))
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func existingKeeper(plan Plan) (bool, error) {
	info, err := os.Lstat(plan.KeeperMarker)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect keeper marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return false, fmt.Errorf("keeper marker is not a private owned regular file")
	}
	fields, err := keeperMarkerFields(plan.KeeperMarker)
	if err != nil {
		return false, err
	}
	if len(fields) != 4 {
		return false, fmt.Errorf("keeper marker is malformed; refusing a new mount namespace")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return false, fmt.Errorf("read Linux boot identity: %w", err)
	}
	if fields[3] != strings.TrimSpace(string(bootID)) {
		if err := os.Remove(plan.KeeperMarker); err != nil {
			return false, fmt.Errorf("remove stale prior-boot keeper marker: %w", err)
		}
		return false, nil
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 1 {
		return false, fmt.Errorf("keeper marker has an invalid PID; refusing a new mount namespace")
	}
	wantInode, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return false, fmt.Errorf("keeper marker has an invalid namespace identity")
	}
	wantStart, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return false, fmt.Errorf("keeper marker has an invalid process identity")
	}
	start, err := processStartTime(pid)
	if err != nil || start != wantStart {
		return false, fmt.Errorf("managed namespace keeper process identity changed; refusing a fresh namespace")
	}
	var ns syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &ns); err != nil {
		return false, fmt.Errorf("managed namespace keeper is absent; refusing a fresh namespace: %w", err)
	}
	if ns.Ino != wantInode {
		return false, fmt.Errorf("managed namespace keeper identity changed; refusing a fresh namespace")
	}
	return true, nil
}

func keeperMarkerFields(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keeper marker: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 4 {
		return nil, fmt.Errorf("keeper marker is malformed; refusing a new mount namespace")
	}
	return fields, nil
}

func processStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("truncated process stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) {
		return fmt.Errorf("containerd socket path has unexpected type or owner; refusing to modify it")
	}
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("containerd socket is accepting connections; refusing to replace it")
	}
	return fmt.Errorf("containerd socket path remains after child exit; refusing raceable unlink: %w", dialErr)
}

func checkNoMountsUnder(path string) error {
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(path))
	if err != nil {
		return fmt.Errorf("inspect managed containerd mount tree: %w", err)
	}
	if len(mounts) != 0 {
		return fmt.Errorf("managed containerd state has unexpected mountpoint %q (%s)", mounts[0].Mountpoint, mounts[0].FSType)
	}
	return nil
}

func launcherError(err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "containerd namespace launcher:", err)
	return 1
}

func filepathIsAbs(path string) bool { return len(path) > 0 && path[0] == '/' }

func systemPath() string { return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" }

func libraryPathName() string { return "LD_LIBRARY_PATH" }
