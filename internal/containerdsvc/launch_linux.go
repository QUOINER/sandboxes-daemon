//go:build linux

package containerdsvc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

func configureParentDeath(*exec.Cmd) (*os.File, bool, error) { return nil, false, nil }
func closeParentDeathReader(*exec.Cmd)                       {}
func persistentKeeper() bool                                 { return true }

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
	plan, commandArgs, err := parseLauncherArgs(args)
	if err != nil {
		return launcherError(err)
	}
	runtime.LockOSThread()
	plan, log, err := prepareKeeper(plan)
	if err != nil {
		return launcherError(err)
	}
	defer func() { _ = log.Close() }()
	return superviseContainerd(plan, commandArgs, log)
}

func parseLauncherArgs(args []string) (Plan, []string, error) {
	if len(args) < 3 || !filepathIsAbs(args[0]) || !filepathIsAbs(args[1]) {
		return Plan{}, nil, fmt.Errorf("internal containerd launcher requires absolute service and binary paths")
	}
	if args[2] == containerdConfigFlag && (len(args) < 4 || !filepathIsAbs(args[3])) {
		return Plan{}, nil, fmt.Errorf("containerd config path must be absolute")
	}
	plan := keeperPlan(args[0])
	plan.Binary = args[1]
	return plan, append([]string(nil), args[1:]...), nil
}

func prepareKeeper(plan Plan) (Plan, *os.File, error) {
	if err := makeRootPrivate(); err != nil {
		return Plan{}, nil, fmt.Errorf("make mount namespace recursively private: %w", err)
	}
	if err := checkNoMountsUnder(plan.ServiceDir); err != nil {
		return Plan{}, nil, err
	}
	if err := writeConfig(plan, currentUID(), currentGID()); err != nil {
		return Plan{}, nil, fmt.Errorf("prepare containerd state in private namespace: %w", err)
	}
	log, err := os.OpenFile(plan.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path is a fixed child of validated private state.
	if err != nil {
		return Plan{}, nil, fmt.Errorf("open containerd log: %w", err)
	}
	if err := writeKeeperMarker(plan.ServiceDir); err != nil {
		_ = log.Close()
		return Plan{}, nil, err
	}
	return plan, log, nil
}

func superviseContainerd(plan Plan, commandArgs []string, log *os.File) int {
	backoff := 100 * time.Millisecond
	restartWindow := time.Now()
	restarts := 0
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	for {
		generationArgs, err := prepareContainerdGeneration(plan, commandArgs)
		if err != nil {
			return launcherError(err)
		}
		child := makeCommand(plan.Binary, generationArgs[1:], os.Environ())
		child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		child.Stdout, child.Stderr = log, log
		if err := child.Start(); err != nil {
			stop, next, err := handleContainerdStartFailure(err, &restartWindow, &restarts, backoff, signals, plan.KeeperMarker)
			backoff = next
			if err != nil {
				return launcherError(err)
			}
			if stop {
				return 0
			}
			continue
		}
		stop, next, err := handleContainerdExit(child, &restartWindow, &restarts, backoff, signals, plan.KeeperMarker)
		if err != nil {
			return launcherError(err)
		}
		if stop {
			return 0
		}
		backoff = next
	}
}

// prepareContainerdGeneration gives each child a never-before-used socket path.
// Containerd v2.4.2 unlinks its configured socket before binding; the keeper
// must therefore never restart against the prior child's path. ctr clients use
// plan.Socket, an atomically replaced symlink to the active generation.
func prepareContainerdGeneration(plan Plan, commandArgs []string) ([]string, error) {
	for attempt := 0; attempt < 5; attempt++ {
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("generate containerd socket generation: %w", err)
		}
		name := "c-" + hex.EncodeToString(nonce[:])
		generation := plan
		generation.Socket = filepath.Join(plan.ServiceDir, name+".sock")
		generation.ConfigFile = filepath.Join(plan.ServiceDir, name+".toml")
		if pathExists(generation.Socket) || pathExists(generation.ConfigFile) {
			continue
		}
		if err := writeConfig(generation, currentUID(), currentGID()); err != nil {
			return nil, fmt.Errorf("write containerd generation config: %w", err)
		}
		args, err := replaceConfigArgument(commandArgs, generation.ConfigFile)
		if err != nil {
			return nil, err
		}
		if err := publishSocketAlias(plan.Socket, generation.Socket, plan.ServiceDir, name); err != nil {
			return nil, err
		}
		return args, nil
	}
	return nil, fmt.Errorf("could not allocate a unique containerd socket generation")
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !os.IsNotExist(err)
}

func replaceConfigArgument(args []string, config string) ([]string, error) {
	updated := append([]string(nil), args...)
	for i := 1; i+1 < len(updated); i++ {
		if updated[i] == containerdConfigFlag {
			updated[i+1] = config
			return updated, nil
		}
	}
	return nil, fmt.Errorf("managed containerd command has no --config argument")
}

func publishSocketAlias(alias, socket, serviceDir, generation string) error {
	if filepath.Dir(alias) != serviceDir || filepath.Dir(socket) != serviceDir {
		return fmt.Errorf("containerd socket alias escaped the private service directory")
	}
	info, err := os.Lstat(alias)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 || !ownedByCurrentUser(info) {
			return fmt.Errorf("containerd socket alias has unexpected type or owner; refusing replacement")
		}
		oldTarget, readErr := os.Readlink(alias)
		if readErr != nil || filepath.Base(oldTarget) != oldTarget || !strings.HasPrefix(oldTarget, "c-") || !strings.HasSuffix(oldTarget, ".sock") {
			return fmt.Errorf("containerd socket alias target is not a managed generation; refusing replacement")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect containerd socket alias: %w", err)
	}
	temporary := filepath.Join(serviceDir, ".socket-alias-"+generation)
	if err := os.Symlink(filepath.Base(socket), temporary); err != nil {
		return fmt.Errorf("create containerd socket alias: %w", err)
	}
	if err := os.Rename(temporary, alias); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish containerd socket alias: %w", err)
	}
	return nil
}

func handleContainerdExit(child *exec.Cmd, window *time.Time, restarts *int, backoff time.Duration, signals <-chan os.Signal, marker string) (bool, time.Duration, error) {
	stop, err := waitContainerd(child, signals, marker)
	if err != nil || stop {
		return stop, backoff, err
	}
	if !keeperRestartAllowed(window, restarts, time.Now()) {
		return false, backoff, fmt.Errorf("containerd exited repeatedly; keeper is stopping in place")
	}
	stop, err = waitRestart(backoff, signals, marker)
	if err != nil {
		return false, backoff, err
	}
	return stop, nextBackoff(backoff), nil
}

func handleContainerdStartFailure(startErr error, window *time.Time, restarts *int, backoff time.Duration, signals <-chan os.Signal, marker string) (bool, time.Duration, error) {
	_, _ = fmt.Fprintf(os.Stderr, "containerd keeper: start failed: %v\n", startErr)
	if !keeperRestartAllowed(window, restarts, time.Now()) {
		return false, backoff, fmt.Errorf("containerd failed to start repeatedly; keeper is stopping in place")
	}
	stop, err := waitRestart(backoff, signals, marker)
	if err != nil {
		return false, backoff, err
	}
	return stop, nextBackoff(backoff), nil
}

func waitContainerd(child *exec.Cmd, signals <-chan os.Signal, marker string) (bool, error) {
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case waitErr := <-done:
		if waitErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "containerd keeper: child exited: %v\n", waitErr)
		}
		return false, nil
	case <-signals:
		_ = child.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(10 * time.Second)
		select {
		case waitErr := <-done:
			timer.Stop()
			if waitErr != nil && !processExitedBySignal(waitErr) {
				return true, errors.Join(fmt.Errorf("containerd shutdown returned an unexpected error: %w", waitErr), removeKeeperMarker(marker))
			}
		case <-timer.C:
			_ = child.Process.Kill()
			waitErr := <-done
			if waitErr != nil && !processExitedBySignal(waitErr) {
				return true, errors.Join(fmt.Errorf("containerd kill returned an unexpected error: %w", waitErr), removeKeeperMarker(marker))
			}
		}
		return true, removeKeeperMarker(marker)
	}
}

func processExitedBySignal(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled()
}

func waitRestart(backoff time.Duration, signals <-chan os.Signal, marker string) (bool, error) {
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-signals:
		return true, removeKeeperMarker(marker)
	case <-timer.C:
		return false, nil
	}
}

func removeKeeperMarker(path string) error {
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove keeper marker: %w", err)
	}
	return nil
}

func nextBackoff(backoff time.Duration) time.Duration {
	if backoff < 5*time.Second {
		return backoff * 2
	}
	return backoff
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed marker basename under validated private service state.
	if err != nil {
		return fmt.Errorf("create keeper marker: %w", err)
	}
	bootID, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil {
		_ = f.Close()
		_ = os.Remove(path) // #nosec G703 -- removes only the just-created marker at its fixed private-state path.
		return fmt.Errorf("read Linux boot identity: %w", bootErr)
	}
	_, writeErr := fmt.Fprintf(f, "%d %d %d %s\n", os.Getpid(), ns.Ino, start, strings.TrimSpace(string(bootID)))
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func existingKeeper(plan Plan) (bool, error) {
	info, err := os.Lstat(plan.KeeperMarker) // #nosec G703 -- marker path is a fixed child of the validated private service state.
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
	return verifyKeeperIdentity(fields, plan.KeeperMarker)
}

func verifyKeeperIdentity(fields []string, markerPath string) (bool, error) {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return false, fmt.Errorf("read Linux boot identity: %w", err)
	}
	if fields[3] != strings.TrimSpace(string(bootID)) {
		if err := os.Remove(markerPath); err != nil {
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
	data, err := os.ReadFile(path) // #nosec G304 -- caller supplies the fixed private keeper marker path.
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

func filepathIsAbs(path string) bool { return path != "" && path[0] == '/' }

func systemPath() string { return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" }

func libraryPathName() string { return "LD_LIBRARY_PATH" }
