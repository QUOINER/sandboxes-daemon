package containerdsvc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	Namespace            = "rheic"
	containerdConfigFlag = "--config"
)

// Config identifies the exact runtime artifacts owned by the daemon.
type Config struct {
	Binary        string
	CTR           string
	RuntimeDir    string
	RuntimeAssets string
	StateDir      string
}

// Plan contains the resolved commands and runtime paths for one instance.
type Plan struct {
	Binary        string
	CTR           string
	Shim          string
	RuntimeAssets string
	ServiceDir    string
	Root          string
	State         string
	SocketDir     string
	Socket        string
	ConfigFile    string
	LogFile       string
	KeeperMarker  string
	Args          []string
	Environment   []string
}

func BuildPlan(cfg Config) (Plan, error) {
	if err := validateInputPaths(cfg); err != nil {
		return Plan{}, err
	}
	if err := validateExecutables(cfg); err != nil {
		return Plan{}, err
	}
	if err := validateRuntimeAssets(cfg.RuntimeAssets); err != nil {
		return Plan{}, err
	}
	if err := validateStateDir(cfg.StateDir); err != nil {
		return Plan{}, err
	}
	if err := validateRuntimeDir(cfg.RuntimeDir); err != nil {
		return Plan{}, err
	}
	serviceDir := filepath.Join(cfg.StateDir, "containerd")
	root := filepath.Join(serviceDir, "root")
	state := filepath.Join(serviceDir, "state")
	socketDir, socket := managedSocketPaths(serviceDir)
	plan := Plan{
		Binary: cfg.Binary, CTR: cfg.CTR,
		Shim:          filepath.Join(cfg.RuntimeDir, "containerd-shim-nerdbox-v1"),
		RuntimeAssets: cfg.RuntimeAssets, ServiceDir: serviceDir, Root: root, State: state, SocketDir: socketDir,
		Socket: socket, ConfigFile: filepath.Join(serviceDir, "config.toml"),
		LogFile:      filepath.Join(serviceDir, "containerd.log"),
		KeeperMarker: filepath.Join(serviceDir, "keeper.pid"),
		Args:         []string{containerdConfigFlag, filepath.Join(serviceDir, "config.toml"), "--log-level", "info"},
		Environment:  environment(cfg.RuntimeDir, cfg.RuntimeAssets, serviceDir),
	}
	return plan, nil
}

func validateInputPaths(cfg Config) error {
	for name, path := range map[string]string{
		"containerd binary": cfg.Binary,
		"ctr binary":        cfg.CTR,
		"runtime directory": cfg.RuntimeDir,
		"runtime assets":    cfg.RuntimeAssets,
		"state directory":   cfg.StateDir,
	} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
		if err := rejectSymlinkPath(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateExecutables(cfg Config) error {
	for name, path := range map[string]string{
		"containerd binary": cfg.Binary,
		"ctr binary":        cfg.CTR,
		"runtime shim":      filepath.Join(cfg.RuntimeDir, "containerd-shim-nerdbox-v1"),
	} {
		if err := checkExecutable(name, path); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeAssets(path string) error {
	assetInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat runtime assets: %w", err)
	}
	if !assetInfo.IsDir() || assetInfo.Mode()&os.ModeSymlink != 0 || assetInfo.Mode().Perm()&0o222 != 0 || !trustedOwner(assetInfo) {
		return fmt.Errorf("runtime assets path must be root- or current-user-owned and non-writable")
	}
	return nil
}

func validateStateDir(path string) error {
	stateInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat state directory: %w", err)
	}
	if !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state path is not a real directory")
	}
	if !ownedByCurrentUser(stateInfo) {
		return fmt.Errorf("state directory is not owned by the daemon user")
	}
	if stateInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory permissions must exclude group and other access")
	}
	return nil
}

func validateRuntimeDir(path string) error {
	runtimeDirInfo, err := os.Lstat(path)
	if err != nil || !runtimeDirInfo.IsDir() || runtimeDirInfo.Mode()&os.ModeSymlink != 0 || runtimeDirInfo.Mode().Perm()&0o222 != 0 || !trustedOwner(runtimeDirInfo) {
		return fmt.Errorf("runtime directory must be root- or current-user-owned and non-writable")
	}
	return nil
}

func (p Plan) TOML(uid, gid int) string {
	return fmt.Sprintf("version = 4\nroot = %q\nstate = %q\n"+
		"[plugins.\"io.containerd.server.v1.grpc\"]\naddress = %q\nuid = %d\ngid = %d\n"+
		"[plugins.\"io.containerd.server.v1.ttrpc\"]\naddress = %q\nuid = %d\ngid = %d\n",
		p.Root, p.State, p.Socket, uid, gid, p.Socket+".ttrpc", uid, gid)
}

func environment(runtimeDir, assets, home string) []string {
	path := runtimeDir + string(os.PathListSeparator) + systemPath()
	env := []string{"PATH=" + path, "HOME=" + home, "LIBKRUN_PATH=" + assets}
	if libraryPathName() != "" {
		env = append(env, libraryPathName()+"="+assets)
	}
	return env
}

func checkExecutable(name, path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- BuildPlan rejects relative/symlink paths before checking executable ownership and mode.
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o222 != 0 || !trustedOwner(info) {
		return fmt.Errorf("%s must be root- or current-user-owned and non-writable", name)
	}
	return nil
}

func writeConfig(plan Plan, uid, gid int) (result error) {
	if err := ensurePrivateDir(plan.ServiceDir); err != nil {
		return fmt.Errorf("containerd service directory: %w", err)
	}
	for _, path := range []string{plan.Root, plan.State} {
		if err := ensurePrivateDir(path); err != nil {
			return fmt.Errorf("containerd directory %s: %w", path, err)
		}
	}
	return verifyOrCreateConfig(plan, uid, gid)
}

func ensurePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return fmt.Errorf("must be a private real directory owned by the daemon user")
	}
	return nil
}

func verifyConfig(plan Plan, uid, gid int) (result error) {
	existing, err := os.Lstat(plan.ConfigFile)
	if err != nil {
		return fmt.Errorf("inspect existing containerd config: %w", err)
	}
	if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 || existing.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(existing) {
		return fmt.Errorf("existing containerd config is not a private regular file")
	}
	root, err := os.OpenRoot(plan.ServiceDir)
	if err != nil {
		return fmt.Errorf("open containerd service directory: %w", err)
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	file, err := root.Open(filepath.Base(plan.ConfigFile))
	if err != nil {
		return fmt.Errorf("open existing containerd config: %w", err)
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	contents, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read existing containerd config: %w", err)
	}
	if string(contents) != plan.TOML(uid, gid) {
		return fmt.Errorf("existing containerd config does not match managed settings")
	}
	return nil
}

func verifyOrCreateConfig(plan Plan, uid, gid int) error {
	expected := plan.TOML(uid, gid)
	existing, err := os.Lstat(plan.ConfigFile)
	if err == nil {
		return verifyExistingConfig(plan, existing, expected)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("check containerd config: %w", err)
	}
	return createConfig(plan, expected)
}

func verifyExistingConfig(plan Plan, info os.FileInfo, expected string) (result error) {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return fmt.Errorf("existing containerd config is not a private regular file")
	}
	root, err := os.OpenRoot(plan.ServiceDir)
	if err != nil {
		return fmt.Errorf("open containerd service directory: %w", err)
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	file, err := root.Open(filepath.Base(plan.ConfigFile))
	if err != nil {
		return fmt.Errorf("open existing containerd config: %w", err)
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	contents, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("read existing containerd config: %w", err)
	}
	if string(contents) != expected {
		return fmt.Errorf("existing containerd config does not match managed settings")
	}
	return nil
}

func createConfig(plan Plan, expected string) (result error) {
	config, err := os.CreateTemp(plan.ServiceDir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create containerd config: %w", err)
	}
	defer func() {
		if err := os.Remove(config.Name()); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("remove temporary containerd config: %w", err))
		}
	}()
	if err := config.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("protect containerd config: %w", err), config.Close())
	}
	if _, err := config.WriteString(expected); err != nil {
		return errors.Join(fmt.Errorf("write containerd config: %w", err), config.Close())
	}
	if err := config.Close(); err != nil {
		return fmt.Errorf("close containerd config: %w", err)
	}
	if err := os.Rename(config.Name(), plan.ConfigFile); err != nil {
		return fmt.Errorf("install containerd config: %w", err)
	}
	return nil
}

func validatePlanEnvironment(plan Plan) error {
	for _, env := range plan.Environment {
		if strings.HasPrefix(env, "PATH=") && strings.Contains(env, "=:") {
			return fmt.Errorf("runtime PATH contains an empty entry")
		}
	}
	return nil
}

func rejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(rest, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path contains symlink component %s", current)
		}
	}
	return nil
}
