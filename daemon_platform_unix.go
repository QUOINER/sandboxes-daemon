//go:build !windows

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var daemonSocketACLMutationPermissions = map[string]struct{}{
	"add_file": {}, "add_subdirectory": {}, "delete": {}, "delete_child": {},
	"write": {}, "append": {}, "writeattr": {}, "writeextattr": {},
	"writeperm": {}, "writesecurity": {}, "chown": {},
}

func validateDaemonSocketACLListing(output string) error {
	headerSeen := false
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if !headerSeen {
			if err := validateDaemonSocketACLHeader(line); err != nil {
				return err
			}
			headerSeen = true
			continue
		}
		if err := validateDaemonSocketACLEntry(line); err != nil {
			return err
		}
	}
	if !headerSeen {
		return errors.New("empty directory listing")
	}
	return nil
}

func validateDaemonSocketACLHeader(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "d") {
		return errors.New("unexpected directory listing header")
	}
	return nil
}

func validateDaemonSocketACLEntry(line string) error {
	prefix, entry, hasEntry := strings.Cut(line, ":")
	if !hasEntry {
		return nil
	}
	if _, err := strconv.Atoi(prefix); err != nil {
		return errors.New("unrecognized ACL entry prefix")
	}
	fields := strings.Fields(entry)
	modeIndex := -1
	for index, field := range fields {
		if field == "deny" {
			return nil
		}
		if field == "allow" {
			modeIndex = index
			break
		}
	}
	if modeIndex == -1 || modeIndex == len(fields)-1 {
		return errors.New("unrecognized or incomplete ACL entry")
	}
	for _, field := range fields[modeIndex+1:] {
		for _, permission := range strings.Split(strings.Trim(field, ","), ",") {
			if _, unsafe := daemonSocketACLMutationPermissions[strings.ToLower(permission)]; unsafe {
				return fmt.Errorf("ACL grants mutation permission %q", permission)
			}
		}
	}
	return nil
}

func prepareDaemonStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect daemon state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("daemon state path must be a directory, not a symlink")
	}
	//nolint:gosec // This is a directory verified by Lstat above; 0700 keeps daemon state private.
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict daemon state directory permissions: %w", err)
	}
	return nil
}

func listenDaemon(ctx context.Context, path string) (net.Listener, error) {
	endpoint, err := prepareDaemonSocketEndpoint(path)
	if err != nil {
		return nil, err
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "unix", endpoint.generationPath)
	if err != nil {
		_ = endpoint.lock.Close()
		return nil, fmt.Errorf("listen on daemon socket generation: %w", err)
	}
	if err := os.Chmod(endpoint.generationPath, 0o600); err != nil {
		_ = listener.Close()
		_ = endpoint.lock.Close()
		return nil, fmt.Errorf("chmod daemon socket: %w", err)
	}
	if err := publishDaemonSocketAlias(endpoint); err != nil {
		_ = listener.Close()
		_ = endpoint.lock.Close()
		return nil, err
	}
	return &managedDaemonListener{Listener: listener, endpoint: endpoint}, nil
}

type daemonSocketEndpoint struct {
	aliasPath      string
	endpointDir    string
	endpointHash   string
	generationPath string
	lock           *os.File
}

type managedDaemonListener struct {
	net.Listener
	endpoint  daemonSocketEndpoint
	closeOnce sync.Once
	closeErr  error
}

func (l *managedDaemonListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = errors.Join(l.Listener.Close(), removeDaemonSocketAlias(l.endpoint), l.endpoint.lock.Close())
	})
	return l.closeErr
}

func removeDaemonSocketAlias(endpoint daemonSocketEndpoint) error {
	info, err := os.Lstat(endpoint.aliasPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect daemon socket alias during close: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 || !daemonPathOwnedByCurrentUser(info) {
		return nil
	}
	target, err := os.Readlink(endpoint.aliasPath)
	if err != nil {
		return fmt.Errorf("read daemon socket alias during close: %w", err)
	}
	if target != endpoint.generationPath {
		return nil
	}
	if err := os.Remove(endpoint.aliasPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove daemon socket alias: %w", err)
	}
	return nil
}

func prepareDaemonSocketEndpoint(path string) (daemonSocketEndpoint, error) {
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return daemonSocketEndpoint{}, fmt.Errorf("resolve daemon socket path: %w", err)
		}
		path = absolute
	}
	if err := validateDaemonSocketAliasPath(path); err != nil {
		return daemonSocketEndpoint{}, err
	}
	if err := validateDaemonSocketParent(filepath.Dir(path)); err != nil {
		return daemonSocketEndpoint{}, err
	}
	hash := sha256.Sum256([]byte(filepath.Clean(path)))
	endpointHash := hex.EncodeToString(hash[:8])
	endpointDir := fmt.Sprintf("/tmp/.rsbx-daemon-%d", os.Getuid())
	if err := ensureDaemonSocketDir(endpointDir); err != nil {
		return daemonSocketEndpoint{}, err
	}
	lockPath := filepath.Join(endpointDir, "l-"+endpointHash+".lock")
	lock, err := lockDaemonSocketEndpoint(lockPath)
	if err != nil {
		return daemonSocketEndpoint{}, err
	}
	endpoint := daemonSocketEndpoint{
		aliasPath: path, endpointDir: endpointDir, endpointHash: endpointHash, lock: lock,
	}
	if err := validateExistingDaemonSocketAlias(endpoint); err != nil {
		_ = lock.Close()
		return daemonSocketEndpoint{}, err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = lock.Close()
		return daemonSocketEndpoint{}, fmt.Errorf("generate daemon socket generation: %w", err)
	}
	endpoint.generationPath = filepath.Join(endpointDir, "g-"+endpointHash+"-"+hex.EncodeToString(nonce[:])+".sock")
	if _, err := os.Lstat(endpoint.generationPath); err == nil || !errors.Is(err, os.ErrNotExist) { // #nosec G703 -- path is generated under a validated 0700 per-user directory
		_ = lock.Close()
		if err == nil {
			return daemonSocketEndpoint{}, errors.New("daemon socket generation path collision")
		}
		return daemonSocketEndpoint{}, fmt.Errorf("inspect daemon socket generation path: %w", err)
	}
	return endpoint, nil
}

func validateDaemonSocketAliasPath(path string) error {
	maxPathBytes := len(syscall.RawSockaddrUnix{}.Path) - 1
	if len(path) > maxPathBytes {
		return fmt.Errorf("daemon socket path is %d bytes; Unix socket pathname limit is %d bytes", len(path), maxPathBytes)
	}
	return nil
}

func validateDaemonSocketParent(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve daemon socket parent directory: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(strings.TrimPrefix(absolute, volume), string(os.PathSeparator))
	components := strings.FieldsFunc(relative, func(char rune) bool { return char == os.PathSeparator })
	if len(components) == 0 {
		components = []string{""}
	}
	for index, component := range components {
		if component != "" {
			current = filepath.Join(current, component)
		}
		info, resolved, err := inspectDaemonSocketParentComponent(current)
		if err != nil {
			return err
		}
		current = resolved
		if index == len(components)-1 {
			return validateDaemonSocketLeafParent(info)
		}
		if err := validateDaemonSocketAncestor(info); err != nil {
			return err
		}
	}
	return errors.New("daemon socket parent path is empty")
}

func inspectDaemonSocketParentComponent(path string) (os.FileInfo, string, error) {
	info, err := os.Lstat(path) // #nosec G703 -- each configured path component is inspected and symlinks are rejected
	if err != nil {
		return nil, "", fmt.Errorf("inspect daemon socket parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 && runtime.GOOS == "darwin" {
		resolved, allowed := allowedDarwinSystemPathAlias(path)
		if allowed {
			path = resolved
			info, err = os.Lstat(path) // #nosec G703 -- canonical target is restricted to the two verified macOS system aliases
			if err != nil {
				return nil, "", fmt.Errorf("inspect canonical macOS socket parent: %w", err)
			}
		}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("daemon socket parent path must contain only real directories")
	}
	if err := validateDaemonSocketACL(path); err != nil {
		return nil, "", err
	}
	return info, path, nil
}

func validateDaemonSocketLeafParent(info os.FileInfo) error {
	if !daemonPathOwnedByCurrentUser(info) || info.Mode().Perm()&0o077 != 0 {
		return errors.New("daemon socket parent must be a private real directory owned by the current user")
	}
	return nil
}

func validateDaemonSocketAncestor(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("inspect daemon socket ancestor owner")
	}
	return validateDaemonSocketAncestorIdentity(stat.Uid, info.Mode())
}

func validateDaemonSocketAncestorIdentity(uid uint32, mode os.FileMode) error {
	if uid != 0 && int(uid) != os.Getuid() {
		return errors.New("daemon socket ancestors must be owned by root or the current user")
	}
	if mode.Perm()&0o022 != 0 && (uid != 0 || mode&os.ModeSticky == 0) {
		return errors.New("writable daemon socket ancestors must be root-owned sticky directories")
	}
	return nil
}

func allowedDarwinSystemPathAlias(path string) (string, bool) {
	want := map[string]string{"/tmp": "/private/tmp", "/var": "/private/var"}[path]
	if want == "" {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return resolved, err == nil && resolved == want
}

func ensureDaemonSocketDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create private daemon socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private daemon socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !daemonPathOwnedByCurrentUser(info) {
		return errors.New("daemon socket directory must be a private real directory owned by the current user")
	}
	return nil
}

func lockDaemonSocketEndpoint(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304,G703 -- path is generated from the fixed-length endpoint hash under the validated private per-user directory; O_NOFOLLOW rejects symlink substitution
	if err != nil {
		return nil, fmt.Errorf("open daemon socket endpoint lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !daemonPathOwnedByCurrentUser(info) {
		_ = file.Close()
		return nil, errors.New("daemon socket endpoint lock must be a private owned regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon socket endpoint is already in use: %w", err)
	}
	return file, nil
}

func validateExistingDaemonSocketAlias(endpoint daemonSocketEndpoint) error {
	info, err := os.Lstat(endpoint.aliasPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect daemon socket endpoint: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 || !daemonPathOwnedByCurrentUser(info) {
		return rejectUnmanagedDaemonSocket(endpoint.aliasPath, info)
	}
	target, err := os.Readlink(endpoint.aliasPath)
	if err != nil || !filepath.IsAbs(target) || filepath.Dir(target) != endpoint.endpointDir || !managedDaemonSocketName(filepath.Base(target), endpoint.endpointHash) {
		return errors.New("daemon socket symlink does not reference a managed generation; refusing to replace it")
	}
	if active, probeErr := daemonSocketAccepting(endpoint.aliasPath); active {
		return errors.New("daemon socket endpoint is already accepting connections")
	} else if probeErr != nil {
		return fmt.Errorf("probe managed daemon socket endpoint: %w", probeErr)
	}
	return nil
}

func rejectUnmanagedDaemonSocket(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("daemon socket path is not a managed symlink; refusing to replace it")
	}
	active, err := daemonSocketAccepting(path)
	if err != nil {
		return fmt.Errorf("probe existing daemon socket: %w", err)
	}
	if active {
		return errors.New("daemon socket path is already accepting connections")
	}
	return errors.New("daemon socket path is not a managed symlink; refusing to replace it")
}

func managedDaemonSocketName(name, endpointHash string) bool {
	if !strings.HasPrefix(name, "g-"+endpointHash+"-") || !strings.HasSuffix(name, ".sock") {
		return false
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(name, "g-"+endpointHash+"-"), ".sock")
	if len(nonce) != 16 {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil && strings.ToLower(nonce) == nonce
}

func daemonSocketAccepting(path string) (bool, error) {
	conn, err := net.DialTimeout("unix", path, 150*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return false, err
}

func publishDaemonSocketAlias(endpoint daemonSocketEndpoint) error {
	info, err := os.Lstat(endpoint.aliasPath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink(endpoint.generationPath, endpoint.aliasPath); err != nil {
			return fmt.Errorf("publish daemon socket alias: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect daemon socket alias before publication: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 || !daemonPathOwnedByCurrentUser(info) {
		return errors.New("daemon socket alias changed to an unmanaged path; refusing replacement")
	}
	target, err := os.Readlink(endpoint.aliasPath)
	if err != nil || filepath.Dir(target) != endpoint.endpointDir || !filepath.IsAbs(target) || !managedDaemonSocketName(filepath.Base(target), endpoint.endpointHash) {
		return errors.New("daemon socket alias changed to an unmanaged target; refusing replacement")
	}
	if active, probeErr := daemonSocketAccepting(endpoint.aliasPath); active {
		return errors.New("daemon socket alias became active before replacement")
	} else if probeErr != nil {
		return fmt.Errorf("recheck daemon socket alias before replacement: %w", probeErr)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate daemon socket alias temp name: %w", err)
	}
	temporary := endpoint.aliasPath + "." + hex.EncodeToString(nonce[:]) + ".tmp"
	if err := os.Symlink(endpoint.generationPath, temporary); err != nil {
		return fmt.Errorf("create temporary daemon socket alias: %w", err)
	}
	if err := os.Rename(temporary, endpoint.aliasPath); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("atomically replace daemon socket alias: %w", err)
	}
	return nil
}

func daemonPathOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

// lockStateDirectory prevents cooperative daemon instances from sharing one
// SQLite store and runtime resources. The lock file is retained after shutdown.
func lockStateDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- state directory is configured by the operator; symlinks are rejected
	if err != nil {
		return nil, fmt.Errorf("open daemon state lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state lock must be a regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state directory is already in use: %w", err)
	}
	return file, nil
}

func ensureSocketAvailable(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect daemon socket: %w", err)
	}
	return fmt.Errorf("daemon socket path already exists")
}
