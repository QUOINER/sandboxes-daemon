//go:build windows

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const daemonPipePrefix = `\\.\pipe\lickren-sandboxesd-`

func listenDaemon(_ context.Context, address string) (net.Listener, error) {
	pipe, sid, err := daemonPipePath(address)
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)",
	})
}

func ensureSocketAvailable(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect daemon endpoint: %w", err)
	}
	return fmt.Errorf("daemon endpoint path already exists")
}

func daemonPipePath(address string) (string, string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(strings.ToLower(address), strings.ToLower(`\\.\pipe\`)) {
		return address, sid, nil
	}
	identity := sid + "\x00" + strings.ToLower(filepath.Clean(address))
	sum := sha256.Sum256([]byte(identity))
	return daemonPipePrefix + hex.EncodeToString(sum[:16]), sid, nil
}

func currentUserSID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

func prepareDaemonStateDirectory(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	sddl := stateDirectorySDDL(sid)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("create state directory security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	if volume == "" {
		return errors.New("state directory must have an absolute volume path")
	}
	current := volume + string(filepath.Separator)
	remainder := strings.TrimLeft(strings.TrimPrefix(abs, volume), string(filepath.Separator))
	parts := strings.Split(remainder, string(filepath.Separator))
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return errors.New("state directory must not be a volume root")
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		createErr := windows.CreateDirectory(name, &sa)
		if createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create state directory component: %w", createErr)
		}
		final := i == len(parts)-1
		if err := validateDirectoryPath(current, sid, final); err != nil {
			return err
		}
	}
	return nil
}

func validateDirectoryPath(path, sid string, requirePrivate bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open state directory component: %w", err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect state directory component: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("state directory path contains a non-directory or reparse point")
	}
	if !requirePrivate {
		return nil
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect state directory permissions: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner.String() != sid || !hasExpectedDACL(sd, sid) {
		return errors.New("state directory must have a current-user-only security descriptor")
	}
	return nil
}

func stateDirectorySDDL(sid string) string {
	return "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)"
}

func hasExpectedDACL(descriptor *windows.SECURITY_DESCRIPTOR, sid string) bool {
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || defaulted || dacl == nil || dacl.AceCount != 2 {
		return false
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		aceSID, ok := daemonACEPrincipal(dacl, i)
		if !ok {
			return false
		}
		switch aceSID {
		case sid:
			seenUser = true
		case "S-1-5-18":
			seenSystem = true
		default:
			return false
		}
	}
	return seenUser && seenSystem
}

func daemonACEPrincipal(dacl *windows.ACL, index uint32) (string, bool) {
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, index, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != 0 || ace.Mask != 0x001f01ff {
		return "", false
	}
	// #nosec G103 -- SidStart is the SID's first DWORD in the Win32 ACCESS_ALLOWED_ACE layout.
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(), true
}

// lockStateDirectory obtains a nonblocking exclusive byte-range lock on a
// private, non-reparse regular file. The handle is the synchronization object.
func lockStateDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sddl := stateDirectorySDDL(sid)
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("create daemon lock security descriptor: %w", err)
	}
	securityAttributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode daemon lock path: %w", err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &securityAttributes,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open daemon state lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if err := validateLockFile(handle, sid); err != nil {
		_ = file.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state directory is already in use: %w", err)
	}
	return file, nil
}

func validateLockFile(handle windows.Handle, sid string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect daemon state lock: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
		return errors.New("daemon state lock must be a non-reparse regular file with one link")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect daemon state lock permissions: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner.String() != sid || !hasExpectedDACL(sd, sid) {
		return errors.New("daemon state lock must have the current-user-only security descriptor")
	}
	return nil
}
