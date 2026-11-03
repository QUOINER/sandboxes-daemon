//go:build darwin || linux

package service

import (
	"errors"
	"os"
	"syscall"
)

func dockerVolumeSecuritySupported() bool { return true }

func validateDockerVolumeDirectoryInfo(info os.FileInfo) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("must not be accessible by group or others")
	}
	return validateDockerVolumeOwner(info, false)
}

func validateDockerVolumeFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("must have private 0600 permissions")
	}
	return validateDockerVolumeOwner(info, true)
}

func validateDockerVolumeOwner(info os.FileInfo, requireSingleLink bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not verify owner and link count")
	}
	if int(stat.Uid) != os.Getuid() {
		return errors.New("must be owned by the daemon user")
	}
	if requireSingleLink && int64(stat.Nlink) != 1 {
		return errors.New("must have exactly one hard link")
	}
	return nil
}
