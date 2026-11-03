//go:build !darwin && !linux

package service

import (
	"errors"
	"os"
)

func dockerVolumeSecuritySupported() bool { return false }

func validateDockerVolumeDirectoryInfo(os.FileInfo) error {
	return errors.New("owner and permission validation is unsupported on this platform")
}

func validateDockerVolumeFileInfo(os.FileInfo) error {
	return errors.New("owner and hard-link validation is unsupported on this platform")
}
