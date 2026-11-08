//go:build !windows

package policysync

import (
	"errors"
	"os"
)

func checkPrivateFileMode(mode os.FileMode) error {
	if mode.Perm() != 0o600 {
		return errors.New("must have private 0600 permissions")
	}
	return nil
}
