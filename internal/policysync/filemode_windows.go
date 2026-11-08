//go:build windows

package policysync

import "os"

func checkPrivateFileMode(os.FileMode) error {
	return nil
}
