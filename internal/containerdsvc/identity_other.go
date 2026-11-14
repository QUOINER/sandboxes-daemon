//go:build !linux && !darwin

package containerdsvc

import "os"

func currentUID() int               { return 0 }
func currentGID() int               { return 0 }
func trustedOwner(os.FileInfo) bool { return false }
