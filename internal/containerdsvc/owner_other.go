//go:build !linux && !darwin

package containerdsvc

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return false }
