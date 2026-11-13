//go:build linux || darwin

package containerdsvc

import (
	"os"
	"syscall"
)

func currentUID() int { return os.Getuid() }
func currentGID() int { return os.Getgid() }

func trustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(stat.Uid) == 0 || int(stat.Uid) == currentUID())
}
