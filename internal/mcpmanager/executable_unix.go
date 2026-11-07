//go:build darwin || linux

package mcpmanager

import "os"

func isMCPExecutable(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}
