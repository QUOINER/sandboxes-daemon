//go:build windows

package mcpmanager

import (
	"os"
	"path/filepath"
	"strings"
)

func isMCPExecutable(path string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".exe" || extension == ".com"
}
