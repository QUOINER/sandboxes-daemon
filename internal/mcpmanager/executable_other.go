//go:build !windows && !darwin && !linux

package mcpmanager

import "os"

func isMCPExecutable(string, os.FileInfo) bool { return false }
