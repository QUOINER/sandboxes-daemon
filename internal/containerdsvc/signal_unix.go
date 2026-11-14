//go:build linux || darwin

package containerdsvc

import (
	"os"
	"syscall"
)

func signalShutdown(process *os.Process) error {
	return process.Signal(syscall.SIGTERM)
}
