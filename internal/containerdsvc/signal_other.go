//go:build !linux && !darwin

package containerdsvc

import "os"

func signalShutdown(process *os.Process) error { return process.Signal(os.Interrupt) }
