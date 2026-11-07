//go:build darwin || linux

package mcpprocess

import (
	"errors"
	"os/exec"
	"syscall"
)

func startTree(cmd *exec.Cmd) (func() error, func() error, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	kill := func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return errors.Join(err, cmd.Process.Kill())
	}
	return kill, func() error { return nil }, nil
}
