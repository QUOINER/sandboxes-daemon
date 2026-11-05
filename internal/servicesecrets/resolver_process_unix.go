//go:build darwin || linux

package servicesecrets

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

func hostShellCommand(ctx context.Context, command string) *exec.Cmd {
	//nolint:gosec // Explicit --command source is user-approved host shell text; process execution stays bounded and on the host.
	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
}

func startResolverProcess(command *exec.Cmd) (func() error, func() error, error) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	terminate := func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return terminate, terminate, nil
}
