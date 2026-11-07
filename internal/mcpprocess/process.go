// Package mcpprocess starts bounded host MCP stdio processes and owns their
// complete process trees for the lifetime of one protocol call.
package mcpprocess

import (
	"errors"
	"io"
	"os/exec"
	"sync"
)

// Process owns one started command and its pipes. Call Close to terminate and
// reap it; MCP servers are never detached from the daemon.
type Process struct {
	Command  *exec.Cmd
	Stdin    io.WriteCloser
	Stdout   io.ReadCloser
	kill     func() error
	finish   func() error
	once     sync.Once
	closeErr error
}

// Start starts an executable directly without a shell and configures platform
// process-tree containment before execution.
func Start(command string, args []string, dir string, env []string) (*Process, error) {
	// #nosec G204 -- the daemon validates the absolute executable and rechecks its approved digest; no shell is involved.
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), env...)
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	kill, finish, err := startTree(cmd)
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	return &Process{Command: cmd, Stdin: stdin, Stdout: stdout, kill: kill, finish: finish}, nil
}

// StartProcess starts a configured command using OS process-tree containment.
func StartProcess(cmd *exec.Cmd) (*Process, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	kill, finish, err := startTree(cmd)
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	return &Process{Command: cmd, Stdin: stdin, Stdout: stdout, kill: kill, finish: finish}, nil
}

// Close kills and reaps the process tree. It is safe to call more than once.
func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		_ = p.Stdin.Close()
		_ = p.Stdout.Close()
		killErr := p.kill()
		waitErr := p.Command.Wait()
		finishErr := p.finish()
		var exitErr *exec.ExitError
		if errors.Is(waitErr, exec.ErrWaitDelay) || errors.As(waitErr, &exitErr) {
			waitErr = nil
		}
		p.closeErr = errors.Join(killErr, waitErr, finishErr)
	})
	return p.closeErr
}
