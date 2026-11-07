//go:build !windows && !darwin && !linux

package mcpprocess

import (
	"errors"
	"os/exec"
)

func startTree(*exec.Cmd) (func() error, func() error, error) {
	return nil, nil, errors.New("MCP process containment is unsupported on this platform")
}
