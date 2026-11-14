//go:build darwin

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func validateDaemonSocketACL(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", path) // #nosec G204,G702 -- fixed absolute executable; absolute path argument cannot select an option or be interpreted by a shell
	for _, item := range cmd.Environ() {
		if !strings.HasPrefix(item, "LC_ALL=") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C")
	output, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("timed out inspecting daemon socket path ACL")
		}
		return fmt.Errorf("inspect daemon socket path ACL: %w", err)
	}
	if err := validateDaemonSocketACLListing(string(output)); err != nil {
		return fmt.Errorf("daemon socket path ACL is not safe: %w", err)
	}
	return nil
}
