//go:build !linux && !darwin

package containerdsvc

import (
	"fmt"
	"os"
	"os/exec"
)

const LauncherArgument = "--internal-containerd-launcher"

func newCommand(string, Plan) (*exec.Cmd, error) {
	return nil, fmt.Errorf("managed containerd runtime is unsupported on this platform")
}

func configureParentDeath(*exec.Cmd) (*os.File, bool, error) { return nil, false, nil }
func closeParentDeathReader(*exec.Cmd)                       {}
func persistentKeeper() bool                                 { return false }
func precheckStateMounts(Plan) error                         { return nil }
func existingKeeper(Plan) (bool, error)                      { return false, nil }
func stopKeeper(Plan) (bool, error)                          { return false, nil }

func RunLauncher([]string) int {
	return launcherError(fmt.Errorf("managed containerd runtime is unsupported on this platform"))
}

func launcherError(err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "containerd launcher:", err)
	return 1
}

func systemPath() string { return "" }

func libraryPathName() string { return "" }
