//go:build darwin || linux

package servicesecrets

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func testPrintCommand() string {
	return "printf ' synthetic-value \\n'"
}

func testFailCommand() string {
	return "printf 'synthetic-provider-error' >&2; exit 7"
}

func testWaitCommand() string {
	return "sleep 30"
}

func TestCommandSourceRejectsOutputOverLimit(t *testing.T) {
	_, err := resolveSource(context.Background(), Source{Command: "printf '%8193s' x"})
	if err == nil || !strings.Contains(err.Error(), "output exceeded its limit") {
		t.Fatalf("resolveSource error = %v, want bounded-output rejection", err)
	}
}

func TestCommandSourceUsesFreshWorkingDirectoryAndFilteredEnvironment(t *testing.T) {
	const privateEnv = "RHEIC_SECRET_RESOLVER_TEST_PRIVATE"
	t.Setenv(privateEnv, "must-not-be-inherited")
	value, err := resolveSource(context.Background(), Source{Command: "printf '%s|%s' \"${" + privateEnv + "-unset}\" \"$PWD\""})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	parts := strings.SplitN(string(value), "|", 2)
	if len(parts) != 2 || parts[0] != "unset" {
		t.Fatalf("resolver output = %q, want filtered environment and cwd", value)
	}
	if parts[1] == "" || parts[1] == "." || parts[1] == os.Getenv("PWD") {
		t.Fatalf("resolver cwd = %q, want a fresh temporary directory", parts[1])
	}
	if _, err := os.Stat(parts[1]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver temporary directory still exists after completion: stat error = %v", err)
	}
}
