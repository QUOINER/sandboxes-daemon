//go:build unix

package containerdsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyBinaryVersionSleepingBinaryTimesOut(t *testing.T) {
	binary := writeVersionTestScript(t, "exec sleep 30")

	started := time.Now()
	err := verifyBinaryVersionWithTimeout(binary, "containerd", versionTestEnvironment(), 250*time.Millisecond)
	if err == nil {
		t.Fatal("verifyBinaryVersionWithTimeout() error = nil, want timeout")
	}
	if !errors.Is(err, ErrBinaryVersionTimeout) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error = %v, want ErrBinaryVersionTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error = %v, want wrapped context deadline", err)
	}
	var checkErr *VersionCheckError
	if !errors.As(err, &checkErr) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error type = %T, want *VersionCheckError", err)
	}
	if checkErr.Binary != "containerd" {
		t.Fatalf("version check binary = %q, want containerd", checkErr.Binary)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("timed out version check took %s, want bounded at 5s", elapsed)
	}
}

func TestVerifyBinaryVersionForkedWriterTimesOut(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "child.pid")
	binary := writeVersionTestScript(t, "sleep 30 & echo $! > "+pidPath+"\nexit 0")
	t.Cleanup(func() {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return
		}
		process, err := os.FindProcess(pid)
		if err == nil {
			_ = process.Kill()
		}
	})

	started := time.Now()
	err := verifyBinaryVersionWithTimeout(binary, "containerd", versionTestEnvironment(), 250*time.Millisecond)
	if !errors.Is(err, ErrBinaryVersionTimeout) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error = %v, want ErrBinaryVersionTimeout", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("forked-writer version check took %s, want bounded at 5s", elapsed)
	}
}

func TestVerifyBinaryVersionRejectsOversizedOutput(t *testing.T) {
	binary := writeVersionTestScript(t, "yes x | head -c 131072")

	err := verifyBinaryVersionWithTimeout(binary, "ctr", versionTestEnvironment(), 5*time.Second)
	if err == nil {
		t.Fatal("verifyBinaryVersionWithTimeout() error = nil, want oversized output error")
	}
	if !errors.Is(err, ErrBinaryVersionOutputTooLarge) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error = %v, want ErrBinaryVersionOutputTooLarge", err)
	}
	var checkErr *VersionCheckError
	if !errors.As(err, &checkErr) {
		t.Fatalf("verifyBinaryVersionWithTimeout() error type = %T, want *VersionCheckError", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const limit = 1024
	output, runErr := runCommandWithOutputLimit(ctx, binary, []string{"--version"}, versionTestEnvironment(), limit)
	if !errors.Is(runErr, errCommandOutputTooLarge) {
		t.Fatalf("runCommandWithOutputLimit() error = %v, want errCommandOutputTooLarge", runErr)
	}
	if len(output) > limit {
		t.Fatalf("captured output length = %d, want at most %d", len(output), limit)
	}
}

func writeVersionTestScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "version-binary")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write version test script: %v", err)
	}
	return path
}

func versionTestEnvironment() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	return []string{"PATH=" + path}
}
