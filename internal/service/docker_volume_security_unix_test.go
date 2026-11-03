//go:build darwin || linux

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDockerVolumeAcceptsOnlyPrivateOwnedFile(t *testing.T) {
	volumeDir := privateDockerVolumeTestDir(t)
	const sandboxID = "sbx-volume-positive"
	path := filepath.Join(volumeDir, sandboxID+".ext4")
	if err := os.WriteFile(path, []byte("synthetic-volume"), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := Service{DockerVolumeDir: volumeDir}
	got, err := svc.ensureDockerVolume(context.Background(), sandboxID)
	resolvedDir, resolveErr := filepath.EvalSymlinks(volumeDir)
	want := filepath.Join(resolvedDir, sandboxID+".ext4")
	if err != nil || resolveErr != nil || got != want {
		t.Fatalf("ensureDockerVolume() = %q, %v; want %q (resolve error %v)", got, err, want, resolveErr)
	}
}

func TestEnsureDockerVolumeFormatsThroughValidatedFileDescriptor(t *testing.T) {
	volumeDir := privateDockerVolumeTestDir(t)
	mkfs := filepath.Join(t.TempDir(), "fake-mkfs")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\nprintf formatted > \"$3\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	svc := Service{DockerVolumeDir: volumeDir, DockerVolumeSize: "512m", MkfsExt4: mkfs}
	path, err := svc.ensureDockerVolume(context.Background(), "sbx-volume-format-fd")
	if err != nil {
		t.Fatal(err)
	}
	volume, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]byte, len("formatted"))
	_, readErr := volume.ReadAt(contents, 0)
	closeErr := volume.Close()
	if readErr != nil || closeErr != nil || string(contents) != "formatted" {
		t.Fatalf("formatter did not write to the validated volume descriptor: contents=%q readErr=%v closeErr=%v", contents, readErr, closeErr)
	}
}

func TestEnsureDockerVolumeRejectsSymlinkWithoutFollowingIt(t *testing.T) {
	volumeDir := privateDockerVolumeTestDir(t)
	outside := filepath.Join(t.TempDir(), "outside.ext4")
	if err := os.WriteFile(outside, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	const sandboxID = "sbx-volume-symlink"
	path := filepath.Join(volumeDir, sandboxID+".ext4")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}

	svc := Service{DockerVolumeDir: volumeDir}
	if _, err := svc.ensureDockerVolume(context.Background(), sandboxID); err == nil {
		t.Fatal("existing symlink volume was accepted")
	}
	if err := svc.removeDockerVolume(sandboxID); err == nil {
		t.Fatal("symlink volume was removed")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "preserve-me" {
		t.Fatalf("outside target changed: data=%q err=%v", data, err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink path changed: info=%v err=%v", info, err)
	}
}

func TestEnsureDockerVolumeRejectsHardLinkWithoutUsingIt(t *testing.T) {
	volumeDir := privateDockerVolumeTestDir(t)
	outside := filepath.Join(t.TempDir(), "outside.ext4")
	if err := os.WriteFile(outside, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	const sandboxID = "sbx-volume-hardlink"
	path := filepath.Join(volumeDir, sandboxID+".ext4")
	if err := os.Link(outside, path); err != nil {
		t.Fatal(err)
	}

	svc := Service{DockerVolumeDir: volumeDir}
	if _, err := svc.ensureDockerVolume(context.Background(), sandboxID); err == nil {
		t.Fatal("hard-linked volume was accepted")
	}
	if err := svc.removeDockerVolume(sandboxID); err == nil {
		t.Fatal("hard-linked volume was removed")
	}
	for _, name := range []string{outside, path} {
		if data, err := os.ReadFile(name); err != nil || string(data) != "preserve-me" {
			t.Fatalf("hard-link data at %q changed: data=%q err=%v", name, data, err)
		}
	}
}

func TestEnsureDockerVolumeRejectsBroadFilePermissions(t *testing.T) {
	volumeDir := privateDockerVolumeTestDir(t)
	const sandboxID = "sbx-volume-mode"
	path := filepath.Join(volumeDir, sandboxID+".ext4")
	if err := os.WriteFile(path, []byte("synthetic-volume"), 0o644); err != nil {
		t.Fatal(err)
	}

	svc := Service{DockerVolumeDir: volumeDir}
	if _, err := svc.ensureDockerVolume(context.Background(), sandboxID); err == nil {
		t.Fatal("volume with group/other permissions was accepted")
	}
	if err := svc.removeDockerVolume(sandboxID); err == nil {
		t.Fatal("volume with unsafe permissions was removed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unsafe volume was unexpectedly removed: %v", err)
	}
}

func privateDockerVolumeTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volumes")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnsureDockerVolumeRejectsUnsafeDirectory(t *testing.T) {
	volumeDir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(volumeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svc := Service{DockerVolumeDir: volumeDir}
	if _, err := svc.ensureDockerVolume(context.Background(), "sbx-volume-shared"); err == nil {
		t.Fatal("volume directory accessible by others was accepted")
	}
	if _, err := os.Lstat(filepath.Join(volumeDir, "sbx-volume-shared.ext4")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("volume created under unsafe directory: %v", err)
	}
}
