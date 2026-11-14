package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	posixpath "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	runtime "github.com/rheic/sandboxes-runtime"
)

const (
	cloneSourceGuestPath = "/run/sandbox/source"
	cloneGitGuestIP      = "192.168.127.3"
	cloneGitGuestPort    = 9418
	cloneGitHostIP       = "127.0.0.1"
	cloneCommandTimeout  = 2 * time.Minute
	cloneOutputLimit     = 4096
	cloneGitCommand      = "git"
	cloneGitConfig       = "config"
	cloneGitLocalFlag    = "--local"
)

var cloneRepositorySlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// normalizeCloneOptions validates a non-nil clone request. Callers must skip
// this function when no clone options were supplied.
func normalizeCloneOptions(clone *sandbox.CloneOptions, workspaces []sandbox.Workspace) (*sandbox.CloneOptions, error) {
	if len(workspaces) != 1 {
		return nil, fmt.Errorf("%w: clone mode requires exactly one workspace", core.ErrConflict)
	}
	source, match, err := findCloneSourceWorkspace(clone.SourceWorkspacePath, workspaces)
	if err != nil {
		return nil, err
	}
	if err := validateCloneGuestWorkdir(clone.GuestWorkdir); err != nil {
		return nil, err
	}
	workspaces[match].ReadOnly = true
	workspaces[match].GuestPath = cloneSourceGuestPath
	if err := validateCloneWorkspaceOverlaps(workspaces, match); err != nil {
		return nil, err
	}
	if _, err := normalizeWorkspaces(CreateRequest{Workspaces: workspaces}); err != nil {
		return nil, err
	}
	return newCloneOptions(source, clone.GuestWorkdir), nil
}

func findCloneSourceWorkspace(source string, workspaces []sandbox.Workspace) (string, int, error) {
	if source == "" || !filepath.IsAbs(source) || strings.ContainsRune(source, '\x00') {
		return "", 0, fmt.Errorf("%w: clone source must identify one absolute workspace path", core.ErrConflict)
	}
	source = filepath.Clean(source)
	match := -1
	for i := range workspaces {
		if workspaces[i].Path != source {
			continue
		}
		if match >= 0 {
			return "", 0, fmt.Errorf("%w: clone source matches multiple workspaces", core.ErrConflict)
		}
		match = i
	}
	if match < 0 {
		return "", 0, fmt.Errorf("%w: clone source must match exactly one workspace", core.ErrConflict)
	}
	if err := validateCloneSourceRepository(source); err != nil {
		return "", 0, err
	}
	return source, match, nil
}

func validateCloneGuestWorkdir(guestWorkdir *string) error {
	if guestWorkdir == nil {
		return nil
	}
	if !validCloneGuestPath(*guestWorkdir) || !validCloneRepositorySlug(posixpath.Base(*guestWorkdir)) {
		return fmt.Errorf("%w: clone guest workdir must be a clean absolute POSIX path with a safe repository name", core.ErrConflict)
	}
	return nil
}

func validateCloneWorkspaceOverlaps(workspaces []sandbox.Workspace, sourceIndex int) error {
	for i := range workspaces {
		if i == sourceIndex {
			continue
		}
		destination := workspaces[i].GuestPath
		if destination == "" {
			destination = workspaces[i].Path
		}
		if posixPathsOverlap(destination, cloneSourceGuestPath) {
			return fmt.Errorf("%w: another workspace overlaps the clone source mount", core.ErrConflict)
		}
	}
	return nil
}

func newCloneOptions(source string, guestWorkdir *string) *sandbox.CloneOptions {
	result := &sandbox.CloneOptions{SourceWorkspacePath: source}
	if guestWorkdir != nil {
		workdir := *guestWorkdir
		result.GuestWorkdir = &workdir
	}
	return result
}

func validCloneGuestPath(value string) bool {
	return value != "" && posixpath.IsAbs(value) && posixpath.Clean(value) == value && !strings.ContainsAny(value, ",=\x00\r\n")
}

func validCloneRepositorySlug(value string) bool {
	return value != "." && value != ".." && cloneRepositorySlug.MatchString(value)
}

func posixPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func validateCloneSourceRepository(source string) error {
	before, err := os.Lstat(source)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: clone source must be a real directory", core.ErrConflict)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return fmt.Errorf("%w: clone source cannot be safely opened", core.ErrConflict)
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) || !opened.IsDir() {
		return fmt.Errorf("%w: clone source changed while opening", core.ErrConflict)
	}
	gitInfo, err := root.Lstat(".git")
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: clone source must contain a .git directory; worktree files are unsupported", core.ErrConflict)
	}
	configInfo, err := root.Lstat(".git/config")
	if err != nil || !configInfo.Mode().IsRegular() {
		return fmt.Errorf("%w: clone source Git config must be a regular file", core.ErrConflict)
	}
	return nil
}

func (s *Service) requireCloneCapabilities(ctx context.Context) error {
	if s.backend == nil {
		return fmt.Errorf("%w: clone mode requires a VM runtime", core.ErrConflict)
	}
	if _, ok := s.backend.(runtime.NativeExecutor); !ok {
		return fmt.Errorf("%w: runtime does not support bounded clone initialization", core.ErrConflict)
	}
	if _, ok := s.backend.(runtime.GitDaemonForwarder); !ok {
		return fmt.Errorf("%w: runtime network does not support managed Git forwarding", core.ErrConflict)
	}
	capabilities, err := s.backend.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("inspect clone runtime capabilities: %w", err)
	}
	if !capabilities.Workspace || !capabilities.Network {
		return fmt.Errorf("%w: clone mode requires workspace mounts and managed networking", core.ErrConflict)
	}
	return nil
}

func (s *Service) bootstrapClone(ctx context.Context, handle runtime.Handle, name string, clone *sandbox.CloneOptions, sb *sandbox.Sandbox) error {
	if err := s.requireCloneTooling(ctx, handle); err != nil {
		return err
	}
	workdir, err := s.resolveCloneWorkdir(ctx, handle, clone)
	if err != nil {
		return err
	}
	if err := s.prepareCloneWorkdir(ctx, handle, workdir, sb.Workspaces); err != nil {
		return err
	}
	if err := s.initializeGuestClone(ctx, handle, workdir); err != nil {
		return err
	}
	state := &sandbox.CloneState{Options: *clone, Info: &sandbox.CloneInfo{GuestWorkdir: workdir, RemoteName: "sandbox-" + name}}
	sb.Meta.Clone = state
	port, err := s.startCloneGitDaemon(ctx, handle, name, state.Info)
	if err != nil {
		return err
	}
	state.Info.GitEndpoint = &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: posixpath.Base(workdir)}
	return nil
}

func (s *Service) requireCloneTooling(ctx context.Context, handle runtime.Handle) error {
	if err := s.requireClonePathResolution(ctx, handle, "/", "-e"); err != nil {
		return fmt.Errorf("%w: clone image must include a working realpath command: %w", core.ErrConflict, err)
	}
	gitVersion, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "--version"}, cloneGitEnvironment())
	if err != nil {
		return fmt.Errorf("%w: clone image must include a working Git client and daemon: %w", core.ErrConflict, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(gitVersion), "git version ") {
		return fmt.Errorf("%w: clone image must include a working Git client and daemon", core.ErrConflict)
	}
	return nil
}

func (s *Service) resolveCloneWorkdir(ctx context.Context, handle runtime.Handle, clone *sandbox.CloneOptions) (string, error) {
	if clone.GuestWorkdir != nil {
		return *clone.GuestWorkdir, nil
	}
	output, err := s.runCloneCommand(ctx, handle, []string{"/bin/pwd"}, nil)
	if err != nil {
		return "", fmt.Errorf("discover guest working directory: %w", err)
	}
	return parseClonePwd(output)
}

func parseClonePwd(output string) (string, error) {
	if !strings.HasSuffix(output, "\n") || strings.Count(output, "\n") != 1 {
		return "", errors.New("guest pwd returned an invalid working directory")
	}
	workdir := strings.TrimSuffix(output, "\n")
	if !validCloneGuestPath(workdir) {
		return "", errors.New("guest pwd returned an invalid working directory")
	}
	return workdir, nil
}

func (s *Service) prepareCloneWorkdir(ctx context.Context, handle runtime.Handle, workdir string, workspaces []sandbox.Workspace) error {
	if !validCloneRepositorySlug(posixpath.Base(workdir)) {
		return errors.New("clone working directory has an unsafe repository name")
	}
	if err := validateCloneWorkdirAgainstWorkspaces(workdir, workspaces); err != nil {
		return err
	}
	parent := posixpath.Dir(workdir)
	if err := s.requireClonePathResolution(ctx, handle, parent, "-m"); err != nil {
		return fmt.Errorf("validate clone destination parent: %w", err)
	}
	if err := s.requireClonePathResolution(ctx, handle, workdir, "-m"); err != nil {
		return fmt.Errorf("validate clone destination: %w", err)
	}
	if parent != "/" {
		if _, err := s.runCloneCommand(ctx, handle, []string{"mkdir", "-p", "--", parent}, nil); err != nil {
			return fmt.Errorf("prepare clone parent directory: %w", err)
		}
	}
	if err := s.requireClonePathResolution(ctx, handle, parent, "-e"); err != nil {
		return fmt.Errorf("revalidate clone destination parent: %w", err)
	}
	if err := s.requireClonePathResolution(ctx, handle, workdir, "-m"); err != nil {
		return fmt.Errorf("revalidate clone destination: %w", err)
	}
	return nil
}

func (s *Service) initializeGuestClone(ctx context.Context, handle runtime.Handle, workdir string) error {
	cloneEnv := cloneGitEnvironment()
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "clone", "--no-local", "--no-hardlinks", "--no-recurse-submodules", "--", cloneSourceGuestPath, workdir}, cloneEnv); err != nil {
		return fmt.Errorf("create private guest clone: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, "remote", "remove", "origin"}, cloneEnv); err != nil {
		return fmt.Errorf("remove source path from guest clone configuration: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, cloneGitConfig, cloneGitLocalFlag, "core.hooksPath", "/dev/null"}, cloneEnv); err != nil {
		return fmt.Errorf("disable clone hooks: %w", err)
	}
	if _, err := s.runCloneCommand(ctx, handle, []string{cloneGitCommand, "-C", workdir, cloneGitConfig, cloneGitLocalFlag, "credential.helper", ""}, cloneEnv); err != nil {
		return fmt.Errorf("disable clone credential helpers: %w", err)
	}
	return nil
}

func (s *Service) requireClonePathResolution(ctx context.Context, handle runtime.Handle, guestPath, mode string) error {
	resolved, err := s.runCloneCommand(ctx, handle, []string{"realpath", mode, "--", guestPath}, nil)
	if err != nil {
		return err
	}
	if strings.TrimSuffix(resolved, "\n") != guestPath || strings.Count(resolved, "\n") != 1 {
		return fmt.Errorf("guest path %q resolves to a different or ambiguous destination", guestPath)
	}
	return nil
}

func validateCloneWorkdirAgainstWorkspaces(workdir string, workspaces []sandbox.Workspace) error {
	for i := range workspaces {
		destination := workspaces[i].GuestPath
		if destination == "" {
			destination = workspaces[i].Path
		}
		if posixPathsOverlap(workdir, destination) {
			return fmt.Errorf("%w: clone guest workdir overlaps a workspace mount", core.ErrConflict)
		}
	}
	return nil
}

func (s *Service) startCloneGitDaemon(ctx context.Context, handle runtime.Handle, name string, info *sandbox.CloneInfo) (uint16, error) {
	workdir := info.GuestWorkdir
	args := []string{cloneGitCommand, "daemon", "--detach", "--reuseaddr", "--listen=" + cloneGitGuestIP,
		"--port=" + strconv.Itoa(cloneGitGuestPort), "--base-path=" + posixpath.Dir(workdir), "--strict-paths", "--export-all", "--enable=upload-pack", "--disable=receive-pack", workdir}
	if _, err := s.runCloneCommand(ctx, handle, args, daemonGitEnvironment()); err != nil {
		return 0, fmt.Errorf("start guest Git daemon: %w", err)
	}
	forwarder := s.backend.(runtime.GitDaemonForwarder)
	port, err := forwarder.SetGitDaemon(ctx, name, true)
	if err != nil {
		return 0, errors.Join(fmt.Errorf("publish guest Git daemon: %w", err), s.withdrawCloneGitForward(ctx, name))
	}
	if port == 0 {
		return 0, errors.Join(errors.New("gateway returned an empty Git daemon port"), s.withdrawCloneGitForward(ctx, name))
	}
	return port, nil
}

func (s *Service) withdrawCloneGitForward(ctx context.Context, name string) error {
	forwarder, ok := s.backend.(runtime.GitDaemonForwarder)
	if !ok {
		return errors.New("runtime does not support Git daemon forward withdrawal")
	}
	if _, err := forwarder.SetGitDaemon(ctx, name, false); err != nil {
		return fmt.Errorf("withdraw guest Git daemon forward: %w", err)
	}
	return nil
}

func (s *Service) startStoredClone(ctx context.Context, sb *sandbox.Sandbox) error {
	if sb.Meta.Clone == nil {
		return nil
	}
	if sb.Meta.Clone.Info == nil || !validCloneGuestPath(sb.Meta.Clone.Info.GuestWorkdir) || !validCloneRepositorySlug(posixpath.Base(sb.Meta.Clone.Info.GuestWorkdir)) {
		return errors.New("stored clone metadata is invalid")
	}
	if _, err := s.runCloneCommand(ctx, s.backend.Handle(sb.Name), []string{cloneGitCommand, "-C", sb.Meta.Clone.Info.GuestWorkdir, cloneGitConfig, cloneGitLocalFlag, "core.hooksPath", "/dev/null"}, cloneGitEnvironment()); err != nil {
		return fmt.Errorf("restore clone hook policy: %w", err)
	}
	port, err := s.startCloneGitDaemon(ctx, s.backend.Handle(sb.Name), sb.Name, sb.Meta.Clone.Info)
	if err != nil {
		return err
	}
	sb.Meta.Clone.Info.GitEndpoint = &sandbox.GitEndpoint{HostIP: cloneGitHostIP, Port: port, Repository: posixpath.Base(sb.Meta.Clone.Info.GuestWorkdir)}
	return nil
}

func (s *Service) stopStoredClone(ctx context.Context, sb *sandbox.Sandbox) error {
	if sb.Meta.Clone == nil {
		return nil
	}
	if (sb.Meta.Clone.Info == nil || sb.Meta.Clone.Info.GitEndpoint == nil) && sb.State != sandbox.Running && sb.State != sandbox.Unknown {
		return nil
	}
	if err := s.withdrawCloneGitForward(ctx, sb.Name); err != nil {
		return err
	}
	if sb.Meta.Clone.Info != nil {
		sb.Meta.Clone.Info.GitEndpoint = nil
	}
	return nil
}

func (s *Service) runCloneCommand(ctx context.Context, handle runtime.Handle, argv, extraEnv []string) (string, error) {
	executor, ok := s.backend.(runtime.NativeExecutor)
	if !ok {
		return "", fmt.Errorf("%w: runtime does not support bounded clone initialization", core.ErrConflict)
	}
	commandCtx, cancel := context.WithTimeout(ctx, cloneCommandTimeout)
	defer cancel()
	var stdout, stderr limitedCloneBuffer
	stdout.limit = cloneOutputLimit
	stderr.limit = cloneOutputLimit
	env := append([]string(nil), extraEnv...)
	args := make([]string, 0, len(argv)+len(env)+3)
	args = append(args, "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin")
	args = append(args, env...)
	args = append(args, argv...)
	code, err := executor.ExecNative(commandCtx, handle, runtime.ExecRequest{
		Argv: args, Workdir: "", Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil || code != 0 {
		return "", errors.Join(fmt.Errorf("guest command failed with exit code %d", code), err, stdout.err, stderr.err)
	}
	return stdout.String(), nil
}

type limitedCloneBuffer struct {
	bytes.Buffer
	limit int
	err   error
}

func (b *limitedCloneBuffer) Write(p []byte) (int, error) {
	if b.limit < 0 || len(p) > b.limit-b.Len() {
		b.err = errors.New("guest command output exceeded the limit")
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

func cloneGitEnvironment() []string {
	return []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "GIT_ALLOW_PROTOCOL=file",
		"GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=credential.helper", "GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=init.templateDir", "GIT_CONFIG_VALUE_2=/dev/null",
	}
}

func daemonGitEnvironment() []string {
	return []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=/nonexistent"}
}
