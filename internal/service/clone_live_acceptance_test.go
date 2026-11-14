//go:build darwin && rheic_clone_live

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	posixpath "path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	daemonnetwork "github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/store"
	gateway "github.com/rheic/sandboxes-gateway"
	rt "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/sandboxes-runtime/ctr"
)

const cloneLiveAcceptanceTimeout = 12 * time.Minute

// TestCloneLiveAcceptanceAgainstOwnedVM exercises the complete clone contract
// against a daemon-owned VM: private guest clone, managed Git daemon forward,
// stop/start endpoint rotation and force delete.
func TestCloneLiveAcceptanceAgainstOwnedVM(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("clone live acceptance requires macOS ARM64")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("clone live acceptance requires macOS")
	}
	inputs := getCloneLiveInputs(t)

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), cloneLiveAcceptanceTimeout)
	defer cancel()

	root, err := os.MkdirTemp("/private/tmp", "rclive-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs after every process/log cleanup below.
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned clone acceptance directory: %v", err)
		}
	})
	if evidenceDir := os.Getenv("RHEIC_CLONE_EVIDENCE_DIR"); evidenceDir != "" {
		// Registered after the removal cleanup so evidence is captured first.
		t.Cleanup(func() { copyCloneLiveEvidence(t, root, evidenceDir) })
	}

	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ source, name string }{
		{inputs.shim, "containerd-shim-nerdbox-v1"},
		{inputs.kernel, "nerdbox-kernel-arm64"},
		{inputs.rootfs, "nerdbox-rootfs-arm64.erofs"},
	} {
		if err := os.Symlink(item.source, filepath.Join(binDir, item.name)); err != nil {
			t.Fatal(err)
		}
	}

	containerdSocket := filepath.Join(root, "containerd.sock")
	containerdConfig := filepath.Join(root, "containerd.toml")
	config := fmt.Sprintf("version = 4\nroot = %q\nstate = %q\n[plugins.'io.containerd.server.v1.grpc']\naddress = %q\nuid = %d\ngid = %d\n[plugins.'io.containerd.server.v1.ttrpc']\naddress = %q\nuid = %d\ngid = %d\n",
		filepath.Join(root, "root"), filepath.Join(root, "state"), containerdSocket, os.Getuid(), os.Getgid(), containerdSocket+".ttrpc", os.Getuid(), os.Getgid())
	if err := os.WriteFile(containerdConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	containerdLogPath := filepath.Join(root, "containerd.log")
	containerdLog, err := os.Create(containerdLogPath)
	if err != nil {
		t.Fatal(err)
	}
	containerd := exec.Command(inputs.containerd, "--config", containerdConfig)
	containerd.Env = append(os.Environ(),
		"PATH="+strings.Join([]string{binDir, "/opt/homebrew/bin", "/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/bin", "/usr/bin", "/bin"}, string(os.PathListSeparator)),
		"LIBKRUN_PATH="+inputs.libkrun,
		"SAILOR_PATH="+filepath.Join(filepath.Dir(inputs.shim), "lib"),
	)
	containerd.Stdout, containerd.Stderr = containerdLog, containerdLog
	if err := containerd.Start(); err != nil {
		_ = containerdLog.Close()
		t.Fatal(err)
	}
	containerdDone := make(chan struct{})
	containerdResult := make(chan error, 1)
	go func() {
		containerdResult <- containerd.Wait()
		close(containerdDone)
	}()
	defer func() {
		select {
		case <-containerdDone:
			if err := <-containerdResult; err != nil {
				t.Errorf("owned containerd exited: %v", err)
			}
		default:
			_ = containerd.Process.Signal(os.Interrupt)
			select {
			case <-containerdDone:
				if err := <-containerdResult; err != nil {
					t.Errorf("stop owned containerd: %v", err)
				}
			case <-time.After(15 * time.Second):
				_ = containerd.Process.Kill()
				<-containerdDone
				_ = <-containerdResult
				t.Error("owned containerd did not stop after SIGINT")
			}
		}
		if err := containerdLog.Close(); err != nil {
			t.Errorf("close containerd log: %v", err)
		}
	}()

	if err := waitCloneLiveContainerd(ctx, inputs.ctr, containerdSocket, containerdDone); err != nil {
		t.Fatalf("wait for owned containerd: %v (log %s)", err, containerdLogPath)
	}

	// The runtime does not pull images itself, so do a bounded explicit pull.
	pullCtx, pullCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer pullCancel()
	pull := exec.CommandContext(pullCtx, inputs.ctr, "--address", containerdSocket, "--namespace", "default", "images", "pull", inputs.image)
	pullOutput, err := pull.CombinedOutput()
	if err != nil {
		t.Fatalf("pre-pull %s: %v\n%s", inputs.image, err, strings.TrimSpace(string(pullOutput)))
	}

	networkManager, err := gateway.New(gateway.Config{
		GVProxy: inputs.gvproxy, Supervisor: inputs.daemon, RunDir: filepath.Join(root, "run", "gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer closeCancel()
		if err := networkManager.Close(closeCtx); err != nil {
			t.Errorf("close owned gateway manager: %v", err)
		}
	}()
	backend, err := ctr.NewBackend(
		ctr.Config{Socket: containerdSocket, CTR: inputs.ctr, Runtime: "io.containerd.nerdbox.v1", Snapshotter: "erofs", Platform: "linux/arm64"},
		ctr.BackendOptions{Image: inputs.image, FIFODir: filepath.Join(root, "fifo"), Network: daemonnetwork.New(networkManager, filepath.Join(root, "run", "audit"))},
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(ctx, filepath.Join(root, "sandboxes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			t.Errorf("close owned daemon state: %v", err)
		}
	}()

	repoDir, hostHead, branch := makeCloneLiveRepository(t, root)
	svc := New(state, backend)
	svc.DefaultImage = inputs.image

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	sandboxName := "clone-live-" + hex.EncodeToString(nonce[:])

	op, err := svc.Create(ctx, CreateRequest{
		Name:       sandboxName,
		Image:      inputs.image,
		Workspaces: []sandbox.Workspace{{Path: repoDir}},
		Clone:      &sandbox.CloneOptions{SourceWorkspacePath: repoDir},
	})
	if err != nil {
		t.Fatalf("service Create with clone mode: %v", err)
	}
	sandboxID := op.SandboxID
	if sandboxID == "" {
		t.Fatal("service Create returned an empty sandbox ID")
	}
	deleted := false
	defer func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if _, err := svc.Delete(cleanupCtx, sandboxID, true); err != nil {
			t.Errorf("delete owned clone acceptance sandbox: %v", err)
		}
	}()

	sb := loadCloneLiveSandbox(t, ctx, svc, state, sandboxID)
	if sb.Meta == nil || sb.Meta.Clone == nil || sb.Meta.Clone.Info == nil {
		t.Fatalf("daemon did not persist clone metadata: %+v", sb.Meta)
	}
	info := sb.Meta.Clone.Info
	workdir := info.GuestWorkdir
	if workdir == "" || !posixpath.IsAbs(workdir) || posixpath.Clean(workdir) != workdir {
		t.Fatalf("guest workdir is not a clean absolute POSIX path: %q", workdir)
	}
	if want := "sandbox-" + sandboxName; info.RemoteName != want {
		t.Fatalf("clone remote name = %q, want %q", info.RemoteName, want)
	}
	if info.GitEndpoint == nil {
		t.Fatal("daemon did not publish a host Git endpoint")
	}
	firstEndpoint := *info.GitEndpoint
	if firstEndpoint.HostIP != "127.0.0.1" || firstEndpoint.Port == 0 {
		t.Fatalf("unsafe clone Git endpoint: %+v", firstEndpoint)
	}
	if want := posixpath.Base(workdir); firstEndpoint.Repository != want {
		t.Fatalf("endpoint repository = %q, want %q", firstEndpoint.Repository, want)
	}

	// 1. The guest clone must hold the exact host HEAD.
	out, stderr, code, err := execCloneLiveGuest(ctx, svc, sandboxID, []string{"git", "-C", workdir, "rev-parse", "HEAD"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("git rev-parse HEAD: code=%d err=%v stderr=%q", code, err, stderr)
	}
	if got := strings.TrimSpace(out); got != hostHead {
		t.Fatalf("guest HEAD = %q, want host HEAD %q", got, hostHead)
	}

	// 2. The source path remote must be gone.
	out, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID, []string{"git", "-C", workdir, "remote", "-v"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("git remote -v: code=%d err=%v stderr=%q", code, err, stderr)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("guest clone retained remotes:\n%s", out)
	}

	// 3. Hooks and credential helpers must be disabled locally.
	out, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID, []string{"git", "-C", workdir, "config", "--get", "core.hooksPath"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("git config core.hooksPath: code=%d err=%v stderr=%q", code, err, stderr)
	}
	if got := strings.TrimSpace(out); got != "/dev/null" {
		t.Fatalf("guest core.hooksPath = %q, want /dev/null", got)
	}
	out, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID, []string{"git", "-C", workdir, "config", "--get", "credential.helper"}, nil)
	if err != nil {
		t.Fatalf("git config credential.helper transport: %v (stderr %q)", err, stderr)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("guest clone retained a credential helper: %q (exit %d)", out, code)
	}

	// 5. The source workspace mount must be read-only.
	_, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "printf probe > /run/sandbox/source/.rheic-clone-write-probe"}, nil)
	// A read-only mount makes the write fail inside the guest, so a non-zero
	// exit is the expected control result rather than a transport error.
	if err != nil && code == 0 {
		t.Fatalf("write probe transport: %v (stderr %q)", err, stderr)
	}
	if code == 0 {
		t.Fatal("writing to the cloned source mount unexpectedly succeeded")
	}
	if !strings.Contains(stderr, "Read-only file system") {
		t.Fatalf("write probe failed for a reason other than a read-only mount: %q", stderr)
	}
	_, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID,
		[]string{"/bin/sh", "-c", "test ! -e /run/sandbox/source/.rheic-clone-write-probe"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("write probe left an artifact on the source mount: code=%d err=%v stderr=%q", code, err, stderr)
	}

	// 6. A new guest commit proves the clone is writable and private.
	_, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID, []string{
		"git", "-C", workdir, "-c", "user.email=clone-live@example.invalid", "-c", "user.name=Rheic Clone Live",
		"commit", "--allow-empty", "-q", "-m", "guest",
	}, nil)
	if err != nil || code != 0 {
		t.Fatalf("guest commit: code=%d err=%v stderr=%q", code, err, stderr)
	}
	out, stderr, code, err = execCloneLiveGuest(ctx, svc, sandboxID, []string{"git", "-C", workdir, "rev-parse", "HEAD"}, nil)
	if err != nil || code != 0 {
		t.Fatalf("guest rev-parse after commit: code=%d err=%v stderr=%q", code, err, stderr)
	}
	guestCommit := strings.TrimSpace(out)
	if guestCommit == "" || guestCommit == hostHead {
		t.Fatalf("guest commit did not advance HEAD: %q (host %q)", guestCommit, hostHead)
	}

	// Host-side transfer through the managed forward proves the private clone
	// is really served. The forward is a raw TCP forward to the guest Git
	// daemon, so the client-visible scheme is git:// (the CLI contract).
	firstURL := cloneLiveEndpointURL(t, firstEndpoint)
	lsRemote := waitCloneLiveLSRemote(ctx, firstURL, guestCommit)
	if !strings.Contains(lsRemote, guestCommit) || !strings.Contains(lsRemote, "refs/heads/"+branch) {
		t.Fatalf("git ls-remote %s did not list guest commit %s on %s:\n%s", firstURL, guestCommit, branch, lsRemote)
	}
	fetchDir := filepath.Join(root, "fetch-"+hex.EncodeToString(nonce[:]))
	runCloneLiveGit(t, "", "init", "-q", fetchDir)
	runCloneLiveGit(t, fetchDir, "fetch", "-q", firstURL, branch)
	fetched := strings.TrimSpace(runCloneLiveGit(t, fetchDir, "rev-parse", "FETCH_HEAD"))
	if fetched != guestCommit {
		t.Fatalf("fetched commit = %q, want guest commit %q", fetched, guestCommit)
	}

	// Stop must withdraw the forward and clear the stored endpoint.
	if _, err := svc.Stop(ctx, sandboxID); err != nil {
		t.Fatalf("service Stop: %v", err)
	}
	waitCloneLivePortClosed(t, ctx, firstEndpoint.Port, 15*time.Second)
	stopped := loadCloneLiveSandbox(t, ctx, svc, state, sandboxID)
	if stopped.Meta == nil || stopped.Meta.Clone == nil || stopped.Meta.Clone.Info == nil {
		t.Fatalf("stop lost clone metadata: %+v", stopped.Meta)
	}
	if stopped.Meta.Clone.Info.GitEndpoint != nil {
		t.Fatalf("stop retained the live Git endpoint: %+v", stopped.Meta.Clone.Info.GitEndpoint)
	}

	// Start must allocate a fresh forward that still serves the guest commit.
	if _, err := svc.Start(ctx, sandboxID); err != nil {
		t.Fatalf("service Start: %v", err)
	}
	restarted := loadCloneLiveSandbox(t, ctx, svc, state, sandboxID)
	if restarted.Meta == nil || restarted.Meta.Clone == nil || restarted.Meta.Clone.Info == nil {
		t.Fatalf("restart lost clone metadata: %+v", restarted.Meta)
	}
	secondEndpoint := restarted.Meta.Clone.Info.GitEndpoint
	if secondEndpoint == nil {
		t.Fatal("restart did not publish a new Git endpoint")
	}
	if secondEndpoint.HostIP != "127.0.0.1" || secondEndpoint.Port == 0 {
		t.Fatalf("unsafe restarted clone Git endpoint: %+v", *secondEndpoint)
	}
	if secondEndpoint.Repository != firstEndpoint.Repository {
		t.Fatalf("restart changed repository %q -> %q", firstEndpoint.Repository, secondEndpoint.Repository)
	}
	secondURL := cloneLiveEndpointURL(t, *secondEndpoint)
	lsRemote = waitCloneLiveLSRemote(ctx, secondURL, guestCommit)
	if !strings.Contains(lsRemote, guestCommit) {
		t.Fatalf("git ls-remote after restart %s did not list guest commit %s:\n%s", secondURL, guestCommit, lsRemote)
	}

	// Delete must withdraw the last forward and remove the durable row.
	if _, err := svc.Delete(ctx, sandboxID, true); err != nil {
		t.Fatalf("service Delete(force): %v", err)
	}
	deleted = true
	waitCloneLivePortClosed(t, ctx, secondEndpoint.Port, 15*time.Second)
	if _, err := state.Get(ctx, sandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("deleted sandbox is still readable: %v", err)
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("clone live acceptance exceeded the 12-minute deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= cloneLiveAcceptanceTimeout {
		t.Fatalf("clone live acceptance exceeded 12 minutes: %s", elapsed)
	}
	t.Logf("PASS: clone live acceptance name=%s guest_workdir=%s remote=%s repository=%s port_before=%d port_after=%d host_head=%s guest_commit=%s source_mount=read-only",
		sandboxName, workdir, info.RemoteName, firstEndpoint.Repository, firstEndpoint.Port, secondEndpoint.Port, hostHead, guestCommit)
}

type cloneLiveInputs struct {
	containerd, ctr, shim, kernel, rootfs, libkrun, gvproxy, daemon, image string
}

func getCloneLiveInputs(t *testing.T) cloneLiveInputs {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Skipf("set %s to explicitly select owned-VM test input", name)
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatalf("%s is unavailable: %v", name, err)
		}
		return value
	}
	image := os.Getenv("RHEIC_CLONE_IMAGE")
	if image == "" {
		image = "docker.io/library/buildpack-deps:bookworm-scm"
	}
	return cloneLiveInputs{
		containerd: get("RHEIC_CLONE_CONTAINERD"), ctr: get("RHEIC_CLONE_CTR"),
		shim: get("RHEIC_CLONE_SHIM"), kernel: get("RHEIC_CLONE_KERNEL"),
		rootfs: get("RHEIC_CLONE_ROOTFS"), libkrun: get("RHEIC_CLONE_LIBKRUN"),
		gvproxy: get("RHEIC_CLONE_GVPROXY"), daemon: get("RHEIC_CLONE_DAEMON"),
		image: image,
	}
}

func waitCloneLiveContainerd(ctx context.Context, ctrPath, socket string, done <-chan struct{}) error {
	for {
		command := exec.CommandContext(ctx, ctrPath, "--address", socket, "version")
		if err := command.Run(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("owned containerd exited before socket readiness")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func makeCloneLiveRepository(t *testing.T, root string) (repoDir, head, branch string) {
	t.Helper()
	repoDir = filepath.Join(root, "source-repo")
	if err := os.Mkdir(repoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", args...)
		command.Dir = repoDir
		command.Env = cloneLiveGitEnvironment()
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
		return strings.TrimSpace(string(output))
	}
	run("init", "-q")
	run("config", "user.email", "clone-live@example.invalid")
	run("config", "user.name", "Rheic Clone Live")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("rheic clone live acceptance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-q", "-m", "initial")
	head = run("rev-parse", "HEAD")
	branch = run("rev-parse", "--abbrev-ref", "HEAD")
	if head == "" || branch == "" || branch == "HEAD" {
		t.Fatalf("synthetic repository has no HEAD: head=%q branch=%q", head, branch)
	}
	return repoDir, head, branch
}

func cloneLiveGitEnvironment() []string {
	return append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
}

func runCloneLiveGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	if dir != "" {
		command.Dir = dir
	}
	command.Env = cloneLiveGitEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func loadCloneLiveSandbox(t *testing.T, ctx context.Context, svc *Service, state *store.Store, id string) sandbox.Sandbox {
	t.Helper()
	sb, err := svc.Get(ctx, id)
	if err == nil {
		return sb
	}
	sb, storeErr := state.Get(ctx, id)
	if storeErr != nil {
		t.Fatalf("load sandbox %s: service=%v store=%v", id, err, storeErr)
	}
	return sb
}

func execCloneLiveGuest(ctx context.Context, svc *Service, sandboxID string, argv, env []string) (stdout, stderr string, code int, err error) {
	execCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var out, errOut strings.Builder
	// Workdir is explicitly / because Service.Exec otherwise defaults to the
	// host workspace path, which is not present at that path inside the guest.
	code, err = svc.Exec(execCtx, sandboxID, rt.ExecRequest{
		Argv: argv, Env: env, Workdir: "/", Stdout: &out, Stderr: &errOut,
	})
	return out.String(), errOut.String(), code, err
}

func cloneLiveEndpointURL(t *testing.T, endpoint sandbox.GitEndpoint) string {
	t.Helper()
	if endpoint.HostIP != "127.0.0.1" || endpoint.Port == 0 {
		t.Fatalf("unsafe clone Git endpoint: %+v", endpoint)
	}
	if endpoint.Repository == "" || endpoint.Repository == "." || endpoint.Repository == ".." || strings.ContainsAny(endpoint.Repository, "/\\\x00\r\n") {
		t.Fatalf("unsafe clone repository name: %q", endpoint.Repository)
	}
	// The managed forward exports the clone's Git directory, and the CLI
	// client addresses it as <repository>/.git over the Git protocol.
	return "git://" + net.JoinHostPort(endpoint.HostIP, strconv.FormatUint(uint64(endpoint.Port), 10)) + "/" + endpoint.Repository + "/.git"
}

func waitCloneLiveLSRemote(ctx context.Context, endpointURL, wantCommit string) string {
	deadline := time.Now().Add(30 * time.Second)
	var lastOutput string
	var lastErr error
	for {
		commandCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		command := exec.CommandContext(commandCtx, "git", "ls-remote", endpointURL)
		command.Env = cloneLiveGitEnvironment()
		output, err := command.CombinedOutput()
		cancel()
		lastOutput, lastErr = string(output), err
		if err == nil && strings.Contains(lastOutput, wantCommit) {
			return lastOutput
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			if lastErr != nil {
				return fmt.Sprintf("last error: %v\n%s", lastErr, lastOutput)
			}
			return lastOutput
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitCloneLivePortClosed(t *testing.T, ctx context.Context, port uint16, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	for {
		connection, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err != nil {
			return
		}
		_ = connection.Close()
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("host port %d still accepts TCP connections", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func copyCloneLiveEvidence(t *testing.T, root, evidenceDir string) {
	t.Helper()
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		t.Errorf("create clone evidence directory: %v", err)
		return
	}
	prefix := "clone-live-" + filepath.Base(root)
	copyOne := func(source, name string) {
		data, err := os.ReadFile(source)
		if err != nil {
			if !os.IsNotExist(err) {
				t.Errorf("read clone evidence %s: %v", source, err)
			}
			return
		}
		if err := os.WriteFile(filepath.Join(evidenceDir, name), data, 0o600); err != nil {
			t.Errorf("write clone evidence %s: %v", name, err)
		}
	}
	copyOne(filepath.Join(root, "containerd.log"), prefix+"-containerd.log")
	gatewayDir := filepath.Join(root, "run", "gateway")
	_ = filepath.WalkDir(gatewayDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".gateway.log") {
			return err
		}
		copyOne(path, prefix+"-"+entry.Name())
		return nil
	})
}
