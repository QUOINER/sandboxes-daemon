//go:build darwin && rheic_p04_service_live

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	core "github.com/rheic/sandboxes-core"
	daemonnetwork "github.com/rheic/sandboxes-daemon/internal/network"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
	gateway "github.com/rheic/sandboxes-gateway"
	rt "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/sandboxes-runtime/ctr"
)

const p04ServiceCredential = "rheic-p04-service-synthetic-credential"

func TestP04ServiceCreateStartExecRevokeAgainstOwnedVM(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("P-04 service-level owned-VM acceptance currently requires macOS ARM64")
	}
	inputs := getP04ServiceInputs(t)
	root, err := os.MkdirTemp("/private/tmp", "rsbx-p04-service-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned service acceptance directory: %v", err)
		}
	})
	defer func() {
		evidenceDir := os.Getenv("RHEIC_P04_EVIDENCE_DIR")
		if !t.Failed() || evidenceDir == "" {
			return
		}
		if data, readErr := os.ReadFile(filepath.Join(root, "containerd.log")); readErr == nil {
			if writeErr := os.WriteFile(filepath.Join(evidenceDir, "service-containerd-failure.log"), data, 0o600); writeErr != nil {
				t.Errorf("preserve owned containerd diagnostic: %v", writeErr)
			}
		}
		gatewayDir := filepath.Join(root, "run", "gateway")
		_ = filepath.WalkDir(gatewayDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".gateway.log") {
				return err
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("read owned gateway diagnostic: %v", readErr)
				return nil
			}
			destination := filepath.Join(evidenceDir, "service-"+entry.Name())
			if writeErr := os.WriteFile(destination, data, 0o600); writeErr != nil {
				t.Errorf("preserve owned gateway diagnostic: %v", writeErr)
			}
			return nil
		})
	}()

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
	containerdLog, err := os.Create(filepath.Join(root, "containerd.log"))
	if err != nil {
		t.Fatal(err)
	}
	containerd := exec.Command(inputs.containerd, "--config", containerdConfig)
	containerd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+"/opt/homebrew/bin:/opt/homebrew/opt/e2fsprogs/sbin:/usr/bin:/bin",
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

	// A cold pinned sandbox-template pull is several hundred MiB; allow the
	// controlled registry fetch to complete before testing VM lifecycle.
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer startupCancel()
	if err := waitP04ServiceContainerd(startupCtx, inputs.ctr, containerdSocket, containerdDone); err != nil {
		t.Fatalf("wait for owned containerd: %v (log %s)", err, filepath.Join(root, "containerd.log"))
	}
	imageClient, err := ctr.New(ctr.Config{
		Socket: containerdSocket, CTR: inputs.ctr, Snapshotter: "erofs", Platform: "linux/arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := imageClient.EnsureImage(startupCtx, inputs.image); err != nil {
		t.Fatalf("pre-pull pinned sandbox image before lifecycle budget: %v", err)
	}
	// The cold template pull is complete; bound the service lifecycle independently.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
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

	serviceSecrets, err := servicesecrets.NewStore(servicesecrets.NativeVault{})
	if err != nil {
		t.Fatal(err)
	}
	proxies := secretproxy.New()
	svc := New(state, backend)
	svc.DefaultImage = inputs.image
	svc.DockerVolumeDir = filepath.Join(root, "docker-volumes")
	if err := os.Mkdir(svc.DockerVolumeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	svc.DockerVolumeSize = "512m"
	svc.SetServiceSecretStore(serviceSecrets)
	svc.SetSecretProxyManager(proxies)
	proxyRoot := filepath.Join(root, "proxy")
	if err := os.Mkdir(proxyRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	svc.SetSecretProxyRuntime(inputs.helper, proxyRoot)
	defer func() {
		if err := proxies.Close(); err != nil {
			t.Errorf("close host proxy manager: %v", err)
		}
	}()

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	sandboxName := "p04-service-" + hex.EncodeToString(nonce[:])
	if _, err := serviceSecrets.Load(ctx, "openai", servicesecrets.ScopeSandbox, sandboxName); !errors.Is(err, servicesecrets.ErrNotFound) {
		t.Fatalf("unique sandbox keychain account already exists: %v", err)
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, sandboxName, []byte(p04ServiceCredential)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := serviceSecrets.Delete(context.Background(), "openai", servicesecrets.ScopeSandbox, sandboxName); err != nil && !errors.Is(err, servicesecrets.ErrNotFound) {
			t.Errorf("delete owned synthetic service credential: %v", err)
		}
	})

	started := time.Now()
	operation, err := svc.Create(ctx, CreateRequest{
		Name:  sandboxName,
		Image: inputs.image,
		Env:   map[string]string{"OPENAI_API_KEY": "${proxy:openai}"},
	})
	if err != nil {
		t.Fatalf("service Create with sandbox-scoped proxy credential: %v", err)
	}
	sandboxID := operation.SandboxID
	if sandboxID == "" || !proxies.Has(sandboxName, "openai") {
		t.Fatalf("service Create did not persist sandbox identity and start broker (id=%q)", sandboxID)
	}
	deleted := false
	defer func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		if _, err := svc.Delete(cleanupCtx, sandboxID, true); err != nil {
			t.Errorf("delete owned service acceptance sandbox: %v", err)
		}
	}()

	checkEnv := `/bin/sh -c 'test "$OPENAI_API_KEY" = rheic-proxy-placeholder && test "$OPENAI_BASE_URL" = http://127.0.0.1:3128/v1'`
	if err := waitP04ServiceHelper(ctx, svc, sandboxID); err != nil {
		t.Fatalf("guest proxy helper did not start: %v", err)
	}
	if _, err := execP04Service(ctx, svc, sandboxID, checkEnv, []string{"OPENAI_API_KEY=${proxy:openai}"}); err != nil {
		t.Fatalf("service Exec did not resolve proxy environment: %v", err)
	}
	if err := scanP04ServiceState(root, []byte(p04ServiceCredential)); err != nil {
		t.Fatalf("synthetic credential persisted in daemon state: %v", err)
	}

	if _, err := svc.Stop(ctx, sandboxID); err != nil {
		t.Fatalf("service Stop: %v", err)
	}
	if proxies.Has(sandboxName, "openai") {
		t.Fatal("service Stop retained the host service broker")
	}
	if _, err := svc.Start(ctx, sandboxID); err != nil {
		t.Fatalf("service Start did not reload the host keychain credential: %v", err)
	}
	if !proxies.Has(sandboxName, "openai") {
		t.Fatal("service Start did not restore the host service broker")
	}
	if err := waitP04ServiceHelper(ctx, svc, sandboxID); err != nil {
		t.Fatalf("guest proxy helper did not restart: %v", err)
	}
	if _, err := execP04Service(ctx, svc, sandboxID, checkEnv, []string{"OPENAI_API_KEY=${proxy:openai}"}); err != nil {
		t.Fatalf("service Exec after restart did not resolve proxy environment: %v", err)
	}

	if removed, err := svc.RemoveServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, sandboxName); err != nil || !removed {
		t.Fatalf("service-level credential revoke removed=%t err=%v", removed, err)
	}
	if proxies.Has(sandboxName, "openai") {
		t.Fatal("service-level credential revoke left the broker active")
	}
	if _, err := execP04Service(ctx, svc, sandboxID, "true", []string{"OPENAI_API_KEY=${proxy:openai}"}); err == nil {
		t.Fatal("service Exec succeeded after the sandbox-scoped credential was revoked")
	}
	if _, err := svc.Stop(ctx, sandboxID); err != nil {
		t.Fatalf("service Stop after revoke: %v", err)
	}
	if _, err := svc.Delete(ctx, sandboxID, false); err != nil {
		t.Fatalf("service Delete after revoke: %v", err)
	}
	deleted = true
	if _, err := state.GetSetting(ctx, proxyServiceSettingKey(sandboxID)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("service Delete retained proxy mapping: %v", err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("service acceptance exceeded operation deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Minute {
		t.Fatalf("service lifecycle acceptance exceeded 5 minutes: %s", elapsed)
	}
	t.Log("PASS: native sandbox-scoped keychain credential drove service Create/Stop/Start/Exec; env stayed placeholder-only; revoke closed broker and blocked Exec; Delete removed proxy metadata; credential absent from SQLite")
}

type p04ServiceInputs struct {
	containerd, ctr, shim, kernel, rootfs, helper, libkrun, gvproxy, daemon, image string
}

func getP04ServiceInputs(t *testing.T) p04ServiceInputs {
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
	image := os.Getenv("RHEIC_P04_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine:3.22"
	}
	return p04ServiceInputs{
		containerd: get("RHEIC_P04_CONTAINERD"), ctr: get("RHEIC_P04_CTR"),
		shim: get("RHEIC_P04_SHIM"), kernel: get("RHEIC_P04_KERNEL"),
		rootfs: get("RHEIC_P04_ROOTFS"), helper: get("RHEIC_P04_HELPER"),
		libkrun: get("RHEIC_P04_LIBKRUN"), gvproxy: get("RHEIC_P04_GVPROXY"),
		daemon: get("RHEIC_P04_DAEMON"), image: image,
	}
}

func waitP04ServiceContainerd(ctx context.Context, ctrPath, socket string, done <-chan struct{}) error {
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

func execP04Service(ctx context.Context, svc *Service, sandboxID, command string, env []string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var stdout, stderr strings.Builder
	code, err := svc.Exec(execCtx, sandboxID, rt.ExecRequest{
		Argv: []string{"/bin/sh", "-c", command}, Env: env, Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil {
		return stdout.String(), err
	}
	if code != 0 {
		return stdout.String(), fmt.Errorf("guest command exited %d: %s", code, stderr.String())
	}
	return stdout.String(), nil
}

func waitP04ServiceHelper(ctx context.Context, svc *Service, sandboxID string) error {
	command := `/bin/sh -c 'i=0; while [ "$i" -lt 50 ]; do grep -Eq "^ *[0-9]+: 0100007F:0C38 +00000000:0000 +0A " /proc/net/tcp && exit 0; i=$((i + 1)); sleep 0.1; done; exit 1'`
	if _, err := execP04Service(ctx, svc, sandboxID, command, nil); err != nil {
		diagnostics, diagnosticErr := execP04Service(ctx, svc, sandboxID, `/bin/sh -c 'echo helper; ls -l /tmp/rheic-proxy-helper; echo tcp; cat /proc/net/tcp; echo tcp6; cat /proc/net/tcp6; echo fds; ls -l /proc/2/fd'`, nil)
		return fmt.Errorf("wait for guest proxy listener: %w; diagnostics=%q (diagnostic error: %v)", err, diagnostics, diagnosticErr)
	}
	return nil
}

func scanP04ServiceState(root string, needle []byte) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), string(needle)) {
			return errors.New("synthetic credential found in owned daemon state")
		}
		return nil
	})
}
