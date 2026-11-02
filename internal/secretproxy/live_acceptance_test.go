//go:build klorq_p04_live

package secretproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	daemonnetwork "github.com/KLORQ/sandboxes-daemon/internal/network"
	gateway "github.com/KLORQ/sandboxes-gateway"
	rt "github.com/KLORQ/sandboxes-runtime"
	"github.com/KLORQ/sandboxes-runtime/ctr"
)

const liveSecret = "klorq-p04-synthetic-fixture-credential"

func TestP04LiveVsockProxyAgainstControlledFixture(t *testing.T) {
	testStarted := time.Now()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("P-04 owned-VM acceptance currently requires macOS ARM64")
	}
	inputs := getLiveInputs(t)
	root, err := os.MkdirTemp("/private/tmp", "ksbx-p04-vsock-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned acceptance directory: %v", err)
		}
	}()
	defer func() {
		if !t.Failed() {
			return
		}
		evidenceDir := os.Getenv("KLORQ_P04_EVIDENCE_DIR")
		if evidenceDir == "" {
			return
		}
		if err := copyEvidenceFile(filepath.Join(root, "containerd.log"), filepath.Join(evidenceDir, "live-containerd-failure.log")); err != nil {
			t.Errorf("preserve owned containerd diagnostic: %v", err)
		}
		gatewayDir := filepath.Join(root, "run", "gateway")
		_ = filepath.WalkDir(gatewayDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".gateway.log") {
				return err
			}
			return copyEvidenceFile(path, filepath.Join(evidenceDir, "live-"+entry.Name()))
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
	containerd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+"/opt/homebrew/bin:/opt/homebrew/opt/e2fsprogs/sbin:/usr/bin:/bin", "LIBKRUN_PATH="+inputs.libkrun)
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

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	networkManager, err := gateway.New(gateway.Config{
		GVProxy: inputs.gvproxy, Supervisor: inputs.daemon, RunDir: filepath.Join(root, "run", "gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	networkAdapter := daemonnetwork.New(networkManager, filepath.Join(root, "run", "audit"))
	backend, err := ctr.NewBackend(ctr.Config{Socket: containerdSocket, CTR: inputs.ctr, Runtime: "io.containerd.nerdbox.v1", Snapshotter: "erofs", Platform: "linux/arm64"}, ctr.BackendOptions{Image: inputs.image, FIFODir: filepath.Join(root, "fifo"), Network: networkAdapter})
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
	if err := waitForContainerd(ctx, inputs.ctr, containerdSocket, containerdDone); err != nil {
		t.Fatalf("wait for owned containerd: %v (log %s)", err, filepath.Join(root, "containerd.log"))
	}

	var mu sync.Mutex
	fixtureCalls := 0
	fixtureAuth := ""
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fixtureCalls++
		fixtureAuth = r.Header.Get("Authorization")
		mu.Unlock()
		if r.URL.Path != "/v1/controlled" || r.Method != http.MethodGet {
			http.Error(w, "fixture route mismatch", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "controlled-upstream-ok")
	}))
	defer fixture.Close()

	manager := New()
	fixtureHostPort := strings.TrimPrefix(fixture.URL, "http://")
	var dialedAddress string
	manager.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialedAddress = address
		mu.Unlock()
		if address != fixtureHostPort {
			return nil, fmt.Errorf("controlled fixture dial denied for %q", address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, fixtureHostPort)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close host broker: %v", err)
		}
	}()

	serviceURL := fixture.URL
	serviceHost := strings.TrimPrefix(strings.TrimPrefix(serviceURL, "http://"), "https://")
	serviceHost, _, _ = strings.Cut(serviceHost, ":")
	if serviceHost != "127.0.0.1" {
		t.Fatalf("controlled fixture must bind loopback, got host %q", serviceHost)
	}
	nameA := "p04-proxy-a-" + shortNonce(t)
	tokenA := strings.Repeat("a", 64)
	tokenB := strings.Repeat("b", 64)
	proxyDirA := filepath.Join("/tmp", "kp4a-"+shortNonce(t))
	if err := os.Mkdir(proxyDirA, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(proxyDirA); err != nil {
			t.Errorf("remove owned VM A proxy directory: %v", err)
		}
	}()
	socketA := filepath.Join(proxyDirA, "p.sock")
	if _, err := manager.StartUnix(ctx, nameA, "openai", Service{Upstream: serviceURL, Header: "Authorization", Prefix: "Bearer "}, []byte(liveSecret), socketA, tokenA); err != nil {
		t.Fatal(err)
	}

	var owned []rt.Handle
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		for i := len(owned) - 1; i >= 0; i-- {
			h := owned[i]
			if err := backend.Stop(cleanupCtx, h, 3*time.Second); err != nil {
				t.Errorf("stop owned VM %q: %v", h.ID, err)
			}
			if err := backend.Delete(cleanupCtx, h); err != nil {
				t.Errorf("delete owned VM %q: %v", h.ID, err)
			}
		}
	}()

	cfgA := rt.Config{Name: nameA, Image: inputs.image, CPUs: 2, MemoryMiB: 1024, ProxyPort: 1027, ProxySocket: socketA, Env: []string{
		"OPENAI_API_KEY=klorq-proxy-placeholder",
		"OPENAI_BASE_URL=http://127.0.0.1:3128/v1",
	}}
	handleA, err := backend.CreateWithProxy(ctx, &cfgA, inputs.helper, 3128, serviceHost)
	if err != nil {
		t.Fatalf("create owned VM A with broker: %v", err)
	}
	owned = append(owned, handleA)

	checkEnv := `/bin/sh -c 'test "$OPENAI_API_KEY" = klorq-proxy-placeholder && test "$OPENAI_BASE_URL" = http://127.0.0.1:3128/v1'`
	if _, err := execInVM(ctx, backend, handleA, checkEnv); err != nil {
		t.Fatalf("VM A did not receive only proxy placeholder env: %v", err)
	}
	if err := waitForGuestHelper(ctx, backend, handleA); err != nil {
		t.Fatalf("VM A helper did not start: %v", err)
	}
	request := `/bin/sh -c 'wget -T 3 -q -O - --header="Authorization: Bearer $OPENAI_API_KEY" "$OPENAI_BASE_URL/controlled"'`
	output, err := execInVM(ctx, backend, handleA, request)
	if err != nil || output != "controlled-upstream-ok" {
		diagnostic, diagnosticErr := execInVM(ctx, backend, handleA, `/bin/sh -c 'printf "GET /v1/controlled HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" | busybox nc -w 2 127.0.0.1 3128 || true; ps; cat /proc/net/tcp; cat /proc/net/tcp6; ls -l /tmp/klorq-proxy-helper; ip addr show lo 2>/dev/null || true'`)
		mu.Lock()
		callsAtFailure := fixtureCalls
		dialAtFailure := dialedAddress
		mu.Unlock()
		t.Fatalf("VM A controlled proxy request failed (output=%q): %v; guest diagnostic (%v, fixture_calls=%d, dial=%q want=%q): %s", output, err, diagnosticErr, callsAtFailure, dialAtFailure, fixtureHostPort, diagnostic)
	}
	mu.Lock()
	callsAfterA, authAfterA := fixtureCalls, fixtureAuth
	mu.Unlock()
	if callsAfterA != 1 || authAfterA != "Bearer "+liveSecret {
		t.Fatalf("fixture observed unexpected request count/auth (calls=%d, auth_matches=%t)", callsAfterA, authAfterA == "Bearer "+liveSecret)
	}

	nameB := "p04-proxy-b-" + shortNonce(t)
	proxyDirB := filepath.Join("/tmp", "kp4b-"+shortNonce(t))
	if err := os.Mkdir(proxyDirB, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(proxyDirB); err != nil {
			t.Errorf("remove owned VM B proxy directory: %v", err)
		}
	}()
	cfgB := rt.Config{Name: nameB, Image: inputs.image, CPUs: 2, MemoryMiB: 1024, ProxyPort: 1027, ProxySocket: filepath.Join(proxyDirB, "p.sock"), Env: []string{
		"OPENAI_API_KEY=klorq-proxy-placeholder",
		"OPENAI_BASE_URL=http://127.0.0.1:3128/v1",
	}}
	handleB, err := backend.CreateWithProxy(ctx, &cfgB, inputs.helper, 3128, serviceHost)
	if err != nil {
		t.Fatalf("create owned VM B without a broker grant: %v", err)
	}
	owned = append(owned, handleB)
	if _, err := execInVM(ctx, backend, handleB, checkEnv); err != nil {
		t.Fatalf("VM B env check failed: %v", err)
	}
	if err := waitForGuestHelper(ctx, backend, handleB); err != nil {
		t.Fatalf("VM B helper did not start: %v", err)
	}
	expectPromptProxyFailure(t, ctx, backend, handleB, request, "VM B without a broker grant")
	mu.Lock()
	callsAfterB := fixtureCalls
	mu.Unlock()
	if callsAfterB != 1 {
		t.Fatalf("VM B without a grant reached upstream; fixture calls=%d", callsAfterB)
	}

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	expectPromptProxyFailure(t, ctx, backend, handleA, request, "VM A while broker is stopped")
	mu.Lock()
	callsWhileStopped := fixtureCalls
	mu.Unlock()
	if callsWhileStopped != 1 {
		t.Fatalf("request escaped while broker was stopped; fixture calls=%d", callsWhileStopped)
	}
	if _, err := manager.StartUnix(ctx, nameA, "openai", Service{Upstream: serviceURL, Header: "Authorization", Prefix: "Bearer "}, []byte(liveSecret), socketA, tokenB); err != nil {
		t.Fatalf("restart owned broker with rotated token: %v", err)
	}
	output, err = execInVM(ctx, backend, handleA, request)
	if err != nil || output != "controlled-upstream-ok" {
		t.Fatalf("VM A failed after broker restart/token rotation (output=%q): %v", output, err)
	}
	mu.Lock()
	callsAfterRestart := fixtureCalls
	mu.Unlock()
	if callsAfterRestart != 2 {
		t.Fatalf("broker restart caused a missing or duplicate request (fixture calls=%d, want=2)", callsAfterRestart)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	expectPromptProxyFailure(t, ctx, backend, handleA, request, "VM A after final broker shutdown")
	mu.Lock()
	callsAfterBrokerStop := fixtureCalls
	mu.Unlock()
	if callsAfterBrokerStop != 2 {
		t.Fatalf("request escaped after final broker shutdown; fixture calls=%d", callsAfterBrokerStop)
	}

	if err := scanForBytes(root, []byte(liveSecret)); err != nil {
		t.Fatalf("synthetic credential persisted in owned host state: %v", err)
	}
	if _, err := os.Lstat(socketA); !os.IsNotExist(err) {
		t.Fatalf("owned broker socket survived shutdown: %v", err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("live acceptance exceeded its operation deadline: %v", err)
	}
	if elapsed := time.Since(testStarted); elapsed >= 90*time.Second {
		t.Fatalf("live acceptance did not complete promptly (elapsed=%s)", elapsed)
	}
	t.Logf("PASS: VM A got controlled authenticated responses before/after broker restart; VM B denied; broker loss failed closed; token rotation worked; secret absent from guest env and owned host files; fixture calls=%d", callsAfterBrokerStop)
}

type liveTestInputs struct{ containerd, ctr, shim, kernel, rootfs, helper, libkrun, gvproxy, daemon, image string }

func getLiveInputs(t *testing.T) liveTestInputs {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Skipf("set %s to explicitly select the owned-VM test input", name)
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatalf("%s is unavailable: %v", name, err)
		}
		return value
	}
	image := os.Getenv("KLORQ_P04_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine:3.22"
	}
	return liveTestInputs{
		containerd: get("KLORQ_P04_CONTAINERD"), ctr: get("KLORQ_P04_CTR"),
		shim: get("KLORQ_P04_SHIM"), kernel: get("KLORQ_P04_KERNEL"),
		rootfs: get("KLORQ_P04_ROOTFS"), helper: get("KLORQ_P04_HELPER"),
		libkrun: get("KLORQ_P04_LIBKRUN"), gvproxy: get("KLORQ_P04_GVPROXY"),
		daemon: get("KLORQ_P04_DAEMON"), image: image,
	}
}

func waitForContainerd(ctx context.Context, ctrPath, socket string, containerdDone <-chan struct{}) error {
	for {
		cmd := exec.CommandContext(ctx, ctrPath, "--address", socket, "version")
		if err := cmd.Run(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-containerdDone:
			return fmt.Errorf("containerd exited before its socket became ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func execInVM(ctx context.Context, backend *ctr.Backend, handle rt.Handle, command string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := backend.ExecNative(execCtx, handle, rt.ExecRequest{
		Argv: []string{"/bin/sh", "-c", command}, Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil {
		return stdout.String(), err
	}
	if code != 0 {
		return stdout.String(), fmt.Errorf("guest command exit %d (stderr=%q)", code, stderr.String())
	}
	return stdout.String(), nil
}

func waitForGuestHelper(ctx context.Context, backend *ctr.Backend, handle rt.Handle) error {
	command := `/bin/sh -c 'i=0; while [ "$i" -lt 50 ]; do busybox nc -z -w 1 127.0.0.1 3128 2>/dev/null && exit 0; i=$((i + 1)); sleep 0.1; done; exit 1'`
	_, err := execInVM(ctx, backend, handle, command)
	return err
}

func expectPromptProxyFailure(t *testing.T, ctx context.Context, backend *ctr.Backend, handle rt.Handle, command, scenario string) {
	t.Helper()
	shortCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := execInVM(shortCtx, backend, handle, command); err == nil {
		t.Fatalf("%s unexpectedly succeeded", scenario)
	}
	if elapsed := time.Since(started); elapsed >= 7*time.Second {
		t.Fatalf("%s did not fail closed promptly (elapsed=%s)", scenario, elapsed)
	}
}

func shortNonce(t *testing.T) string {
	t.Helper()
	data := make([]byte, 4)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", data)
}

func scanForBytes(root string, needle []byte) error {
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
		if bytes.Contains(data, needle) {
			return fmt.Errorf("synthetic credential found in an owned file")
		}
		return nil
	})
}

func copyEvidenceFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o600)
}
