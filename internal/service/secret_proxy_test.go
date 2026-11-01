package service

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/KLORQ/sandboxes-core"
	runtime "github.com/KLORQ/sandboxes-runtime"

	"github.com/KLORQ/sandboxes-daemon/internal/secretproxy"
	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

func TestStripProxyCreateEnv(t *testing.T) {
	filtered, serviceName, err := stripProxyCreateEnv([]string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=${proxy:openai}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if serviceName != "openai" || len(filtered) != 1 || filtered[0] != "PATH=/usr/bin" {
		t.Fatalf("filtered=%v service=%q", filtered, serviceName)
	}
	for _, env := range [][]string{
		{"API_KEY=${proxy:openai}"},
		{"OPENAI_API_KEY=${proxy:unknown}"},
		{"OPENAI_API_KEY=${proxy:openai", "PATH=/bin"},
		{"OPENAI_API_KEY=${proxy:openai}", "ANTHROPIC_API_KEY=${proxy:anthropic}"},
		{"OPENAI_API_KEY=${proxy:openai}", "OPENAI_BASE_URL=https://attacker.invalid"},
	} {
		if _, _, err := stripProxyCreateEnv(env); err == nil {
			t.Errorf("accepted invalid proxy create env %v", env)
		}
	}
}

func TestProxyEnvironmentUsesHostBrokerAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(stateDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	helperPath := writeStaticProxyHelperFixture(t)
	secretVault := &fakeServiceSecretVault{items: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(secretVault)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	svc.SetSecretProxyManager(secretproxy.New())
	t.Cleanup(func() {
		_ = svc.secretProxies.Close()
		if backend.lastConfig.ProxySocket != "" {
			_ = secretproxy.RemovePrivateDir(filepath.Dir(backend.lastConfig.ProxySocket))
		}
	})
	svc.SetSecretProxyRuntime(helperPath, "/tmp")
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("sk-synthetic-proxy-secret")); err != nil {
		t.Fatal(err)
	}
	op, err := svc.Create(ctx, CreateRequest{
		Name:  "proxy-run",
		Image: "alpine:3.22",
		Env:   map[string]string{"OPENAI_API_KEY": "${proxy:openai}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if backend.lastConfig.ProxyPort != proxySocketPort || backend.lastConfig.ProxySocket == "" ||
		backend.proxyGuestPort != proxyGuestListenPort || backend.proxyHelperPath != helperPath || backend.proxyServiceHost != "api.openai.com" {
		t.Fatalf("runtime proxy config=%+v helper=%q guest_port=%d host=%q", backend.lastConfig, backend.proxyHelperPath, backend.proxyGuestPort, backend.proxyServiceHost)
	}
	if strings.Contains(strings.Join(backend.lastConfig.Env, "\n"), "proxy:openai") || strings.Contains(strings.Join(backend.lastConfig.Env, "\n"), "sk-synthetic-proxy-secret") {
		t.Fatalf("proxy reference or secret was baked into runtime env: %v", backend.lastConfig.Env)
	}
	if got, err := st.GetSetting(ctx, proxyServiceSettingKey(op.SandboxID)); err != nil || got != "openai" {
		t.Fatalf("persisted proxy service=%q err=%v", got, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(ctx, op.SandboxID, runtimeExecRequest("OPENAI_API_KEY=${proxy:openai}")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(ctx, op.SandboxID, runtimeExecRequest("OPENAI_API_KEY=${proxy:openai}")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(backend.lastExec.Env, "\n"), "sk-synthetic-proxy-secret") {
		t.Fatalf("secret value entered guest environment: %v", backend.lastExec.Env)
	}
	if !containsEnv(backend.lastExec.Env, "OPENAI_API_KEY=klorq-proxy-placeholder") || !containsEnv(backend.lastExec.Env, "OPENAI_BASE_URL=http://127.0.0.1:3128/v1") {
		t.Fatalf("proxy environment contract=%v", backend.lastExec.Env)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSetting(ctx, proxyServiceSettingKey(op.SandboxID)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("proxy mapping remains after delete: %v", err)
	}
}

func runtimeExecRequest(entry string) runtime.ExecRequest {
	return runtime.ExecRequest{Argv: []string{"/bin/true"}, Env: []string{entry}}
}

func containsEnv(env []string, expected string) bool {
	for _, entry := range env {
		if entry == expected {
			return true
		}
	}
	return false
}

func writeStaticProxyHelperFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy-helper")
	data := make([]byte, 64)
	copy(data[:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4], data[5], data[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(data[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(data[52:54], 64)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
