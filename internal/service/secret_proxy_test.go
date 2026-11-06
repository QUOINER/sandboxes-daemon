package service

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	core "github.com/rheic/sandboxes-core"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestStripProxyCreateEnv(t *testing.T) {
	filtered, serviceNames, err := stripProxyCreateEnv([]string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=${proxy:openai}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(serviceNames) != 1 || serviceNames[0] != "openai" || len(filtered) != 1 || filtered[0] != "PATH=/usr/bin" {
		t.Fatalf("filtered=%v services=%q", filtered, serviceNames)
	}
	for _, env := range [][]string{
		{"API_KEY=${proxy:openai}"},
		{"OPENAI_API_KEY=${proxy:unknown}"},
		{"OPENAI_API_KEY=${proxy:openai", "PATH=/bin"},
		{"OPENAI_API_KEY=${proxy:openai}", "OPENAI_BASE_URL=https://attacker.invalid"},
	} {
		if _, _, err := stripProxyCreateEnv(env); err == nil {
			t.Errorf("accepted invalid proxy create env %v", env)
		}
	}
	filtered, serviceNames, err = stripProxyCreateEnv([]string{
		"OPENAI_API_KEY=${proxy:openai}", "ANTHROPIC_API_KEY=${proxy:anthropic}",
	})
	if err != nil || len(filtered) != 0 || strings.Join(serviceNames, ",") != "anthropic,openai" {
		t.Fatalf("multiple services filtered=%v services=%v err=%v", filtered, serviceNames, err)
	}
	filtered, serviceNames, err = stripProxyCreateEnv([]string{
		"GH_TOKEN=${proxy:github}", "RHEIC_PROXY_GITHUB_WEB=${proxy:github-web}",
		"RHEIC_PROXY_GITHUB_COPILOT_API=${proxy:github-copilot-api}",
	})
	if err != nil || len(filtered) != 0 || strings.Join(serviceNames, ",") != "github,github-copilot-api,github-web" {
		t.Fatalf("fixed host aliases filtered=%v services=%v err=%v", filtered, serviceNames, err)
	}
	filtered, serviceNames, err = stripProxyCreateEnv([]string{"OPENAI_API_KEY=${oauth:openai}", "PATH=/bin"})
	if err != nil || len(filtered) != 1 || filtered[0] != "PATH=/bin" || strings.Join(serviceNames, ",") != "openai-oauth" {
		t.Fatalf("OAuth proxy env filtered=%v services=%v err=%v", filtered, serviceNames, err)
	}
	for _, env := range [][]string{
		{"ANTHROPIC_API_KEY=${oauth:openai}"},
		{"OPENAI_API_KEY=${oauth:anthropic}"},
		{"OPENAI_API_KEY=${oauth:openai}", "OPENAI_API_KEY=${proxy:openai}"},
		{"OPENAI_API_KEY=prefix${oauth:openai}"},
	} {
		if _, _, err := stripProxyCreateEnv(env); err == nil {
			t.Errorf("accepted invalid OAuth proxy env %v", env)
		}
	}
}

func TestProxyContractsUseProviderAPIBasePaths(t *testing.T) {
	for service, want := range map[string]string{
		"openai":       "http://127.0.0.1:3128/v1",
		"openai-oauth": "http://127.0.0.1:3128/v1",
		"mistral":      "http://127.0.0.1:43131/v1",
		"groq":         "http://127.0.0.1:43130/openai/v1",
		"openrouter":   "http://127.0.0.1:43132/api/v1",
		"xai":          "http://127.0.0.1:43133/v1",
		"anthropic":    "http://127.0.0.1:43129",
		"google":       "http://127.0.0.1:43134",
	} {
		contract, ok := proxyContract(service)
		if !ok || contract.baseURL != want {
			t.Errorf("proxy contract %q = %+v, want base URL %q", service, contract, want)
		}
	}
	google, ok := proxyContract("google")
	if !ok || google.credentialEnv != "GEMINI_API_KEY" || google.baseURLEnv != "GOOGLE_GEMINI_BASE_URL" || google.upstreamHost != "generativelanguage.googleapis.com" {
		t.Fatalf("Google proxy contract=%+v, valid=%t", google, ok)
	}
}

func TestAgentCredentialAliasesHaveFixedHostsAndCredentialScopes(t *testing.T) {
	want := map[string]struct {
		host    string
		key     string
		service string
	}{
		"github":             {"api.github.com", "GH_TOKEN", githubCredentialService},
		"github-web":         {"github.com", "RHEIC_PROXY_GITHUB_WEB", githubCredentialService},
		"github-raw":         {"raw.githubusercontent.com", "RHEIC_PROXY_GITHUB_RAW", githubCredentialService},
		"github-gist":        {"gist.github.com", "RHEIC_PROXY_GITHUB_GIST", githubCredentialService},
		"github-copilot":     {"copilot.github.com", "RHEIC_PROXY_GITHUB_COPILOT", githubCredentialService},
		"github-copilot-api": {"api.githubcopilot.com", "RHEIC_PROXY_GITHUB_COPILOT_API", githubCredentialService},
		"cursor":             {"api2.cursor.sh", "CURSOR_API_KEY", cursorCredentialService},
		"cursor-api3":        {"api3.cursor.sh", "RHEIC_PROXY_CURSOR_API3", cursorCredentialService},
		"cursor-repo42":      {"repo42.cursor.sh", "RHEIC_PROXY_CURSOR_REPO42", cursorCredentialService},
		"cursor-web":         {"cursor.com", "RHEIC_PROXY_CURSOR_WEB", cursorCredentialService},
		"droid":              {"api.factory.ai", "FACTORY_API_KEY", droidCredentialService},
		"droid-app":          {"app.factory.ai", "RHEIC_PROXY_DROID_APP", droidCredentialService},
		"droid-relay":        {"relay.factory.ai", "RHEIC_PROXY_DROID_RELAY", droidCredentialService},
	}
	ports := make(map[uint16]string, len(want))
	for name, expected := range want {
		contract, ok := proxyContract(name)
		if !ok || contract.upstreamHost != expected.host || contract.credentialEnv != expected.key || contract.credentialService != expected.service {
			t.Errorf("contract %q = %+v, valid=%t; want host=%q env=%q secret=%q", name, contract, ok, expected.host, expected.key, expected.service)
			continue
		}
		if previous, exists := ports[contract.guestPort]; exists {
			t.Errorf("routes %q and %q share guest port %d", previous, name, contract.guestPort)
		}
		ports[contract.guestPort] = name
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
	if goruntime.GOOS == "windows" {
		if !errors.Is(err, core.ErrConflict) || backend.created != 0 {
			t.Fatalf("unsupported Windows proxy was not rejected before runtime start: err=%v created=%d", err, backend.created)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if backend.lastConfig.ProxyPort != proxySocketPort || backend.lastConfig.ProxySocket == "" ||
		backend.proxyGuestPort != 3128 || backend.proxyHelperPath != helperPath || backend.proxyServiceHost != "api.openai.com" {
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
	if !containsEnv(backend.lastExec.Env, "OPENAI_API_KEY=rheic-proxy-placeholder") || !containsEnv(backend.lastExec.Env, "OPENAI_BASE_URL=http://127.0.0.1:3128/v1") {
		t.Fatalf("proxy environment contract=%v", backend.lastExec.Env)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSetting(ctx, proxyServiceSettingKey(op.SandboxID)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("proxy mapping remains after delete: %v", err)
	}
}

func TestSandboxSupportsMultipleIsolatedServiceSecrets(t *testing.T) {
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
	manager := secretproxy.New()
	svc.SetSecretProxyManager(manager)
	svc.SetSecretProxyRuntime(helperPath, "/tmp")
	t.Cleanup(func() { _ = manager.Close() })
	for name, value := range map[string]string{"openai": "synthetic-openai-key", "anthropic": "synthetic-anthropic-key"} {
		if _, err := svc.SetServiceSecret(ctx, name, servicesecrets.ScopeGlobal, "", []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	op, err := svc.Create(ctx, CreateRequest{
		Name: "multi-proxy-run", Image: "alpine:3.22",
		Env: map[string]string{
			"OPENAI_API_KEY":     "${proxy:openai}",
			"ANTHROPIC_API_KEY":  "${proxy:anthropic}",
			"SAFE_LITERAL_VALUE": "not-a-secret",
		},
	})
	if goruntime.GOOS == "windows" {
		if !errors.Is(err, core.ErrConflict) || backend.created != 0 {
			t.Fatalf("unsupported Windows proxy was not rejected before runtime start: err=%v created=%d", err, backend.created)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(backend.proxyRouteArgs, ",") != "anthropic=api.anthropic.com:43129,openai=api.openai.com:3128" {
		t.Fatalf("runtime routes=%v", backend.proxyRouteArgs)
	}
	if strings.Contains(strings.Join(backend.lastConfig.Env, "\n"), "synthetic-") || len(backend.lastConfig.Env) != 1 || backend.lastConfig.Env[0] != "SAFE_LITERAL_VALUE=not-a-secret" {
		t.Fatalf("secret refs or values entered runtime env: %v", backend.lastConfig.Env)
	}
	if got, err := st.GetSetting(ctx, proxyServiceSettingKey(op.SandboxID)); err != nil || got != "anthropic,openai" {
		t.Fatalf("persisted proxy services=%q err=%v", got, err)
	}
	if _, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"/bin/true"}, Env: []string{
		"OPENAI_API_KEY=${proxy:openai}", "ANTHROPIC_API_KEY=${proxy:anthropic}",
	}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"OPENAI_API_KEY=rheic-proxy-placeholder",
		"OPENAI_BASE_URL=http://127.0.0.1:3128/v1",
		"ANTHROPIC_API_KEY=rheic-proxy-placeholder",
		"ANTHROPIC_BASE_URL=http://127.0.0.1:43129",
	} {
		if !containsEnv(backend.lastExec.Env, want) {
			t.Errorf("exec environment missing %q: %v", want, backend.lastExec.Env)
		}
	}
	if strings.Contains(strings.Join(backend.lastExec.Env, "\n"), "synthetic-") {
		t.Fatalf("secret value entered exec environment: %v", backend.lastExec.Env)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
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
