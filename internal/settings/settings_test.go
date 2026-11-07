package settings

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadDefaultsAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	values, err := Load(path)
	if err != nil || values.DNSUpstream != "" || values.DefaultPolicyProfile != "" || values.DefaultCPUs != 0 || values.DefaultMemoryMiB != 0 || values.DockerVolumeSize != "" || len(values.MCPRemoteAllowedHosts) != 0 {
		t.Fatalf("missing file = %+v, %v", values, err)
	}
	body := `# host settings
dns_upstream = "1.1.1.1:53"
default_policy_profile = "balanced"
default_cpus = 4
default_memory_mib = 2048
docker_volume_size = "20g"
mcp_remote_allowed_hosts = "mcp.example.com,api.example.com"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err = Load(path)
	if runtime.GOOS == "windows" {
		if err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Fatalf("Load error = %v; expected fail-closed ACL rejection", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if values.DNSUpstream != "1.1.1.1:53" || values.DefaultPolicyProfile != "balanced" ||
		values.DefaultCPUs != 4 || values.DefaultMemoryMiB != 2048 || values.DockerVolumeSize != "20g" ||
		strings.Join(values.MCPRemoteAllowedHosts, ",") != "mcp.example.com,api.example.com" {
		t.Fatalf("values=%+v", values)
	}
}

func TestParseHostListFailsClosed(t *testing.T) {
	for _, value := range []string{"*.example.com", "127.0.0.1", "example.com,,api.example.com", "example.com,EXAMPLE.com", "-bad.example.com", "example.com:8443"} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseHostList(value); err == nil {
				t.Fatalf("accepted invalid host list %q", value)
			}
		})
	}
}

func TestLoadRejectsUnsafeAndUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.toml")
	if err := os.WriteFile(path, []byte("unknown = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Fatalf("Load error = %v; expected fail-closed ACL rejection", err)
		}
		return
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("unknown key error=%v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("permissions error=%v", err)
	}
}
