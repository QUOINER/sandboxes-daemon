package settings

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeSettingsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOrgPolicySettingsDefaultOff(t *testing.T) {
	values, err := Load(filepath.Join(t.TempDir(), "missing-settings.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if values.OrgPolicyEnforce || values.OrgPolicyOrg != "" {
		t.Fatalf("organization policy defaults = %+v", values)
	}
}

func TestOrgPolicySettingsValid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("settings mode checks are covered on Unix")
	}
	values, err := Load(writeSettingsFile(t, "org_policy.enforce = true\norg_policy.org = \"acme.example\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !values.OrgPolicyEnforce || values.OrgPolicyOrg != "acme.example" {
		t.Fatalf("values = %+v", values)
	}

	values, err = Load(writeSettingsFile(t, "org_policy.enforce = false\norg_policy.org = \"acme.example\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if values.OrgPolicyEnforce || values.OrgPolicyOrg != "acme.example" {
		t.Fatalf("disabled values = %+v", values)
	}
}

func TestOrgPolicySettingsFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("settings mode checks are covered on Unix")
	}
	for name, content := range map[string]string{
		"enforce without org": "org_policy.enforce = true\n",
		"invalid org":         "org_policy.enforce = true\norg_policy.org = \"../acme\"\n",
		"empty org":           "org_policy.enforce = true\norg_policy.org = \"\"\n",
		"invalid bool":        "org_policy.enforce = yes\norg_policy.org = \"acme\"\n",
		"numeric bool":        "org_policy.enforce = 1\norg_policy.org = \"acme\"\n",
		"unknown key":         "org_policy.enforced = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeSettingsFile(t, content))
			if err == nil {
				t.Fatal("invalid organization policy settings accepted")
			}
			if name == "unknown key" && !strings.Contains(err.Error(), "unknown key") {
				t.Fatalf("unknown key error = %v", err)
			}
		})
	}
}
