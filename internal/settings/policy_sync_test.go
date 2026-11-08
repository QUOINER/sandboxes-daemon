package settings

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/policysync"
)

func TestPolicySyncSettingsDefaultOff(t *testing.T) {
	values, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if values.PolicySyncURL != "" || values.PolicySyncOrg != "" || values.PolicySyncPublicKeyFile != "" || values.PolicySyncTokenFile != "" || values.PolicySyncInterval != 0 {
		t.Fatalf("policy sync defaults = %+v", values)
	}
}

func TestPolicySyncSettingsValid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("settings mode checks are covered on Unix")
	}
	body := `policy_sync.url = "https://control.example.test"
policy_sync.org = "acme.example"
policy_sync.public_key_file = "/etc/rheic/policy.public"
policy_sync.token_file = "/etc/rheic/policy.token"
policy_sync.interval = "90s"
`
	values, err := Load(writeSettingsFile(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if values.PolicySyncURL != "https://control.example.test" || values.PolicySyncOrg != "acme.example" ||
		values.PolicySyncPublicKeyFile != "/etc/rheic/policy.public" || values.PolicySyncTokenFile != "/etc/rheic/policy.token" ||
		values.PolicySyncInterval != 90*time.Second {
		t.Fatalf("policy sync values = %+v", values)
	}
}

func TestPolicySyncSettingsFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("settings mode checks are covered on Unix")
	}
	valid := `policy_sync.url = "https://control.example.test"
policy_sync.org = "acme.example"
policy_sync.public_key_file = "/etc/rheic/policy.public"
policy_sync.token_file = "/etc/rheic/policy.token"
`
	cases := map[string]string{
		"missing URL":           strings.ReplaceAll(valid, `policy_sync.url = "https://control.example.test"`+"\n", ""),
		"missing org":           strings.ReplaceAll(valid, `policy_sync.org = "acme.example"`+"\n", ""),
		"missing public key":    strings.ReplaceAll(valid, `policy_sync.public_key_file = "/etc/rheic/policy.public"`+"\n", ""),
		"missing token":         strings.ReplaceAll(valid, `policy_sync.token_file = "/etc/rheic/policy.token"`+"\n", ""),
		"interval only":         `policy_sync.interval = "5m"`,
		"http URL":              strings.Replace(valid, "https://", "http://", 1),
		"URL path":              strings.Replace(valid, `"https://control.example.test"`, `"https://control.example.test/api"`, 1),
		"URL query":             strings.Replace(valid, `"https://control.example.test"`, `"https://control.example.test?x=1"`, 1),
		"URL userinfo":          strings.Replace(valid, `"https://control.example.test"`, `"https://user@control.example.test"`, 1),
		"invalid org":           strings.Replace(valid, `"acme.example"`, `"../acme"`, 1),
		"interval too short":    valid + `policy_sync.interval = "29s"` + "\n",
		"interval too long":     valid + `policy_sync.interval = "25h"` + "\n",
		"interval not duration": valid + `policy_sync.interval = "often"` + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeSettingsFile(t, content)); err == nil {
				t.Fatal("invalid policy sync settings accepted")
			}
		})
	}
}

func TestPolicySyncIntervalBounds(t *testing.T) {
	for _, interval := range []time.Duration{policysync.MinInterval, policysync.MaxInterval} {
		if err := policysync.ValidateInterval(interval); err != nil {
			t.Fatalf("bound %s rejected: %v", interval, err)
		}
	}
	for _, interval := range []time.Duration{0, time.Second, policysync.MinInterval - time.Second, policysync.MaxInterval + time.Second} {
		if err := policysync.ValidateInterval(interval); err == nil {
			t.Fatalf("out-of-range interval %s accepted", interval)
		}
	}
}
