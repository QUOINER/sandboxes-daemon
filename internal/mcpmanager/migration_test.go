package mcpmanager

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	core "github.com/rheic/sandboxes-core"
)

const legacyRegistryFixture = `[
 {"name":"legacy-auth","transport":"remote","url":"https://mcp.example.test/auth","headers":{"Authorization":"Bearer legacy-synthetic-token"}},
 {"name":"legacy-cookie","transport":"remote","url":"https://mcp.example.test/cookie","headers":{"Cookie":"session=legacy-synthetic-cookie","X-Custom":"legacy-synthetic-custom"}},
 {"name":"legacy-headerless","transport":"remote","url":"https://mcp.example.test/plain"},
 {"name":"legacy-vault","transport":"remote","url":"https://mcp.example.test/vault","secret_headers":{"Authorization":"Bearer ${token}"}}
]`

func TestLegacyRegistryMigrationStripsRemoteStaticHeaders(t *testing.T) {
	ctx := context.Background()
	state := &memoryMCPState{values: map[string]string{registrySettingKey: legacyRegistryFixture}}
	manager, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()

	names := make(map[string]bool)
	for _, summary := range manager.List() {
		names[summary.Name] = true
	}
	for _, name := range []string{"legacy-auth", "legacy-cookie", "legacy-headerless", "legacy-vault"} {
		if !names[name] {
			t.Fatalf("migration lost record %q: %+v", name, manager.List())
		}
	}

	stored, err := state.GetSetting(ctx, registrySettingKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"legacy-synthetic-token", "legacy-synthetic-cookie", "legacy-synthetic-custom"} {
		if strings.Contains(stored, canary) {
			t.Fatalf("migration persisted legacy header value %q: %s", canary, stored)
		}
	}
	for _, marker := range []string{`"legacy-headerless"`, `"legacy-vault"`, `${token}`, `"https://mcp.example.test/plain"`} {
		if !strings.Contains(stored, marker) {
			t.Fatalf("migration lost record data %q: %s", marker, stored)
		}
	}
	var items []Server
	if err := json.Unmarshal([]byte(stored), &items); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if len(item.Headers) != 0 {
			t.Fatalf("migration retained remote static headers for %q", item.Name)
		}
	}
	version, err := state.GetSetting(ctx, registrySchemaSettingKey)
	if err != nil || version != "3" {
		t.Fatalf("schema version = %q err=%v", version, err)
	}

	// A second startup must be safe and must not rewrite the sanitized data.
	reloaded, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reloaded.Close() }()
	again, err := state.GetSetting(ctx, registrySettingKey)
	if err != nil || again != stored {
		t.Fatalf("repeated startup rewrote registry: before=%q after=%q err=%v", stored, again, err)
	}
	if got := reloaded.List(); len(got) != 4 {
		t.Fatalf("repeated startup lost records: %+v", got)
	}
}

func TestLegacyRegistryMigrationFailsClosedWhenPersistenceFails(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		failKey string
	}{
		{name: "sanitized registry write", failKey: registrySettingKey},
		{name: "schema marker write", failKey: registrySchemaSettingKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &failingWriteState{
				values:  map[string]string{registrySettingKey: legacyRegistryFixture},
				failKey: tc.failKey,
			}
			if _, err := New(ctx, state); err == nil {
				t.Fatal("startup succeeded after migration persistence failure")
			} else if strings.Contains(err.Error(), "legacy-synthetic") {
				t.Fatalf("migration error exposed a legacy value: %v", err)
			}
		})
	}
}

func TestSchemaV2StaticHeadersAreMigratedAndNeverAccepted(t *testing.T) {
	ctx := context.Background()
	legacy := `[{"name":"v2-static","transport":"remote","url":"https://mcp.example.test/mcp","headers":{"X-Session":"synthetic-credential"}}]`
	state := &memoryMCPState{values: map[string]string{registrySchemaSettingKey: "2", registrySettingKey: legacy}}
	manager, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	stored, err := state.GetSetting(ctx, registrySettingKey)
	if err != nil || strings.Contains(stored, "synthetic-credential") {
		t.Fatalf("schema-v2 migration retained static credential: stored=%q err=%v", stored, err)
	}
	version, err := state.GetSetting(ctx, registrySchemaSettingKey)
	if err != nil || version != "3" {
		t.Fatalf("schema version = %q err=%v", version, err)
	}
	manager.SetRemoteAllowlist([]string{"mcp.example.test"})
	if _, err := manager.RegisterRemote(ctx, "new-static", "https://mcp.example.test/mcp", map[string]string{"X-Session": "synthetic-credential"}, nil); err == nil {
		t.Fatal("new static header registration was accepted")
	}

	reloaded, err := New(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reloaded.Close() }()
	again, err := state.GetSetting(ctx, registrySettingKey)
	if err != nil || again != stored {
		t.Fatalf("later startup rewrote sanitized registry: before=%q after=%q err=%v", stored, again, err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Name != "v2-static" {
		t.Fatalf("later startup lost migrated record: %+v", got)
	}
}

func TestNewerRegistrySchemaFailsClosed(t *testing.T) {
	ctx := context.Background()
	state := &memoryMCPState{values: map[string]string{registrySchemaSettingKey: "4"}}
	if _, err := New(ctx, state); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("newer schema err = %v", err)
	}
}

func TestSanitizeRegistrySettingScrubsLegacyValuesIdempotently(t *testing.T) {
	sanitized, err := SanitizeRegistrySetting(legacyRegistryFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"legacy-synthetic-token", "legacy-synthetic-cookie", "legacy-synthetic-custom"} {
		if strings.Contains(sanitized, canary) {
			t.Fatalf("backup sanitizer retained legacy value %q", canary)
		}
	}
	for _, marker := range []string{`"legacy-auth"`, `"legacy-headerless"`, `"legacy-vault"`, `${token}`} {
		if !strings.Contains(sanitized, marker) {
			t.Fatalf("backup sanitizer lost registry data %q: %s", marker, sanitized)
		}
	}
	again, err := SanitizeRegistrySetting(sanitized)
	if err != nil || again != sanitized {
		t.Fatalf("backup sanitizer is not idempotent: err=%v changed=%v", err, again != sanitized)
	}
	clean := `[{"name":"clean","transport":"remote","url":"https://mcp.example.test/mcp"}]`
	if got, err := SanitizeRegistrySetting(clean); err != nil || got != clean {
		t.Fatalf("already-clean backup changed: %q err=%v", got, err)
	}
}

type failingWriteState struct {
	values  map[string]string
	failKey string
}

func (s *failingWriteState) GetSetting(_ context.Context, key string) (string, error) {
	value, ok := s.values[key]
	if !ok {
		return "", core.ErrNotFound
	}
	return value, nil
}

func (s *failingWriteState) SetSetting(_ context.Context, key, value string) error {
	if key == s.failKey {
		return errors.New("synthetic persistence failure")
	}
	s.values[key] = value
	return nil
}
