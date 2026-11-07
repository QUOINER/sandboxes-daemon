package servicesecrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

type fakeBackend struct{ items map[string]string }

func (f *fakeBackend) Set(service, account, secret string) error {
	f.items[service+"/"+account] = secret
	return nil
}
func (f *fakeBackend) Get(service, account string) (string, error) {
	value, ok := f.items[service+"/"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}
func (f *fakeBackend) Delete(service, account string) error {
	key := service + "/" + account
	if _, ok := f.items[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.items, key)
	return nil
}

func TestStoreRoundTripAndScopes(t *testing.T) {
	backend := &fakeBackend{items: make(map[string]string)}
	store, err := NewStore(NativeVault{Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	summary, err := store.Save(ctx, "openai", ScopeSandbox, "dev", []byte("sk-synthetic"))
	if err != nil || summary.Scope != ScopeSandbox || summary.SandboxName != "dev" {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	value, err := store.Load(ctx, "openai", ScopeSandbox, "dev")
	if err != nil || string(value) != "sk-synthetic" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if _, err := store.Load(ctx, "openai", ScopeGlobal, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope load err=%v", err)
	}
	removed, err := store.Delete(ctx, "openai", ScopeSandbox, "dev")
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
}

func TestMCPHeaderSecretUsesExactGlobalVaultKey(t *testing.T) {
	backend := &fakeBackend{items: make(map[string]string)}
	store, err := NewStore(NativeVault{Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "mcp:CaseSensitive.Server:api_token"
	if _, err := store.Save(ctx, key, ScopeGlobal, "", []byte("synthetic-mcp-secret")); err != nil {
		t.Fatal(err)
	}
	secret, err := store.Resolve(ctx, key, ScopeGlobal, "")
	if err != nil || string(secret) != "synthetic-mcp-secret" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	clear(secret)
	if _, err := store.Save(ctx, key, ScopeSandbox, "owned-fixture", []byte("x")); err == nil {
		t.Fatal("accepted sandbox-scoped MCP header secret")
	}
	for _, invalid := range []string{"mcp:../server:token", "mcp:server:../token", "mcp:server:token:extra", "MCP:server:token"} {
		if _, err := store.Save(ctx, invalid, ScopeGlobal, "", []byte("x")); err == nil {
			t.Errorf("accepted invalid MCP vault key %q", invalid)
		}
	}
}

func TestStoreRejectsUnsafeInputs(t *testing.T) {
	store, _ := NewStore(NativeVault{Backend: &fakeBackend{items: make(map[string]string)}})
	ctx := context.Background()
	for _, tc := range []struct {
		service string
		scope   Scope
		sandbox string
		value   []byte
	}{
		{"unknown", ScopeGlobal, "", []byte("x")},
		{"openai", ScopeSandbox, "", []byte("x")},
		{"openai", ScopeGlobal, "dev", []byte("x")},
		{"openai", ScopeGlobal, "", nil},
		{"openai", ScopeGlobal, "", []byte{0xff}},
	} {
		if _, err := store.Save(ctx, tc.service, tc.scope, tc.sandbox, tc.value); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	if !validService("openai") {
		t.Fatal("openai not registered")
	}
	if strings.Contains(account(Summary{Service: "openai", Scope: ScopeGlobal}), "secret") {
		t.Fatal("unexpected account")
	}
}
