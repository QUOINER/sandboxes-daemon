//go:build darwin && rheic_p04_keychain_live

package servicesecrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func TestP04NativeKeychainScopedCredentialRoundTrip(t *testing.T) {
	ctx := context.Background()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	sandboxName := "p04-keychain-" + hex.EncodeToString(nonce[:])
	store, err := NewStore(NativeVault{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "openai", ScopeSandbox, sandboxName); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unique scoped keychain account already exists: %v", err)
	}

	const synthetic = "rheic-p04-keychain-synthetic-credential"
	if _, err := store.Save(ctx, "openai", ScopeSandbox, sandboxName, []byte(synthetic)); err != nil {
		t.Fatalf("save synthetic value in native host keychain: %v", err)
	}
	t.Cleanup(func() {
		deleted, err := store.Delete(context.Background(), "openai", ScopeSandbox, sandboxName)
		if err != nil {
			t.Errorf("delete owned synthetic keychain item: %v", err)
		} else if !deleted {
			t.Error("owned synthetic keychain item was missing during cleanup")
		}
	})

	got, err := store.Load(ctx, "openai", ScopeSandbox, sandboxName)
	if err != nil {
		t.Fatalf("load synthetic value from native host keychain: %v", err)
	}
	if string(got) != synthetic {
		t.Fatal("native host keychain returned a different synthetic value")
	}
	clear(got)
}
