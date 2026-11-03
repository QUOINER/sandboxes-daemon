package oauthsession

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func TestNativeVaultSyntheticRoundTrip(t *testing.T) {
	if os.Getenv("RHEIC_TEST_NATIVE_VAULT") != "1" {
		t.Skip("native vault integration is opt-in")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	sink, err := NewNativeVaultSink("test-" + hex.EncodeToString(id[:]))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owned := false
	t.Cleanup(func() {
		if owned {
			if err := sink.Delete(ctx); err != nil {
				t.Errorf("cleanup owned test entry: %v", err)
			}
		}
	})
	if err := sink.Save(ctx, Tokens{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 300}); err != nil {
		t.Fatal(err)
	}
	owned = true
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.AccessToken != "synthetic-access" {
		t.Fatal("native vault roundtrip failed")
	}
	if err := sink.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	owned = false
	if _, _, err := sink.Load(ctx); err == nil {
		t.Fatal("test credential remains after deletion")
	}
}
