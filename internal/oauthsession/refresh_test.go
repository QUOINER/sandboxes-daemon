package oauthsession

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenManagerConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "synthetic-refresh" {
			t.Error("unexpected refresh request")
		}
		_, _ = fmt.Fprint(w, `{"access_token":"new-token","refresh_token":"new-refresh","token_type":"Bearer","expires_in":300}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "old-token", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	coordinator := NewRefreshCoordinator()
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", coordinator)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", coordinator)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := range 20 {
		selected := manager
		if i%2 != 0 {
			selected = second
		}
		wg.Go(func() {
			value, err := selected.AccessToken(context.Background())
			if err == nil && value != "new-token" {
				err = fmt.Errorf("unexpected access token")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls: %d", calls.Load())
	}
	stored, _, err := sink.Load(context.Background())
	if err != nil || stored.RefreshToken != "new-refresh" {
		t.Fatal("rotated refresh token not stored")
	}
	if stored.AccessToken != "new-token" {
		t.Fatal("refreshed access token not stored")
	}
	_, expiresAt, err := sink.Load(context.Background())
	if err != nil || time.Until(expiresAt) <= 30*time.Second {
		t.Fatal("refreshed token expiry was not persisted")
	}
	restarted, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", coordinator)
	if err != nil {
		t.Fatal(err)
	}
	value, err := restarted.AccessToken(context.Background())
	if err != nil || value != "new-token" || calls.Load() != 1 {
		t.Fatalf("manager restart did not use persisted fresh token: value_matches=%t calls=%d err=%v", value == "new-token", calls.Load(), err)
	}
}

func TestTokenManagerUsesFreshTokenWithoutRefreshing(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "synthetic-fresh-access", RefreshToken: "synthetic-fresh-refresh", TokenType: "Bearer", ExpiresIn: 300}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	value, err := manager.AccessToken(context.Background())
	if err != nil || value != "synthetic-fresh-access" || calls.Load() != 0 {
		t.Fatalf("fresh token path failed: value_matches=%t calls=%d err=%v", value == "synthetic-fresh-access", calls.Load(), err)
	}
}

func TestTokenManagerDeletesCredentialAfterInvalidGrant(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"synthetic-refresh-must-not-leak"}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider-invalid-grant")
	if err != nil {
		t.Fatal(err)
	}
	original := Tokens{AccessToken: "synthetic-old-access", RefreshToken: "synthetic-old-refresh", TokenType: "Bearer", ExpiresIn: 1}
	if err := sink.Save(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); !errors.Is(err, ErrOAuthReauthRequired) || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("provider error was not failed closed and redacted: %v", err)
	}
	if _, exists := vault.values[oauthVaultService+":provider-invalid-grant"]; exists {
		t.Fatal("invalid_grant did not clear locally unusable credentials")
	}
}

func TestTokenManagerRetainsCredentialAfterTransientFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":"temporarily_unavailable","error_description":"synthetic-refresh-must-not-leak"}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider-transient-error")
	if err != nil {
		t.Fatal(err)
	}
	original := Tokens{AccessToken: "synthetic-old-access", RefreshToken: "synthetic-old-refresh", TokenType: "Bearer", ExpiresIn: 1}
	if err := sink.Save(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("transient provider error was accepted or leaked: %v", err)
	}
	stored, _, err := sink.Load(context.Background())
	if err != nil || stored.AccessToken != original.AccessToken || stored.RefreshToken != original.RefreshToken {
		t.Fatal("transient failure destroyed retryable local credential state")
	}
}

func TestTokenManagerRefreshesExpiredAccessToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "synthetic-expired-refresh" {
			t.Error("unexpected expired-token refresh request")
		}
		_, _ = fmt.Fprint(w, `{"access_token":"synthetic-recovered-access","refresh_token":"synthetic-recovered-refresh","token_type":"Bearer","expires_in":300}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider-expired")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "synthetic-expired-access", RefreshToken: "synthetic-expired-refresh", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	value, err := manager.AccessToken(context.Background())
	if err != nil || value != "synthetic-recovered-access" || calls.Load() != 1 {
		t.Fatalf("expired token did not refresh: value_matches=%t calls=%d err=%v", value == "synthetic-recovered-access", calls.Load(), err)
	}
}

func TestLogoutWaitsForRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, `{"access_token":"new-token","refresh_token":"new-refresh","token_type":"Bearer","expires_in":300}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "old-token", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() { _, err := manager.AccessToken(context.Background()); refreshDone <- err }()
	<-started
	logoutDone := make(chan error, 1)
	go func() { logoutDone <- manager.Logout(context.Background()) }()
	close(release)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); err == nil {
		t.Fatal("credential survived logout")
	}
}

func TestTokenManagerRejectsUnknownExpiry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected refresh") }))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "synthetic-token", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); err == nil {
		t.Fatal("unknown token expiry accepted")
	}
}
