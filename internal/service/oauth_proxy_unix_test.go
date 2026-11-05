//go:build !windows

package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/secretproxy"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

func TestOpenAIOAuthLogoutRevokesProxyBeforeProviderRequest(t *testing.T) {
	ctx := context.Background()
	vault := &memoryOAuthVault{values: make(map[string]string)}
	sink, err := oauthsession.NewVaultSink(vault, openAIServiceName)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(ctx, oauthsession.Tokens{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 60}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "oauth-proxy-logout.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	manager := secretproxy.New()
	defer func() { _ = manager.Close() }()
	proxyDir, err := os.MkdirTemp("", "rp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(proxyDir); err != nil {
			t.Errorf("remove owned OAuth proxy test directory: %v", err)
		}
	})
	if err := secretproxy.EnsurePrivateDir(proxyDir); err != nil {
		t.Fatal(err)
	}
	_, err = manager.StartUnixRoutes(ctx, "oauth-sandbox", map[string]secretproxy.RouteConfig{
		openAIOAuthRoute: {
			Service: secretproxy.Service{Upstream: "https://api.openai.com", Header: "Authorization", Prefix: "Bearer ", CredentialScope: "global-oauth",
				Credential: func(context.Context) ([]byte, error) { return []byte("synthetic-access"), nil }},
			Token: strings.Repeat("a", 64),
		},
	}, filepath.Join(proxyDir, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Has("oauth-sandbox", openAIOAuthRoute) {
		t.Fatal("OAuth proxy route was not started")
	}
	svc := New(st, nil)
	svc.SetOAuthVault(vault)
	svc.SetSecretProxyManager(manager)
	providerSawProxyRevoked := false
	svc.SetOAuthProviders(map[string]OAuthProvider{openAIServiceName: {
		RevokeToken: func(_ context.Context, token string) error {
			providerSawProxyRevoked = !manager.Has("oauth-sandbox", openAIOAuthRoute)
			if token != "synthetic-refresh" {
				t.Errorf("provider revoke received unexpected token %q", token)
			}
			return errors.New("synthetic provider unavailable")
		},
	}})
	removed, err := svc.LogoutAccount(ctx, openAIServiceName)
	if !removed || !errors.Is(err, ErrOAuthRevocationFailed) || !providerSawProxyRevoked {
		t.Fatalf("logout removed=%t providerSawRevoked=%t err=%v", removed, providerSawProxyRevoked, err)
	}
	if manager.Has("oauth-sandbox", openAIOAuthRoute) {
		t.Fatal("OAuth proxy route remains active after logout")
	}
}

func TestSandboxScopedRegistryLogoutDoesNotRevokeOtherSandboxProxy(t *testing.T) {
	ctx := context.Background()
	vault := &memoryOAuthVault{values: make(map[string]string)}
	credentials, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"registry-sandbox", "other-sandbox"} {
		if _, err := credentials.Save(ctx, registrycredentials.Credential{
			Registry: "docker.io", Username: "synthetic-user", Password: []byte("synthetic-token"),
			Scope: registrycredentials.ScopeSandbox, SandboxName: name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	manager := secretproxy.New()
	defer func() { _ = manager.Close() }()
	proxyDir, err := os.MkdirTemp("", "rp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(proxyDir); err != nil {
			t.Errorf("remove owned registry proxy test directory: %v", err)
		}
	})
	if err := secretproxy.EnsurePrivateDir(proxyDir); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"registry-sandbox", "other-sandbox"} {
		_, err = manager.StartUnixRoutes(ctx, name, map[string]secretproxy.RouteConfig{
			dockerHubProxyService: {
				Service: secretproxy.Service{Upstream: "https://registry-1.docker.io", CredentialScope: string(registrycredentials.ScopeSandbox)},
				Handler: http.NotFoundHandler(), Token: strings.Repeat(string(rune('b'+i)), 64),
			},
		}, filepath.Join(proxyDir, name+".sock"))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"registry-sandbox", "other-sandbox"} {
		if !manager.Has(name, dockerHubProxyService) {
			t.Fatalf("registry proxy route was not started for %s", name)
		}
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "registry-proxy-logout.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.SetRegistryCredentialStore(credentials)
	svc.SetSecretProxyManager(manager)
	removed, err := svc.LogoutRegistry(ctx, "docker.io", registrycredentials.ScopeSandbox, "registry-sandbox")
	if err != nil || !removed || manager.Has("registry-sandbox", dockerHubProxyService) || !manager.Has("other-sandbox", dockerHubProxyService) {
		t.Fatalf("registry logout removed=%t targetActive=%t otherActive=%t err=%v", removed,
			manager.Has("registry-sandbox", dockerHubProxyService), manager.Has("other-sandbox", dockerHubProxyService), err)
	}
}
