package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KLORQ/sandboxes-daemon/internal/oauthsession"
	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

func TestDeviceAccountLoginStoresAndLogoutRevokesHostTokens(t *testing.T) {
	var approved atomic.Bool
	var revokeCalls atomic.Int32
	var patCalls atomic.Int32
	var revokeFail atomic.Bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		switch r.URL.Path {
		case "/device":
			_, _ = fmt.Fprintf(w, `{"device_code":"synthetic-code","user_code":"ABCD","verification_uri_complete":%q,"expires_in":60,"interval":1}`, server.URL+"/activate?user_code=ABCD")
		case "/token":
			if r.Form.Get("device_code") != "synthetic-code" {
				t.Error("device code mismatch")
			}
			if !approved.Load() {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`, syntheticHubAccessToken())
		case "/pat":
			patCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer "+syntheticHubAccessToken() {
				t.Error("PAT request did not use the OAuth access token")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"token":"synthetic-hub-pat"}}`))
		case "/revoke":
			if r.Form.Get("token") != "synthetic-refresh" || r.Form.Get("client_id") != "synthetic-client" {
				t.Error("revoke request did not use the stored refresh token")
			}
			revokeCalls.Add(1)
			if revokeFail.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	vault := &memoryOAuthVault{values: make(map[string]string)}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), t.TempDir()+"/oauth-test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.SetOAuthVault(vault)
	svc.SetRegistryCredentialStore(registryStore)
	svc.SetOAuthProviders(map[string]OAuthProvider{"docker": {
		Device:         oauthsession.DeviceProvider{DeviceEndpoint: server.URL + "/device", TokenEndpoint: server.URL + "/token", PATEndpoint: server.URL + "/pat", ClientID: "synthetic-client", Audience: server.URL, Transport: transport},
		RevokeEndpoint: server.URL + "/revoke", DeviceHandoff: func(_ context.Context, code, _ string) error {
			if code != "ABCD" {
				t.Errorf("unexpected user code %q", code)
			}
			approved.Store(true)
			return nil
		},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.LoginAccount(ctx, "docker"); err != nil {
		t.Fatal(err)
	}
	sink, err := oauthsession.NewVaultSink(vault, "docker")
	if err != nil {
		t.Fatal(err)
	}
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.AccessToken != syntheticHubAccessToken() {
		t.Fatal("account token was not persisted in the host vault")
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		credential, err := registryStore.Load(ctx, "docker.io", scope, "")
		if err != nil || string(credential.Password) != "synthetic-hub-pat" || credential.Username != "fixture-user" {
			t.Fatalf("Docker Hub credential was not saved for %s: %v", scope, err)
		}
		clear(credential.Password)
	}
	if err := svc.LoginAccount(ctx, "docker"); !errors.Is(err, ErrOAuthCredentialConflict) {
		t.Fatalf("second login must refuse to overwrite credentials silently, got %v", err)
	}
	if patCalls.Load() != 1 {
		t.Fatalf("conflicting login must not mint another PAT, got %d calls", patCalls.Load())
	}
	unchanged, err := registryStore.Load(ctx, "docker.io", registrycredentials.ScopeAllSandboxes, "")
	if err != nil || string(unchanged.Password) != "synthetic-hub-pat" {
		t.Fatal("conflicting account login changed existing registry credentials")
	}
	clear(unchanged.Password)
	revokeFail.Store(true)
	if removed, err := svc.LogoutAccount(ctx, "docker"); !removed || !errors.Is(err, ErrOAuthRevocationFailed) {
		t.Fatalf("failed provider revoke should retain retryable state: removed=%t err=%v", removed, err)
	}
	if _, _, err := sink.Load(ctx); err != nil {
		t.Fatalf("refresh token was removed before successful provider revoke: %v", err)
	}
	revokeFail.Store(false)
	removed, err := svc.LogoutAccount(ctx, "docker")
	if err != nil || !removed || revokeCalls.Load() != 2 {
		t.Fatalf("logout removed=%t revoke calls=%d err=%v", removed, revokeCalls.Load(), err)
	}
	if _, _, err := sink.Load(ctx); !errors.Is(err, oauthsession.ErrNoTokens) {
		t.Fatalf("tokens remain after logout: %v", err)
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		if _, err := registryStore.Load(ctx, "docker.io", scope, ""); !errors.Is(err, registrycredentials.ErrNotFound) {
			t.Fatalf("Docker Hub credentials remain after logout for %s: %v", scope, err)
		}
	}
	removed, err = svc.LogoutAccount(ctx, "docker")
	if err != nil || removed || revokeCalls.Load() != 2 {
		t.Fatalf("second logout removed=%t revoke calls=%d err=%v", removed, revokeCalls.Load(), err)
	}
}

type dockerPATRoundTripper func(*http.Request) (*http.Response, error)

func (f dockerPATRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestDockerHubPATLoginValidatesAndStoresOnlyPAT(t *testing.T) {
	vault := &memoryOAuthVault{values: make(map[string]string)}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), t.TempDir()+"/docker-pat-login.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	svc.SetOAuthVault(vault)
	svc.SetRegistryCredentialStore(registryStore)
	svc.SetDockerHubAuthTransport(dockerPATRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != oauthsession.DockerHubAuthEndpoint || req.Method != http.MethodPost {
			t.Fatalf("unexpected Docker Hub validation request: %s %s", req.Method, req.URL)
		}
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		defer clear(body)
		if !strings.Contains(string(body), `"identifier":"alice"`) || !strings.Contains(string(body), `"secret":"synthetic-pat"`) {
			t.Fatal("validation request did not contain supplied synthetic credentials")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic-bearer"}`))}, nil
	}))
	if err := svc.LoginDockerHubPAT(context.Background(), "alice", []byte("synthetic-pat")); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		credential, err := registryStore.Load(context.Background(), "docker.io", scope, "")
		if err != nil || credential.Username != "alice" || string(credential.Password) != "synthetic-pat" {
			t.Fatalf("stored credential scope=%s credential=%+v error=%v", scope, credential, err)
		}
		clear(credential.Password)
	}
	for key, value := range vault.values {
		if strings.HasPrefix(key, "com.klorq.oauth.v1/") && (strings.Contains(value, "synthetic-bearer") || strings.Contains(value, "synthetic-pat")) {
			t.Fatal("short-lived bearer or PAT was persisted in the OAuth account vault entry")
		}
	}
	if err := svc.LoginDockerHubPAT(context.Background(), "alice", []byte("synthetic-another-pat")); !errors.Is(err, ErrOAuthCredentialConflict) {
		t.Fatalf("second login must not overwrite existing Docker credentials, got %v", err)
	}
	svc.SetRegistryCredentialStore(nil)
	if removed, err := svc.LogoutAccount(context.Background(), "docker"); !removed || err == nil {
		t.Fatalf("logout must report incomplete cleanup when registry store is unavailable: removed=%t err=%v", removed, err)
	}
	svc.SetRegistryCredentialStore(registryStore)
	if removed, err := svc.LogoutAccount(context.Background(), "docker"); !removed || err != nil {
		t.Fatalf("logout retry failed: removed=%t err=%v", removed, err)
	}
	for _, scope := range []registrycredentials.Scope{registrycredentials.ScopeHostOnly, registrycredentials.ScopeAllSandboxes} {
		if _, err := registryStore.Load(context.Background(), "docker.io", scope, ""); !errors.Is(err, registrycredentials.ErrNotFound) {
			t.Fatalf("credential remained after logout retry: scope=%s err=%v", scope, err)
		}
	}
}

func syntheticHubAccessToken() string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"https://hub.docker.com":{"username":"fixture-user"}}`))
	return "eyJhbGciOiJub25lIn0." + payload + ".synthetic-signature"
}

type memoryOAuthVault struct {
	mu     sync.Mutex
	values map[string]string
}

func (v *memoryOAuthVault) Set(ctx context.Context, service, account, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	v.values[service+"/"+account] = value
	v.mu.Unlock()
	return nil
}

func (v *memoryOAuthVault) Get(ctx context.Context, service, account string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	value, ok := v.values[service+"/"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	return value, nil
}

func (v *memoryOAuthVault) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	key := service + "/" + account
	if _, ok := v.values[key]; !ok {
		return registrycredentials.ErrNotFound
	}
	delete(v.values, key)
	return nil
}

var _ oauthsession.Vault = (*memoryOAuthVault)(nil)
