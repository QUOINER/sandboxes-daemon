package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/rheic/sandboxes-runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/rheic/sandboxes-daemon/internal/oauthsession"
	"github.com/rheic/sandboxes-daemon/internal/registrycredentials"
	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type graceBackend struct{ grace time.Duration }

func (*graceBackend) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{}, nil
}
func (*graceBackend) Create(context.Context, runtime.Config) (runtime.Handle, error) {
	return runtime.Handle{ID: "fixture"}, nil
}
func (*graceBackend) Start(context.Context, runtime.Handle) error { return nil }
func (b *graceBackend) Stop(_ context.Context, _ runtime.Handle, grace time.Duration) error {
	b.grace = grace
	return nil
}
func (*graceBackend) Delete(context.Context, runtime.Handle) error { return nil }
func (*graceBackend) Handle(string) runtime.Handle                 { return runtime.Handle{ID: "fixture"} }

func TestStopPassesGraceToRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &graceBackend{}
	svc := service.New(st, backend)
	op, err := svc.Create(ctx, service.CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSandbox(svc).Stop(ctx, &localv1.StopRequest{Id: op.SandboxID, GraceSeconds: 23}); err != nil {
		t.Fatal(err)
	}
	if backend.grace != 23*time.Second {
		t.Fatalf("runtime grace = %s", backend.grace)
	}
}

func TestGRPCLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	svc := service.New(st, nil)
	localv1.RegisterSandboxServiceServer(grpcServer, NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, NewOperation(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sandboxes := localv1.NewSandboxServiceClient(conn)
	operations := localv1.NewOperationServiceClient(conn)

	versionResp, err := sandboxes.GetVersion(ctx, &localv1.GetVersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if versionResp.GetVersion() == "" || versionResp.GetApiVersion() == "" {
		t.Fatalf("version response = %+v", versionResp)
	}

	if _, err := sandboxes.Create(ctx, &localv1.CreateRequest{
		Name: "invalid-deny", Deny: []*localv1.NetworkRule{{Protocol: "tcp", Cidr: "192.0.2.0/24", Port: 65536}},
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid deny was not rejected: %v", err)
	}
	if _, err := sandboxes.Create(ctx, &localv1.CreateRequest{
		Name: "unsupported-oauth", OauthCredentials: []*localv1.OAuthCredential{{
			Service:        "fixture",
			TokenEndpoint:  &localv1.OAuthTokenEndpoint{Host: "auth.example.test", Path: "/oauth/token"},
			ResourceHosts:  []string{"api.example.test"},
			Sentinels:      &localv1.OAuthSentinels{AccessToken: "ACCESS_SENTINEL", RefreshToken: "REFRESH_SENTINEL"},
			CredentialFile: &localv1.OAuthCredentialFile{Path: "~/.fixture/credentials.json", StructureJson: `{"access_token":"{{.AccessToken}}"}`},
		}},
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unsupported custom OAuth declaration was not rejected: %v", err)
	}
	created, err := sandboxes.Create(ctx, &localv1.CreateRequest{
		Name: "dev", Deny: []*localv1.NetworkRule{{Protocol: "tcp", Cidr: "192.0.2.0/24", Port: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetOperation().GetState() != localv1.OperationState_OPERATION_STATE_DONE {
		t.Fatalf("create state = %s", created.GetOperation().GetState())
	}
	id := created.GetOperation().GetSandboxId()
	if _, err := sandboxes.UpdatePolicy(ctx, &localv1.UpdatePolicyRequest{Id: id}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("legacy policy replacement error = %v", err)
	}
	updated, err := sandboxes.MutatePolicy(ctx, &localv1.MutatePolicyRequest{
		Id: id, Action: "allow", Rule: &localv1.NetworkRule{Protocol: "tcp", Cidr: "192.0.2.0/24", Port: 443},
	})
	if err != nil || len(updated.GetSandbox().GetAllow()) != 1 {
		t.Fatalf("atomic policy mutation = %+v, %v", updated, err)
	}

	got, err := sandboxes.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_STOPPED {
		t.Fatalf("state = %s", got.GetSandbox().GetState())
	}
	if len(got.GetSandbox().GetDeny()) != 1 || got.GetSandbox().GetDeny()[0].GetPort() != 443 {
		t.Fatal("valid deny rule was not persisted")
	}

	list, err := sandboxes.List(ctx, &localv1.ListRequest{PageSize: 10})
	if err != nil || len(list.GetItems()) != 1 {
		t.Fatalf("list: %+v, %v", list, err)
	}

	if _, err := sandboxes.Start(ctx, &localv1.StartRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	got, err = sandboxes.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil || got.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_RUNNING {
		t.Fatalf("start: %+v, %v", got, err)
	}

	if _, err := sandboxes.Stop(ctx, &localv1.StopRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int64{-1, 3601} {
		if _, err := sandboxes.Stop(ctx, &localv1.StopRequest{Id: id, GraceSeconds: seconds}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid grace %d: %v", seconds, err)
		}
	}
	if _, err := sandboxes.Delete(ctx, &localv1.DeleteRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxes.Get(ctx, &localv1.GetRequest{Id: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected not found, got %v", err)
	}

	if _, err := operations.Get(ctx, &localv1.OperationServiceGetRequest{Id: created.GetOperation().GetId()}); err != nil {
		t.Fatal(err)
	}
}

type emptyOAuthVault struct{}

func (emptyOAuthVault) Set(context.Context, string, string, string) error { return nil }
func (emptyOAuthVault) Get(context.Context, string, string) (string, error) {
	return "", registrycredentials.ErrNotFound
}
func (emptyOAuthVault) Delete(context.Context, string, string) error { return nil }

type failingOAuthVault struct{}

func (failingOAuthVault) Set(context.Context, string, string, string) error {
	return errors.New("synthetic vault failure")
}
func (failingOAuthVault) Get(context.Context, string, string) (string, error) {
	return "", errors.New("synthetic vault failure")
}
func (failingOAuthVault) Delete(context.Context, string, string) error {
	return errors.New("synthetic vault failure")
}

func TestAccountRPCFailsClosedWithoutTrustedProvider(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "account.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	svc := service.New(st, nil)
	svc.SetOAuthVault(emptyOAuthVault{})
	localv1.RegisterAccountServiceServer(grpcServer, NewAccount(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := localv1.NewAccountServiceClient(conn)
	if _, err := client.Login(ctx, &localv1.AccountServiceLoginRequest{Provider: "docker"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("login should fail closed without configured provider, got %v", err)
	}
	accountStatus, err := client.Status(ctx, &localv1.AccountServiceStatusRequest{Provider: "docker"})
	if err != nil || accountStatus.GetCredentialPresent() {
		t.Fatalf("empty account status present=%t err=%v", accountStatus.GetCredentialPresent(), err)
	}
	if _, err := client.Status(ctx, &localv1.AccountServiceStatusRequest{Provider: "unregistered"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unregistered provider status should fail closed, got %v", err)
	}
	device, err := client.LoginDevice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Send(&localv1.AccountServiceLoginDeviceRequest{Provider: "docker"}); err != nil {
		t.Fatal(err)
	}
	if _, err := device.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("device login should fail closed without configured provider, got %v", err)
	}
	if response, err := client.Logout(ctx, &localv1.AccountServiceLogoutRequest{Provider: "docker"}); err != nil || response.GetRemoved() {
		t.Fatalf("logout without any local account state should be idempotent, response=%#v err=%v", response, err)
	}
	svc.SetOAuthVault(failingOAuthVault{})
	if _, err := client.Status(ctx, &localv1.AccountServiceStatusRequest{Provider: "docker"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("status must fail closed when host vault is unavailable, got %v", err)
	}
}

func TestDeviceLoginStreamWaitsForHandoffAndKeepsDeviceCodeHostSide(t *testing.T) {
	var handoff atomic.Bool
	var tokenRequests atomic.Int32
	var patRequests atomic.Int32
	accessPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"https://hub.docker.com":{"username":"fixture-user"}}`))
	accessToken := "header." + accessPayload + ".signature"
	var providerServer *httptest.Server
	providerServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device":
			_, _ = fmt.Fprintf(w, `{"device_code":"synthetic-device-secret","user_code":"ABCD-1234","verification_uri_complete":%q,"expires_in":60,"interval":1}`, providerServer.URL+"/activate?user_code=ABCD-1234")
		case "/token":
			tokenRequests.Add(1)
			if !handoff.Load() {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`, accessToken)
		case "/pat":
			patRequests.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"token":"synthetic-hub-pat"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer providerServer.Close()
	transport := providerServer.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	vault := &serverTestVault{values: make(map[string]string)}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "account-device-stream.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := service.New(st, nil)
	svc.SetOAuthVault(vault)
	svc.SetRegistryCredentialStore(registryStore)
	svc.SetOAuthProviders(map[string]service.OAuthProvider{"docker": {
		Device: oauthsession.DeviceProvider{
			DeviceEndpoint: providerServer.URL + "/device", TokenEndpoint: providerServer.URL + "/token",
			PATEndpoint: providerServer.URL + "/pat", ClientID: "synthetic-client",
			Audience: providerServer.URL, Transport: transport,
		},
		DeviceHandoff: func(_ context.Context, code, uri string) error {
			if code != "ABCD-1234" || uri != providerServer.URL+"/activate?user_code=ABCD-1234" {
				t.Errorf("unexpected browser handoff code=%q uri=%q", code, uri)
			}
			handoff.Store(true)
			return nil
		},
	}})

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	localv1.RegisterAccountServiceServer(grpcServer, NewAccount(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := localv1.NewAccountServiceClient(conn).LoginDevice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&localv1.AccountServiceLoginDeviceRequest{Provider: "docker"}); err != nil {
		t.Fatal(err)
	}
	initial, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if initial.GetUserCode() != "ABCD-1234" || initial.GetVerificationUri() != providerServer.URL+"/activate?user_code=ABCD-1234" || initial.GetAuthenticated() {
		t.Fatalf("unexpected initial device login event: %+v", initial)
	}
	if strings.Contains(initial.String(), "synthetic-device-secret") || handoff.Load() || tokenRequests.Load() != 0 {
		t.Fatal("device code escaped or browser/polling started before handoff confirmation")
	}
	if err := stream.Send(&localv1.AccountServiceLoginDeviceRequest{ContinueAfterHandoff: true}); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	complete, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if !complete.GetAuthenticated() || complete.GetUserCode() != "" || complete.GetVerificationUri() != "" {
		t.Fatalf("unexpected completion event: %+v", complete)
	}
	if !handoff.Load() || tokenRequests.Load() == 0 || patRequests.Load() != 1 {
		t.Fatalf("device flow incomplete: handoff=%t token requests=%d PAT requests=%d", handoff.Load(), tokenRequests.Load(), patRequests.Load())
	}
}

type serverTestVault struct {
	mu     sync.Mutex
	values map[string]string
}

func (v *serverTestVault) Set(_ context.Context, serviceName, account, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[serviceName+"/"+account] = value
	return nil
}

func (v *serverTestVault) Get(_ context.Context, serviceName, account string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	value, ok := v.values[serviceName+"/"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	return value, nil
}

func (v *serverTestVault) Delete(_ context.Context, serviceName, account string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.values[serviceName+"/"+account]; !ok {
		return registrycredentials.ErrNotFound
	}
	delete(v.values, serviceName+"/"+account)
	return nil
}

func TestGRPCWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	svc := service.New(st, nil)
	localv1.RegisterSandboxServiceServer(grpcServer, NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, NewOperation(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sandboxes := localv1.NewSandboxServiceClient(conn)

	created, err := sandboxes.Create(ctx, &localv1.CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := sandboxes.Watch(ctx, &localv1.WatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.GetType() != "sandbox" || event.GetSandbox().GetId() != created.GetOperation().GetSandboxId() {
		t.Fatalf("unexpected event: %+v", event)
	}
	if _, err := sandboxes.Start(ctx, &localv1.StartRequest{Id: event.GetSandbox().GetId()}); err != nil {
		t.Fatal(err)
	}
	event, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_RUNNING {
		t.Fatalf("unexpected state: %s", event.GetSandbox().GetState())
	}
}

func TestRegistryLoginStoresSecretOnlyInVault(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "credentials.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	vault := &testVault{}
	registryStore, err := registrycredentials.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, nil)
	svc.SetRegistryCredentialStore(registryStore)
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	localv1.RegisterRegistryCredentialServiceServer(grpcServer, NewRegistryCredential(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := localv1.NewRegistryCredentialServiceClient(conn)
	response, err := client.Login(ctx, &localv1.RegistryCredentialServiceLoginRequest{
		Registry: "ghcr.io", Username: "alice", Password: []byte("synthetic-token"),
		Scope: localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetRegistry() != "ghcr.io" || response.GetScope() != localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES {
		t.Fatalf("unexpected response: %#v", response)
	}
	var saved struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(vault.secret), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Password != "synthetic-token" || saved.Username != "alice" {
		t.Fatal("credential was not stored in the injected vault")
	}
	if strings.Contains(response.String(), "synthetic-token") {
		t.Fatal("login response leaked the secret")
	}
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dbBytes), "synthetic-token") {
		t.Fatal("login secret was persisted in SQLite")
	}
}

type testVault struct{ secret string }

func (v *testVault) Set(_ context.Context, _, _, secret string) error {
	v.secret = secret
	return nil
}

func (v *testVault) Get(context.Context, string, string) (string, error) { return v.secret, nil }
func (*testVault) Delete(context.Context, string, string) error          { return nil }
