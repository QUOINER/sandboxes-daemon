package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/KLORQ/sandboxes-runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
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
	if response, err := client.Logout(ctx, &localv1.AccountServiceLogoutRequest{Provider: "docker"}); err != nil || response.GetRemoved() {
		t.Fatalf("logout without any local account state should be idempotent, response=%#v err=%v", response, err)
	}
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
