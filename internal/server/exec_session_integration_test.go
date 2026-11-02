package server

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/KLORQ/sandboxes-runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

type interactiveBackend struct{ outputBackend }

func (b *interactiveBackend) ExecInteractive(ctx context.Context, _ runtime.Handle, req runtime.InteractiveExecRequest) (int, error) {
	b.env = req.Env
	b.user = req.User
	defer req.Stdin.Close()
	input, err := io.ReadAll(req.Stdin)
	if err != nil {
		return 0, err
	}
	if _, err = req.Stdout.Write(input); err != nil {
		return 0, err
	}
	return 7, nil
}

func TestExecSessionInputEOFAndExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	backend := &interactiveBackend{}
	svc := service.New(st, backend)
	op, err := svc.Create(ctx, service.CreateRequest{Name: "session-test"})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(srv, NewSandbox(svc))
	go srv.Serve(lis)
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := localv1.NewSandboxServiceClient(conn).ExecSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*localv1.ExecSessionRequest{
		{Frame: &localv1.ExecSessionRequest_Open{Open: &localv1.ExecSessionOpen{SandboxId: op.SandboxID, Argv: []string{"cat"}, Env: []string{"A=1"}, User: "0:0"}}},
		{Frame: &localv1.ExecSessionRequest_Stdin{Stdin: []byte("hello")}},
		{Frame: &localv1.ExecSessionRequest_StdinEof{StdinEof: true}},
	} {
		if err := stream.Send(f); err != nil {
			t.Fatal(err)
		}
	}
	out, err := stream.Recv()
	if err != nil || string(out.GetStdout()) != "hello" {
		t.Fatalf("output %v: %v", out, err)
	}
	exit, err := stream.Recv()
	if err != nil || exit.GetExitCode() != 7 {
		t.Fatalf("exit %v: %v", exit, err)
	}
	if len(backend.env) != 1 || backend.env[0] != "A=1" || backend.user != "0:0" {
		t.Fatalf("session env=%q user=%q", backend.env, backend.user)
	}
}
