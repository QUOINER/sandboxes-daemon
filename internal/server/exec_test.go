package server

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/rheic/sandboxes-runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type outputBackend struct {
	graceBackend
	env  []string
	user string
}

func (b *outputBackend) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	return b.exec(req)
}

func (b *outputBackend) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	return b.exec(req)
}

func (b *outputBackend) exec(req runtime.ExecRequest) (int, error) {
	b.env = req.Env
	b.user = req.User
	if _, err := io.WriteString(req.Stdout, "out"); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(req.Stderr, "err"); err != nil {
		return 0, err
	}
	return 0, nil
}

func TestExecStreamViaGRPC(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &outputBackend{}
	svc := service.New(st, backend)
	op, err := svc.Create(ctx, service.CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, NewSandbox(svc))
	go func() { _ = server.Serve(lis) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := localv1.NewSandboxServiceClient(conn).Exec(ctx, &localv1.ExecRequest{SandboxId: op.SandboxID, Argv: []string{"echo"}, Env: []string{"A=1"}, User: "1000:1001"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil || string(first.GetStdout()) != "out" {
		t.Fatalf("stdout frame: %v %v", first, err)
	}
	second, err := stream.Recv()
	if err != nil || string(second.GetStderr()) != "err" {
		t.Fatalf("stderr frame: %v %v", second, err)
	}
	third, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := third.GetFrame().(*localv1.ExecResponse_ExitCode); !ok {
		t.Fatalf("missing exit frame: %v", third)
	}
	if strings.Join(backend.env, ",") != "A=1" || backend.user != "1000:1001" {
		t.Fatalf("exec env=%q user=%q", backend.env, backend.user)
	}
}

type floodingBackend struct {
	graceBackend
	filled   chan struct{}
	finished chan struct{}
}

func (b *floodingBackend) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	if b.finished != nil {
		defer close(b.finished)
	}
	writes := 0
	for {
		if _, err := req.Stdout.Write(make([]byte, 32*1024)); err != nil {
			return 0, err
		}
		writes++
		if writes == 5 {
			close(b.filled)
		}
	}
}

func TestExecSendFailureCancelsProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &floodingBackend{filled: make(chan struct{}), finished: make(chan struct{})}
	svc := service.New(st, backend)
	op, err := svc.Create(ctx, service.CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	stream := &blockedExecStream{ctx: ctx, entered: make(chan struct{}, 1), release: make(chan struct{})}
	close(stream.release)
	if err := NewSandbox(svc).Exec(&localv1.ExecRequest{SandboxId: op.SandboxID, Argv: []string{"flood"}}, stream); !errors.Is(err, context.Canceled) {
		t.Fatalf("send error = %v", err)
	}
	select {
	case <-backend.finished:
	case <-ctx.Done():
		t.Fatal("producer remained blocked after stream failure")
	}
}

type blockedExecStream struct {
	grpc.ServerStream
	ctx     context.Context
	entered chan struct{}
	release chan struct{}
}

func (s *blockedExecStream) Context() context.Context { return s.ctx }
func (s *blockedExecStream) Send(*localv1.ExecResponse) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return context.Canceled
}

func TestStopCancelsExecWhenClientDoesNotRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &floodingBackend{filled: make(chan struct{})}
	svc := service.New(st, backend)
	op, err := svc.Create(ctx, service.CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	stream := &blockedExecStream{ctx: ctx, entered: make(chan struct{}, 1), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- NewSandbox(svc).Exec(&localv1.ExecRequest{SandboxId: op.SandboxID, Argv: []string{"flood"}}, stream)
	}()
	select {
	case <-stream.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case <-backend.filled:
	case <-ctx.Done():
		t.Fatal("exec output queue did not fill")
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatalf("stop with blocked client: %v", err)
	}
	close(stream.release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
