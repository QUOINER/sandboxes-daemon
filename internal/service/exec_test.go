package service

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/quoiner/sandboxes-runtime"

	"github.com/quoiner/sandboxes-daemon/internal/store"
)

type execTestRuntime struct {
	fakeRuntime
	entered chan struct{}
}

type immediateExecRuntime struct {
	fakeRuntime
	workdir string
}

func (e *immediateExecRuntime) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	e.workdir = req.Workdir
	return 0, nil
}

func TestExecStartsStoppedVMAndDefaultsToWorkspace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &immediateExecRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "owned", Workspace: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	if backend.started != 1 || backend.workdir != "/workspace" {
		t.Fatalf("started=%d workdir=%q", backend.started, backend.workdir)
	}
}

func (e *execTestRuntime) Exec(ctx context.Context, _ runtime.Handle, _ runtime.ExecRequest) (int, error) {
	close(e.entered)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestStopCancelsActiveExecBeforeStoppingVM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &execTestRuntime{entered: make(chan struct{})}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}})
		done <- err
	}()
	select {
	case <-backend.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("exec was not canceled: %v", err)
	}
	if backend.stopped != 1 {
		t.Fatal("VM was not stopped")
	}
}

type selectionExecRuntime struct {
	fakeRuntime
	native       bool
	nativeCalled bool
	nativeErr    error
}

func (e *selectionExecRuntime) Exec(_ context.Context, _ runtime.Handle, _ runtime.ExecRequest) (int, error) {
	return 42, nil
}

func (e *selectionExecRuntime) ExecCancelable(_ context.Context, _ runtime.Handle, _ runtime.ExecRequest) (int, error) {
	e.native = true
	return 7, nil
}

func (e *selectionExecRuntime) ExecNative(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	e.nativeCalled = true
	e.lastExec = req
	return 9, e.nativeErr
}

func TestExecSelectsCancelableExecutor(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &selectionExecRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}})
	if err != nil || code != 7 || !backend.native {
		t.Fatalf("code=%d err=%v native=%t", code, err, backend.native)
	}
	backend.native = false
	code, err = svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}, Stdout: io.Discard})
	if err != nil || code != 42 || backend.native {
		t.Fatalf("fallback: code=%d err=%v native=%t", code, err, backend.native)
	}
}

func TestExecUsesNativeExecutorForEnvironmentOverridesWithoutFallback(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &selectionExecRuntime{nativeErr: errors.New("native execution failed")}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}, Env: []string{"A=1"}})
	if err == nil || code != 9 || !backend.nativeCalled || backend.native {
		t.Fatalf("code=%d err=%v native_called=%t cancelable=%t", code, err, backend.nativeCalled, backend.native)
	}
	if len(backend.lastExec.Env) != 1 || backend.lastExec.Env[0] != "A=1" {
		t.Fatalf("native exec environment=%v", backend.lastExec.Env)
	}
}
