package service

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	runtime "github.com/KLORQ/sandboxes-runtime"

	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev", Image: "scratch"})
	if err != nil {
		t.Fatal(err)
	}
	if op.State != operation.Done {
		t.Fatalf("create state = %s", op.State)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Stopped {
		t.Fatalf("state = %s", sb.State)
	}

	if _, err := svc.Start(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Running {
		t.Fatalf("start: %+v, %v", sb, err)
	}

	if _, err := svc.Stop(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Stopped {
		t.Fatalf("stop: %+v, %v", sb, err)
	}

	if _, err := svc.Delete(ctx, sb.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, sb.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestDuplicateName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestCreateBakesValidatedEnv(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "env-ok", Env: map[string]string{"B": "2", "A": "1"}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(backend.lastConfig.Env, ","); got != "A=1,B=2" {
		t.Fatalf("env = %q", got)
	}
	for _, env := range []map[string]string{
		{"BAD-NAME": "x"},
		{"A": "x\x00y"},
		{strings.Repeat("K", 256): "x"},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "env-bad", Env: env}); err == nil {
			t.Fatalf("invalid env accepted: %v", env)
		}
	}
}

func TestCreateRejectsUnsafeNamesBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	for _, name := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "a\x00b", strings.Repeat("x", 64)} {
		if _, err := svc.Create(ctx, CreateRequest{Name: name}); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("unsafe name %q: %v", name, err)
		}
	}
	if backend.created != 0 {
		t.Fatal("unsafe name reached runtime")
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "fixture-1"}); err != nil || backend.created != 1 {
		t.Fatalf("valid name rejected: %v", err)
	}
}

func TestDeleteRunningRequiresForce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileInterruptedState(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Unix(100, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-1", Name: "dev", State: sandbox.Running, Generation: 2,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	op := operation.Operation{
		ID: "op-1", SandboxID: "sb-1", Kind: operation.KindStart,
		State: operation.Pending, Generation: 2, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Operations().Create(ctx, op); err != nil {
		t.Fatal(err)
	}

	svc := New(st, nil)
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Fatalf("changed = %d", changed)
	}
	got, err := st.Get(ctx, "sb-1")
	if err != nil || got.State != sandbox.Unknown {
		t.Fatalf("sandbox: %+v, %v", got, err)
	}
	if _, err := svc.Delete(ctx, got.ID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unknown runtime state was deleted without force: %v", err)
	}
	gotOp, err := st.Operations().Get(ctx, "op-1")
	if err != nil || gotOp.State != operation.Failed {
		t.Fatalf("operation: %+v, %v", gotOp, err)
	}
}

type fakeRuntime struct {
	created          int
	lastConfig       runtime.Config
	proxyHelperPath  string
	proxyGuestPort   uint16
	proxyServiceHost string
	lastHandle       runtime.Handle
	lastExec         runtime.ExecRequest
	started          int
	stopped          int
	deleted          int
	deleteErr        error
	afterCreate      func()
	deleteCtxErr     error
	stopGrace        time.Duration
}

type blockingStopRuntime struct {
	fakeRuntime
	stopEntered  chan struct{}
	stopRelease  chan struct{}
	deleteCalled chan struct{}
}

func (b *blockingStopRuntime) Stop(ctx context.Context, _ runtime.Handle, _ time.Duration) error {
	close(b.stopEntered)
	select {
	case <-b.stopRelease:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingStopRuntime) Delete(context.Context, runtime.Handle) error {
	close(b.deleteCalled)
	return nil
}

func (f *fakeRuntime) Capabilities(context.Context) (runtime.Capabilities, error) {
	return runtime.Capabilities{Workspace: true}, nil
}
func (f *fakeRuntime) Create(_ context.Context, cfg runtime.Config) (runtime.Handle, error) {
	f.created++
	f.lastConfig = cfg
	if f.afterCreate != nil {
		f.afterCreate()
	}
	return runtime.Handle{ID: "klorq-" + cfg.Name}, nil
}
func (f *fakeRuntime) CreateWithProxy(ctx context.Context, cfg *runtime.Config, helperPath string, guestPort uint16, serviceHost string) (runtime.Handle, error) {
	f.proxyHelperPath = helperPath
	f.proxyGuestPort = guestPort
	f.proxyServiceHost = serviceHost
	return f.Create(ctx, *cfg)
}
func (f *fakeRuntime) Exec(_ context.Context, _ runtime.Handle, req runtime.ExecRequest) (int, error) {
	f.lastExec = req
	return 0, nil
}

func (f *fakeRuntime) ExecNative(context.Context, runtime.Handle, runtime.ExecRequest) (int, error) {
	return 0, nil
}

func (f *fakeRuntime) Start(_ context.Context, h runtime.Handle) error {
	f.started++
	f.lastHandle = h
	return nil
}
func (f *fakeRuntime) Stop(_ context.Context, _ runtime.Handle, grace time.Duration) error {
	f.stopped++
	f.stopGrace = grace
	return nil
}

func TestStopUsesRequestedGrace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StopWithGrace(ctx, op.SandboxID, 23*time.Second); err != nil {
		t.Fatal(err)
	}
	if backend.stopGrace != 23*time.Second {
		t.Fatalf("grace = %s", backend.stopGrace)
	}
	if _, err := svc.StopWithGrace(ctx, op.SandboxID, -time.Second); err == nil {
		t.Fatal("negative grace accepted")
	}
}
func (f *fakeRuntime) Delete(ctx context.Context, _ runtime.Handle) error {
	f.deleted++
	f.deleteCtxErr = ctx.Err()
	return f.deleteErr
}
func (f *fakeRuntime) Handle(name string) runtime.Handle { return runtime.Handle{ID: "klorq-" + name} }

func TestLifecycleWithRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Running {
		t.Fatalf("create: %+v, %v", sb, err)
	}
	if _, err := svc.Start(ctx, sb.ID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected running conflict, got %v", err)
	}
	if _, err := svc.Stop(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	if backend.created != 1 || backend.stopped != 1 || backend.started != 1 || backend.deleted != 1 {
		t.Fatalf("backend calls: %+v", backend)
	}
}

func TestStopAndDeleteSerializePerSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &blockingStopRuntime{stopEntered: make(chan struct{}), stopRelease: make(chan struct{}), deleteCalled: make(chan struct{})}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	stopDone := make(chan error, 1)
	go func() { _, err := svc.Stop(ctx, op.SandboxID); stopDone <- err }()
	<-backend.stopEntered
	deleteDone := make(chan error, 1)
	go func() { _, err := svc.Delete(ctx, op.SandboxID, true); deleteDone <- err }()
	select {
	case <-backend.deleteCalled:
		close(backend.stopRelease)
		t.Fatal("delete reached runtime while stop was in progress")
	case <-time.After(100 * time.Millisecond):
	}
	close(backend.stopRelease)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("sandbox record remains after delete: %v", err)
	}
}

func TestLifecycleWaitHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &blockingStopRuntime{stopEntered: make(chan struct{}), stopRelease: make(chan struct{}), deleteCalled: make(chan struct{})}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := svc.Stop(ctx, op.SandboxID); done <- err }()
	<-backend.stopEntered
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.Delete(canceled, op.SandboxID, true)
	close(backend.stopRelease)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting delete ignored cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.deleteCalled:
		t.Fatal("canceled delete reached runtime")
	default:
	}
}

func TestForceDeleteKeepsRecordOnRuntimeFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{deleteErr: errors.New("runtime unavailable")}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); !errors.Is(err, backend.deleteErr) {
		t.Fatalf("runtime failure not returned: %v", err)
	}
	if got, err := svc.Get(ctx, op.SandboxID); err != nil || got.State != sandbox.Unknown {
		t.Fatalf("sandbox state after failed delete: %+v, %v", got, err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("unknown sandbox deleted without force: %v", err)
	}
	backend.deleteErr = nil
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatalf("retry after runtime recovery failed: %v", err)
	}
	if _, err := svc.Get(ctx, op.SandboxID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("sandbox record not removed on success: %v", err)
	}
}

func TestCreateReportsRollbackFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "one", IdempotencyKey: "first-key"}); err != nil {
		t.Fatal(err)
	}
	backend.deleteErr = errors.New("synthetic cleanup failure")
	backend.afterCreate = func() {
		now := time.Now()
		err := st.Operations().Create(ctx, operation.Operation{ID: "fixture-op", SandboxID: "fixture", Kind: operation.KindCreate, State: operation.Done, Generation: 1, IdempotencyKey: "other-key", CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "two", IdempotencyKey: "other-key"}); !errors.Is(err, backend.deleteErr) {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
	if backend.deleted != 1 {
		t.Fatalf("cleanup calls = %d", backend.deleted)
	}
	if _, err := svc.GetByName(ctx, "one"); err != nil {
		t.Fatalf("existing sandbox record was affected: %v", err)
	}
}

func TestConcurrentCreateSameNameDoesNotRollbackExistingSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	errs := make(chan error, 2)
	for _, key := range []string{"first", "second"} {
		go func() {
			_, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: key})
			errs <- err
		}()
	}
	first, second := <-errs, <-errs
	if (first != nil || !errors.Is(second, core.ErrConflict)) && (second != nil || !errors.Is(first, core.ErrConflict)) {
		t.Fatalf("unexpected create results: %v, %v", first, second)
	}
	if backend.created != 1 || backend.deleted != 0 {
		t.Fatalf("existing resource at risk: created=%d deleted=%d", backend.created, backend.deleted)
	}
}

func TestCreateIdempotencyReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	req := CreateRequest{Name: "dev", IdempotencyKey: "key", Workspace: "/fixture"}
	first, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Create(ctx, req)
	if err != nil || first.ID != second.ID || backend.created != 1 {
		t.Fatalf("idempotent replay: first=%s second=%s created=%d err=%v", first.ID, second.ID, backend.created, err)
	}
	req.Workspace = "/different"
	if _, err := svc.Create(ctx, req); !errors.Is(err, core.ErrConflict) || backend.created != 1 {
		t.Fatalf("different request accepted or reached runtime: %v", err)
	}
	if _, err := svc.Delete(ctx, first.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	req.Workspace = "/fixture"
	if _, err := svc.Create(ctx, req); !errors.Is(err, core.ErrConflict) || backend.created != 1 {
		t.Fatalf("key reused after deletion: %v", err)
	}
}

func TestConcurrentCreateWithSameKeyRunsBackendOnce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	type result struct {
		op  operation.Operation
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			op, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: "same-key"})
			results <- result{op: op, err: err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.op.ID != second.op.ID || backend.created != 1 {
		t.Fatalf("concurrent replay failed: first=%+v second=%+v created=%d", first, second, backend.created)
	}
}

func TestCreateWaitingForSameKeyHonorsCancellation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	entered, release := make(chan struct{}), make(chan struct{})
	backend := &fakeRuntime{afterCreate: func() { close(entered); <-release }}
	svc := New(st, backend)
	done := make(chan error, 1)
	go func() {
		_, err := svc.Create(ctx, CreateRequest{Name: "dev", IdempotencyKey: "key"})
		done <- err
	}()
	<-entered
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.Create(canceled, CreateRequest{Name: "dev", IdempotencyKey: "key"})
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting create ignored cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCreateRollbackContinuesAfterRequestCancellation(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &fakeRuntime{afterCreate: cancel}
	svc := New(st, backend)
	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled request, got %v", err)
	}
	if backend.deleted != 1 || backend.deleteCtxErr != nil {
		t.Fatalf("cleanup did not run with a live context: calls=%d err=%v", backend.deleted, backend.deleteCtxErr)
	}
}

func TestCreatePassesResourceOverridesAndDefaults(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "sized", CPUs: 4, MemoryMiB: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if backend.lastConfig.CPUs != 4 || backend.lastConfig.MemoryMiB != 4096 {
		t.Fatalf("runtime config = %+v", backend.lastConfig)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.CPUs != 4 || sb.MemoryMiB != 4096 {
		t.Fatalf("sandbox = %+v, %v", sb, err)
	}
	op, err = svc.Create(ctx, CreateRequest{Name: "defaults"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || sb.CPUs != svc.DefaultCPUs || sb.MemoryMiB != svc.DefaultMemoryMiB {
		t.Fatalf("defaults = %+v, %v (want %d CPU/%d MiB)", sb, err, svc.DefaultCPUs, svc.DefaultMemoryMiB)
	}
	for _, req := range []CreateRequest{{Name: "bad-cpu", CPUs: 65}, {Name: "bad-memory", MemoryMiB: 64}} {
		if _, err := svc.Create(ctx, req); err == nil {
			t.Fatalf("invalid request accepted: %+v", req)
		}
	}
}

func TestStopAndStartTrackStoppedAt(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "timed"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || !sb.StoppedAt.IsZero() {
		t.Fatalf("running stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || sb.StoppedAt.IsZero() {
		t.Fatalf("stopped stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, op.SandboxID)
	if err != nil || !sb.StoppedAt.IsZero() {
		t.Fatalf("restarted stoppedAt=%v err=%v", sb.StoppedAt, err)
	}
}

func TestCreatePassesWorkspacesAndStoresThem(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "multi", Agent: "shell", Detached: true, Workspaces: []sandbox.Workspace{
		{Path: "/work"}, {Path: "/docs", ReadOnly: true},
	}, Ports: []sandbox.Port{{Host: 8080, Guest: 3000}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Workspaces) != 2 || !backend.lastConfig.Workspaces[1].ReadOnly ||
		backend.lastConfig.Workspace != "/work" || len(backend.lastConfig.Ports) != 1 || backend.lastConfig.Ports[0].Host != 8080 {
		t.Fatalf("runtime config=%+v", backend.lastConfig)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || len(sb.Workspaces) != 2 || sb.Workspace != "/work" || !sb.Workspaces[1].ReadOnly ||
		len(sb.Ports) != 1 || sb.Ports[0].Guest != 3000 || sb.Meta == nil || sb.Meta.Agent != "shell" || !sb.Meta.Detached {
		t.Fatalf("sandbox=%+v err=%v", sb, err)
	}
}

func TestCreateRejectsInvalidWorkspaces(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, workspaces := range [][]sandbox.Workspace{
		{{Path: "relative"}},
		{{Path: "/work"}, {Path: "/work"}},
		{{Path: ""}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Workspaces: workspaces}); err == nil {
			t.Fatalf("invalid workspaces accepted: %+v", workspaces)
		}
	}
}

func TestCreateRejectsOccupiedHostPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	if _, err := svc.Create(ctx, CreateRequest{Name: "busy", Ports: []sandbox.Port{{Host: port, Guest: 80}}}); err == nil {
		t.Fatal("occupied host port was accepted")
	}
}

func TestCreateRejectsInvalidPorts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, ports := range [][]sandbox.Port{
		{{Host: 0, Guest: 3000}},
		{{Host: 8080, Guest: 0}},
		{{Host: 8080, Guest: 3000, Protocol: "sctp"}},
		{{Host: 8080, Guest: 3000}, {Host: 8080, Guest: 4000}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Ports: ports}); err == nil {
			t.Fatalf("invalid ports accepted: %+v", ports)
		}
	}
}

func TestNormalizePortsHostIPAndFamily(t *testing.T) {
	ports, err := normalizePorts([]sandbox.Port{
		{Host: 8080, Guest: 3000, Protocol: "tcp4"},
		{Host: 8080, Guest: 3001, Protocol: "tcp6"},
		{Host: 8080, Guest: 3002, Protocol: "udp6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ports[0].HostIP != "127.0.0.1" || ports[1].HostIP != "::1" || ports[2].HostIP != "::1" || ports[2].Protocol != "udp" {
		t.Fatalf("ports=%+v", ports)
	}
	for _, invalid := range [][]sandbox.Port{
		{{Host: 8080, Guest: 3000, HostIP: "192.0.2.10"}},
		{{Host: 8080, Guest: 3000, Protocol: "tcp4", HostIP: "::1"}},
		{{Host: 8080, Guest: 3000, Protocol: "tcp6", HostIP: "127.0.0.1"}},
		{{Host: 8080, Guest: 3000, HostIP: "127.0.0.1"}, {Host: 8080, Guest: 4000, HostIP: "127.0.0.1"}},
	} {
		if _, err := normalizePorts(invalid); err == nil {
			t.Fatalf("invalid ports accepted: %+v", invalid)
		}
	}
}

func TestProbeHostPortIPv6UDPUsesUDP6(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP loopback unavailable: %v", err)
	}
	_ = probe.Close()
	closeProbe, err := probeHostPort(sandbox.Port{Host: 26759, Guest: 8083, Protocol: "udp", HostIP: "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := closeProbe(); err != nil {
		t.Fatal(err)
	}
}

func TestStartPassesPublishedPortsToRuntime(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "ported", Ports: []sandbox.Port{{Host: 8080, Guest: 3000}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastHandle.Ports) != 1 || backend.lastHandle.Ports[0].Host != 8080 || backend.lastHandle.Ports[0].Guest != 3000 {
		t.Fatalf("start handle=%+v", backend.lastHandle)
	}
}

func TestCreatePassesAndStoresNetworkRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "ruled",
		Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}},
		Deny:  []sandbox.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Allow) != 1 || backend.lastConfig.Allow[0].Port != 80 ||
		len(backend.lastConfig.Deny) != 1 || backend.lastConfig.Deny[0].Protocol != "udp" {
		t.Fatalf("runtime rules=%+v/%+v", backend.lastConfig.Allow, backend.lastConfig.Deny)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Policy == nil || len(sb.Policy.Allow) != 1 || len(sb.Policy.Deny) != 1 {
		t.Fatalf("sandbox policy=%+v err=%v", sb.Policy, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastHandle.Allow) != 1 || backend.lastHandle.Allow[0].Port != 80 {
		t.Fatalf("start handle rules=%+v", backend.lastHandle.Allow)
	}
}

func TestCreateRejectsInvalidNetworkRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, &fakeRuntime{})
	for _, rules := range [][]sandbox.NetworkRule{
		{{Protocol: "icmp", CIDR: "0.0.0.0/0"}},
		{{Protocol: "tcp", CIDR: "domain.example"}},
		{{Protocol: "tcp", CIDR: "2001:db8::/32"}},
	} {
		if _, err := svc.Create(ctx, CreateRequest{Name: "bad", Allow: rules}); err == nil {
			t.Fatalf("invalid rules accepted: %+v", rules)
		}
	}
}

type fakeExecutorRuntime struct {
	fakeRuntime
	execs int
}

func (f *fakeExecutorRuntime) Exec(context.Context, runtime.Handle, runtime.ExecRequest) (int, error) {
	f.execs++
	return 0, nil
}

func TestExecUpdatesLastUsedAndPreservesMeta(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeExecutorRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "used", Agent: "shell", Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Meta == nil || sb.Meta.Agent != "shell" || !sb.Meta.Detached {
		t.Fatalf("created meta=%+v err=%v", sb.Meta, err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if code, err := svc.Exec(ctx, op.SandboxID, runtime.ExecRequest{Argv: []string{"true"}}); err != nil || code != 0 {
		t.Fatalf("exec code=%d err=%v", code, err)
	}
	used, err := svc.Get(ctx, op.SandboxID)
	if err != nil || used.Meta == nil || used.Meta.Agent != "shell" || !used.Meta.Detached {
		t.Fatalf("used meta=%+v err=%v", used.Meta, err)
	}
	if used.State != sandbox.Running || !used.Meta.LastUsedAt.After(sb.Meta.LastUsedAt) {
		t.Fatalf("state/meta after exec=%s/%v", used.State, used.Meta)
	}
}

type fakePolicyRuntime struct {
	fakeRuntime
	revision int
	allow    []runtime.Rule
	err      error
	before   func()
}

func TestConcurrentPolicyMutationsPreserveRevocation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "concurrent-policy"})
	if err != nil {
		t.Fatal(err)
	}
	oldRule := sandbox.NetworkRule{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 80}
	newRule := sandbox.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", oldRule); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, mutation := range []struct {
		action string
		rule   sandbox.NetworkRule
	}{{"rm", oldRule}, {"allow", newRule}} {
		wg.Go(func() {
			_, err := svc.MutatePolicy(ctx, op.SandboxID, mutation.action, mutation.rule)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.Policy == nil || len(sb.Policy.Allow) != 1 || !sameRule(sb.Policy.Allow[0], newRule) {
		t.Fatalf("policy=%+v err=%v", sb.Policy, err)
	}
}

func (f *fakePolicyRuntime) UpdatePolicy(_ context.Context, _ runtime.Handle, allow, _ []runtime.Rule, revision int) error {
	if f.before != nil {
		f.before()
	}
	if f.err != nil {
		return f.err
	}
	f.revision = revision
	f.allow = allow
	return nil
}

func TestUpdatePolicyAppliesLiveAndPersists(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	backend.before = func() {
		stored, getErr := st.Get(ctx, op.SandboxID)
		if getErr != nil || stored.State != sandbox.Unknown || stored.Policy == nil || len(stored.Policy.Allow) != 1 {
			t.Fatalf("policy was not persisted before reload: %+v, %v", stored, getErr)
		}
	}
	updated, err := svc.UpdatePolicy(ctx, op.SandboxID, []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if backend.revision <= 1 || len(backend.allow) != 1 || updated.Policy == nil || len(updated.Policy.Allow) != 1 {
		t.Fatalf("revision=%d allow=%+v policy=%+v", backend.revision, backend.allow, updated.Policy)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.UpdatePolicy(ctx, op.SandboxID, nil, []sandbox.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}})
	if err != nil || stopped.Policy == nil || len(stopped.Policy.Deny) != 1 {
		t.Fatalf("stopped update=%+v err=%v", stopped.Policy, err)
	}
}

func TestUpdatePolicyFailureMarksUnknown(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePolicyRuntime{err: errors.New("synthetic reload failure")}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "policy-fail"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePolicy(ctx, op.SandboxID, []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}}, nil); err == nil {
		t.Fatal("reload failure was hidden")
	}
	if backend.stopped != 1 {
		t.Fatal("failed reload did not attempt to stop the sandbox")
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Unknown {
		t.Fatalf("state=%s err=%v", sb.State, err)
	}
	if sb.Policy == nil || len(sb.Policy.Allow) != 1 {
		t.Fatalf("desired policy lost after reload failure: %+v", sb.Policy)
	}
}

type fakePortRuntime struct {
	fakeRuntime
	ports []runtime.Port
	err   error
}

func (f *fakePortRuntime) UpdatePorts(_ context.Context, _ runtime.Handle, ports []runtime.Port) error {
	if f.err != nil {
		return f.err
	}
	f.ports = ports
	return nil
}

func TestUpdatePortsLiveAndPersist(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakePortRuntime{}
	svc := New(st, backend)
	op, err := svc.Create(ctx, CreateRequest{Name: "ports"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdatePorts(ctx, op.SandboxID, []sandbox.Port{{Host: 18091, Guest: 8080, Protocol: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.ports) != 1 || backend.ports[0].Host != 18091 || len(updated.Ports) != 1 {
		t.Fatalf("runtime=%+v sandbox=%+v", backend.ports, updated.Ports)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.UpdatePorts(ctx, op.SandboxID, nil)
	if err != nil || len(stopped.Ports) != 0 {
		t.Fatalf("stopped ports=%+v err=%v", stopped.Ports, err)
	}
}

type mapVault struct{ items map[string]string }

func (v *mapVault) Set(_ context.Context, service, account, secret string) error {
	if v.items == nil {
		v.items = make(map[string]string)
	}
	v.items[service+"/"+account] = secret
	return nil
}

func (v *mapVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.items[service+"/"+account]
	if !ok {
		return "", registrycredentials.ErrNotFound
	}
	return value, nil
}

func (v *mapVault) Delete(_ context.Context, service, account string) error {
	if _, ok := v.items[service+"/"+account]; !ok {
		return registrycredentials.ErrNotFound
	}
	delete(v.items, service+"/"+account)
	return nil
}

func TestRegistryCredentialListAndSandboxCleanup(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	credentials, err := registrycredentials.NewStore(&mapVault{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetRegistryCredentialStore(credentials)
	op, err := svc.Create(ctx, CreateRequest{Name: "scoped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LoginRegistry(ctx, registrycredentials.Credential{
		Registry: "ghcr.io", Username: "alice", Password: []byte("synthetic"), Scope: registrycredentials.ScopeSandbox, SandboxName: "scoped",
	}); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListRegistryCredentials(ctx)
	if err != nil || len(items) != 1 || items[0].Registry != "ghcr.io" || items[0].SandboxName != "scoped" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
	items, err = svc.ListRegistryCredentials(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("items after delete=%+v err=%v", items, err)
	}
}

func TestPolicyProfileGlobalAndMetadata(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	if profile, err := svc.GetPolicyProfile(ctx); err != nil || profile != "deny-all" {
		t.Fatalf("default profile=%q err=%v", profile, err)
	}
	if profile, err := svc.SetPolicyProfile(ctx, "balanced"); err != nil || profile != "balanced" {
		t.Fatalf("set profile=%q err=%v", profile, err)
	}
	op, err := svc.Create(ctx, CreateRequest{Name: "profile-default"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Meta == nil || sb.Meta.PolicyProfile != "balanced" {
		t.Fatalf("metadata=%+v", sb.Meta)
	}
	if len(backend.lastConfig.Allow) != 4 {
		t.Fatalf("profile rules=%+v", backend.lastConfig.Allow)
	}
	if profile, err := svc.SetPolicyProfile(ctx, "sbx-compat"); err != nil || profile != "allow-all" {
		t.Fatalf("alias profile=%q err=%v", profile, err)
	}
	if _, err := svc.SetPolicyProfile(ctx, "unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestCreatePassesPrivileged(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "priv.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := &fakeRuntime{}
	svc := New(st, backend)
	svc.DockerVolumeDir = t.TempDir()
	svc.DockerVolumeSize = "512m"
	svc.MkfsExt4 = "true"
	if _, err := svc.Create(ctx, CreateRequest{Name: "priv", Privileged: true}); err != nil {
		t.Fatal(err)
	}
	if !backend.lastConfig.Privileged {
		t.Fatal("privileged request did not reach runtime")
	}
}

func sameRule(a, b sandbox.NetworkRule) bool {
	a.RuleID = ""
	b.RuleID = ""
	return a == b
}

func TestNormalizeDomainRules(t *testing.T) {
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.Example.COM.", Port: 443}
	normalized, err := normalizeRules([]sandbox.NetworkRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 1 || normalized[0].Domain != "*.example.com" || !strings.HasPrefix(normalized[0].RuleID, "rul_") {
		t.Fatalf("normalized=%+v", normalized)
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "example.com", CIDR: "192.0.2.0/24"}}); err == nil {
		t.Fatal("domain+cidr accepted")
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "*"}}); err == nil {
		t.Fatal("bare wildcard accepted")
	}
	if _, err := normalizeRules([]sandbox.NetworkRule{{Protocol: "tcp", Domain: "192.0.2.10", Port: 443}}); err == nil {
		t.Fatal("IP literal accepted as a domain rule")
	}
}

func TestCheckPolicyAppliesGlobalProfileRules(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	if _, err := svc.SetPolicyProfile(ctx, policyProfileAllowAll); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.CheckPolicy(ctx, "", "tcp", "192.0.2.1", "", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("global allow-all profile must allow IPv4 tcp, got %+v", decision)
	}
	if _, err := svc.SetPolicyProfile(ctx, policyProfileDenyAll); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.CheckPolicy(ctx, "", "tcp", "192.0.2.1", "", 443)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("global deny-all profile must deny IPv4 tcp, got %+v", decision)
	}
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.example.com", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", rule); err != nil {
		t.Fatal(err)
	}
	decision, err = svc.CheckPolicy(ctx, "", "tcp", "", "api.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("explicit global domain rule must allow, got %+v", decision)
	}
	decision, err = svc.CheckPolicy(ctx, "", "udp", "", "api.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("tcp-only domain rule must not allow udp, got %+v", decision)
	}
}

func TestGlobalPolicyMergesIntoNewSandboxes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	rule := sandbox.NetworkRule{Protocol: "tcp", Domain: "*.example.com", Port: 443}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", rule); err != nil {
		t.Fatal(err)
	}
	op, err := svc.Create(ctx, CreateRequest{Name: "global-policy"})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	allow, _, err := svc.effectivePolicy(ctx, sb)
	if err != nil || len(allow) != 1 || allow[0].Domain != "*.example.com" {
		t.Fatalf("effective allow=%+v err=%v", allow, err)
	}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "rm", rule); err != nil {
		t.Fatal(err)
	}
}

type fakeServiceSecretVault struct{ items map[string]string }

func (f *fakeServiceSecretVault) Set(_ context.Context, service, account, secret string) error {
	f.items[service+"/"+account] = secret
	return nil
}

func (f *fakeServiceSecretVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := f.items[service+"/"+account]
	if !ok {
		return "", servicesecrets.ErrNotFound
	}
	return value, nil
}

func (f *fakeServiceSecretVault) Delete(_ context.Context, service, account string) error {
	key := service + "/" + account
	if _, ok := f.items[key]; !ok {
		return servicesecrets.ErrNotFound
	}
	delete(f.items, key)
	return nil
}

func TestServiceSecretNeverPersistsValue(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	secretStore, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev", []byte("sk-synthetic-value")); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListServiceSecrets(ctx)
	if err != nil || len(items) != 1 || items[0].Service != "openai" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-synthetic-value") {
		t.Fatal("secret value was written to SQLite")
	}
	removed, err := svc.RemoveServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev")
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
}

func TestResolveSecretEnvFailsClosedAndScopes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	secretStore, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("global-value")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeSandbox, "dev", []byte("sandbox-value")); err != nil {
		t.Fatal(err)
	}
	env, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "dev"}, []string{"OPENAI_API_KEY=${secret:openai}", "PLAIN=value"})
	if err != nil || len(env) != 2 || env[0] != "OPENAI_API_KEY=sandbox-value" || env[1] != "PLAIN=value" {
		t.Fatalf("env=%q err=%v", env, err)
	}
	if _, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "other"}, []string{"KEY=${secret:missing}"}); err == nil {
		t.Fatal("missing secret did not fail closed")
	}
}

func TestResolveProxyEnvRequiresConfiguredCredentialVariable(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	secretStore, err := servicesecrets.NewStore(&fakeServiceSecretVault{items: make(map[string]string)})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	if _, err := svc.SetServiceSecret(ctx, "openai", servicesecrets.ScopeGlobal, "", []byte("sk-synthetic-proxy")); err != nil {
		t.Fatal(err)
	}
	env, err := svc.resolveSecretEnv(ctx, sandbox.Sandbox{Name: "dev"}, []string{"OPENAI_BASE_URL=${proxy:openai}"})
	if err == nil || !strings.Contains(err.Error(), "proxy reference is not supported") || len(env) != 0 {
		t.Fatalf("env=%q err=%v", env, err)
	}
}

func TestStopSandboxByNameStopsRunningSandbox(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st, nil)
	op, err := svc.Create(ctx, CreateRequest{Name: "lost-gw", Image: "scratch"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := svc.StopSandboxByName(ctx, "lost-gw"); err != nil {
		t.Fatal(err)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil || sb.State != sandbox.Stopped {
		t.Fatalf("sandbox after gateway loss = %+v, %v", sb, err)
	}
	if err := svc.StopSandboxByName(ctx, "missing"); err != nil {
		t.Fatalf("missing sandbox must be ignored: %v", err)
	}
}
