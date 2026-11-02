package server

import (
	"context"
	"errors"
	"io"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/KLORQ/sandboxes-runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type execResult struct {
	code int
	err  error
}

// Exec streams a non-interactive command's output with bounded backpressure.
func (s *SandboxServer) Exec(req *localv1.ExecRequest, stream grpc.ServerStreamingServer[localv1.ExecResponse]) error {
	if req.GetSandboxId() == "" || len(req.GetArgv()) == 0 || len(req.GetArgv()) > 256 {
		return status.Error(codes.InvalidArgument, "sandbox ID and command are required")
	}
	frames := make(chan *localv1.ExecResponse, 4)
	result := make(chan execResult, 1)
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	go func() {
		code, err := s.svc.Exec(ctx, req.GetSandboxId(), runtime.ExecRequest{
			Argv: req.GetArgv(), Workdir: req.GetWorkdir(), Env: req.GetEnv(), User: req.GetUser(),
			Stdout: execOutput{frames: frames},
			Stderr: execOutput{frames: frames, stderr: true},
		})
		close(frames)
		result <- execResult{code: code, err: err}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-frames:
			if !ok {
				return finishExecStream(stream, <-result)
			}
			if err := stream.Send(frame); err != nil {
				return err
			}
		}
	}
}

func finishExecStream(stream grpc.ServerStreamingServer[localv1.ExecResponse], res execResult) error {
	if res.err != nil {
		return mapError(res.err)
	}
	if res.code < 0 || res.code > 255 {
		return status.Error(codes.Internal, "invalid guest exit status")
	}
	return stream.Send(&localv1.ExecResponse{Frame: &localv1.ExecResponse_ExitCode{ExitCode: int32(res.code)}})
}

type execOutput struct {
	frames chan<- *localv1.ExecResponse
	stderr bool
}

// WithContext ties writes to the tracked exec session, including lifecycle cancellation.
func (w execOutput) WithContext(ctx context.Context) io.Writer {
	return boundExecOutput{output: w, write: func(p []byte) (int, error) { return w.write(ctx, p) }}
}

func (w execOutput) Write(_ []byte) (int, error) {
	return 0, errors.New("exec output is not bound to a session")
}

type boundExecOutput struct {
	output execOutput
	write  func([]byte) (int, error)
}

func (w boundExecOutput) Write(p []byte) (int, error) { return w.write(p) }

func (w boundExecOutput) WriteContext(ctx context.Context, p []byte) (int, error) {
	return w.output.write(ctx, p)
}

func (w execOutput) write(ctx context.Context, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32*1024)
		data := append([]byte(nil), p[:n]...)
		frame := &localv1.ExecResponse{Frame: &localv1.ExecResponse_Stdout{Stdout: data}}
		if w.stderr {
			frame.Frame = &localv1.ExecResponse_Stderr{Stderr: data}
		}
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case w.frames <- frame:
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
