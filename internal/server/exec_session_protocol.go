package server

import (
	"context"
	"errors"
	"io"

	runtime "github.com/KLORQ/sandboxes-runtime"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxExecSessionInput = 32 * 1024

// ExecSession bridges an interactive client to a tracked guest process.
func (s *SandboxServer) ExecSession(stream grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "missing session opening frame")
	}
	protocol := &execSessionProtocol{}
	if err := protocol.accept(first); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	open := first.GetOpen()
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	resize := make(chan runtime.TerminalSize, 1)
	frames := make(chan *localv1.ExecSessionResponse, 4)
	results := make(chan execResult, 1)
	inputErrors := make(chan error, 1)
	go receiveSessionInput(ctx, stream, protocol, writer, resize, inputErrors)
	go func() {
		code, err := s.svc.ExecInteractive(ctx, open.GetSandboxId(), runtime.InteractiveExecRequest{
			ExecRequest: runtime.ExecRequest{Argv: open.GetArgv(), Workdir: open.GetWorkdir(), Env: open.GetEnv(), User: open.GetUser(), Stdout: sessionOutput{frames: frames}, Stderr: sessionOutput{frames: frames, stderr: true}},
			Stdin:       reader, TTY: open.GetTty(), Size: runtime.TerminalSize{Rows: open.GetRows(), Cols: open.GetCols()}, Resize: resize,
		})
		close(frames)
		results <- execResult{code: code, err: err}
	}()
	return sendSessionOutput(ctx, stream, frames, results, inputErrors)
}

func sendSessionOutput(ctx context.Context, stream grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse], frames <-chan *localv1.ExecSessionResponse, results <-chan execResult, inputErrors <-chan error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-inputErrors:
			if err != nil {
				return err
			}
			inputErrors = nil
		case frame, ok := <-frames:
			if !ok {
				return finishSession(stream, <-results)
			}
			if err := stream.Send(frame); err != nil {
				return err
			}
		}
	}
}

func finishSession(stream grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse], result execResult) error {
	if result.err != nil {
		return mapError(result.err)
	}
	if result.code < 0 || result.code > 255 {
		return status.Error(codes.Internal, "invalid guest exit status")
	}
	return stream.Send(&localv1.ExecSessionResponse{Frame: &localv1.ExecSessionResponse_ExitCode{ExitCode: int32(result.code)}})
}

func receiveSessionInput(ctx context.Context, stream grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse], protocol *execSessionProtocol, writer *io.PipeWriter, resize chan<- runtime.TerminalSize, result chan<- error) {
	defer func() { _ = writer.Close() }()
	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				result <- nil
			} else {
				result <- err
			}
			return
		}
		if err := protocol.accept(frame); err != nil {
			result <- status.Error(codes.InvalidArgument, err.Error())
			return
		}
		switch value := frame.GetFrame().(type) {
		case *localv1.ExecSessionRequest_Stdin:
			if _, err := writer.Write(value.Stdin); err != nil {
				result <- nil
				return
			}
		case *localv1.ExecSessionRequest_StdinEof:
			_ = writer.Close()
		case *localv1.ExecSessionRequest_Resize:
			select {
			case resize <- runtime.TerminalSize{Rows: value.Resize.GetRows(), Cols: value.Resize.GetCols()}:
			case <-ctx.Done():
				result <- nil
				return
			}
		}
	}
}

type sessionOutput struct {
	frames chan<- *localv1.ExecSessionResponse
	stderr bool
}

func (w sessionOutput) Write([]byte) (int, error) {
	return 0, errors.New("session output is not bound")
}
func (w sessionOutput) WithContext(ctx context.Context) io.Writer {
	return boundSessionOutput{output: w, write: func(p []byte) (int, error) { return boundSessionOutput{output: w}.WriteContext(ctx, p) }}
}

type boundSessionOutput struct {
	output sessionOutput
	write  func([]byte) (int, error)
}

func (w boundSessionOutput) Write(p []byte) (int, error) { return w.write(p) }
func (w boundSessionOutput) WriteContext(ctx context.Context, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxExecSessionInput)
		data := append([]byte(nil), p[:n]...)
		frame := &localv1.ExecSessionResponse{Frame: &localv1.ExecSessionResponse_Stdout{Stdout: data}}
		if w.output.stderr {
			frame.Frame = &localv1.ExecSessionResponse_Stderr{Stderr: data}
		}
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case w.output.frames <- frame:
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// execSessionProtocol checks ordering and resource bounds before a frame is
// forwarded to a guest. It does not itself authorize or start a session.
type execSessionProtocol struct {
	opened      bool
	tty         bool
	stdinClosed bool
}

func (p *execSessionProtocol) accept(req *localv1.ExecSessionRequest) error {
	if req == nil {
		return errors.New("missing session frame")
	}
	if !p.opened {
		return p.acceptOpen(req.GetOpen())
	}
	switch frame := req.GetFrame().(type) {
	case *localv1.ExecSessionRequest_Stdin:
		if p.stdinClosed || len(frame.Stdin) == 0 || len(frame.Stdin) > maxExecSessionInput {
			return errors.New("invalid stdin frame")
		}
	case *localv1.ExecSessionRequest_Resize:
		if !p.tty || frame.Resize == nil || !validTerminalSize(frame.Resize.GetRows(), frame.Resize.GetCols()) {
			return errors.New("invalid terminal resize")
		}
	case *localv1.ExecSessionRequest_StdinEof:
		if p.stdinClosed || !frame.StdinEof {
			return errors.New("invalid stdin EOF")
		}
		p.stdinClosed = true
	default:
		return errors.New("unexpected session frame")
	}
	return nil
}

func (p *execSessionProtocol) acceptOpen(open *localv1.ExecSessionOpen) error {
	if open == nil || open.GetSandboxId() == "" || len(open.GetArgv()) == 0 || len(open.GetArgv()) > 256 || open.GetArgv()[0] == "" {
		return errors.New("first frame must open a session with sandbox and command")
	}
	if open.GetTty() && !validInitialTerminalSize(open.GetRows(), open.GetCols()) {
		return errors.New("invalid terminal size")
	}
	if !open.GetTty() && (open.GetRows() != 0 || open.GetCols() != 0) {
		return errors.New("terminal size requires tty")
	}
	p.opened = true
	p.tty = open.GetTty()
	return nil
}

func validTerminalSize(rows, cols uint32) bool {
	return rows > 0 && cols > 0 && rows <= 65535 && cols <= 65535
}

func validInitialTerminalSize(rows, cols uint32) bool {
	return rows == 0 && cols == 0 || validTerminalSize(rows, cols)
}
