package server

import (
	"testing"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestExecSessionProtocol(t *testing.T) {
	open := func(tty bool) *localv1.ExecSessionRequest {
		v := &localv1.ExecSessionOpen{SandboxId: "owned", Argv: []string{"cat"}, Tty: tty}
		if tty {
			v.Rows, v.Cols = 24, 80
		}
		return &localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Open{Open: v}}
	}
	input := func(n int) *localv1.ExecSessionRequest {
		return &localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Stdin{Stdin: make([]byte, n)}}
	}
	resize := &localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Resize{Resize: &localv1.ExecSessionResize{Rows: 40, Cols: 120}}}
	eof := &localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_StdinEof{StdinEof: true}}
	for _, tc := range []struct {
		name   string
		frames []*localv1.ExecSessionRequest
		fail   int
	}{
		{name: "tty session", frames: []*localv1.ExecSessionRequest{open(true), input(maxExecSessionInput), resize, eof}, fail: -1},
		{name: "tty without terminal dimensions", frames: []*localv1.ExecSessionRequest{{Frame: &localv1.ExecSessionRequest_Open{Open: &localv1.ExecSessionOpen{SandboxId: "owned", Argv: []string{"cat"}, Tty: true}}}}, fail: -1},
		{name: "pipe session", frames: []*localv1.ExecSessionRequest{open(false), input(1), eof}, fail: -1},
		{name: "missing open", frames: []*localv1.ExecSessionRequest{input(1)}, fail: 0},
		{name: "duplicate open", frames: []*localv1.ExecSessionRequest{open(false), open(false)}, fail: 1},
		{name: "resize without tty", frames: []*localv1.ExecSessionRequest{open(false), resize}, fail: 1},
		{name: "oversized stdin", frames: []*localv1.ExecSessionRequest{open(false), input(maxExecSessionInput + 1)}, fail: 1},
		{name: "stdin after eof", frames: []*localv1.ExecSessionRequest{open(false), eof, input(1)}, fail: 2},
		{name: "duplicate eof", frames: []*localv1.ExecSessionRequest{open(false), eof, eof}, fail: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &execSessionProtocol{}
			for i, frame := range tc.frames {
				err := p.accept(frame)
				if (err != nil) != (i == tc.fail) {
					t.Fatalf("frame %d: %v", i, err)
				}
			}
		})
	}
}
