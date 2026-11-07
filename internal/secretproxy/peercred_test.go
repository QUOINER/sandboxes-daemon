package secretproxy

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func mustTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kqpeercred")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPeerCheckingListenerRejectsForeignOwner(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return currentUID() + 1, true
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- peer
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
		t.Fatal("foreign-owner connection was accepted")
	case err := <-acceptErr:
		t.Fatalf("accept returned error instead of skipping peer: %v", err)
	case <-time.After(2 * time.Second):
	}
	if rejected.Load() != 1 {
		t.Fatalf("rejected=%d want 1", rejected.Load())
	}
}

func TestPeerCheckingListenerAcceptsSameOwner(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return currentUID(), true
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- peer
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("same-owner connection was not accepted")
	}
	if rejected.Load() != 0 {
		t.Fatalf("rejected=%d want 0", rejected.Load())
	}
}

func TestPeerCheckingListenerAcceptsUnverifiablePeer(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{
		Listener: inner,
		rejected: &rejected,
		peerUID: func(net.Conn) (uint64, bool) {
			return 0, false
		},
	}
	defer func() { _ = listener.Close() }()

	conn, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- peer
	}()
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("unverifiable peer was not accepted")
	}
	if rejected.Load() != 0 {
		t.Fatalf("rejected=%d want 0", rejected.Load())
	}
}

func TestPeerCheckingListenerPropagatesAcceptError(t *testing.T) {
	inner, err := net.Listen("unix", filepath.Join(mustTempDir(t), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	listener := peerCheckingListener{Listener: inner, rejected: &rejected, peerUID: peerOwnerUID}
	if err := inner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); err == nil {
		t.Fatal("accept error = nil, want non-nil")
	}
}
