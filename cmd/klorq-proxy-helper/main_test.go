package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/QUOINER/sandboxes-daemon/internal/secretproxy"
)

func TestVsockConnWrapsPollableFile(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	conn := &vsockConn{file: reader, local: vsockAddr{}, remote: vsockAddr{cid: 2, port: 1027}}
	if conn.RemoteAddr().Network() != "vsock" || conn.RemoteAddr().String() != "2:1027" {
		t.Fatalf("remote address = %v", conn.RemoteAddr())
	}
	if _, err := io.WriteString(writer, "connected"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("connected"))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "connected" {
		t.Fatalf("read %q", buffer)
	}
}

func TestVsockConnectWaitHonorsCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := waitForVSockConnect(ctx, int(reader.Fd())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForVSockConnect() error = %v, want deadline exceeded", err)
	}
}

func TestDialVsockRejectsOutOfRangeAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		cid  int
		port int
	}{
		{name: "negative cid", cid: -1, port: 1027},
		{name: "cid overflow", cid: 1 << 32, port: 1027},
		{name: "zero port", cid: 2, port: 0},
		{name: "port overflow", cid: 2, port: 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dialVsock(context.Background(), tc.cid, tc.port); err == nil {
				t.Fatal("dialVsock() accepted an out-of-range address")
			}
		})
	}
}

func TestHelperServerBindsConfiguredLoopbackAddress(t *testing.T) {
	server := newHTTPServer("127.0.0.1:3128", http.NotFoundHandler())
	if server.Addr != "127.0.0.1:3128" {
		t.Fatalf("server listen address = %q", server.Addr)
	}
}

func TestHelperForwardsWithTokenAndBrokerInjectsSecret(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "answer")
	}))
	defer upstream.Close()

	dir, err := os.MkdirTemp("/tmp", "kqhelper")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "broker.sock")
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	broker := secretproxy.New()
	t.Cleanup(func() { _ = broker.Close() })
	if _, err := broker.StartUnix(context.Background(), "dev", "openai", secretproxy.Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, []byte("s3cret"), socket, token); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	bootstrapped, err := fetchToken(context.Background(), transport)
	if err != nil || bootstrapped != token {
		t.Fatalf("fetchToken() = matching:%t, err=%v", bootstrapped == token, err)
	}
	helper := httptest.NewServer(newHandler("api.example.test", transport))
	defer helper.Close()

	req, _ := http.NewRequest(http.MethodGet, helper.URL+"/v1/answer", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "answer" || gotAuth != "Bearer s3cret" || gotPath != "/v1/answer" {
		t.Fatalf("body=%q auth=%q path=%q", body, gotAuth, gotPath)
	}
}
