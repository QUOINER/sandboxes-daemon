package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KLORQ/sandboxes-daemon/internal/secretproxy"
)

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
