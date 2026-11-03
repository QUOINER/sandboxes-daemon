//go:build windows

package secretproxy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixProxyTransportFailsClosedOnWindows(t *testing.T) {
	manager := New()
	t.Cleanup(func() { _ = manager.Close() })
	_, err := manager.StartUnix(context.Background(), "windows-test", "openai", Service{
		Upstream: "https://api.openai.com", Header: "Authorization", Prefix: "Bearer ",
	}, []byte("synthetic-secret"), filepath.Join(t.TempDir(), "proxy.sock"), strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("Unix proxy transport unexpectedly accepted Windows filesystem permissions")
	}
	if manager.Has("windows-test", "openai") {
		t.Fatal("failed Windows proxy setup left an active channel")
	}
}
