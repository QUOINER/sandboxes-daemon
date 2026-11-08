//go:build !windows

package daemon

import (
	"testing"

	"github.com/rheic/sandboxes-daemon/internal/service"
)

func TestApplyConfigPropagatesIPv6Capability(t *testing.T) {
	svc := &service.Service{}
	applyConfig(svc, Config{})
	if svc.IPv6Enabled {
		t.Fatal("IPv6 capability was enabled without an explicit daemon configuration")
	}
	applyConfig(svc, Config{IPv6Enabled: true})
	if !svc.IPv6Enabled {
		t.Fatal("IPv6 capability was not propagated to the service")
	}
	applyConfig(svc, Config{IPv6Enabled: false})
	if svc.IPv6Enabled {
		t.Fatal("IPv6 capability was not reset to fail closed")
	}
}
