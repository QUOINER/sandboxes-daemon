package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/store"
)

func ipv6Rule(port uint16) sandbox.NetworkRule {
	return sandbox.NetworkRule{Protocol: "tcp", CIDR: "2001:db8::/32", Port: port}
}

func openIPv6TestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, &fakePolicyRuntime{}), st
}

func TestIPv6CIDRRulesRequireExplicitCapability(t *testing.T) {
	ctx := context.Background()
	svc, _ := openIPv6TestService(t)
	if _, err := svc.Create(ctx, CreateRequest{Name: "v6-disabled", Allow: []sandbox.NetworkRule{ipv6Rule(443)}}); err == nil {
		t.Fatal("IPv6 create rule accepted while the capability is disabled")
	}

	svc.IPv6Enabled = true
	op, err := svc.Create(ctx, CreateRequest{Name: "v6-enabled", Allow: []sandbox.NetworkRule{ipv6Rule(443)}})
	if err != nil {
		t.Fatalf("IPv6 create rule rejected with the capability enabled: %v", err)
	}
	stored, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Policy == nil || len(stored.Policy.Allow) != 1 || stored.Policy.Allow[0].CIDR != "2001:db8::/32" {
		t.Fatalf("stored IPv6 policy=%+v", stored.Policy)
	}

	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "deny", ipv6Rule(8443)); err != nil {
		t.Fatalf("IPv6 policy mutation rejected with the capability enabled: %v", err)
	}

	svc.IPv6Enabled = false
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", ipv6Rule(9443)); err == nil {
		t.Fatal("IPv6 policy mutation accepted while the capability is disabled")
	}
}

func TestGlobalIPv6PolicyRequiresExplicitCapability(t *testing.T) {
	ctx := context.Background()
	svc, _ := openIPv6TestService(t)
	svc.IPv6Enabled = false
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", ipv6Rule(443)); err == nil {
		t.Fatal("global IPv6 rule accepted while the capability is disabled")
	}
	svc.IPv6Enabled = true
	allow, _, err := svc.MutateGlobalPolicy(ctx, "allow", ipv6Rule(443))
	if err != nil {
		t.Fatalf("global IPv6 rule rejected with the capability enabled: %v", err)
	}
	if len(allow) != 1 || allow[0].CIDR != "2001:db8::/32" {
		t.Fatalf("global allow=%+v", allow)
	}
}
