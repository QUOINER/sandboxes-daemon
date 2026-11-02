package network

import (
	"context"
	"path/filepath"
	"testing"

	gateway "github.com/KLORQ/sandboxes-gateway"
	"github.com/KLORQ/sandboxes-gateway/policy"
	runtime "github.com/KLORQ/sandboxes-runtime"
)

type fakeManager struct {
	policy  policy.Policy
	net     gateway.Network
	stopped string
}

func (f *fakeManager) Start(_ context.Context, p policy.Policy) (gateway.Network, error) {
	f.policy = p
	return f.net, nil
}

func (f *fakeManager) Reload(_ context.Context, p policy.Policy) error {
	f.policy = p
	return nil
}

func (f *fakeManager) SetPorts(_ context.Context, name string, ports []policy.Port) error {
	f.policy.SandboxID = name
	f.policy.Ports = ports
	return nil
}

func (f *fakeManager) Stop(_ context.Context, name string) error {
	f.stopped = name
	return nil
}

func TestAdapterStart(t *testing.T) {
	manager := &fakeManager{net: gateway.Network{
		SocketPath:  "/run/dev.sock",
		MAC:         "fa:43:25:01:02:03",
		DeviceIP:    "192.168.127.2",
		GatewayIP:   "192.168.127.1",
		Annotations: []string{"net=1"},
	}}
	adapter := New(manager, "/tmp/audit")
	attachment, err := adapter.Start(context.Background(), "dev", []runtime.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "::1"}}, []runtime.Rule{{ID: "rul_allow_https", Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 443}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if manager.policy.SandboxID != "dev" || manager.policy.Revision <= 0 {
		t.Fatalf("policy = %+v", manager.policy)
	}
	if manager.policy.AuditPath != filepath.Join("/tmp/audit", "dev.audit.jsonl") {
		t.Fatalf("audit path = %s", manager.policy.AuditPath)
	}
	if len(manager.policy.Ports) != 1 || manager.policy.Ports[0].Host != 8080 || manager.policy.Ports[0].Guest != 3000 || manager.policy.Ports[0].HostIP != "::1" {
		t.Fatalf("policy ports = %+v", manager.policy.Ports)
	}
	if len(manager.policy.Allow) != 1 || manager.policy.Allow[0].CIDR != "0.0.0.0/0" || manager.policy.Allow[0].Port != 443 {
		t.Fatalf("policy allow = %+v", manager.policy.Allow)
	}
	if manager.policy.Allow[0].ID != "rul_allow_https" {
		t.Fatalf("policy rule ID = %q, want rul_allow_https", manager.policy.Allow[0].ID)
	}
	if attachment.SocketPath != "/run/dev.sock" || len(attachment.Annotations) != 1 {
		t.Fatalf("attachment = %+v", attachment)
	}
}

func TestAdapterUpdatePolicy(t *testing.T) {
	manager := &fakeManager{net: gateway.Network{}}
	adapter := New(manager, "/tmp/audit")
	if err := adapter.UpdatePolicy(context.Background(), "dev", nil, []runtime.Rule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}}, nil, 2); err != nil {
		t.Fatal(err)
	}
	if manager.policy.Revision != 2 || len(manager.policy.Allow) != 1 || manager.policy.Allow[0].Port != 80 {
		t.Fatalf("reload policy = %+v", manager.policy)
	}
}

func TestAdapterUpdatePorts(t *testing.T) {
	manager := &fakeManager{net: gateway.Network{}}
	adapter := New(manager, "/tmp/audit")
	if err := adapter.UpdatePorts(context.Background(), "dev", []runtime.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "::1"}}); err != nil {
		t.Fatal(err)
	}
	if len(manager.policy.Ports) != 1 || manager.policy.Ports[0].Host != 8080 || manager.policy.Ports[0].HostIP != "::1" {
		t.Fatalf("ports = %+v", manager.policy.Ports)
	}
}

func TestAdapterStop(t *testing.T) {
	manager := &fakeManager{}
	adapter := New(manager, "/tmp/audit")
	if err := adapter.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	if manager.stopped != "dev" {
		t.Fatalf("stopped = %s", manager.stopped)
	}
}
