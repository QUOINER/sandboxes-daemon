// Package network adapts the gateway manager to the runtime network contract.
package network

import (
	"context"
	"path/filepath"
	"time"

	gateway "github.com/KLORQ/sandboxes-gateway"
	"github.com/KLORQ/sandboxes-gateway/policy"
	runtime "github.com/KLORQ/sandboxes-runtime"
)

// Manager is the subset of the gateway manager used by the adapter.
type Manager interface {
	Start(ctx context.Context, p policy.Policy) (gateway.Network, error)
	Reload(ctx context.Context, p policy.Policy) error
	SetPorts(ctx context.Context, name string, ports []policy.Port) error
	Stop(ctx context.Context, name string) error
}

// Adapter supplies default-deny gateway attachments to the runtime.
type Adapter struct {
	manager  Manager
	auditDir string
}

// New creates a gateway network adapter.
func New(manager Manager, auditDir string) *Adapter {
	return &Adapter{manager: manager, auditDir: auditDir}
}

// Start starts a gateway with a default-deny policy.
func (a *Adapter) Start(ctx context.Context, sandbox string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	net, err := a.manager.Start(ctx, policy.Policy{
		// The start policy uses the same monotonic generation as later
		// reloads so an audit revision never jumps backwards.
		Revision:  int(time.Now().UnixNano()),
		SandboxID: sandbox,
		AuditPath: filepath.Join(a.auditDir, sandbox+".audit.jsonl"),
		Ports:     policyPorts,
		Allow:     toPolicyRules(allow, policy.Allow),
		Deny:      toPolicyRules(deny, policy.Deny),
	})
	if err != nil {
		return runtime.NetworkAttachment{}, err
	}
	return runtime.NetworkAttachment{
		SocketPath:  net.SocketPath,
		MAC:         net.MAC,
		DeviceIP:    net.DeviceIP,
		GatewayIP:   net.GatewayIP,
		Annotations: net.Annotations,
	}, nil
}

// Stop stops the sandbox gateway.
func (a *Adapter) UpdatePolicy(ctx context.Context, sandbox string, ports []runtime.Port, allow, deny []runtime.Rule, revision int) error {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	return a.manager.Reload(ctx, policy.Policy{
		Revision:  revision,
		SandboxID: sandbox,
		AuditPath: filepath.Join(a.auditDir, sandbox+".audit.jsonl"),
		Ports:     policyPorts,
		Allow:     toPolicyRules(allow, policy.Allow),
		Deny:      toPolicyRules(deny, policy.Deny),
	})
}

func (a *Adapter) UpdatePorts(ctx context.Context, sandbox string, ports []runtime.Port) error {
	policyPorts := make([]policy.Port, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, policy.Port{Host: port.Host, Guest: port.Guest, Proto: port.Protocol, HostIP: port.HostIP})
	}
	return a.manager.SetPorts(ctx, sandbox, policyPorts)
}

func (a *Adapter) Stop(ctx context.Context, sandbox string) error {
	return a.manager.Stop(ctx, sandbox)
}

var _ runtime.Network = (*Adapter)(nil)

func toPolicyRules(rules []runtime.Rule, action policy.Action) []policy.Rule {
	out := make([]policy.Rule, 0, len(rules))
	for i := range rules {
		out = append(out, policy.Rule{ID: rules[i].ID, Action: action, Protocol: rules[i].Protocol, CIDR: rules[i].CIDR, Port: rules[i].Port, Domain: rules[i].Domain})
	}
	return out
}
