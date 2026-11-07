package service

import (
	"context"
	"encoding/json"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"

	"github.com/rheic/sandboxes-daemon/internal/mcpmanager"
)

func (s *Service) mcpRegistry(ctx context.Context) (*mcpmanager.Manager, error) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	if s.mcpManager != nil {
		return s.mcpManager, nil
	}
	manager, err := mcpmanager.New(ctx, s.store)
	if err != nil {
		return nil, err
	}
	manager.SetRemoteAllowlist(s.mcpRemoteHosts)
	manager.SetApprovalProvider(s.mcpApprover)
	s.mcpManager = manager
	return manager, nil
}

// SetMCPRemoteAllowlist installs the explicit host administrator policy used
// by remote MCP. An empty list keeps remote registration disabled.
func (s *Service) SetMCPRemoteAllowlist(hosts []string) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	s.mcpRemoteHosts = append([]string(nil), hosts...)
	if s.mcpManager != nil {
		s.mcpManager.SetRemoteAllowlist(hosts)
	}
}

// SetMCPApprovalProvider installs a trusted host-side consent mechanism.
// Production must configure an OS-backed provider before enabling host MCP
// execution; there is deliberately no RPC/CLI boolean fallback.
func (s *Service) SetMCPApprovalProvider(provider mcpmanager.ApprovalProvider) {
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	s.mcpApprover = provider
	if s.mcpManager != nil {
		s.mcpManager.SetApprovalProvider(provider)
	}
}

// Close releases daemon-owned host MCP processes before state storage closes.
func (s *Service) Close() error {
	s.mcpMu.Lock()
	manager := s.mcpManager
	s.mcpMu.Unlock()
	if manager == nil {
		return nil
	}
	return manager.Close()
}

func (s *Service) ListMCPServers(ctx context.Context, sandboxID string) ([]mcpmanager.Summary, error) {
	if sandboxID != "" {
		if _, err := s.store.Get(ctx, sandboxID); err != nil {
			return nil, err
		}
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.List(), nil
}
func (s *Service) RegisterMCPServer(ctx context.Context, name, command string, args []string, directory string) (string, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.Register(ctx, name, command, args, directory)
}

// RegisterRemoteMCPServer queues a remote (streamable HTTP) MCP server. The
// URL must satisfy the daemon's fail-closed host allowlist.
func (s *Service) RegisterRemoteMCPServer(ctx context.Context, name, rawURL string, headers map[string]string) (string, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.RegisterRemote(ctx, name, rawURL, headers)
}
func (s *Service) ApproveMCPRegistration(ctx context.Context, id string) (*mcpmanager.Summary, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.ApproveRegistration(ctx, id)
}
func (s *Service) RemoveMCPServer(ctx context.Context, name string) (bool, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return false, err
	}
	return manager.Remove(ctx, name)
}
func (s *Service) RequestMCPCall(ctx context.Context, sandboxID, server, tool string, args string) (string, error) {
	sb, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return "", err
	}
	if sb.State != sandbox.Running {
		return "", core.ErrConflict
	}
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return "", err
	}
	return manager.RequestCall(sandboxID, server, tool, json.RawMessage(args))
}
func (s *Service) ApproveMCPCall(ctx context.Context, id string) (json.RawMessage, error) {
	manager, err := s.mcpRegistry(ctx)
	if err != nil {
		return nil, err
	}
	return manager.ApproveCall(ctx, id, func(ctx context.Context, sandboxID string) error {
		sb, err := s.store.Get(ctx, sandboxID)
		if err != nil {
			return err
		}
		if sb.State != sandbox.Running {
			return core.ErrConflict
		}
		return nil
	})
}
