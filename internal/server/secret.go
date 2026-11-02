package server

import (
	"context"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
)

// SecretServer implements the local service-secret RPCs.
type SecretServer struct {
	localv1.UnimplementedSecretServiceServer
	svc *service.Service
}

// NewSecret creates a service-secret server.
func NewSecret(svc *service.Service) *SecretServer { return &SecretServer{svc: svc} }

// Set stores one service secret. The value is cleared after the call.
func (s *SecretServer) Set(ctx context.Context, req *localv1.SecretServiceSetRequest) (*localv1.SecretServiceSetResponse, error) {
	value := req.GetValue()
	defer clear(value)
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	summary, err := s.svc.SetServiceSecret(ctx, req.GetService(), scope, req.GetSandboxName(), value)
	if err != nil {
		return nil, err
	}
	return &localv1.SecretServiceSetResponse{Secret: &localv1.SecretSummary{
		Service: summary.Service, Scope: string(summary.Scope), SandboxName: summary.SandboxName,
	}}, nil
}

// List returns non-secret summaries.
func (s *SecretServer) List(ctx context.Context, _ *localv1.SecretServiceListRequest) (*localv1.SecretServiceListResponse, error) {
	items, err := s.svc.ListServiceSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*localv1.SecretSummary, 0, len(items))
	for _, item := range items {
		out = append(out, &localv1.SecretSummary{Service: item.Service, Scope: string(item.Scope), SandboxName: item.SandboxName})
	}
	return &localv1.SecretServiceListResponse{Secrets: out}, nil
}

// Remove deletes one secret.
func (s *SecretServer) Remove(ctx context.Context, req *localv1.SecretServiceRemoveRequest) (*localv1.SecretServiceRemoveResponse, error) {
	scope, err := parseSecretScope(req.GetScope())
	if err != nil {
		return nil, err
	}
	removed, err := s.svc.RemoveServiceSecret(ctx, req.GetService(), scope, req.GetSandboxName())
	if err != nil {
		return nil, err
	}
	return &localv1.SecretServiceRemoveResponse{Removed: removed}, nil
}

func parseSecretScope(value string) (servicesecrets.Scope, error) {
	switch servicesecrets.Scope(value) {
	case "", servicesecrets.ScopeGlobal:
		return servicesecrets.ScopeGlobal, nil
	case servicesecrets.ScopeSandbox:
		return servicesecrets.ScopeSandbox, nil
	default:
		return "", status.Error(codes.InvalidArgument, "secret scope must be global or sandbox")
	}
}
