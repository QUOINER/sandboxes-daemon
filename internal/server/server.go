// Package server exposes the local daemon over gRPC.
package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	localv1 "github.com/QUOINER/sandboxes-api/gen/go/sandboxes/local/v1"
	apiversion "github.com/QUOINER/sandboxes-api/version"
	core "github.com/QUOINER/sandboxes-core"
	"github.com/QUOINER/sandboxes-core/operation"
	"github.com/QUOINER/sandboxes-core/sandbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/QUOINER/sandboxes-daemon/internal/registrycredentials"
	"github.com/QUOINER/sandboxes-daemon/internal/service"
	"github.com/QUOINER/sandboxes-daemon/internal/version"
)

const defaultAccountProvider = "docker"

// SandboxServer implements the sandbox gRPC service.
type SandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
	svc *service.Service
}

// OperationServer implements the operation gRPC service.
type OperationServer struct {
	localv1.UnimplementedOperationServiceServer
	svc *service.Service
}

// RegistryCredentialServer stores credentials in the host keychain.
type RegistryCredentialServer struct {
	localv1.UnimplementedRegistryCredentialServiceServer
	svc *service.Service
}

// AccountServer exposes host-side OAuth login without returning tokens.
type AccountServer struct {
	localv1.UnimplementedAccountServiceServer
	svc *service.Service
}

// NewSandbox creates a sandbox gRPC service.
func NewSandbox(svc *service.Service) *SandboxServer { return &SandboxServer{svc: svc} }

// GetVersion reports the daemon and API contract versions.
func (s *SandboxServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{
		Version:    version.Version,
		ApiVersion: apiversion.Version,
	}, nil
}

// NewOperation creates an operation gRPC service.
func NewOperation(svc *service.Service) *OperationServer { return &OperationServer{svc: svc} }

// NewRegistryCredential creates the host registry credential service.
func NewRegistryCredential(svc *service.Service) *RegistryCredentialServer {
	return &RegistryCredentialServer{svc: svc}
}

// NewAccount creates the host account OAuth service.
func NewAccount(svc *service.Service) *AccountServer { return &AccountServer{svc: svc} }

func (s *AccountServer) Login(ctx context.Context, req *localv1.AccountServiceLoginRequest) (*localv1.AccountServiceLoginResponse, error) {
	provider := req.GetProvider()
	if provider == "" {
		provider = defaultAccountProvider
	}
	loginCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := s.svc.LoginAccount(loginCtx, provider); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, mapError(err)
		}
		if errors.Is(err, service.ErrOAuthProviderUnavailable) {
			return nil, status.Error(codes.FailedPrecondition, "OAuth provider is not configured on this daemon")
		}
		if errors.Is(err, service.ErrOAuthPartialLogin) {
			return nil, status.Error(codes.FailedPrecondition, "OAuth login may have partially completed; run qsbx logout before retrying")
		}
		return nil, status.Error(codes.FailedPrecondition, "OAuth login failed; no credentials were returned")
	}
	return &localv1.AccountServiceLoginResponse{Provider: provider, Authenticated: true}, nil
}

// LoginDevice streams a public user code to the CLI, waits for the CLI's
// explicit continuation after the browser handoff, then completes the trusted
// daemon-side device flow. The provider device code never crosses gRPC.
func (s *AccountServer) LoginDevice(stream grpc.BidiStreamingServer[localv1.AccountServiceLoginDeviceRequest, localv1.AccountServiceLoginDeviceResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return mapError(err)
	}
	if first.GetContinueAfterHandoff() {
		return status.Error(codes.InvalidArgument, "OAuth login must start before handoff confirmation")
	}
	provider := first.GetProvider()
	if provider == "" {
		provider = defaultAccountProvider
	}
	ctx, cancel := context.WithTimeout(stream.Context(), 30*time.Minute)
	defer cancel()
	authorization, err := s.svc.BeginDeviceAccountLogin(ctx, provider)
	if err != nil {
		return accountLoginError(err)
	}
	if err := stream.Send(&localv1.AccountServiceLoginDeviceResponse{
		UserCode: authorization.UserCode, VerificationUri: authorization.VerificationURI,
	}); err != nil {
		return mapError(err)
	}
	ack, err := stream.Recv()
	if err != nil {
		return mapError(err)
	}
	if ack.GetProvider() != "" {
		return status.Error(codes.InvalidArgument, "unexpected OAuth provider in handoff confirmation")
	}
	if !ack.GetContinueAfterHandoff() {
		return status.Error(codes.Canceled, "OAuth login canceled")
	}
	if err := s.svc.CompleteDeviceAccountLogin(ctx, provider, authorization); err != nil {
		return accountLoginError(err)
	}
	return stream.Send(&localv1.AccountServiceLoginDeviceResponse{Authenticated: true})
}

func accountLoginError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return mapError(err)
	}
	if errors.Is(err, service.ErrOAuthProviderUnavailable) {
		return status.Error(codes.FailedPrecondition, "OAuth provider is not configured on this daemon")
	}
	if errors.Is(err, service.ErrOAuthPartialLogin) {
		return status.Error(codes.FailedPrecondition, "OAuth login may have partially completed; run qsbx logout before retrying")
	}
	return status.Error(codes.FailedPrecondition, "OAuth login failed; no credentials were returned")
}

func (s *AccountServer) LoginWithPAT(ctx context.Context, req *localv1.AccountServiceLoginWithPATRequest) (*localv1.AccountServiceLoginWithPATResponse, error) {
	password := req.GetPassword()
	defer clear(password)
	if err := s.svc.LoginDockerHubPAT(ctx, req.GetUsername(), password); err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, mapError(err)
		case errors.Is(err, service.ErrDockerHubCredentialRejected):
			return nil, status.Error(codes.Unauthenticated, "Docker Hub rejected the supplied credentials")
		case errors.Is(err, registrycredentials.ErrInvalidCredential):
			return nil, status.Error(codes.InvalidArgument, "invalid Docker Hub credentials")
		case errors.Is(err, service.ErrOAuthCredentialConflict):
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		case errors.Is(err, service.ErrOAuthPartialLogin):
			return nil, status.Error(codes.FailedPrecondition, "Docker login may have partially completed; run qsbx logout before retrying")
		default:
			return nil, status.Error(codes.Unavailable, "Docker Hub login could not be completed")
		}
	}
	return &localv1.AccountServiceLoginWithPATResponse{Authenticated: true}, nil
}

func (s *AccountServer) Logout(ctx context.Context, req *localv1.AccountServiceLogoutRequest) (*localv1.AccountServiceLogoutResponse, error) {
	provider := req.GetProvider()
	if provider == "" {
		provider = defaultAccountProvider
	}
	removed, err := s.svc.LogoutAccount(ctx, provider)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, mapError(err)
		}
		if errors.Is(err, service.ErrOAuthProviderUnavailable) {
			return nil, status.Error(codes.FailedPrecondition, "OAuth provider is not configured on this daemon")
		}
		if errors.Is(err, service.ErrOAuthRevocationFailed) || errors.Is(err, service.ErrOAuthRevocationUnavailable) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Unavailable, "OAuth host keychain operation failed")
	}
	return &localv1.AccountServiceLogoutResponse{Removed: removed}, nil
}

func (s *AccountServer) Status(ctx context.Context, req *localv1.AccountServiceStatusRequest) (*localv1.AccountServiceStatusResponse, error) {
	provider := req.GetProvider()
	if provider == "" {
		provider = defaultAccountProvider
	}
	present, err := s.svc.AccountCredentialsPresent(ctx, provider)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, mapError(err)
		}
		if errors.Is(err, service.ErrOAuthProviderUnavailable) {
			return nil, status.Error(codes.FailedPrecondition, "OAuth provider is not configured on this daemon")
		}
		return nil, status.Error(codes.Unavailable, "OAuth host credential status is unavailable")
	}
	return &localv1.AccountServiceStatusResponse{Provider: provider, CredentialPresent: present}, nil
}

// Login stores registry credentials without returning or logging secret data.
func (s *RegistryCredentialServer) Login(ctx context.Context, req *localv1.RegistryCredentialServiceLoginRequest) (*localv1.RegistryCredentialServiceLoginResponse, error) {
	defer clear(req.Password)
	scope := registrycredentials.ScopeHostOnly
	switch req.GetScope() {
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_UNSPECIFIED,
		localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_HOST_ONLY:
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES:
		scope = registrycredentials.ScopeAllSandboxes
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_SANDBOX:
		scope = registrycredentials.ScopeSandbox
	default:
		return nil, status.Error(codes.InvalidArgument, "registry credential scope is invalid")
	}
	summary, err := s.svc.LoginRegistry(ctx, registrycredentials.Credential{
		Registry: req.GetRegistry(), Username: req.GetUsername(), Password: req.GetPassword(),
		Scope: scope, SandboxName: req.GetSandboxName(),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, mapError(err)
		}
		if errors.Is(err, registrycredentials.ErrInvalidCredential) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Unavailable, "host registry credential store is unavailable")
	}
	protoScope := localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_HOST_ONLY
	switch summary.Scope {
	case registrycredentials.ScopeAllSandboxes:
		protoScope = localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES
	case registrycredentials.ScopeSandbox:
		protoScope = localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_SANDBOX
	}
	return &localv1.RegistryCredentialServiceLoginResponse{
		Registry: summary.Registry, Username: summary.Username, Scope: protoScope, SandboxName: summary.SandboxName,
	}, nil
}

// Logout removes one registry credential without exposing the stored value.
func (s *RegistryCredentialServer) List(ctx context.Context, _ *localv1.RegistryCredentialServiceListRequest) (*localv1.RegistryCredentialServiceListResponse, error) {
	summaries, err := s.svc.ListRegistryCredentials(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "registry credential index is unavailable")
	}
	out := make([]*localv1.RegistryCredentialSummary, 0, len(summaries))
	for _, summary := range summaries {
		out = append(out, &localv1.RegistryCredentialSummary{
			Registry: summary.Registry, Username: summary.Username,
			Scope: string(summary.Scope), SandboxName: summary.SandboxName,
		})
	}
	return &localv1.RegistryCredentialServiceListResponse{Credentials: out}, nil
}

func (s *RegistryCredentialServer) Logout(ctx context.Context, req *localv1.RegistryCredentialServiceLogoutRequest) (*localv1.RegistryCredentialServiceLogoutResponse, error) {
	scope := registrycredentials.ScopeHostOnly
	switch req.GetScope() {
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_UNSPECIFIED,
		localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_HOST_ONLY:
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES:
		scope = registrycredentials.ScopeAllSandboxes
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_SANDBOX:
		scope = registrycredentials.ScopeSandbox
	default:
		return nil, status.Error(codes.InvalidArgument, "registry credential scope is invalid")
	}
	removed, err := s.svc.LogoutRegistry(ctx, req.GetRegistry(), scope, req.GetSandboxName())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, mapError(err)
		}
		if errors.Is(err, registrycredentials.ErrInvalidCredential) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Unavailable, "host registry credential store is unavailable")
	}
	return &localv1.RegistryCredentialServiceLogoutResponse{Removed: removed}, nil
}

// Create creates a sandbox.
func (s *SandboxServer) Create(ctx context.Context, req *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	allow := fromProtoRules(req.GetAllow())
	deny := fromProtoRules(req.GetDeny())
	if len(allow) != len(req.GetAllow()) || len(deny) != len(req.GetDeny()) {
		return nil, status.Error(codes.InvalidArgument, "network rules must have valid ports")
	}
	op, err := s.svc.Create(ctx, service.CreateRequest{
		Name:           req.GetName(),
		Image:          req.GetImage(),
		Workspace:      req.GetWorkspace(),
		IdempotencyKey: req.GetIdempotencyKey(),
		CPUs:           req.GetCpus(),
		MemoryMiB:      req.GetMemoryMib(),
		Workspaces:     fromProtoWorkspaces(req.GetWorkspaces()),
		Ports:          fromProtoPorts(req.GetPorts()),
		Allow:          allow,
		Deny:           deny,
		Agent:          req.GetAgent(),
		Detached:       req.GetDetached(),
		PolicyProfile:  req.GetPolicyProfile(),
		Privileged:     req.GetPrivileged(),
		Env:            req.GetEnv(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.CreateResponse{Operation: toProtoOperation(op)}, nil
}

// Get returns a sandbox.
func (s *SandboxServer) Get(ctx context.Context, req *localv1.GetRequest) (*localv1.GetResponse, error) {
	sb, err := s.svc.Get(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.GetResponse{Sandbox: toProtoSandbox(sb)}, nil
}

// List returns a page of sandboxes.
func (s *SandboxServer) List(ctx context.Context, req *localv1.ListRequest) (*localv1.ListResponse, error) {
	items, next, err := s.svc.List(ctx, sandbox.ListOptions{
		PageSize:  int(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	resp := &localv1.ListResponse{NextPageToken: next, Items: make([]*localv1.Sandbox, 0, len(items))}
	for i := range items {
		resp.Items = append(resp.Items, toProtoSandbox(items[i]))
	}
	return resp, nil
}

// Start starts a sandbox.
func (s *SandboxServer) Start(ctx context.Context, req *localv1.StartRequest) (*localv1.StartResponse, error) {
	op, err := s.svc.Start(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.StartResponse{Operation: toProtoOperation(op)}, nil
}

// Stop stops a sandbox.
func (s *SandboxServer) Stop(ctx context.Context, req *localv1.StopRequest) (*localv1.StopResponse, error) {
	if req.GetGraceSeconds() < 0 || req.GetGraceSeconds() > 3600 {
		return nil, status.Error(codes.InvalidArgument, "grace_seconds must be between 0 and 3600")
	}
	op, err := s.svc.StopWithGrace(ctx, req.GetId(), time.Duration(req.GetGraceSeconds())*time.Second)
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.StopResponse{Operation: toProtoOperation(op)}, nil
}

// UpdatePolicy replaces the stored and live egress policy.
func (s *SandboxServer) UpdatePolicy(context.Context, *localv1.UpdatePolicyRequest) (*localv1.UpdatePolicyResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "policy replacement is unsafe; upgrade client to atomic policy operations")
}

// MutatePolicy changes one rule atomically against the current stored policy.
func (s *SandboxServer) MutatePolicy(ctx context.Context, req *localv1.MutatePolicyRequest) (*localv1.MutatePolicyResponse, error) {
	rules := fromProtoRules([]*localv1.NetworkRule{req.GetRule()})
	if len(rules) != 1 {
		return nil, status.Error(codes.InvalidArgument, "policy rule is required and must have a valid port")
	}
	sb, err := s.svc.MutatePolicy(ctx, req.GetId(), req.GetAction(), rules[0])
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.MutatePolicyResponse{Sandbox: toProtoSandbox(sb)}, nil
}

// UpdatePorts replaces the stored and live published ports.
func (s *SandboxServer) UpdatePorts(ctx context.Context, req *localv1.UpdatePortsRequest) (*localv1.UpdatePortsResponse, error) {
	sb, err := s.svc.UpdatePorts(ctx, req.GetId(), fromProtoPorts(req.GetPorts()))
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.UpdatePortsResponse{Sandbox: toProtoSandbox(sb)}, nil
}

// Delete deletes a sandbox.
func (s *SandboxServer) Delete(ctx context.Context, req *localv1.DeleteRequest) (*localv1.DeleteResponse, error) {
	op, err := s.svc.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.DeleteResponse{Operation: toProtoOperation(op)}, nil
}

// Watch streams current sandbox state changes.
func (s *SandboxServer) Watch(req *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse]) error {
	ctx := stream.Context()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	seen := make(map[string]string)
	for {
		if err := s.sendChanges(ctx, req, stream, seen); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *SandboxServer) sendChanges(ctx context.Context, req *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse], seen map[string]string) error {
	if id := req.GetSandboxId(); id != "" {
		sb, err := s.svc.Get(ctx, id)
		if err != nil {
			return mapError(err)
		}
		return sendSandbox(stream, seen, sb, req.GetAfterRevision())
	}
	token := ""
	for {
		items, next, err := s.svc.List(ctx, sandbox.ListOptions{PageSize: 200, PageToken: token})
		if err != nil {
			return mapError(err)
		}
		for i := range items {
			if err := sendSandbox(stream, seen, items[i], req.GetAfterRevision()); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		token = next
	}
}

func sendSandbox(stream grpc.ServerStreamingServer[localv1.WatchResponse], seen map[string]string, sb sandbox.Sandbox, after int64) error {
	key := fmt.Sprintf("%d/%s/%s", sb.Generation, sb.State, sb.Error)
	if seen[sb.ID] == key || sb.Generation <= after {
		return nil
	}
	seen[sb.ID] = key
	return stream.Send(&localv1.WatchResponse{
		Type:     "sandbox",
		Sandbox:  toProtoSandbox(sb),
		Revision: sb.Generation,
	})
}

// Get returns an operation.
func (s *OperationServer) Get(ctx context.Context, req *localv1.OperationServiceGetRequest) (*localv1.OperationServiceGetResponse, error) {
	op, err := s.svc.GetOperation(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.OperationServiceGetResponse{Operation: toProtoOperation(op)}, nil
}

// Wait waits for an operation.
func (s *OperationServer) Wait(ctx context.Context, req *localv1.OperationServiceWaitRequest) (*localv1.OperationServiceWaitResponse, error) {
	op, err := s.svc.WaitOperation(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.OperationServiceWaitResponse{Operation: toProtoOperation(op)}, nil
}

// GetPolicyProfile returns the global default profile for new sandboxes.
func (s *SandboxServer) GetPolicyProfile(ctx context.Context, _ *localv1.GetPolicyProfileRequest) (*localv1.GetPolicyProfileResponse, error) {
	profile, err := s.svc.GetPolicyProfile(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.GetPolicyProfileResponse{Profile: profile}, nil
}

// SetPolicyProfile sets the global default profile for new sandboxes.
func (s *SandboxServer) SetPolicyProfile(ctx context.Context, req *localv1.SetPolicyProfileRequest) (*localv1.SetPolicyProfileResponse, error) {
	profile, err := s.svc.SetPolicyProfile(ctx, req.GetProfile())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.SetPolicyProfileResponse{Profile: profile}, nil
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, core.ErrConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func toProtoSandbox(sb sandbox.Sandbox) *localv1.Sandbox {
	return &localv1.Sandbox{
		Id:                 sb.ID,
		Name:               sb.Name,
		State:              sandboxState(sb.State),
		Generation:         sb.Generation,
		Image:              sb.Image,
		Workspace:          sb.Workspace,
		Error:              sb.Error,
		CreatedAtUnix:      unix(sb.CreatedAt),
		UpdatedAtUnix:      unix(sb.UpdatedAt),
		Cpus:               sb.CPUs,
		MemoryMib:          sb.MemoryMiB,
		StoppedAtUnix:      unix(sb.StoppedAt),
		Workspaces:         toProtoWorkspaces(sb.Workspaces),
		Ports:              toProtoPorts(sb.Ports),
		Allow:              toProtoRules(policyRules(sb.Policy, true)),
		Deny:               toProtoRules(policyRules(sb.Policy, false)),
		Agent:              metaAgent(sb),
		Detached:           metaDetached(sb),
		PolicyProfile:      metaPolicyProfile(sb),
		LastUsedAtUnix:     metaLastUsed(sb),
		LastUsedAtUnixNano: metaLastUsedNano(sb),
	}
}

func toProtoOperation(op operation.Operation) *localv1.Operation {
	return &localv1.Operation{
		Id:            op.ID,
		SandboxId:     op.SandboxID,
		Kind:          operationKind(op.Kind),
		State:         operationState(op.State),
		Generation:    op.Generation,
		Error:         op.Error,
		CreatedAtUnix: unix(op.CreatedAt),
		UpdatedAtUnix: unix(op.UpdatedAt),
	}
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func sandboxState(v sandbox.State) localv1.SandboxState {
	switch v {
	case sandbox.Pending:
		return localv1.SandboxState_SANDBOX_STATE_PENDING
	case sandbox.Creating:
		return localv1.SandboxState_SANDBOX_STATE_CREATING
	case sandbox.Running:
		return localv1.SandboxState_SANDBOX_STATE_RUNNING
	case sandbox.Stopping:
		return localv1.SandboxState_SANDBOX_STATE_STOPPING
	case sandbox.Stopped:
		return localv1.SandboxState_SANDBOX_STATE_STOPPED
	case sandbox.Deleting:
		return localv1.SandboxState_SANDBOX_STATE_DELETING
	case sandbox.Deleted:
		return localv1.SandboxState_SANDBOX_STATE_DELETED
	case sandbox.Failed:
		return localv1.SandboxState_SANDBOX_STATE_FAILED
	default:
		return localv1.SandboxState_SANDBOX_STATE_UNKNOWN
	}
}

func operationKind(v operation.Kind) localv1.OperationKind {
	switch v {
	case operation.KindCreate:
		return localv1.OperationKind_OPERATION_KIND_CREATE
	case operation.KindStart:
		return localv1.OperationKind_OPERATION_KIND_START
	case operation.KindStop:
		return localv1.OperationKind_OPERATION_KIND_STOP
	case operation.KindDelete:
		return localv1.OperationKind_OPERATION_KIND_DELETE
	default:
		return localv1.OperationKind_OPERATION_KIND_UNSPECIFIED
	}
}

func operationState(v operation.State) localv1.OperationState {
	switch v {
	case operation.Pending:
		return localv1.OperationState_OPERATION_STATE_PENDING
	case operation.Running:
		return localv1.OperationState_OPERATION_STATE_RUNNING
	case operation.Done:
		return localv1.OperationState_OPERATION_STATE_DONE
	case operation.Failed:
		return localv1.OperationState_OPERATION_STATE_FAILED
	default:
		return localv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}

func toProtoWorkspaces(workspaces []sandbox.Workspace) []*localv1.Workspace {
	out := make([]*localv1.Workspace, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, &localv1.Workspace{Path: workspaces[i].Path, ReadOnly: workspaces[i].ReadOnly})
	}
	return out
}

func fromProtoWorkspaces(workspaces []*localv1.Workspace) []sandbox.Workspace {
	out := make([]sandbox.Workspace, 0, len(workspaces))
	for _, workspace := range workspaces {
		if workspace == nil {
			continue
		}
		out = append(out, sandbox.Workspace{Path: workspace.GetPath(), ReadOnly: workspace.GetReadOnly()})
	}
	return out
}

func toProtoPorts(ports []sandbox.Port) []*localv1.Port {
	out := make([]*localv1.Port, 0, len(ports))
	for i := range ports {
		out = append(out, &localv1.Port{Host: uint32(ports[i].Host), Guest: uint32(ports[i].Guest), Protocol: ports[i].Protocol, HostIp: ports[i].HostIP})
	}
	return out
}

func fromProtoPorts(ports []*localv1.Port) []sandbox.Port {
	out := make([]sandbox.Port, 0, len(ports))
	for _, port := range ports {
		if port == nil || port.GetHost() > 65535 || port.GetGuest() > 65535 {
			continue
		}
		out = append(out, sandbox.Port{Host: uint16(port.GetHost()), Guest: uint16(port.GetGuest()), Protocol: port.GetProtocol(), HostIP: port.GetHostIp()}) //nolint:gosec // bounds checked above.
	}
	return out
}

func toProtoRules(rules []sandbox.NetworkRule) []*localv1.NetworkRule {
	out := make([]*localv1.NetworkRule, 0, len(rules))
	for i := range rules {
		out = append(out, &localv1.NetworkRule{Protocol: rules[i].Protocol, Cidr: rules[i].CIDR, Port: uint32(rules[i].Port), Domain: rules[i].Domain, RuleId: rules[i].RuleID})
	}
	return out
}

func fromProtoRules(rules []*localv1.NetworkRule) []sandbox.NetworkRule {
	out := make([]sandbox.NetworkRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil || rule.GetPort() > 65535 {
			continue
		}
		out = append(out, sandbox.NetworkRule{Protocol: rule.GetProtocol(), CIDR: rule.GetCidr(), Port: uint16(rule.GetPort()), Domain: rule.GetDomain(), RuleID: rule.GetRuleId()}) //nolint:gosec // port is bounded to 65535 above.
	}
	return out
}

func policyRules(policy *sandbox.NetworkPolicy, allow bool) []sandbox.NetworkRule {
	if policy == nil {
		return nil
	}
	if allow {
		return policy.Allow
	}
	return policy.Deny
}

func metaPolicyProfile(sb sandbox.Sandbox) string {
	if sb.Meta == nil {
		return ""
	}
	return sb.Meta.PolicyProfile
}

func metaAgent(sb sandbox.Sandbox) string {
	if sb.Meta == nil {
		return ""
	}
	return sb.Meta.Agent
}

func metaDetached(sb sandbox.Sandbox) bool {
	return sb.Meta != nil && sb.Meta.Detached
}

func metaLastUsed(sb sandbox.Sandbox) int64 {
	if sb.Meta == nil {
		return 0
	}
	return unix(sb.Meta.LastUsedAt)
}

func metaLastUsedNano(sb sandbox.Sandbox) int64 {
	if sb.Meta == nil || sb.Meta.LastUsedAt.IsZero() {
		return 0
	}
	return sb.Meta.LastUsedAt.UnixNano()
}

// GetGlobalPolicy returns the global network rules applied to new sandboxes.
func (s *SandboxServer) GetGlobalPolicy(ctx context.Context, _ *localv1.GetGlobalPolicyRequest) (*localv1.GetGlobalPolicyResponse, error) {
	allow, deny, err := s.svc.GlobalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return &localv1.GetGlobalPolicyResponse{Allow: toProtoRules(allow), Deny: toProtoRules(deny)}, nil
}

// MutateGlobalPolicy changes one global rule atomically.
func (s *SandboxServer) MutateGlobalPolicy(ctx context.Context, req *localv1.MutateGlobalPolicyRequest) (*localv1.MutateGlobalPolicyResponse, error) {
	rules := fromProtoRules([]*localv1.NetworkRule{req.GetRule()})
	if len(rules) != 1 {
		return nil, status.Error(codes.InvalidArgument, "one valid rule is required")
	}
	allow, deny, err := s.svc.MutateGlobalPolicy(ctx, req.GetAction(), rules[0])
	if err != nil {
		return nil, err
	}
	return &localv1.MutateGlobalPolicyResponse{Allow: toProtoRules(allow), Deny: toProtoRules(deny)}, nil
}

// CheckPolicy evaluates stored/global rules with the gateway matcher.
func (s *SandboxServer) CheckPolicy(ctx context.Context, req *localv1.CheckPolicyRequest) (*localv1.CheckPolicyResponse, error) {
	if req.GetPort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "port must be 0..65535")
	}
	decision, err := s.svc.CheckPolicy(ctx, req.GetSandboxId(), req.GetProtocol(), req.GetAddress(), req.GetDomain(), uint16(req.GetPort())) //nolint:gosec // bounded above.
	if err != nil {
		return nil, err
	}
	return &localv1.CheckPolicyResponse{Allowed: decision.Allowed, RuleId: decision.RuleID, Reason: decision.Reason}, nil
}
