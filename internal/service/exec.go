package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	runtime "github.com/KLORQ/sandboxes-runtime"

	"github.com/KLORQ/sandboxes-daemon/internal/servicesecrets"
)

type execSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Exec runs a non-interactive guest command while tracking its lifecycle.
func (s *Service) Exec(ctx context.Context, id string, req runtime.ExecRequest) (int, error) {
	return s.exec(ctx, id, req, nil)
}

// ExecInteractive runs a tracked interactive guest process.
func (s *Service) ExecInteractive(ctx context.Context, id string, req runtime.InteractiveExecRequest) (int, error) {
	return s.exec(ctx, id, req.ExecRequest, &req)
}

func (s *Service) exec(ctx context.Context, id string, req runtime.ExecRequest, interactive *runtime.InteractiveExecRequest) (int, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return 0, err
	}
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		release()
		return 0, err
	}
	executor, ok := s.backend.(runtime.Executor)
	if !ok {
		release()
		return 0, fmt.Errorf("%w: runtime does not support exec", core.ErrConflict)
	}
	sb, err = s.readyForExec(ctx, sb)
	if err != nil {
		release()
		return 0, err
	}
	if req.Workdir == "" {
		req.Workdir = sb.Workspace
	}
	req.Env, err = s.resolveSecretEnv(ctx, sb, req.Env)
	if err != nil {
		release()
		return 0, err
	}
	execCtx, cancel := context.WithCancel(ctx)
	for _, output := range []*io.Writer{&req.Stdout, &req.Stderr} {
		if contextual, ok := (*output).(interface {
			WithContext(context.Context) io.Writer
		}); ok {
			*output = contextual.WithContext(execCtx)
		}
	}
	session := &execSession{cancel: cancel, done: make(chan struct{})}
	s.execMu.Lock()
	if s.execSessions == nil {
		s.execSessions = make(map[string]map[*execSession]struct{})
	}
	if len(s.execSessions[id]) >= 32 {
		s.execMu.Unlock()
		release()
		cancel()
		return 0, fmt.Errorf("%w: too many active exec sessions", core.ErrConflict)
	}
	if s.execSessions[id] == nil {
		s.execSessions[id] = make(map[*execSession]struct{})
	}
	s.execSessions[id][session] = struct{}{}
	s.execMu.Unlock()
	release()
	defer func() {
		cancel()
		s.execMu.Lock()
		delete(s.execSessions[id], session)
		if len(s.execSessions[id]) == 0 {
			delete(s.execSessions, id)
		}
		close(session.done)
		s.execMu.Unlock()
	}()
	return s.runSession(execCtx, executor, s.backend.Handle(sb.Name), req, interactive)
}

func (s *Service) runSession(ctx context.Context, executor runtime.Executor, handle runtime.Handle, req runtime.ExecRequest, interactive *runtime.InteractiveExecRequest) (int, error) {
	if interactive == nil {
		return s.runExec(ctx, executor, handle, req)
	}
	native, ok := s.backend.(runtime.InteractiveExecutor)
	if !ok {
		return 0, fmt.Errorf("%w: runtime does not support interactive exec", core.ErrConflict)
	}
	interactive.ExecRequest = req
	return native.ExecInteractive(ctx, handle, *interactive)
}

func (s *Service) readyForExec(ctx context.Context, sb sandbox.Sandbox) (sandbox.Sandbox, error) {
	if sb.State == sandbox.Stopped {
		if err := s.startForExec(ctx, sb); err != nil {
			return sandbox.Sandbox{}, err
		}
		updated, err := s.store.Get(ctx, sb.ID)
		if err != nil {
			return sandbox.Sandbox{}, err
		}
		sb = updated
	} else if sb.State != sandbox.Running {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is not ready for exec", core.ErrConflict)
	}
	if sb.Meta == nil {
		sb.Meta = &sandbox.Meta{}
	}
	sb.Meta.LastUsedAt = s.now().UTC()
	if err := s.store.Update(ctx, sb); err != nil {
		return sandbox.Sandbox{}, fmt.Errorf("record sandbox use: %w", err)
	}
	return sb, nil
}

func (s *Service) startForExec(ctx context.Context, sb sandbox.Sandbox) error {
	if err := s.prepareStoredProxy(ctx, sb); err != nil {
		return err
	}
	handle := s.backend.Handle(sb.Name)
	handle.Ports = runtimePorts(sb.Ports)
	handle.Allow = runtimeRules(policyAllow(sb.Policy))
	handle.Deny = runtimeRules(policyDeny(sb.Policy))
	if err := s.backend.Start(ctx, handle); err != nil {
		return s.markRuntimeUnknown(ctx, sb, err)
	}
	if _, err := s.apply(ctx, sb, operation.KindStart, sandbox.Running); err != nil {
		return s.markRuntimeUnknown(ctx, sb, err)
	}
	return nil
}

func (s *Service) runExec(ctx context.Context, fallback runtime.Executor, handle runtime.Handle, req runtime.ExecRequest) (int, error) {
	if native, ok := s.backend.(runtime.CancelableExecutor); ok && cancelableOutputs(req) {
		return native.ExecCancelable(ctx, handle, req)
	}
	return fallback.Exec(ctx, handle, req)
}

func cancelableOutputs(req runtime.ExecRequest) bool {
	for _, output := range []io.Writer{req.Stdout, req.Stderr} {
		if output != nil {
			if _, ok := output.(runtime.ContextWriter); !ok {
				return false
			}
		}
	}
	return true
}

const (
	secretRefPrefix = "${secret:"
	proxyRefPrefix  = "${proxy:"
)

// resolveSecretEnv expands whole-value "${secret:service}" references from the
// host vault at exec time. Only the selected process receives the value; it is
// never written to SQLite or sandbox metadata. Sandbox scope wins over global.
func (s *Service) resolveSecretEnv(ctx context.Context, sb sandbox.Sandbox, env []string) ([]string, error) {
	out := make([]string, 0, len(env)+1)
	proxyService := ""
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			out = append(out, entry)
			continue
		}
		resolved, serviceName, err := s.resolveEnvEntry(ctx, sb, key, value, proxyService)
		if err != nil {
			return nil, err
		}
		if serviceName != "" {
			proxyService = serviceName
		}
		out = append(out, resolved)
	}
	if proxyService == "" {
		return out, nil
	}
	return s.finishProxyEnv(ctx, sb, env, out, proxyService)
}

func (s *Service) resolveEnvEntry(ctx context.Context, sb sandbox.Sandbox, key, value, currentProxy string) (string, string, error) {
	if strings.Contains(value, proxyRefPrefix) {
		return s.resolveProxyEnvEntry(ctx, sb, key, value, currentProxy)
	}
	if strings.HasPrefix(value, secretRefPrefix) {
		resolved, err := s.resolveSecretReference(ctx, sb, key, value)
		return resolved, "", err
	}
	return key + "=" + value, "", nil
}

func (s *Service) resolveProxyEnvEntry(ctx context.Context, sb sandbox.Sandbox, key, value, current string) (string, string, error) {
	if !strings.HasPrefix(value, proxyRefPrefix) || !strings.HasSuffix(value, "}") || strings.Count(value, proxyRefPrefix) != 1 {
		return "", current, fmt.Errorf("%w: invalid proxy reference for %s", core.ErrConflict, key)
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(value, proxyRefPrefix), "}"))
	contract, ok := proxyContract(name)
	if !ok || key != contract.credentialEnv {
		return "", current, fmt.Errorf("%w: proxy reference is not supported for %s", core.ErrConflict, key)
	}
	if current != "" && current != name {
		return "", current, fmt.Errorf("%w: one proxy service may be used per exec", core.ErrConflict)
	}
	configured, err := s.store.GetSetting(ctx, proxyServiceSettingKey(sb.ID))
	if err != nil || configured != name {
		return "", current, fmt.Errorf("%w: sandbox was not created with the %s proxy channel", core.ErrConflict, name)
	}
	return key + "=klorq-proxy-placeholder", name, nil
}

func (s *Service) resolveSecretReference(ctx context.Context, sb sandbox.Sandbox, key, value string) (string, error) {
	if !strings.HasSuffix(value, "}") || strings.Count(value, secretRefPrefix) != 1 {
		return "", fmt.Errorf("%w: invalid secret reference for %s", core.ErrConflict, key)
	}
	if s.serviceSecrets == nil {
		return "", fmt.Errorf("%w: service secret store is unavailable", core.ErrConflict)
	}
	service := strings.TrimSuffix(strings.TrimPrefix(value, secretRefPrefix), "}")
	if service == "" || strings.ContainsAny(service, "/\\\x00\r\n") {
		return "", fmt.Errorf("%w: invalid secret reference for %s", core.ErrConflict, key)
	}
	secret, err := s.serviceSecrets.Load(ctx, service, servicesecrets.ScopeSandbox, sb.Name)
	if errors.Is(err, servicesecrets.ErrNotFound) {
		secret, err = s.serviceSecrets.Load(ctx, service, servicesecrets.ScopeGlobal, "")
	}
	if err != nil {
		return "", fmt.Errorf("%w: secret %q is unavailable", core.ErrConflict, service)
	}
	defer clear(secret)
	return key + "=" + string(secret), nil
}

func (s *Service) finishProxyEnv(ctx context.Context, sb sandbox.Sandbox, env, out []string, proxyService string) ([]string, error) {
	contract, _ := proxyContract(proxyService)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == contract.baseURLEnv {
			return nil, fmt.Errorf("%w: %s is managed by the service proxy", core.ErrConflict, contract.baseURLEnv)
		}
	}
	if err := s.prepareStoredProxy(ctx, sb); err != nil {
		return nil, err
	}
	return append(out, contract.baseURLEnv+"="+contract.baseURL), nil
}

// cancelExecSessions is called with the sandbox lifecycle gate held.
func (s *Service) cancelExecSessions(ctx context.Context, id string) error {
	s.execMu.Lock()
	sessions := make([]*execSession, 0, len(s.execSessions[id]))
	for session := range s.execSessions[id] {
		sessions = append(sessions, session)
		session.cancel()
	}
	s.execMu.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, session := range sessions {
		select {
		case <-session.done:
		case <-waitCtx.Done():
			return fmt.Errorf("wait for exec sessions: %w", waitCtx.Err())
		}
	}
	return nil
}
