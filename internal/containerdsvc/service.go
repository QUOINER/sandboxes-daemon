package containerdsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ExpectedVersion = "2.4.2"
	startupTimeout  = 20 * time.Second
	// Leave the Darwin guardian's ten-second child escalation window time to
	// finish before the daemon escalates against the launcher process.
	shutdownTimeout = 12 * time.Second
	probeInterval   = 100 * time.Millisecond
)

type Service struct {
	plan     Plan
	cmd      *exec.Cmd
	log      *os.File
	guardian *os.File

	done      chan struct{}
	waitMu    sync.Mutex
	waitErr   error
	closeOnce sync.Once
	closeErr  error
	closing   atomic.Bool
	failures  chan error
}

func Start(ctx context.Context, cfg Config, launcher string) (*Service, error) {
	plan, err := preparePlan(cfg)
	if err != nil {
		return nil, err
	}
	reused, err := prepareServiceState(plan)
	if err != nil {
		return nil, err
	}
	svc, err := launchService(plan, launcher, reused)
	if err != nil {
		return nil, err
	}
	if err := awaitServiceReady(ctx, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

func preparePlan(cfg Config) (Plan, error) {
	plan, err := BuildPlan(cfg)
	if err != nil {
		return Plan{}, err
	}
	if err := validatePlanEnvironment(plan); err != nil {
		return Plan{}, err
	}
	for _, binary := range []struct{ path, name string }{{plan.Binary, "containerd"}, {plan.CTR, "ctr"}} {
		if err := verifyBinaryVersion(binary.path, binary.name, plan.Environment); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}

func prepareServiceState(plan Plan) (bool, error) {
	if persistentKeeper() {
		if err := precheckStateMounts(plan); err != nil {
			return false, err
		}
	}
	reused, err := existingKeeper(plan)
	if err != nil {
		return false, err
	}
	if !persistentKeeper() {
		return reused, writeConfig(plan, currentUID(), currentGID())
	}
	if reused {
		err = verifyConfig(plan, currentUID(), currentGID())
	}
	return reused, err
}

func launchService(plan Plan, launcher string, reused bool) (*Service, error) {
	var log *os.File
	var err error
	if !persistentKeeper() {
		log, err = os.OpenFile(plan.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open containerd log: %w", err)
		}
	}
	var cmd *exec.Cmd
	var guardian *os.File
	if !reused {
		cmd, guardian, err = startLauncher(launcher, plan, log)
		if err != nil {
			if log != nil {
				_ = log.Close()
			}
			return nil, err
		}
	}
	svc := &Service{plan: plan, cmd: cmd, log: log, guardian: guardian, done: make(chan struct{}), failures: make(chan error, 1)}
	if cmd != nil {
		go svc.wait()
	} else {
		go svc.watchKeeper()
	}
	return svc, nil
}

func startLauncher(launcher string, plan Plan, log *os.File) (*exec.Cmd, *os.File, error) {
	cmd, err := newCommand(launcher, plan)
	if err != nil {
		return nil, nil, err
	}
	guardian, _, err := configureParentDeath(cmd)
	if err != nil {
		return nil, nil, err
	}
	if log != nil {
		cmd.Stdout, cmd.Stderr = log, log
	}
	if err := cmd.Start(); err != nil {
		if guardian != nil {
			_ = guardian.Close()
		}
		closeParentDeathReader(cmd)
		return nil, nil, fmt.Errorf("start managed containerd: %w", err)
	}
	closeParentDeathReader(cmd)
	return cmd, guardian, nil
}

func awaitServiceReady(ctx context.Context, svc *Service) error {
	readyCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := svc.waitReady(readyCtx); err != nil {
		closeErr := svc.closeAfterStartFailure()
		return errors.Join(fmt.Errorf("containerd did not become ready: %w", err), closeErr)
	}
	return nil
}

func (s *Service) closeAfterStartFailure() error {
	if persistentKeeper() {
		// A local ctr client can create a task while readiness is pending. There
		// is no atomic task-inventory-and-stop operation, so never signal a Linux
		// keeper here, even when this Start call created it. Leave it available
		// for a later daemon retry and fail closed to avoid killing user work.
		s.closing.Store(true)
		return nil
	}
	return s.Close()
}

func (s *Service) Socket() string { return s.plan.Socket }

func (s *Service) Failures() <-chan error { return s.failures }

func (s *Service) wait() {
	err := s.cmd.Wait()
	s.waitMu.Lock()
	s.waitErr = err
	s.waitMu.Unlock()
	if s.log != nil {
		_ = s.log.Close()
	}
	if s.guardian != nil {
		_ = s.guardian.Close()
	}
	if !s.closing.Load() {
		if err == nil {
			err = errors.New("managed containerd exited unexpectedly")
		} else {
			err = fmt.Errorf("managed containerd exited unexpectedly: %w", err)
		}
		s.failures <- err
	}
	close(s.done)
}

func (s *Service) watchKeeper() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.closing.Load() {
			return
		}
		alive, err := existingKeeper(s.plan)
		if err != nil || !alive {
			if err == nil {
				err = errors.New("managed namespace keeper disappeared")
			}
			if !s.closing.Load() {
				s.failures <- err
			}
			s.waitMu.Lock()
			s.waitErr = err
			s.waitMu.Unlock()
			close(s.done)
			return
		}
	}
}

func (s *Service) waitReady(ctx context.Context) error {
	var lastErr error
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := runCommand(probeCtx, s.plan.CTR, []string{"--address", s.plan.Socket, "--namespace", Namespace, "version"}, s.plan.Environment)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("ctr readiness probe: %w", err)
		select {
		case <-s.done:
			return errors.Join(fmt.Errorf("containerd exited before readiness"), s.exitError())
		case <-ctx.Done():
			return errors.Join(lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Service) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.closeService() })
	return s.closeErr
}

func (s *Service) closeService() error {
	if persistentKeeper() {
		return s.closePersistentKeeper()
	}
	return s.closeTransientService()
}

func (s *Service) closePersistentKeeper() error {
	s.closing.Store(true)
	if s.log != nil {
		return s.log.Close()
	}
	return nil
}

func (s *Service) closeTransientService() error {
	select {
	case <-s.done:
		return s.exitError()
	default:
	}
	s.closing.Store(true)
	if err := s.signalServiceShutdown(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal containerd shutdown: %w", err)
	}
	return s.waitForServiceShutdown()
}

func (s *Service) signalServiceShutdown() error {
	if s.guardian != nil {
		return s.guardian.Close()
	}
	return signalShutdown(s.cmd.Process)
}

func (s *Service) waitForServiceShutdown() error {
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return s.exitError()
	case <-timer.C:
		if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return errors.Join(fmt.Errorf("kill containerd after shutdown timeout: %w", err), s.exitError())
		}
		<-s.done
		return errors.Join(fmt.Errorf("containerd did not stop within %s", shutdownTimeout), s.exitError())
	}
}

func verifyBinaryVersion(binary, name string, environment []string) error {
	output, err := runCommand(context.Background(), binary, []string{"--version"}, environment)
	if err != nil {
		return fmt.Errorf("run %s version check: %w", name, err)
	}
	if versionOutputMatches(string(output), name) {
		return nil
	}
	return fmt.Errorf("%s binary does not report the pinned containerd v%s version", name, ExpectedVersion)
}

func makeCommand(path string, args []string, environment []string) *exec.Cmd {
	argv := make([]string, 1, len(args)+1)
	argv[0] = path
	argv = append(argv, args...)
	return &exec.Cmd{Path: path, Args: argv, Env: environment}
}

func runCommand(ctx context.Context, path string, args, environment []string) ([]byte, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := makeCommand(path, args, environment)
	cmd.Stdout, cmd.Stderr = writer, writer
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	_ = writer.Close()
	outputDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		_ = reader.Close()
		outputDone <- data
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		waitErr = <-waitDone
		if waitErr == nil {
			waitErr = ctx.Err()
		}
	}
	return <-outputDone, waitErr
}

func versionOutputMatches(output, name string) bool {
	fields := strings.Fields(output)
	return len(fields) >= 3 && fields[0] == name && isExpectedVersion(fields[2])
}

func isExpectedVersion(token string) bool {
	version := strings.TrimPrefix(token, "v")
	if strings.Contains(version, "-") {
		return false
	}
	version = strings.SplitN(version, "+", 2)[0]
	return version == ExpectedVersion
}

func (s *Service) exitError() error {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	return s.waitErr
}
