package daemon

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/policysync"
)

// PolicySyncConfig configures the opt-in background org policy sync. The
// client is built at the process boundary from protected files; the token and
// public key are never accepted as command-line values.
type PolicySyncConfig struct {
	Client   *policysync.Client
	Interval time.Duration
}

// policySyncRunner performs one sync attempt at startup and then a jittered
// periodic attempt until ctx is canceled. Attempts are sequential, so a slow
// control plane can never overlap two syncs.
type policySyncRunner struct {
	client   *policysync.Client
	bundles  policysync.BundleStore
	orgID    string
	interval time.Duration
	jitter   func(time.Duration) time.Duration
}

func newPolicySyncRunner(cfg PolicySyncConfig, bundles policysync.BundleStore) (*policySyncRunner, error) {
	if bundles == nil {
		return nil, errors.New("policy bundle store is required")
	}
	if cfg.Client == nil {
		return nil, errors.New("policy sync client is required")
	}
	interval := cfg.Interval
	if interval == 0 {
		interval = policysync.DefaultInterval
	}
	if err := policysync.ValidateInterval(interval); err != nil {
		return nil, err
	}
	return &policySyncRunner{
		client:   cfg.Client,
		bundles:  bundles,
		orgID:    cfg.Client.OrgID(),
		interval: interval,
		jitter:   policySyncJitter,
	}, nil
}

// startPolicySync starts the background runner and returns a stop function.
// Stop cancels the runner context and waits for an in-flight attempt to exit so
// the caller can close the bundle store safely.
func startPolicySync(ctx context.Context, runner *policySyncRunner) func() {
	syncCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.run(syncCtx)
	}()
	return func() {
		cancel()
		<-done
	}
}

func (r *policySyncRunner) run(ctx context.Context) {
	r.syncOnce(ctx)
	for {
		timer := time.NewTimer(r.interval + r.jitter(r.interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		r.syncOnce(ctx)
	}
}

func (r *policySyncRunner) syncOnce(ctx context.Context) {
	result, err := r.client.Sync(ctx, r.bundles)
	if err != nil {
		if ctx.Err() != nil {
			// Shutdown canceled the attempt; do not report it as a policy error.
			return
		}
		slog.Error("policy sync failed", "org", r.orgID, "error", err)
		return
	}
	if !result.Changed {
		slog.Debug("policy bundle already current", "org", result.OrgID, "revision", result.Revision)
		return
	}
	slog.Info("policy bundle synced", "org", result.OrgID, "revision", result.Revision, "expires_at", result.ExpiresAt)
}

// policySyncJitter returns a non-negative delay of at most one fifth of the
// interval, so replicas do not poll in lockstep.
func policySyncJitter(interval time.Duration) time.Duration {
	maxJitter := interval / 5
	if maxJitter <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
