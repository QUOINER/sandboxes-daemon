package registrycredentials

import "context"

const (
	maxConcurrentRegistryPulls = 16
	maxQueuedRegistryPulls     = 32
)

// PullLimiter bounds active registry requests across all sandbox proxies in a
// daemon. Each proxy still applies its own smaller per-sandbox limit.
type PullLimiter struct {
	active chan struct{}
	queued chan struct{}
}

// NewPullLimiter returns the daemon-wide registry pull limiter.
func NewPullLimiter() *PullLimiter {
	return &PullLimiter{
		active: make(chan struct{}, maxConcurrentRegistryPulls),
		queued: make(chan struct{}, maxQueuedRegistryPulls),
	}
}

func (l *PullLimiter) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case l.queued <- struct{}{}:
	case <-ctx.Done():
		return false
	default:
		return false
	}
	defer func() { <-l.queued }()

	select {
	case l.active <- struct{}{}:
		if ctx.Err() != nil {
			<-l.active
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *PullLimiter) release() {
	<-l.active
}
