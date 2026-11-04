package registrycredentials

import "context"

const maxConcurrentRegistryPulls = 16

// PullLimiter bounds active registry requests across all sandbox proxies in a
// daemon. Each proxy still applies its own smaller per-sandbox limit.
type PullLimiter struct {
	active chan struct{}
}

// NewPullLimiter returns the daemon-wide registry pull limiter.
func NewPullLimiter() *PullLimiter {
	return &PullLimiter{active: make(chan struct{}, maxConcurrentRegistryPulls)}
}

func (l *PullLimiter) acquire(ctx context.Context) bool {
	select {
	case l.active <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *PullLimiter) release() {
	<-l.active
}
