package registrycredentials

import (
	"context"
	"testing"
)

func TestPullLimiterBoundsAggregateRequestsAndHonorsCancellation(t *testing.T) {
	limiter := NewPullLimiter()
	for range maxConcurrentRegistryPulls {
		if !limiter.acquire(context.Background()) {
			t.Fatal("limiter rejected a slot below its capacity")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	acquired := make(chan bool, 1)
	go func() { acquired <- limiter.acquire(ctx) }()
	cancel()
	if <-acquired {
		t.Fatal("limiter admitted a request after its context was canceled")
	}

	limiter.release()
	if !limiter.acquire(context.Background()) {
		t.Fatal("limiter did not release capacity")
	}
	for range maxConcurrentRegistryPulls {
		limiter.release()
	}
}
