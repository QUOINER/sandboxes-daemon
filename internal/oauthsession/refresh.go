package oauthsession

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"time"
)

// RefreshCoordinator coordinates OAuth operations across managers in a daemon.
// All managers using one vault must share it; it does not coordinate processes.
type RefreshCoordinator struct{ locks [64]chan struct{} }

// NewRefreshCoordinator allocates bounded locks for credential operations.
func NewRefreshCoordinator() *RefreshCoordinator {
	c := &RefreshCoordinator{}
	for i := range c.locks {
		c.locks[i] = make(chan struct{}, 1)
	}
	return c
}

func (c *RefreshCoordinator) lockFor(account string) chan struct{} {
	h := fnv.New64a()
	_, _ = h.Write([]byte(account))
	return c.locks[h.Sum64()%uint64(len(c.locks))]
}

// TokenManager serializes refreshes for one host-owned credential. It must not
// be shared across different credential records or used to expose tokens to VMs.
type TokenManager struct {
	sink      *VaultSink
	transport http.RoundTripper
	endpoint  string
	clientID  string
	lock      chan struct{}
}

// NewTokenManager constructs a manager from trusted host provider config.
func NewTokenManager(sink *VaultSink, transport http.RoundTripper, endpoint, clientID string, coordinator *RefreshCoordinator) (*TokenManager, error) {
	if sink == nil || transport == nil || !validEndpointString(endpoint) || clientID == "" || coordinator == nil {
		return nil, errors.New("invalid OAuth refresh configuration")
	}
	lock := coordinator.lockFor(sink.account)
	if lock == nil {
		return nil, errors.New("OAuth refresh coordinator is not initialized")
	}
	return &TokenManager{sink: sink, transport: transport, endpoint: endpoint, clientID: clientID, lock: lock}, nil
}

// AccessToken returns a host-only token, refreshing near expiry. A missing
// expiry fails closed because freshness cannot be determined.
func (m *TokenManager) AccessToken(ctx context.Context) (string, error) {
	select {
	case m.lock <- struct{}{}:
		defer func() { <-m.lock }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	tokens, expiresAt, err := m.sink.Load(ctx)
	if err != nil {
		return "", err
	}
	if expiresAt.IsZero() {
		return "", errors.New("OAuth token expiry is unknown")
	}
	if time.Until(expiresAt) > 30*time.Second {
		return tokens.AccessToken, nil
	}
	if tokens.RefreshToken == "" {
		return "", errors.New("OAuth token requires sign-in")
	}
	updated, err := Refresh(ctx, m.transport, m.endpoint, m.clientID, tokens.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrOAuthReauthRequired) {
			if deleteErr := m.sink.Delete(ctx); deleteErr != nil {
				return "", errors.Join(ErrOAuthReauthRequired, fmt.Errorf("remove rejected OAuth credentials: %w", deleteErr))
			}
		}
		return "", err
	}
	if updated.ExpiresIn <= 0 {
		return "", errors.New("OAuth refresh did not return an expiry")
	}
	if updated.RefreshToken == "" {
		updated.RefreshToken = tokens.RefreshToken
	}
	if err := m.sink.Save(ctx, updated); err != nil {
		return "", err
	}
	return updated.AccessToken, nil
}

// Logout removes the local host credential after any in-flight refresh on this
// manager completes. It does not revoke the token at the upstream provider.
func (m *TokenManager) Logout(ctx context.Context) error {
	select {
	case m.lock <- struct{}{}:
		defer func() { <-m.lock }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return m.sink.Delete(ctx)
}
