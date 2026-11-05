package oauthsession

import (
	"context"
	"errors"
	"net/http"
)

func listenForProvider(session *Session, provider Provider) (*Callback, error) {
	if len(provider.CallbackPorts) == 0 {
		if provider.CallbackPath != "" {
			return nil, errors.New("OAuth callback path requires fixed callback ports")
		}
		return Listen(session)
	}
	return listenOnPorts(session, provider.CallbackPorts, provider.CallbackPath)
}

// Provider is trusted host configuration for one OAuth provider, never guest
// input. Provider registration, endpoint and TLS policy must be verified by
// the integration before invoking this flow.
type Provider struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	Scopes                []string
	AuthorizationParams   map[string]string
	CallbackPorts         []uint16
	CallbackPath          string
	Transport             http.RoundTripper
}

// TokenSink persists tokens on the host; implementations must not log them.
type TokenSink interface {
	Save(context.Context, Tokens) error
}

// Authorize runs an in-memory authorization-code flow. The opener receives an
// authorization URL and must open it without logging it. Tokens are passed
// directly to the host sink and are not returned to the caller.
func Authorize(ctx context.Context, provider Provider, open func(context.Context, string) error, sink TokenSink) error {
	if _, ok := ctx.Deadline(); !ok || open == nil || sink == nil || provider.Transport == nil {
		return errors.New("invalid OAuth flow configuration")
	}
	if !validEndpointString(provider.TokenEndpoint) {
		return errors.New("invalid OAuth token endpoint")
	}
	s, err := New()
	if err != nil {
		return err
	}
	if err := s.bindTokenEndpoint(provider.TokenEndpoint); err != nil {
		return err
	}
	callback, err := listenForProvider(s, provider)
	if err != nil {
		return err
	}
	defer func() { _ = callback.Close() }()
	redirect := callback.RedirectURI()
	authURL, err := s.AuthorizationURLWithParams(provider.AuthorizationEndpoint, provider.ClientID, redirect, provider.Scopes, provider.AuthorizationParams)
	if err != nil {
		return err
	}
	if err := open(ctx, authURL); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("open OAuth authorization failed")
	}
	code, err := callback.Wait(ctx)
	if err != nil {
		return err
	}
	tokens, err := s.Exchange(ctx, provider.Transport, provider.TokenEndpoint, provider.ClientID, redirect, code)
	if err != nil {
		return err
	}
	if err := sink.Save(ctx, tokens); err != nil {
		return errors.New("store OAuth tokens failed")
	}
	return nil
}
