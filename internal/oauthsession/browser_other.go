//go:build !darwin

package oauthsession

import (
	"context"
)

// OpenBrowser is not supported on this platform yet.
func OpenBrowser(context.Context, string) error {
	return ErrBrowserUnavailable
}
