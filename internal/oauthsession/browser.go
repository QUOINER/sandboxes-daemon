package oauthsession

import "errors"

// ErrBrowserUnavailable reports that the browser could not be launched. Device
// authorization may continue because callers can complete the displayed URL
// and code manually.
var ErrBrowserUnavailable = errors.New("OAuth browser is unavailable")
