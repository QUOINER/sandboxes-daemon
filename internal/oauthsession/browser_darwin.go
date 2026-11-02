//go:build darwin

package oauthsession

import (
	"context"
	"errors"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

// OpenBrowser opens a trusted HTTPS authorization URL in the host browser.
// The URL is passed over stdin rather than in process arguments.
func OpenBrowser(ctx context.Context, raw string) error {
	script, err := browserScript(raw)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-")
	cmd.Stdin = strings.NewReader(script)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrBrowserUnavailable
	}
	return nil
}

func browserScript(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != httpsScheme || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("invalid OAuth browser URL")
	}
	return "open location " + strconv.Quote(raw) + "\n", nil
}
