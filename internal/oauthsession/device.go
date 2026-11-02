package oauthsession

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceProvider is immutable host configuration for an OAuth device grant.
// None of its endpoint or client fields may come from an RPC or guest.
type DeviceProvider struct {
	DeviceEndpoint string
	TokenEndpoint  string
	PATEndpoint    string
	ClientID       string
	Audience       string
	Scopes         []string
	Transport      http.RoundTripper
}

const (
	DockerOAuthAudience  = "https://hub.docker.com"
	DockerOAuthDeviceURL = "https://login.docker.com/oauth/device/code"
	// DockerOAuthClientID is Docker CLI's public device-flow client ID. It is
	// embedded by Docker CLI and the installed Docker Sandboxes sbx binary.
	DockerOAuthClientID = "L4v0dmlNBpYUjGGab0C2JtgTgXr1Qz4d"
	//nolint:gosec // G101: this is a public OAuth protocol endpoint, not a credential.
	DockerOAuthTokenURL  = "https://login.docker.com/oauth/token"
	DockerOAuthRevokeURL = "https://login.docker.com/oauth/revoke"
	DockerHubPATEndpoint = "https://hub.docker.com/v2/access-tokens/desktop-generate"
)

// NewDockerDeviceProvider binds the documented Docker Hub device grant to a
// caller-supplied, authorized public OAuth client registration.
func NewDockerDeviceProvider(clientID string, transport http.RoundTripper) (DeviceProvider, error) {
	if clientID == "" || transport == nil {
		return DeviceProvider{}, errors.New("docker OAuth public client ID and transport are required")
	}
	return DeviceProvider{
		DeviceEndpoint: DockerOAuthDeviceURL,
		TokenEndpoint:  DockerOAuthTokenURL,
		PATEndpoint:    DockerHubPATEndpoint,
		ClientID:       clientID,
		Audience:       DockerOAuthAudience,
		Scopes:         []string{"openid", "offline_access"},
		Transport:      transport,
	}, nil
}

// NewDockerHubProvider configures the same public Docker device-flow client
// used by Docker CLI and Docker Sandboxes for Docker account sign-in.
func NewDockerHubProvider(transport http.RoundTripper) (DeviceProvider, error) {
	return NewDockerDeviceProvider(DockerOAuthClientID, transport)
}

// DeviceAuthorization contains only the user-facing verification data. The
// sensitive device_code is kept private and redacted from formatting.
type DeviceAuthorization struct {
	UserCode        string
	VerificationURI string
	deviceCode      string
	interval        time.Duration
	expiresAt       time.Time
}

func (DeviceAuthorization) String() string   { return "[redacted OAuth device authorization]" }
func (DeviceAuthorization) GoString() string { return "[redacted OAuth device authorization]" }

var (
	ErrDeviceDenied       = errors.New("OAuth device authorization denied")
	ErrDeviceExpired      = errors.New("OAuth device authorization expired")
	ErrCredentialConflict = errors.New("docker Hub credentials already exist; remove them explicitly before account login")
)

// BeginDeviceAuthorization asks the trusted provider for a short-lived device
// code. The device code is not returned to callers or included in errors.
func BeginDeviceAuthorization(ctx context.Context, provider DeviceProvider) (DeviceAuthorization, error) {
	if err := validateDeviceProvider(provider); err != nil {
		return DeviceAuthorization{}, err
	}
	form := url.Values{clientIDKey: {provider.ClientID}, "audience": {provider.Audience}}
	if len(provider.Scopes) > 0 {
		form.Set("scope", strings.Join(provider.Scopes, " "))
	}
	body, statusCode, err := deviceRequest(ctx, provider.Transport, provider.DeviceEndpoint, form)
	if err != nil || statusCode != http.StatusOK {
		clear(body)
		return DeviceAuthorization{}, errors.New("OAuth device authorization request failed")
	}
	return parseDeviceAuthorization(body, provider.DeviceEndpoint)
}

func validateDeviceProvider(provider DeviceProvider) error {
	if provider.ClientID == "" || provider.Audience == "" || provider.Transport == nil || !validEndpointString(provider.DeviceEndpoint) || !validEndpointString(provider.TokenEndpoint) {
		return errors.New("invalid OAuth device provider configuration")
	}
	if !SameHTTPSOrigin(provider.DeviceEndpoint, provider.TokenEndpoint) {
		return errors.New("OAuth device and token endpoints must share an issuer")
	}
	for _, scope := range provider.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return errors.New("invalid OAuth device provider scope")
		}
	}
	return nil
}

func parseDeviceAuthorization(body []byte, deviceEndpoint string) (DeviceAuthorization, error) {
	defer clear(body)
	response, err := decodeDeviceAuthorizationResponse(body)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	verification, err := validateVerificationURI(response, deviceEndpoint)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	return DeviceAuthorization{
		UserCode: response.UserCode, VerificationURI: verification, deviceCode: response.DeviceCode,
		interval: devicePollingInterval(response.Interval), expiresAt: time.Now().Add(time.Duration(response.ExpiresIn) * time.Second),
	}, nil
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

func decodeDeviceAuthorizationResponse(body []byte) (deviceAuthorizationResponse, error) {
	var response deviceAuthorizationResponse
	if json.Unmarshal(body, &response) != nil || response.DeviceCode == "" || !validUserCode(response.UserCode) || response.ExpiresIn < 30 || response.ExpiresIn > 1800 {
		return deviceAuthorizationResponse{}, errors.New("invalid OAuth device authorization response")
	}
	return response, nil
}

func validUserCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if char < '!' || char > '~' {
			return false
		}
	}
	return true
}

func validateVerificationURI(response deviceAuthorizationResponse, deviceEndpoint string) (string, error) {
	verificationURI := response.VerificationURIComplete
	if verificationURI == "" {
		verificationURI = response.VerificationURI
	}
	if !validVerificationURL(verificationURI) || !SameHTTPSOrigin(deviceEndpoint, verificationURI) {
		return "", errors.New("invalid OAuth verification URL")
	}
	u, _ := url.Parse(verificationURI)
	if response.VerificationURIComplete == "" {
		query := u.Query()
		query.Set("user_code", response.UserCode)
		u.RawQuery = query.Encode()
	}
	return u.String(), nil
}

func validVerificationURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == httpsScheme && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Fragment == "" && u.RawFragment == ""
}

func devicePollingInterval(interval int64) time.Duration {
	if interval < 1 || interval > 30 {
		return 5 * time.Second
	}
	return time.Duration(interval) * time.Second
}

func SameHTTPSOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || ua.Scheme != "https" || ub.Scheme != "https" || ua.User != nil || ub.User != nil {
		return false
	}
	portA, portB := ua.Port(), ub.Port()
	if portA == "" {
		portA = "443"
	}
	if portB == "" {
		portB = "443"
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname()) && portA == portB
}

// WaitForDeviceToken polls until authorization, denial, expiry or cancellation.
func WaitForDeviceToken(ctx context.Context, provider DeviceProvider, authorization DeviceAuthorization) (Tokens, error) {
	if authorization.deviceCode == "" || authorization.interval <= 0 || authorization.expiresAt.IsZero() || validateDeviceProvider(provider) != nil {
		return Tokens{}, errors.New("invalid OAuth device polling configuration")
	}
	interval := authorization.interval
	for {
		delay := time.Until(authorization.expiresAt)
		if delay <= 0 {
			return Tokens{}, ErrDeviceExpired
		}
		if delay > interval {
			delay = interval
		}
		if err := waitDeviceInterval(ctx, delay); err != nil {
			return Tokens{}, err
		}
		tokens, err := pollDeviceToken(ctx, provider, authorization.deviceCode)
		switch {
		case errors.Is(err, errDevicePending):
			continue
		case errors.Is(err, errDeviceSlowDown):
			interval = min(interval+5*time.Second, 30*time.Second)
			continue
		case err != nil:
			return Tokens{}, err
		default:
			return tokens, nil
		}
	}
}

var (
	errDevicePending  = errors.New("OAuth device authorization pending")
	errDeviceSlowDown = errors.New("OAuth device authorization polling too fast")
)

func waitDeviceInterval(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func pollDeviceToken(ctx context.Context, provider DeviceProvider, deviceCode string) (Tokens, error) {
	body, statusCode, err := deviceRequest(ctx, provider.Transport, provider.TokenEndpoint, url.Values{
		clientIDKey: {provider.ClientID}, grantTypeKey: {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	if err != nil {
		return Tokens{}, errors.New("OAuth device token request failed")
	}
	defer clear(body)
	var response struct {
		Tokens
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Tokens{}, errors.New("invalid OAuth device token response")
	}
	if statusCode == http.StatusOK && response.AccessToken != "" && strings.EqualFold(response.TokenType, "bearer") && response.ExpiresIn > 0 {
		return response.Tokens, nil
	}
	return Tokens{}, classifyDeviceTokenError(statusCode, response.Error)
}

func classifyDeviceTokenError(statusCode int, errorCode string) error {
	if statusCode != http.StatusBadRequest && statusCode != http.StatusForbidden {
		return errors.New("OAuth device token endpoint rejected request")
	}
	switch errorCode {
	case "authorization_pending":
		return errDevicePending
	case "slow_down":
		return errDeviceSlowDown
	case "access_denied":
		return ErrDeviceDenied
	case "expired_token":
		return ErrDeviceExpired
	default:
		return errors.New("OAuth device token endpoint rejected request")
	}
}

// AuthorizeDevice runs a device grant and persists the token on the host.
func AuthorizeDevice(ctx context.Context, provider DeviceProvider, handoff func(context.Context, string, string) error, sink TokenSink) error {
	if handoff == nil || sink == nil {
		return errors.New("invalid OAuth device flow configuration")
	}
	authorization, err := BeginDeviceAuthorization(ctx, provider)
	if err != nil {
		return err
	}
	return CompleteDeviceAuthorization(ctx, provider, authorization, handoff, sink)
}

// CompleteDeviceAuthorization performs the interactive handoff, polls the
// provider, and stores the resulting token. The authorization stays in host
// memory; callers may display only its user code and verification URI.
func CompleteDeviceAuthorization(ctx context.Context, provider DeviceProvider, authorization DeviceAuthorization, handoff func(context.Context, string, string) error, sink TokenSink) error {
	if handoff == nil || sink == nil {
		return errors.New("invalid OAuth device flow configuration")
	}
	if err := handoff(ctx, authorization.UserCode, authorization.VerificationURI); err != nil {
		return errors.New("open OAuth verification page failed")
	}
	tokens, err := WaitForDeviceToken(ctx, provider, authorization)
	if err != nil {
		return err
	}
	if err := sink.Save(ctx, tokens); err != nil {
		if errors.Is(err, ErrCredentialConflict) || errors.Is(err, ErrOAuthPartialLogin) {
			return err
		}
		return errors.New("store OAuth tokens failed")
	}
	return nil
}

// ErrOAuthPartialLogin indicates that an upstream credential may have been
// created and host-side state may be partial. The user must run logout before
// retrying so locally tracked credentials and refresh tokens are cleaned up.
var ErrOAuthPartialLogin = errors.New("OAuth login may have partially completed")

// GeneratePAT exchanges a provider access token for the Docker Hub PAT used by
// registry clients. The caller must supply this fixed, trusted host endpoint.
func GeneratePAT(ctx context.Context, transport http.RoundTripper, endpoint, accessToken string) (string, error) {
	if transport == nil || accessToken == "" || !validEndpointString(endpoint) {
		return "", errors.New("invalid Docker Hub token exchange configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return "", errors.New("invalid Docker Hub token exchange request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("docker Hub token exchange failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("docker Hub token exchange was rejected")
	}
	const maxPATResponse = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPATResponse+1))
	if err != nil || len(body) > maxPATResponse {
		clear(body)
		return "", errors.New("invalid Docker Hub token response")
	}
	defer clear(body)
	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil || result.Data.Token == "" || strings.ContainsAny(result.Data.Token, "\x00\r\n") {
		return "", errors.New("invalid Docker Hub token response")
	}
	return result.Data.Token, nil
}

// HubUsernameFromAccessToken extracts the account label from the Docker Hub
// JWT. The value is display/storage metadata only; it is never an auth proof.
// The PAT endpoint must independently accept the access token before use.
func HubUsernameFromAccessToken(accessToken string) (string, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 || parts[1] == "" {
		return "", errors.New("invalid Docker Hub access token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) > 16<<10 {
		clear(payload)
		return "", errors.New("invalid Docker Hub access token")
	}
	defer clear(payload)
	var claims struct {
		Hub struct {
			Username string `json:"username"`
		} `json:"https://hub.docker.com"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Hub.Username == "" || strings.ContainsAny(claims.Hub.Username, "\x00\r\n") {
		return "", errors.New("docker Hub account name is missing")
	}
	return claims.Hub.Username, nil
}

func deviceRequest(ctx context.Context, transport http.RoundTripper, endpoint string, values url.Values) ([]byte, int, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !validAuthorizationEndpoint(u) || transport == nil {
		return nil, 0, errors.New("invalid device endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, 0, errors.New("invalid device request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	const maxDeviceResponse = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDeviceResponse+1))
	if err != nil || len(body) > maxDeviceResponse {
		clear(body)
		return nil, 0, errors.New("invalid device response")
	}
	return body, resp.StatusCode, nil
}
