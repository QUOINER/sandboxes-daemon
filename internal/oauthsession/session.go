// Package oauthsession provides host-side OAuth flows, token lifecycle, and
// loopback callback handling for explicitly registered providers.
package oauthsession

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	clientIDKey  = "client_id"
	grantTypeKey = "grant_type"
	httpsScheme  = "https"
	refreshGrant = "refresh_token"
)

// ErrDenied indicates that the authorization server returned an error for a
// transaction with a valid state. Provider error text is never propagated.
var ErrDenied = errors.New("OAuth authorization denied")

// Session holds transaction-specific values. It must remain on the host and
// must not be logged, persisted, or reused for another authorization attempt.
type Session struct {
	mu                    sync.Mutex
	state                 string
	verifier              string
	used                  bool
	code                  string
	redirect              string
	clientID              string
	authorizationEndpoint string
	tokenEndpoint         string
	exchanged             bool
}

// New creates independent random state and PKCE verifier values.
func New() (*Session, error) {
	var state, verifier [32]byte
	if _, err := rand.Read(state[:]); err != nil {
		return nil, errors.New("generate OAuth state")
	}
	if _, err := rand.Read(verifier[:]); err != nil {
		return nil, errors.New("generate OAuth verifier")
	}
	return &Session{state: base64.RawURLEncoding.EncodeToString(state[:]), verifier: base64.RawURLEncoding.EncodeToString(verifier[:])}, nil
}

// AuthorizationURL constructs an S256 authorization request using a trusted
// provider endpoint and a loopback IP redirect with an already bound port.
func (s *Session) AuthorizationURL(endpoint, clientID, redirect string, scopes []string) (string, error) {
	return s.AuthorizationURLWithParams(endpoint, clientID, redirect, scopes, nil)
}

// AuthorizationURLWithParams adds only trusted provider-specific parameters
// without allowing them to override the transaction's security fields.
func (s *Session) AuthorizationURLWithParams(endpoint, clientID, redirect string, scopes []string, extra map[string]string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !validAuthorizationEndpoint(u) || clientID == "" || s == nil || s.state == "" || s.verifier == "" {
		return "", errors.New("invalid OAuth authorization configuration")
	}
	if !validRedirect(redirect) {
		return "", errors.New("invalid OAuth redirect")
	}
	if err := s.bindAuthorization(endpoint, clientID, redirect); err != nil {
		return "", err
	}
	q, err := authorizationQuery(clientID, redirect, s.state, s.verifier, scopes, extra)
	if err != nil {
		return "", err
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func authorizationQuery(clientID, redirect, state, verifier string, scopes []string, extra map[string]string) (url.Values, error) {
	for _, scope := range scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("invalid OAuth scope")
		}
	}
	hash := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, clientIDKey: {clientID}, "redirect_uri": {redirect}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}}
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	for key, value := range extra {
		if !validAuthorizationExtra(key, value) {
			return nil, errors.New("invalid OAuth provider authorization parameter")
		}
		if _, exists := q[key]; exists {
			return nil, errors.New("OAuth provider parameter overrides transaction field")
		}
		q.Set(key, value)
	}
	return q, nil
}

func validAuthorizationExtra(key, value string) bool {
	if key == "" || len(key) > 64 || len(value) > 256 || strings.ContainsAny(key+value, "\x00\r\n") {
		return false
	}
	for i := range key {
		c := key[i]
		if !isAuthorizationParamChar(c) {
			return false
		}
	}
	return true
}

func isAuthorizationParamChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (s *Session) bindAuthorization(endpoint, clientID, redirect string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.redirect != "" && (s.redirect != redirect || s.clientID != clientID || s.authorizationEndpoint != endpoint) {
		return errors.New("OAuth authorization already bound")
	}
	s.redirect = redirect
	s.clientID = clientID
	s.authorizationEndpoint = endpoint
	return nil
}

func validAuthorizationEndpoint(u *url.URL) bool {
	return u.Scheme == httpsScheme && u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == ""
}

func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	return ip != nil && ip.IsLoopback() && err == nil && port > 0 && port <= 65535
}

// ValidateCallback checks state and unambiguous callback parameters and
// consumes a successful response exactly once.
func (s *Session) ValidateCallback(query url.Values) (string, error) {
	if s == nil || s.state == "" || len(query["state"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(s.state)) != 1 {
		return "", errors.New("invalid OAuth callback")
	}
	denied := len(query["error"]) == 1 && query.Get("error") != "" && len(query["code"]) == 0
	if !denied && (len(query["code"]) != 1 || query.Get("code") == "" || len(query["error"]) != 0) {
		return "", errors.New("invalid OAuth callback")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.redirect == "" {
		return "", errors.New("OAuth callback already used")
	}
	s.used = true
	if denied {
		return "", ErrDenied
	}
	s.code = query.Get("code")
	return query.Get("code"), nil
}

// Verifier is needed only by the host-side token exchange.
func (s *Session) Verifier() string { return s.verifier }
