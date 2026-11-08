// Package policysync pulls signed organization policy bundles from a
// self-hosted rheic-server and persists only locally verified bundles.
//
// The client pins the Ed25519 policy public key, re-verifies the canonical
// signature itself, and refuses expired bundles or revisions that would roll
// back the locally stored revision. Network, TLS, signature and revision
// failures fail closed: the previous stored bundle is left untouched.
//
// This package is deliberately not wired into the daemon CLI, local API or SDK
// yet. The stored bundle can be enforced for sandbox network deny rules by
// internal/orgpolicy when org_policy.enforce is on. Multi-tenancy, offline
// last-known-good behavior and non-network resources remain out of scope.
package policysync

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

const (
	maxBundleBytes = 1 << 20
	syncTimeout    = 15 * time.Second
	minTokenBytes  = 32
)

var (
	// ErrInvalidBundle reports malformed, cross-org or otherwise invalid policy
	// metadata returned by the server.
	ErrInvalidBundle = errors.New("policy bundle is invalid")
	// ErrBundleExpired reports a bundle whose expiry is not in the future.
	ErrBundleExpired = errors.New("policy bundle is expired")
	// ErrInvalidSignature reports a bundle that does not verify with the pinned
	// Ed25519 policy key.
	ErrInvalidSignature = errors.New("policy bundle signature is invalid")
	// ErrRevisionNotNewer reports a bundle that would replace the stored bundle
	// with the same or an older revision.
	ErrRevisionNotNewer = errors.New("policy bundle revision would roll back local policy")
)

// Config configures one organization's policy sync client.
type Config struct {
	BaseURL    string
	OrgID      string
	Token      string
	PublicKey  ed25519.PublicKey
	HTTPClient *http.Client
	Clock      func() time.Time
}

// Result describes the outcome of one sync attempt.
type Result struct {
	OrgID     string
	Revision  uint64
	ExpiresAt time.Time
	Changed   bool
}

// BundleStore is the local persistence seam used by the client. store.Store
// implements it.
type BundleStore interface {
	GetPolicyBundle(ctx context.Context, org string) (store.StoredPolicyBundle, bool, error)
	SavePolicyBundle(ctx context.Context, bundle store.StoredPolicyBundle) error
}

// Client pulls and verifies one organization's signed policy bundle.
type Client struct {
	endpoint   string
	orgID      string
	token      string
	publicKey  ed25519.PublicKey
	httpClient *http.Client
	clock      func() time.Time
}

// New validates the sync configuration and builds a client.
func New(config Config) (*Client, error) {
	baseURL, err := parseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	if !controlplane.ValidOrgID(config.OrgID) {
		return nil, errors.New("policy sync org ID is invalid")
	}
	if len(config.Token) < minTokenBytes || strings.ContainsAny(config.Token, " \t\r\n") {
		return nil, errors.New("policy sync token is invalid")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("policy sync public key must be an Ed25519 key")
	}
	client := config.HTTPClient
	if client == nil {
		client = newSyncHTTPClient()
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Client{
		endpoint:   strings.TrimRight(baseURL, "/") + "/v1/orgs/" + url.PathEscape(config.OrgID) + "/policy",
		orgID:      config.OrgID,
		token:      config.Token,
		publicKey:  append(ed25519.PublicKey(nil), config.PublicKey...),
		httpClient: client,
		clock:      clock,
	}, nil
}

func parseBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("policy sync base URL must be an absolute HTTPS URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("policy sync base URL must not contain a query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("policy sync base URL must not contain a path")
	}
	return parsed.String(), nil
}

func newSyncHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   syncTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("policy sync refuses HTTP redirects")
		},
	}
}

// Sync fetches the latest bundle, verifies it locally and persists it when it
// is strictly newer. Equal revisions are an idempotent no-op; older revisions
// and all verification failures return an error without touching the store.
func (c *Client) Sync(ctx context.Context, bundles BundleStore) (Result, error) {
	if bundles == nil {
		return Result{}, errors.New("policy bundle store is required")
	}
	local, found, err := bundles.GetPolicyBundle(ctx, c.orgID)
	if err != nil {
		return Result{}, err
	}
	remote, err := c.fetch(ctx)
	if err != nil {
		return Result{}, err
	}
	now := c.clock()
	if err := c.verify(remote, now); err != nil {
		return Result{}, err
	}
	result := Result{OrgID: c.orgID, Revision: remote.Payload.Revision, ExpiresAt: remote.Payload.ExpiresAt.UTC()}
	if found {
		if remote.Payload.Revision < local.Revision {
			return Result{}, fmt.Errorf("%w: remote revision %d is older than local %d", ErrRevisionNotNewer, remote.Payload.Revision, local.Revision)
		}
		if remote.Payload.Revision == local.Revision {
			return result, nil
		}
	}
	stored, err := storedBundle(remote, now)
	if err != nil {
		return Result{}, err
	}
	if err := bundles.SavePolicyBundle(ctx, stored); err != nil {
		if errors.Is(err, store.ErrPolicyRevisionNotNewer) {
			return Result{}, fmt.Errorf("%w: %w", ErrRevisionNotNewer, err)
		}
		return Result{}, err
	}
	result.Changed = true
	return result, nil
}

func (c *Client) verify(bundle controlplane.SignedPolicyBundle, now time.Time) error {
	if bundle.Payload.OrgID != c.orgID {
		return fmt.Errorf("%w: org mismatch", ErrInvalidBundle)
	}
	if !bundle.Payload.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry %s is not in the future", ErrBundleExpired, bundle.Payload.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if err := controlplane.ValidatePolicyPayload(bundle.Payload, c.orgID, now); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if !controlplane.VerifyPolicySignature(bundle.Payload, bundle.Signature, c.publicKey) {
		return ErrInvalidSignature
	}
	return nil
}

func storedBundle(bundle controlplane.SignedPolicyBundle, now time.Time) (store.StoredPolicyBundle, error) {
	bundle.Payload.IssuedAt = bundle.Payload.IssuedAt.UTC()
	bundle.Payload.ExpiresAt = bundle.Payload.ExpiresAt.UTC()
	payload, err := json.Marshal(bundle.Payload)
	if err != nil {
		return store.StoredPolicyBundle{}, fmt.Errorf("encode policy payload: %w", err)
	}
	return store.StoredPolicyBundle{
		OrgID: bundle.Payload.OrgID, Revision: bundle.Payload.Revision,
		Payload: payload, Signature: bundle.Signature,
		IssuedAt: bundle.Payload.IssuedAt, ExpiresAt: bundle.Payload.ExpiresAt, SyncedAt: now.UTC(),
	}, nil
}

func (c *Client) fetch(ctx context.Context) (controlplane.SignedPolicyBundle, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, http.NoBody)
	if err != nil {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("build policy request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("fetch policy bundle: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("fetch policy bundle: unexpected status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBundleBytes+1))
	if err != nil {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("read policy bundle: %w", err)
	}
	if len(body) > maxBundleBytes {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("%w: response exceeds size limit", ErrInvalidBundle)
	}
	bundle, err := controlplane.DecodeSignedPolicyBundleJSON(body)
	if err != nil {
		return controlplane.SignedPolicyBundle{}, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	return bundle, nil
}
