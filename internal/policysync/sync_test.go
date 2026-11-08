//go:build !windows

package policysync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

const testSyncToken = "synthetic-policy-sync-token-000000000000000000000000000000"

type bundleServer struct {
	server        *httptest.Server
	mu            sync.Mutex
	body          []byte
	status        int
	authorization string
	requests      int
}

func newBundleServer(t *testing.T, body []byte) *bundleServer {
	t.Helper()
	bundle := &bundleServer{body: body}
	bundle.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundle.mu.Lock()
		defer bundle.mu.Unlock()
		bundle.requests++
		bundle.authorization = r.Header.Get("Authorization")
		if r.Method != http.MethodGet || r.URL.Path != "/v1/orgs/org-a/policy" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if bundle.status != 0 {
			w.WriteHeader(bundle.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bundle.body)
	}))
	t.Cleanup(bundle.server.Close)
	return bundle
}

func (s *bundleServer) authHeader() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorization
}

func (s *bundleServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func testPayload(now time.Time, revision uint64) controlplane.PolicyPayload {
	return controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: "org-a", Revision: revision,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []controlplane.PolicyRule{{Resource: "network:api.example.test:443", Action: "allow", RuleID: "r1"}},
	}
}

func signedBundleJSON(t *testing.T, payload controlplane.PolicyPayload, key ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle := controlplane.SignedPolicyBundle{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	state, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func newTestClient(t *testing.T, server *httptest.Server, publicKey ed25519.PublicKey, now time.Time) *Client {
	t.Helper()
	client, err := New(Config{
		BaseURL: server.URL, OrgID: "org-a", Token: testSyncToken,
		PublicKey: publicKey, HTTPClient: server.Client(), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func syntheticKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestSyncVerifiesAndPersistsBundle(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	payload := testPayload(now, 1)
	server := newBundleServer(t, signedBundleJSON(t, payload, privateKey))
	state := openTestStore(t)
	client := newTestClient(t, server.server, publicKey, now)

	result, err := client.Sync(context.Background(), state)
	if err != nil {
		t.Fatalf("sync valid bundle: %v", err)
	}
	if !result.Changed || result.Revision != 1 || result.OrgID != "org-a" {
		t.Fatalf("result=%+v", result)
	}
	stored, found, err := state.GetPolicyBundle(context.Background(), "org-a")
	if err != nil || !found {
		t.Fatalf("stored found=%v err=%v", found, err)
	}
	if stored.Revision != 1 || stored.Signature == "" || len(stored.Payload) == 0 {
		t.Fatalf("stored bundle=%+v", stored)
	}
	if !stored.ExpiresAt.Equal(payload.ExpiresAt.UTC()) || !stored.IssuedAt.Equal(payload.IssuedAt.UTC()) {
		t.Fatalf("stored timestamps=%+v", stored)
	}
	if got := server.authHeader(); got != "Bearer "+testSyncToken {
		t.Fatalf("authorization header=%q", got)
	}
	result, err = client.Sync(context.Background(), state)
	if err != nil {
		t.Fatalf("idempotent sync: %v", err)
	}
	if result.Changed || result.Revision != 1 {
		t.Fatalf("idempotent result=%+v", result)
	}
	if server.requestCount() != 2 {
		t.Fatalf("requests=%d", server.requestCount())
	}
}

func TestSyncRefusesStaleRevision(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	state := openTestStore(t)
	newer := testPayload(now, 2)
	seedStoredBundle(t, state, newer, privateKey)
	server := newBundleServer(t, signedBundleJSON(t, testPayload(now, 1), privateKey))
	client := newTestClient(t, server.server, publicKey, now)

	if _, err := client.Sync(context.Background(), state); !errors.Is(err, ErrRevisionNotNewer) {
		t.Fatalf("stale revision error=%v, want ErrRevisionNotNewer", err)
	}
	stored, found, err := state.GetPolicyBundle(context.Background(), "org-a")
	if err != nil || !found || stored.Revision != 2 {
		t.Fatalf("stored revision=%d found=%v err=%v", stored.Revision, found, err)
	}
}

func TestSyncRefusesBadSignature(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, _ := syntheticKey(t)
	_, attackerKey := syntheticKey(t)
	server := newBundleServer(t, signedBundleJSON(t, testPayload(now, 1), attackerKey))
	state := openTestStore(t)
	client := newTestClient(t, server.server, publicKey, now)

	if _, err := client.Sync(context.Background(), state); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("bad signature error=%v, want ErrInvalidSignature", err)
	}
	if _, found, err := state.GetPolicyBundle(context.Background(), "org-a"); err != nil || found {
		t.Fatalf("store changed after bad signature: found=%v err=%v", found, err)
	}
}

func TestSyncRefusesExpiredBundle(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	payload := testPayload(now, 1)
	payload.IssuedAt = now.Add(-2 * time.Hour)
	payload.ExpiresAt = now.Add(-time.Second)
	server := newBundleServer(t, signedBundleJSON(t, payload, privateKey))
	state := openTestStore(t)
	client := newTestClient(t, server.server, publicKey, now)

	if _, err := client.Sync(context.Background(), state); !errors.Is(err, ErrBundleExpired) {
		t.Fatalf("expired bundle error=%v, want ErrBundleExpired", err)
	}
	if _, found, err := state.GetPolicyBundle(context.Background(), "org-a"); err != nil || found {
		t.Fatalf("store changed after expired bundle: found=%v err=%v", found, err)
	}
}

func TestSyncRefusesCrossOrgBundle(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	payload := testPayload(now, 1)
	payload.OrgID = "org-b"
	server := newBundleServer(t, signedBundleJSON(t, payload, privateKey))
	state := openTestStore(t)
	client := newTestClient(t, server.server, publicKey, now)

	if _, err := client.Sync(context.Background(), state); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("cross-org error=%v, want ErrInvalidBundle", err)
	}
}

func TestSyncFailsClosedOnNetworkAndTLS(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	state := openTestStore(t)

	closedServer := newBundleServer(t, signedBundleJSON(t, testPayload(now, 1), privateKey))
	closedClient := newTestClient(t, closedServer.server, publicKey, now)
	closedServer.server.Close()
	if _, err := closedClient.Sync(context.Background(), state); err == nil {
		t.Fatal("network failure was not reported")
	}

	tlsServer := newBundleServer(t, signedBundleJSON(t, testPayload(now, 1), privateKey))
	untrusted, err := New(Config{
		BaseURL: tlsServer.server.URL, OrgID: "org-a", Token: testSyncToken, PublicKey: publicKey,
		HTTPClient: &http.Client{Timeout: time.Second}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Sync(context.Background(), state); err == nil {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	if _, found, err := state.GetPolicyBundle(context.Background(), "org-a"); err != nil || found {
		t.Fatalf("store changed after network failures: found=%v err=%v", found, err)
	}
}

func TestSyncRefusesUnexpectedStatus(t *testing.T) {
	now := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := syntheticKey(t)
	server := newBundleServer(t, signedBundleJSON(t, testPayload(now, 1), privateKey))
	server.status = http.StatusForbidden
	state := openTestStore(t)
	if _, err := newTestClient(t, server.server, publicKey, now).Sync(context.Background(), state); err == nil {
		t.Fatal("unexpected HTTP status was accepted")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	publicKey, _ := syntheticKey(t)
	cases := map[string]Config{
		"http URL":       {BaseURL: "http://control.example.test", OrgID: "org-a", Token: testSyncToken, PublicKey: publicKey},
		"URL path":       {BaseURL: "https://control.example.test/api", OrgID: "org-a", Token: testSyncToken, PublicKey: publicKey},
		"URL query":      {BaseURL: "https://control.example.test?x=1", OrgID: "org-a", Token: testSyncToken, PublicKey: publicKey},
		"URL userinfo":   {BaseURL: "https://user@control.example.test", OrgID: "org-a", Token: testSyncToken, PublicKey: publicKey},
		"empty org":      {BaseURL: "https://control.example.test", OrgID: "", Token: testSyncToken, PublicKey: publicKey},
		"short token":    {BaseURL: "https://control.example.test", OrgID: "org-a", Token: "short", PublicKey: publicKey},
		"whitespace":     {BaseURL: "https://control.example.test", OrgID: "org-a", Token: testSyncToken + " ", PublicKey: publicKey},
		"missing key":    {BaseURL: "https://control.example.test", OrgID: "org-a", Token: testSyncToken},
		"wrong key size": {BaseURL: "https://control.example.test", OrgID: "org-a", Token: testSyncToken, PublicKey: []byte("short")},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(config); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func seedStoredBundle(t *testing.T, state *store.Store, payload controlplane.PolicyPayload, key ed25519.PrivateKey) {
	t.Helper()
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	err = state.SavePolicyBundle(context.Background(), store.StoredPolicyBundle{
		OrgID: payload.OrgID, Revision: payload.Revision, Payload: encoded,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
		IssuedAt:  payload.IssuedAt.UTC(), ExpiresAt: payload.ExpiresAt.UTC(), SyncedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
}
