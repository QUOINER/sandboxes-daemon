//go:build !windows

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/policysync"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

const testPolicySyncToken = "synthetic-policy-sync-token-000000000000000000000000000000"

type policySyncTestServer struct {
	server        *httptest.Server
	mu            sync.Mutex
	body          []byte
	status        int
	requests      int
	authorization string
	started       chan struct{}
	block         bool
	delay         time.Duration
	concurrent    int
	maxConcurrent int
}

func newPolicySyncTestServer(t *testing.T, body []byte) *policySyncTestServer {
	t.Helper()
	ts := &policySyncTestServer{body: body, started: make(chan struct{}, 1)}
	ts.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.requests++
		ts.authorization = r.Header.Get("Authorization")
		ts.concurrent++
		if ts.concurrent > ts.maxConcurrent {
			ts.maxConcurrent = ts.concurrent
		}
		body, status, block, delay := ts.body, ts.status, ts.block, ts.delay
		ts.mu.Unlock()
		defer func() {
			ts.mu.Lock()
			ts.concurrent--
			ts.mu.Unlock()
		}()
		select {
		case ts.started <- struct{}{}:
		default:
		}
		if block {
			<-r.Context().Done()
			return
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/orgs/org-a/policy" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.server.Close)
	return ts
}

func (s *policySyncTestServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *policySyncTestServer) authHeader() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorization
}

func (s *policySyncTestServer) maxParallel() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxConcurrent
}

func policySyncPayload(now time.Time, revision uint64) controlplane.PolicyPayload {
	return controlplane.PolicyPayload{
		SchemaVersion: 1, OrgID: "org-a", Revision: revision,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []controlplane.PolicyRule{{Resource: "network:api.example.test:443", Action: "allow", RuleID: "r1"}},
	}
}

func signedPolicySyncBundle(t *testing.T, payload controlplane.PolicyPayload, key ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(controlplane.SignedPolicyBundle{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func policySyncSyntheticKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func openPolicySyncStore(t *testing.T) *store.Store {
	t.Helper()
	state, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func newPolicySyncTestRunner(t *testing.T, ts *policySyncTestServer, publicKey ed25519.PublicKey, state *store.Store, interval time.Duration, client *http.Client) *policySyncRunner {
	t.Helper()
	if client == nil {
		client = ts.server.Client()
	}
	syncClient, err := policysync.New(policysync.Config{
		BaseURL: ts.server.URL, OrgID: "org-a", Token: testPolicySyncToken,
		PublicKey: publicKey, HTTPClient: client, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &policySyncRunner{
		client: syncClient, bundles: state, orgID: "org-a", interval: interval,
		jitter: func(time.Duration) time.Duration { return 0 },
	}
}

func newPolicySyncTestClient(t *testing.T, ts *policySyncTestServer, publicKey ed25519.PublicKey) *policysync.Client {
	t.Helper()
	client, err := policysync.New(policysync.Config{
		BaseURL: ts.server.URL, OrgID: "org-a", Token: testPolicySyncToken,
		PublicKey: publicKey, HTTPClient: ts.server.Client(), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func seedPolicySyncBundle(t *testing.T, state *store.Store, payload controlplane.PolicyPayload, key ed25519.PrivateKey, syncedAt time.Time) store.StoredPolicyBundle {
	t.Helper()
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	stored := store.StoredPolicyBundle{
		OrgID: payload.OrgID, Revision: payload.Revision, Payload: encoded,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
		IssuedAt:  payload.IssuedAt.UTC(), ExpiresAt: payload.ExpiresAt.UTC(), SyncedAt: syncedAt.UTC(),
	}
	if err := state.SavePolicyBundle(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

func waitPolicySync(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(message)
}

func stopPolicySyncRunner(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("policy sync runner did not stop on shutdown")
	}
}

func TestPolicySyncRunnerPersistsVerifiedBundle(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 1), privateKey))
	state := openPolicySyncStore(t)
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.run(ctx)
	}()
	waitPolicySync(t, func() bool {
		stored, found, err := state.GetPolicyBundle(context.Background(), "org-a")
		return err == nil && found && stored.Revision == 1
	}, "verified bundle was not persisted")
	if got := ts.authHeader(); got != "Bearer "+testPolicySyncToken {
		t.Fatalf("authorization header = %q", got)
	}
	stopPolicySyncRunner(t, cancel, done)
}

func TestPolicySyncRunnerEqualRevisionIsNoOp(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	payload := policySyncPayload(now, 2)
	state := openPolicySyncStore(t)
	syncedAt := now.Add(-time.Hour)
	before := seedPolicySyncBundle(t, state, payload, privateKey, syncedAt)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, payload, privateKey))
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

	runner.syncOnce(context.Background())

	after, found, err := state.GetPolicyBundle(context.Background(), "org-a")
	if err != nil || !found {
		t.Fatalf("stored found=%v err=%v", found, err)
	}
	if after.Revision != before.Revision || !after.SyncedAt.Equal(before.SyncedAt) || after.Signature != before.Signature {
		t.Fatalf("equal revision changed stored bundle: before=%+v after=%+v", before, after)
	}
	if ts.requestCount() != 1 {
		t.Fatalf("requests = %d", ts.requestCount())
	}
}

func TestPolicySyncRunnerRefusesOlderRevision(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	state := openPolicySyncStore(t)
	before := seedPolicySyncBundle(t, state, policySyncPayload(now, 3), privateKey, now)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 2), privateKey))
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

	runner.syncOnce(context.Background())

	after, found, err := state.GetPolicyBundle(context.Background(), "org-a")
	if err != nil || !found || after.Revision != before.Revision || after.Signature != before.Signature {
		t.Fatalf("older revision changed stored bundle: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestPolicySyncRunnerRefusesBadSignatureAndExpiredBundles(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	_, attackerKey := policySyncSyntheticKey(t)
	expired := policySyncPayload(now, 1)
	expired.IssuedAt = now.Add(-2 * time.Hour)
	expired.ExpiresAt = now.Add(-time.Second)

	for name, body := range map[string][]byte{
		"bad signature": signedPolicySyncBundle(t, policySyncPayload(now, 1), attackerKey),
		"expired":       signedPolicySyncBundle(t, expired, privateKey),
	} {
		t.Run(name, func(t *testing.T) {
			ts := newPolicySyncTestServer(t, body)
			state := openPolicySyncStore(t)
			runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

			runner.syncOnce(context.Background())

			if _, found, err := state.GetPolicyBundle(context.Background(), "org-a"); err != nil || found {
				t.Fatalf("store changed after %s: found=%v err=%v", name, found, err)
			}
		})
	}
}

func TestPolicySyncRunnerNetworkAndTLSFailureLeavesStateUntouched(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	state := openPolicySyncStore(t)
	before := seedPolicySyncBundle(t, state, policySyncPayload(now, 4), privateKey, now)

	closed := newPolicySyncTestServer(t, nil)
	closedClient := newPolicySyncTestRunner(t, closed, publicKey, state, time.Hour, nil)
	closed.server.Close()
	closedClient.syncOnce(context.Background())

	untrusted := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 5), privateKey))
	untrustedRunner := newPolicySyncTestRunner(t, untrusted, publicKey, state, time.Hour, &http.Client{Timeout: time.Second})
	untrustedRunner.syncOnce(context.Background())

	after, found, err := state.GetPolicyBundle(context.Background(), "org-a")
	if err != nil || !found || after.Revision != before.Revision || after.Signature != before.Signature {
		t.Fatalf("network/TLS failure changed stored bundle: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestPolicySyncRunnerDoesNotOverlapAttempts(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 1), privateKey))
	ts.delay = 25 * time.Millisecond
	state := openPolicySyncStore(t)
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, 5*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.run(ctx)
	}()
	waitPolicySync(t, func() bool { return ts.requestCount() >= 3 }, "periodic sync did not run")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("policy sync runner did not stop on shutdown")
	}
	if peak := ts.maxParallel(); peak != 1 {
		t.Fatalf("overlapping policy sync attempts: max concurrency = %d", peak)
	}
}

func TestPolicySyncRunnerShutdownCancelsInFlightAttempt(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 1), privateKey))
	ts.block = true
	state := openPolicySyncStore(t)
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.run(ctx)
	}()
	select {
	case <-ts.started:
	case <-time.After(2 * time.Second):
		t.Fatal("policy sync attempt did not start")
	}
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the in-flight policy sync promptly")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
}

func TestPolicySyncRunnerDoesNotLogToken(t *testing.T) {
	publicKey, _ := policySyncSyntheticKey(t)
	ts := newPolicySyncTestServer(t, nil)
	ts.status = http.StatusForbidden
	state := openPolicySyncStore(t)
	runner := newPolicySyncTestRunner(t, ts, publicKey, state, time.Hour, nil)

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	runner.syncOnce(context.Background())
	if strings.Contains(logs.String(), testPolicySyncToken) {
		t.Fatalf("token leaked into logs: %s", logs.String())
	}
	if logs.Len() == 0 {
		t.Fatal("failed sync did not log an error")
	}
	if _, err := runner.client.Sync(context.Background(), state); err != nil && strings.Contains(err.Error(), testPolicySyncToken) {
		t.Fatalf("token leaked into error: %v", err)
	}
}

func testPolicySyncClient(t *testing.T, publicKey ed25519.PublicKey) *policysync.Client {
	t.Helper()
	client, err := policysync.New(policysync.Config{
		BaseURL: "https://control.example.test", OrgID: "org-a",
		Token: testPolicySyncToken, PublicKey: publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNewPolicySyncRunnerRejectsInvalidConfiguration(t *testing.T) {
	publicKey, _ := policySyncSyntheticKey(t)
	state := openPolicySyncStore(t)
	client := testPolicySyncClient(t, publicKey)
	for name, cfg := range map[string]PolicySyncConfig{
		"missing client": {},
		"short interval": {Client: client, Interval: time.Second},
		"long interval":  {Client: client, Interval: 25 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newPolicySyncRunner(cfg, state); err == nil {
				t.Fatal("invalid policy sync configuration accepted")
			}
		})
	}
	if _, err := newPolicySyncRunner(PolicySyncConfig{Client: client}, nil); err == nil {
		t.Fatal("missing store accepted")
	}
}

func TestPolicySyncRunnerDefaultsInterval(t *testing.T) {
	publicKey, _ := policySyncSyntheticKey(t)
	state := openPolicySyncStore(t)
	runner, err := newPolicySyncRunner(PolicySyncConfig{Client: testPolicySyncClient(t, publicKey)}, state)
	if err != nil {
		t.Fatal(err)
	}
	if runner.interval != policysync.DefaultInterval {
		t.Fatalf("interval = %s", runner.interval)
	}
}

func TestRunWiresPolicySync(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey := policySyncSyntheticKey(t)
	ts := newPolicySyncTestServer(t, signedPolicySyncBundle(t, policySyncPayload(now, 1), privateKey))
	dir := t.TempDir()
	socket := filepath.Join(dir, "sandboxesd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			SocketPath: socket,
			StateDir:   dir,
			PolicySync: &PolicySyncConfig{
				Client:   newPolicySyncTestClient(t, ts, publicKey),
				Interval: time.Hour,
			},
		})
	}()

	var readStore *store.Store
	waitPolicySync(t, func() bool {
		if readStore == nil {
			opened, err := store.Open(context.Background(), filepath.Join(dir, "sandboxes.db"))
			if err != nil {
				return false
			}
			readStore = opened
		}
		stored, found, err := readStore.GetPolicyBundle(context.Background(), "org-a")
		return err == nil && found && stored.Revision == 1
	}, "daemon startup policy sync did not persist the bundle")
	if err := readStore.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}
