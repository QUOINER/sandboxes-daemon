//go:build !windows

package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedPolicyLifecycle(t *testing.T) {
	server, privateKey, now := newTestServer(t)
	handler := server.Handler()
	payload := PolicyPayload{
		SchemaVersion: 1,
		OrgID:         "example-org",
		Revision:      1,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
		Rules:         []PolicyRule{{Resource: "network:api.example.test:443", Action: "allow", RuleID: "r1"}},
	}
	bundle := signedBundle(t, payload, privateKey)
	response := requestJSON(t, handler, http.MethodPut, "/v1/orgs/example-org/policy", bundle, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	response = requestJSON(t, handler, http.MethodGet, "/v1/orgs/example-org/policy", nil, true)
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	var got SignedPolicyBundle
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Payload.Revision != payload.Revision || !verifySignature(got.Payload, got.Signature, server.policyKey) {
		t.Fatalf("stored bundle mismatch: %+v", got)
	}
	response = requestJSON(t, handler, http.MethodPut, "/v1/orgs/example-org/policy", bundle, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("replayed revision status=%d, want %d", response.Code, http.StatusConflict)
	}
	payload.Revision++
	bundle = signedBundle(t, payload, privateKey)
	bundle.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	response = requestJSON(t, handler, http.MethodPut, "/v1/orgs/example-org/policy", bundle, true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad signature status=%d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
}

func TestExpiredPolicyIsRejected(t *testing.T) {
	server, privateKey, now := newTestServer(t)
	payload := PolicyPayload{SchemaVersion: 1, OrgID: "example-org", Revision: 1, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)}
	response := requestJSON(t, server.Handler(), http.MethodPut, "/v1/orgs/example-org/policy", signedBundle(t, payload, privateKey), true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expired policy status=%d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
}

func TestMigrationBacksUpExistingDatabaseAndRejectsNewerSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controlplane.db")
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE legacy_marker(value TEXT); INSERT INTO legacy_marker(value) VALUES('preserve-me')`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{DBPath: dbPath, AdminToken: testToken, PolicyKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(dbPath + ".backup-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup files=%v err=%v", backups, err)
	}
	backupInfo, err := os.Stat(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode=%v", backupInfo.Mode().Perm())
	}
	backup, err := sql.Open("sqlite", backups[0])
	if err != nil {
		t.Fatal(err)
	}
	var marker string
	err = backup.QueryRow(`SELECT value FROM legacy_marker`).Scan(&marker)
	_ = backup.Close()
	if err != nil || marker != "preserve-me" {
		t.Fatalf("backup marker=%q err=%v", marker, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := New(Config{DBPath: dbPath, AdminToken: testToken, PolicyKey: publicKey}); err == nil {
		t.Fatal("newer schema was accepted")
	}
}

func TestAuditIngestIsBoundedStructuredAndAuthenticated(t *testing.T) {
	server, _, now := newTestServer(t)
	batch := strings.Join([]string{
		`{"occurredAt":"` + now.Format(time.RFC3339Nano) + `","sandboxId":"sbx_123","operationId":"op_123","action":"network.connect","resource":"network","decision":"allow","ruleId":"r_1"}`,
		`{"occurredAt":"` + now.Format(time.RFC3339Nano) + `","sandboxId":"sbx_123","operationId":"op_124","action":"network.connect","resource":"network","decision":"deny"}`,
	}, "\n")
	request := httptest.NewRequest(http.MethodPost, "/v1/orgs/example-org/audit", strings.NewReader(batch))
	request.Header.Set("Authorization", "Bearer "+string(testToken))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("audit status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := server.db.QueryRow(`SELECT count(*) FROM audit_events WHERE org_id=?`, "example-org").Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit rows=%d err=%v", count, err)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/orgs/example-org/audit", strings.NewReader(`{"occurredAt":"`+now.Format(time.RFC3339Nano)+`","sandboxId":"sbx_1","operationId":"op_1","action":"x","resource":"network","decision":"allow","payload":"must reject"}`))
	request.Header.Set("Authorization", "Bearer "+string(testToken))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown audit field status=%d, want %d", response.Code, http.StatusBadRequest)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/orgs/example-org/audit", strings.NewReader(batch))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated audit status=%d, want %d", response.Code, http.StatusUnauthorized)
	}
}

var testToken = []byte("test-only-random-admin-token-000000000000000000000000000000000000")

func newTestServer(t *testing.T) (*Server, ed25519.PrivateKey, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
	server, err := New(Config{DBPath: filepath.Join(t.TempDir(), "controlplane.db"), AdminToken: testToken, PolicyKey: publicKey, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, privateKey, now
}

func signedBundle(t *testing.T, payload PolicyPayload, key ed25519.PrivateKey) SignedPolicyBundle {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return SignedPolicyBundle{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, encoded))}
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, value any, authorized bool) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader = strings.NewReader("")
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(encoded))
	}
	request := httptest.NewRequest(method, path, body)
	if authorized {
		request.Header.Set("Authorization", "Bearer "+string(testToken))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
