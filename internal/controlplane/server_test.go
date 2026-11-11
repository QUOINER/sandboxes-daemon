//go:build !windows

package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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

func TestPolicySigningVectorAndUTCNormalization(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	payload := PolicyPayload{
		SchemaVersion: 1,
		OrgID:         "acme",
		Revision:      7,
		IssuedAt:      time.Date(2026, time.January, 2, 3, 4, 5, 123456789, time.FixedZone("UTC+02", 2*60*60)),
		ExpiresAt:     time.Date(2026, time.January, 3, 4, 5, 6, 987654321, time.UTC),
		Rules: []PolicyRule{
			{Resource: "network:api.example.test:443", Action: "allow", RuleID: "r-1"},
			{Resource: "filesystem:/work", Action: "deny", RuleID: "r-2"},
		},
	}
	canonical, err := PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, canonical)
	const wantCanonicalHex = "72686569632d706f6c6963792d7061796c6f616400763100000000010000000461636d6500000000000000070000000069571985075bcd1500000000695895723ade68b1000000020000001c6e6574776f726b3a6170692e6578616d706c652e746573743a34343300000005616c6c6f7700000003722d310000001066696c6573797374656d3a2f776f726b0000000464656e7900000003722d32"
	const wantSignatureBase64 = "mypTm0Wj1KhKqZ9FvMa5wlmCKz0IPbnnmcS9AlIyCAM36n13c+aLkFh2y07Ib0/WdE4cF2ibYRPDpRnrz5j2Aw=="
	if hex.EncodeToString(canonical) != wantCanonicalHex {
		t.Fatalf("canonical bytes = %x", canonical)
	}
	if base64.StdEncoding.EncodeToString(signature) != wantSignatureBase64 {
		t.Fatalf("signature = %s", base64.StdEncoding.EncodeToString(signature))
	}
	utcPayload := payload
	utcPayload.IssuedAt = payload.IssuedAt.UTC()
	canonicalUTC, err := PolicySigningBytes(utcPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, canonicalUTC) {
		t.Fatal("equivalent timestamp offsets produced different signing bytes")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, canonical, signature) || !verifySignature(payload, wantSignatureBase64, publicKey) {
		t.Fatal("fixed Ed25519 policy signature did not interoperate with verifier")
	}
	if verifySignature(payload, wantSignatureBase64+"\n", publicKey) {
		t.Fatal("noncanonical Base64 signature was accepted")
	}
}

func TestPolicyRulesMustBeStrictlyOrderedByRuleID(t *testing.T) {
	server, _, now := newTestServer(t)
	payload := PolicyPayload{
		SchemaVersion: 1,
		OrgID:         "example-org",
		Revision:      1,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
		Rules: []PolicyRule{
			{Resource: "network:b.example.test:443", Action: "allow", RuleID: "r-2"},
			{Resource: "network:a.example.test:443", Action: "deny", RuleID: "r-1"},
		},
	}
	response := requestJSON(t, server.Handler(), http.MethodPut, "/v1/orgs/example-org/policy", SignedPolicyBundle{Payload: payload, Signature: "invalid"}, true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsorted policy status=%d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
}

func TestPolicyJSONRejectsDuplicateMembersAndExcessTimestampPrecision(t *testing.T) {
	valid := `{"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00Z","expiresAt":"2026-11-08T01:00:00Z","rules":[]}`
	for name, raw := range map[string]string{
		"duplicate":          `{"schemaVersion":1,"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00Z","expiresAt":"2026-11-08T01:00:00Z","rules":[]}`,
		"excess precision":   `{"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00.1234567890Z","expiresAt":"2026-11-08T01:00:00Z","rules":[]}`,
		"duplicate nested":   `{"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00Z","expiresAt":"2026-11-08T01:00:00Z","rules":[{"resource":"x","resource":"y","action":"allow","ruleId":"r1"}]}`,
		"unpaired surrogate": `{"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00Z","expiresAt":"2026-11-08T01:00:00Z","rules":[{"resource":"\ud800","action":"allow","ruleId":"r1"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicyPayloadJSON([]byte(raw)); err == nil {
				t.Fatal("invalid policy JSON was accepted")
			}
		})
	}
	if _, err := DecodePolicyPayloadJSON([]byte(valid)); err != nil {
		t.Fatalf("valid policy JSON rejected: %v", err)
	}
	validSurrogatePair := `{"schemaVersion":1,"orgId":"example-org","revision":1,"issuedAt":"2026-11-08T00:00:00Z","expiresAt":"2026-11-08T01:00:00Z","rules":[{"resource":"\ud83d\ude00","action":"allow","ruleId":"r1"}]}`
	if _, err := DecodePolicyPayloadJSON([]byte(validSurrogatePair)); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	invalidUTF8 := append([]byte(valid[:len(valid)-1]), 0xff, '}')
	if _, err := DecodePolicyPayloadJSON(invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 policy JSON was accepted")
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
	server, err := New(Config{DBPath: dbPath, Credentials: testCredentials(t), PolicyKey: publicKey})
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
	if _, err := New(Config{DBPath: dbPath, Credentials: testCredentials(t), PolicyKey: publicKey}); err == nil {
		t.Fatal("newer schema was accepted")
	}
}

func TestNewSupportsURICharactersInDatabaseFilename(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "control plane ?# [alpha].db")
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{DBPath: dbPath, Credentials: testCredentials(t), PolicyKey: publicKey})
	if err != nil {
		t.Fatalf("open control-plane database at URI-like path: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("database was not created at requested path: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("database path is not a regular file: %v", info.Mode())
	}
}

func TestAuditIngestIsBoundedStructuredAndAuthenticated(t *testing.T) {
	server, _, now := newTestServer(t)
	batch := strings.Join([]string{
		`{"occurredAt":"` + now.Format(time.RFC3339Nano) + `","sandboxId":"sbx_123","operationId":"op_123","action":"network.connect","resource":"network","decision":"allow","ruleId":"r_1"}`,
		`{"occurredAt":"` + now.Format(time.RFC3339Nano) + `","sandboxId":"sbx_123","operationId":"op_124","action":"network.connect","resource":"network","decision":"deny"}`,
	}, "\n")
	request := httptest.NewRequest(http.MethodPost, "/v1/orgs/example-org/audit", strings.NewReader(batch))
	request.Header.Set("Authorization", "Bearer "+string(testAdminToken))
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
	request.Header.Set("Authorization", "Bearer "+string(testAdminToken))
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

var (
	testAdminToken  = []byte("test-only-synthetic-admin-token-000000000000000000000000000000")
	testReaderToken = []byte("test-only-synthetic-reader-token-00000000000000000000000000000")
)

func testCredentials(t *testing.T) *CredentialSet {
	t.Helper()
	credentials, err := NewCredentialSet([]Credential{
		{Name: "test-admin", Role: RoleAdmin, Token: string(testAdminToken)},
		{Name: "test-reader", Role: RoleReader, Token: string(testReaderToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func newTestServer(t *testing.T) (*Server, ed25519.PrivateKey, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
	server, err := New(Config{DBPath: filepath.Join(t.TempDir(), "controlplane.db"), Credentials: testCredentials(t), PolicyKey: publicKey, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, privateKey, now
}

func signedBundle(t *testing.T, payload PolicyPayload, key ed25519.PrivateKey) SignedPolicyBundle {
	t.Helper()
	encoded, err := PolicySigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	return SignedPolicyBundle{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, encoded))}
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, value any, authorized bool) *httptest.ResponseRecorder {
	t.Helper()
	token := []byte(nil)
	if authorized {
		token = testAdminToken
	}
	return requestWithToken(t, handler, method, path, value, token)
}

func requestWithToken(t *testing.T, handler http.Handler, method, path string, value any, token []byte) *httptest.ResponseRecorder {
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
	if token != nil {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
