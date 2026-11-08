//go:build !windows

package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditExportPaginatesWithStableOrderingAndOrgIsolation(t *testing.T) {
	server, _, now := newTestServer(t)
	handler := server.Handler()
	orgAIds := []string{"a-1", "a-2", "a-3", "a-4", "a-5"}
	orgBIds := []string{"b-1", "b-2"}
	postAuditEvents(t, handler, "org-a", now, orgAIds...)
	postAuditEvents(t, handler, "org-b", now, orgBIds...)

	first := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2", testReaderToken))
	if len(first.Events) != 2 || first.NextCursor == "" {
		t.Fatalf("first page=%+v", first)
	}
	if first.Events[0].ID >= first.Events[1].ID {
		t.Fatalf("first page is not ordered: %+v", first.Events)
	}
	second := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2&after="+first.NextCursor, testReaderToken))
	if len(second.Events) != 2 || second.NextCursor == "" {
		t.Fatalf("second page=%+v", second)
	}
	if second.Events[0].ID <= first.Events[1].ID {
		t.Fatalf("second page did not resume after cursor: %+v", second.Events)
	}
	third := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2&after="+second.NextCursor, testReaderToken))
	if len(third.Events) != 1 || third.NextCursor != "" {
		t.Fatalf("third page=%+v", third)
	}
	seen := make(map[int64]struct{})
	for _, event := range append(append(first.Events, second.Events...), third.Events...) {
		if _, exists := seen[event.ID]; exists {
			t.Fatalf("duplicate audit id %d across pages", event.ID)
		}
		seen[event.ID] = struct{}{}
		if !strings.HasPrefix(event.SandboxID, "a-") {
			t.Fatalf("cross-org audit event leaked: %+v", event)
		}
	}
	if len(seen) != len(orgAIds) {
		t.Fatalf("exported %d events, want %d", len(seen), len(orgAIds))
	}
	other := decodeAuditPage(t, getAudit(t, handler, "org-b", "", testReaderToken))
	if len(other.Events) != len(orgBIds) {
		t.Fatalf("org-b events=%d, want %d", len(other.Events), len(orgBIds))
	}
	for _, event := range other.Events {
		if !strings.HasPrefix(event.SandboxID, "b-") {
			t.Fatalf("cross-org audit event leaked: %+v", event)
		}
	}
}

func TestAuditExportCursorRemainsStableWhenNewEventsArrive(t *testing.T) {
	server, _, now := newTestServer(t)
	handler := server.Handler()
	postAuditEvents(t, handler, "org-a", now, "a-1", "a-2", "a-3", "a-4")
	first := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2", testReaderToken))
	postAuditEvents(t, handler, "org-a", now, "a-5")
	second := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2&after="+first.NextCursor, testReaderToken))
	for _, event := range second.Events {
		for _, earlier := range first.Events {
			if event.ID == earlier.ID {
				t.Fatalf("cursor replayed audit id %d", event.ID)
			}
		}
		if event.SandboxID == "a-5" {
			t.Fatalf("page overran its limit: %+v", second.Events)
		}
	}
	third := decodeAuditPage(t, getAudit(t, handler, "org-a", "?limit=2&after="+second.NextCursor, testReaderToken))
	if len(third.Events) != 1 || third.Events[0].SandboxID != "a-5" {
		t.Fatalf("third page=%+v", third)
	}
}

func TestAuditExportLimitAndCursorBounds(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := server.Handler()
	for _, query := range []string{"?limit=1", "?limit=100", "?limit=500", ""} {
		if response := getAudit(t, handler, "org-a", query, testReaderToken); response.Code != http.StatusOK {
			t.Fatalf("query %q status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
	invalidLimits := []string{"?limit=0", "?limit=-1", "?limit=501", "?limit=abc", "?limit=", "?limit=1.5"}
	for _, query := range invalidLimits {
		response := getAudit(t, handler, "org-a", query, testReaderToken)
		if response.Code != http.StatusBadRequest || decodeErrorCode(t, response) != "invalid_limit" {
			t.Fatalf("query %q status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
	for _, query := range []string{"?after=abc", "?after=-1", "?after=", "?after=9223372036854775808"} {
		response := getAudit(t, handler, "org-a", query, testReaderToken)
		if response.Code != http.StatusBadRequest || decodeErrorCode(t, response) != "invalid_cursor" {
			t.Fatalf("query %q status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
}

func TestAuditExportRequiresAuthenticationAndReadRole(t *testing.T) {
	server, _, _ := newTestServer(t)
	if response := getAudit(t, server.Handler(), "org-a", "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d, want %d", response.Code, http.StatusUnauthorized)
	}
	nonReader := newServerWithRole(t, Role("device"))
	response := getAudit(t, nonReader.Handler(), "org-a", "", []byte(nonReaderToken))
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-reader role status=%d, want %d", response.Code, http.StatusForbidden)
	}
}

const nonReaderToken = "synthetic-non-reader-role-token-000000000000000000000000000000"

func newServerWithRole(t *testing.T, role Role) *Server {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(nonReaderToken))
	credentials := &CredentialSet{hashes: [][sha256.Size]byte{digest}, roles: []Role{role}}
	now := time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
	server, err := New(Config{DBPath: filepath.Join(t.TempDir(), "controlplane.db"), Credentials: credentials, PolicyKey: publicKey, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func postAuditEvents(t *testing.T, handler http.Handler, org string, now time.Time, sandboxIDs ...string) {
	t.Helper()
	lines := make([]string, 0, len(sandboxIDs))
	for _, sandboxID := range sandboxIDs {
		event := AuditEvent{
			OccurredAt: now, SandboxID: sandboxID, OperationID: "op-" + sandboxID,
			Action: "network.connect", Resource: "network", Decision: "allow",
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(encoded))
	}
	response := requestWithRawBody(t, handler, http.MethodPost, "/v1/orgs/"+org+"/audit", strings.Join(lines, "\n"), testAdminToken)
	if response.Code != http.StatusAccepted {
		t.Fatalf("seed audit status=%d body=%s", response.Code, response.Body.String())
	}
}

func requestWithRawBody(t *testing.T, handler http.Handler, method, path, body string, token []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != nil {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func getAudit(t *testing.T, handler http.Handler, org, query string, token []byte) *httptest.ResponseRecorder {
	t.Helper()
	return requestWithToken(t, handler, http.MethodGet, "/v1/orgs/"+org+"/audit"+query, nil, token)
}

func decodeAuditPage(t *testing.T, response *httptest.ResponseRecorder) AuditPage {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("audit export status=%d body=%s", response.Code, response.Body.String())
	}
	var page AuditPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func decodeErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", response.Body.String(), err)
	}
	return body.Code
}
