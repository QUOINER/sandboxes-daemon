//go:build !windows

package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCredentialFileAcceptsRoleScopedTokens(t *testing.T) {
	raw := fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q},{"name":"audit","role":"reader","token":%q}]}`, testAdminToken, testReaderToken)
	credentials, err := ParseCredentials([]byte(raw))
	if err != nil {
		t.Fatalf("parse valid credentials: %v", err)
	}
	if role, ok := credentials.Authenticate(string(testAdminToken)); !ok || role != RoleAdmin {
		t.Fatalf("admin token role=%q ok=%v", role, ok)
	}
	if role, ok := credentials.Authenticate(string(testReaderToken)); !ok || role != RoleReader {
		t.Fatalf("reader token role=%q ok=%v", role, ok)
	}
	for name, token := range map[string]string{
		"unknown": "synthetic-unknown-token-000000000000000000000000000000000000",
		"empty":   "",
		"prefix":  string(testAdminToken[:len(testAdminToken)-1]),
	} {
		if _, ok := credentials.Authenticate(token); ok {
			t.Fatalf("%s token was accepted", name)
		}
	}
}

func TestCredentialFileRejectsMalformedInput(t *testing.T) {
	shortToken := strings.Repeat("s", minCredentialTokenBytes-1)
	admin := string(testAdminToken)
	reader := string(testReaderToken)
	cases := map[string]string{
		"empty file":            "",
		"invalid json":          `{`,
		"missing credentials":   `{}`,
		"empty credentials":     `{"credentials":[]}`,
		"unknown field":         fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q}],"extra":true}`, admin),
		"unknown role":          fmt.Sprintf(`{"credentials":[{"name":"ops","role":"owner","token":%q}]}`, admin),
		"empty role":            fmt.Sprintf(`{"credentials":[{"name":"ops","role":"","token":%q}]}`, admin),
		"malformed name":        fmt.Sprintf(`{"credentials":[{"name":"bad name","role":"admin","token":%q}]}`, admin),
		"empty name":            fmt.Sprintf(`{"credentials":[{"name":"","role":"admin","token":%q}]}`, admin),
		"short token":           fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q}]}`, shortToken),
		"duplicate name":        fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q},{"name":"ops","role":"reader","token":%q}]}`, admin, reader),
		"duplicate token":       fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q},{"name":"audit","role":"reader","token":%q}]}`, admin, admin),
		"duplicate json member": fmt.Sprintf(`{"credentials":[{"name":"ops","role":"admin","token":%q}],"credentials":[]}`, admin),
		"credentials not array": `{"credentials":{"name":"ops"}}`,
		"token not string":      `{"credentials":[{"name":"ops","role":"admin","token":42}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if credentials, err := ParseCredentials([]byte(raw)); err == nil {
				t.Fatalf("malformed credential file was accepted: %+v", credentials)
			}
		})
	}
}

func TestCredentialSetRequiresUniqueRoleScopedEntries(t *testing.T) {
	cases := map[string][]Credential{
		"nil":              nil,
		"empty":            {},
		"unknown role":     {{Name: "ops", Role: "owner", Token: string(testAdminToken)}},
		"short token":      {{Name: "ops", Role: RoleAdmin, Token: "short"}},
		"duplicate names":  {{Name: "ops", Role: RoleAdmin, Token: string(testAdminToken)}, {Name: "ops", Role: RoleReader, Token: string(testReaderToken)}},
		"duplicate tokens": {{Name: "ops", Role: RoleAdmin, Token: string(testAdminToken)}, {Name: "audit", Role: RoleReader, Token: string(testAdminToken)}},
	}
	for name, credentials := range cases {
		t.Run(name, func(t *testing.T) {
			if set, err := NewCredentialSet(credentials); err == nil {
				t.Fatalf("invalid credential set was accepted: %+v", set)
			}
		})
	}
}

func TestRoleScopedAuthorization(t *testing.T) {
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
	if response := requestWithToken(t, handler, http.MethodPut, "/v1/orgs/example-org/policy", bundle, testAdminToken); response.Code != http.StatusCreated {
		t.Fatalf("admin publish status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestWithToken(t, handler, http.MethodGet, "/v1/orgs/example-org/policy", nil, testReaderToken); response.Code != http.StatusOK {
		t.Fatalf("reader policy read status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestWithToken(t, handler, http.MethodPut, "/v1/orgs/example-org/policy", bundle, testReaderToken); response.Code != http.StatusForbidden {
		t.Fatalf("reader publish status=%d, want %d", response.Code, http.StatusForbidden)
	}
	auditBatch := `{"occurredAt":"` + now.Format(time.RFC3339Nano) + `","sandboxId":"sbx_123","operationId":"op_123","action":"network.connect","resource":"network","decision":"allow"}`
	if response := requestWithToken(t, handler, http.MethodPost, "/v1/orgs/example-org/audit", rawJSON(auditBatch), testReaderToken); response.Code != http.StatusForbidden {
		t.Fatalf("reader audit ingest status=%d, want %d", response.Code, http.StatusForbidden)
	}
	if response := requestWithToken(t, handler, http.MethodPost, "/v1/orgs/example-org/audit", rawJSON(auditBatch), testAdminToken); response.Code != http.StatusAccepted {
		t.Fatalf("admin audit ingest status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUnauthenticatedAndUnknownCredentialsAreRejected(t *testing.T) {
	server, _, _ := newTestServer(t)
	cases := map[string]string{
		"missing header": "",
		"unknown token":  "Bearer synthetic-unknown-token-000000000000000000000000000000000000",
		"empty token":    "Bearer ",
		"wrong scheme":   "Basic " + string(testAdminToken),
		"no scheme":      string(testAdminToken),
		"whitespace":     "Bearer " + string(testAdminToken) + " ",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/orgs/example-org/policy", nil)
			if header != "" {
				request.Header.Set("Authorization", header)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want %d", response.Code, http.StatusUnauthorized)
			}
			if response.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("401 response is missing WWW-Authenticate")
			}
		})
	}
}

// rawJSON marks a pre-encoded JSON body so request helpers do not re-encode it.
func rawJSON(raw string) json.RawMessage { return json.RawMessage(raw) }
