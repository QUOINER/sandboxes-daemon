//go:build !windows

package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOIDCIssuer   = "https://issuer.example.test"
	testOIDCAudience = "rheic-control-plane"
)

type mockIDP struct {
	server *httptest.Server
	mu     sync.Mutex
	body   []byte
	fail   bool
	hits   int
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	idp := &mockIDP{}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.hits++
		if idp.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(idp.body)
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func (m *mockIDP) setKeys(t *testing.T, document jwksDocument) {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = encoded
}

func (m *mockIDP) setFailure(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

func (m *mockIDP) missCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits
}

type oidcFixture struct {
	idp    *mockIDP
	rsaKey *rsa.PrivateKey
	edKey  ed25519.PrivateKey
	now    time.Time
	config OIDCConfig
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := newMockIDP(t)
	fixture := &oidcFixture{
		idp: idp, rsaKey: rsaKey, edKey: edPrivate,
		now: time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC),
	}
	fixture.config = OIDCConfig{
		Issuer: testOIDCIssuer, Audience: testOIDCAudience, JWKSURL: idp.server.URL + "/jwks",
		HTTPClient: idp.server.Client(), Clock: func() time.Time { return fixture.now },
		RefreshInterval: time.Minute, MaxCacheAge: 5 * time.Minute, MinRefreshInterval: time.Second,
	}
	idp.setKeys(t, jwksDocument{Keys: []jwkKey{
		rsaJWK(rsaKey.Public().(*rsa.PublicKey), "rsa-1"),
		okpJWK(edPublic, "ed-1"),
	}})
	return fixture
}

func (f *oidcFixture) claims() map[string]any {
	return map[string]any{
		"iss": testOIDCIssuer, "aud": []string{testOIDCAudience}, "sub": "user-1",
		"exp": f.now.Add(time.Hour).Unix(), "nbf": f.now.Add(-time.Minute).Unix(),
		"org": "org-a", "role": "reader",
	}
}

func (f *oidcFixture) validator(t *testing.T) *OIDCValidator {
	t.Helper()
	validator, err := NewOIDCValidator(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func rsaJWK(key *rsa.PublicKey, kid string) jwkKey {
	return jwkKey{
		KeyType: "RSA", KeyID: kid, Use: "sig", Algorithm: "RS256",
		Modulus:  base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func okpJWK(key ed25519.PublicKey, kid string) jwkKey {
	return jwkKey{KeyType: "OKP", KeyID: kid, Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(key)}
}

func encodeJWTPart(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := encodeJWTPart(t, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload := encodeJWTPart(t, claims)
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signEdDSA(t *testing.T, key ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := encodeJWTPart(t, map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	payload := encodeJWTPart(t, claims)
	signingInput := header + "." + payload
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signingInput)))
}

func TestOIDCValidTokensMapOrgAndRole(t *testing.T) {
	fixture := newOIDCFixture(t)
	validator := fixture.validator(t)
	for name, token := range map[string]string{
		"rs256": signRS256(t, fixture.rsaKey, "rsa-1", fixture.claims()),
		"eddsa": signEdDSA(t, fixture.edKey, "ed-1", fixture.claims()),
	} {
		t.Run(name, func(t *testing.T) {
			principal, err := validator.Authenticate(context.Background(), token)
			if err != nil {
				t.Fatalf("valid token rejected: %v", err)
			}
			if principal.Role != RoleReader || principal.Org != "org-a" || principal.Subject != "user-1" {
				t.Fatalf("principal=%+v", principal)
			}
		})
	}
}

func TestOIDCRejectsInvalidClaimsAndKeys(t *testing.T) {
	fixture := newOIDCFixture(t)
	validator := fixture.validator(t)
	cases := map[string]struct {
		kid    string
		mutate func(map[string]any)
	}{
		"expired":         {"rsa-1", func(claims map[string]any) { claims["exp"] = fixture.now.Add(-time.Hour).Unix() }},
		"wrong audience":  {"rsa-1", func(claims map[string]any) { claims["aud"] = "other-service" }},
		"wrong issuer":    {"rsa-1", func(claims map[string]any) { claims["iss"] = "https://attacker.example.test" }},
		"not yet valid":   {"rsa-1", func(claims map[string]any) { claims["nbf"] = fixture.now.Add(time.Hour).Unix() }},
		"missing expiry":  {"rsa-1", func(claims map[string]any) { delete(claims, "exp") }},
		"missing org":     {"rsa-1", func(claims map[string]any) { delete(claims, "org") }},
		"malformed org":   {"rsa-1", func(claims map[string]any) { claims["org"] = "../other" }},
		"unknown role":    {"rsa-1", func(claims map[string]any) { claims["role"] = "owner" }},
		"missing subject": {"rsa-1", func(claims map[string]any) { delete(claims, "sub") }},
		"unknown kid":     {"missing-kid", func(map[string]any) {}},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			claims := fixture.claims()
			testCase.mutate(claims)
			token := signRS256(t, fixture.rsaKey, testCase.kid, claims)
			principal, err := validator.Authenticate(context.Background(), token)
			if err == nil {
				t.Fatalf("invalid token accepted: %+v", principal)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatal("validation error contains the token")
			}
		})
	}
}

func TestOIDCRejectsUnsignedAndSymmetricAlgorithms(t *testing.T) {
	fixture := newOIDCFixture(t)
	validator := fixture.validator(t)
	unsigned := encodeJWTPart(t, map[string]any{"alg": "none", "kid": "rsa-1"}) + "." + encodeJWTPart(t, fixture.claims()) + "."
	symmetricHeader := encodeJWTPart(t, map[string]any{"alg": "HS256", "kid": "rsa-1"})
	symmetricPayload := encodeJWTPart(t, fixture.claims())
	symmetric := symmetricHeader + "." + symmetricPayload + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-real-hmac"))
	for name, token := range map[string]string{"none": unsigned, "hs256": symmetric} {
		t.Run(name, func(t *testing.T) {
			if _, err := validator.Authenticate(context.Background(), token); err == nil {
				t.Fatal("token with a non-asymmetric algorithm was accepted")
			}
		})
	}
}

func TestOIDCRefreshesJWKSForNewKid(t *testing.T) {
	fixture := newOIDCFixture(t)
	validator := fixture.validator(t)
	if _, err := validator.Authenticate(context.Background(), signRS256(t, fixture.rsaKey, "rsa-1", fixture.claims())); err != nil {
		t.Fatalf("initial token rejected: %v", err)
	}
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.idp.setKeys(t, jwksDocument{Keys: []jwkKey{
		rsaJWK(fixture.rsaKey.Public().(*rsa.PublicKey), "rsa-1"),
		rsaJWK(secondKey.Public().(*rsa.PublicKey), "rsa-2"),
	}})
	fixture.now = fixture.now.Add(2 * time.Second)
	if _, err := validator.Authenticate(context.Background(), signRS256(t, secondKey, "rsa-2", fixture.claims())); err != nil {
		t.Fatalf("rotated key was not refreshed: %v", err)
	}
	if fixture.idp.missCount() < 2 {
		t.Fatalf("JWKS was fetched %d times, want at least 2", fixture.idp.missCount())
	}
}

func TestOIDCRejectsStaleKeyCacheWhenRefreshFails(t *testing.T) {
	fixture := newOIDCFixture(t)
	validator := fixture.validator(t)
	token := signRS256(t, fixture.rsaKey, "rsa-1", fixture.claims())
	if _, err := validator.Authenticate(context.Background(), token); err != nil {
		t.Fatalf("initial token rejected: %v", err)
	}
	fixture.idp.setFailure(true)
	fixture.now = fixture.now.Add(10 * time.Minute)
	if _, err := validator.Authenticate(context.Background(), token); err == nil {
		t.Fatal("stale JWKS was accepted after refresh failure")
	}
	fixture.idp.setFailure(false)
	fixture.now = fixture.now.Add(2 * time.Second)
	if _, err := validator.Authenticate(context.Background(), token); err != nil {
		t.Fatalf("recovered JWKS was rejected: %v", err)
	}
}

func TestOIDCConfigValidationFailsClosed(t *testing.T) {
	base := OIDCConfig{Issuer: testOIDCIssuer, Audience: testOIDCAudience, JWKSURL: "https://issuer.example.test/jwks"}
	cases := map[string]OIDCConfig{
		"missing issuer":   {Audience: base.Audience, JWKSURL: base.JWKSURL},
		"missing audience": {Issuer: base.Issuer, JWKSURL: base.JWKSURL},
		"missing jwks":     {Issuer: base.Issuer, Audience: base.Audience},
		"http issuer":      {Issuer: "http://issuer.example.test", Audience: base.Audience, JWKSURL: base.JWKSURL},
		"http jwks":        {Issuer: base.Issuer, Audience: base.Audience, JWKSURL: "http://issuer.example.test/jwks"},
		"negative leeway":  {Issuer: base.Issuer, Audience: base.Audience, JWKSURL: base.JWKSURL, Leeway: -time.Second},
		"inconsistent cache": {
			Issuer: base.Issuer, Audience: base.Audience, JWKSURL: base.JWKSURL,
			RefreshInterval: 10 * time.Minute, MaxCacheAge: time.Minute, MinRefreshInterval: time.Second,
		},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOIDCValidator(config); err == nil {
				t.Fatal("invalid OIDC configuration was accepted")
			}
		})
	}
}

func TestOIDCTokenAuthorizesOrgScopedRequests(t *testing.T) {
	fixture := newOIDCFixture(t)
	server, policyPrivateKey := fixture.newServer(t)
	handler := server.Handler()
	now := fixture.now
	published := PolicyPayload{
		SchemaVersion: 1, OrgID: "org-a", Revision: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Rules: []PolicyRule{{Resource: "network:api.example.test:443", Action: "allow", RuleID: "r1"}},
	}
	if response := requestWithToken(t, handler, http.MethodPut, "/v1/orgs/org-a/policy", signedBundle(t, published, policyPrivateKey), testAdminToken); response.Code != http.StatusCreated {
		t.Fatalf("static admin publish status=%d body=%s", response.Code, response.Body.String())
	}
	adminClaims := fixture.claims()
	adminClaims["role"] = "admin"
	adminToken := []byte(signRS256(t, fixture.rsaKey, "rsa-1", adminClaims))
	if response := requestWithToken(t, handler, http.MethodGet, "/v1/orgs/org-a/policy", nil, adminToken); response.Code != http.StatusOK {
		t.Fatalf("OIDC admin read status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestWithToken(t, handler, http.MethodGet, "/v1/orgs/org-b/policy", nil, adminToken); response.Code != http.StatusForbidden {
		t.Fatalf("cross-org OIDC read status=%d, want %d", response.Code, http.StatusForbidden)
	}
	readerToken := []byte(signRS256(t, fixture.rsaKey, "rsa-1", fixture.claims()))
	if response := requestWithToken(t, handler, http.MethodPut, "/v1/orgs/org-a/policy", signedBundle(t, published, policyPrivateKey), readerToken); response.Code != http.StatusForbidden {
		t.Fatalf("OIDC reader publish status=%d, want %d", response.Code, http.StatusForbidden)
	}
	if response := requestWithToken(t, handler, http.MethodGet, "/v1/orgs/org-a/policy", nil, readerToken); response.Code != http.StatusOK {
		t.Fatalf("OIDC reader policy read status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestWithToken(t, handler, http.MethodGet, "/v1/orgs/org-a/policy", nil, []byte("tampered.invalid.token")); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid JWT status=%d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestOIDCTokenIsNotLogged(t *testing.T) {
	fixture := newOIDCFixture(t)
	server, _ := fixture.newServer(t)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	token := "header.payload.invalidsignature"
	request := httptest.NewRequest(http.MethodGet, "/v1/orgs/org-a/policy", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("token was written to logs")
	}
}

func (f *oidcFixture) newServer(t *testing.T) (*Server, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	server, err := New(Config{
		DBPath: filepath.Join(t.TempDir(), "controlplane.db"), Credentials: testCredentials(t),
		PolicyKey: publicKey, OIDC: &config, Clock: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, privateKey
}
