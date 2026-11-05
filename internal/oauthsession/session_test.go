package oauthsession

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"sync"
	"testing"
)

func TestAuthorizationAndCallback(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.AuthorizationURL("https://identity.example/authorize", "synthetic-client", "http://127.0.0.1:12345/callback", []string{"openid", "profile"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	hash := sha256.Sum256([]byte(s.Verifier()))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "openid profile" {
		t.Fatal("incorrect authorization parameters")
	}
	code, err := s.ValidateCallback(url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}})
	if err != nil || code != "synthetic-code" {
		t.Fatalf("valid callback: %q %v", code, err)
	}
	if _, err := s.ValidateCallback(url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}}); err == nil {
		t.Fatal("callback replay accepted")
	}
	for _, callback := range []url.Values{
		{"state": {"wrong"}, "code": {"code"}},
		{"state": {q.Get("state"), q.Get("state")}, "code": {"code"}},
		{"state": {q.Get("state")}, "code": {"one", "two"}},
		{"state": {q.Get("state")}, "code": {"code"}, "error": {"access_denied"}},
	} {
		if _, err := s.ValidateCallback(callback); err == nil {
			t.Fatal("invalid callback accepted")
		}
	}
}

func TestCallbackConcurrentReplay(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizationURL("https://identity.example/authorize", "client", "http://127.0.0.1:12345/callback", nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			_, err := s.ValidateCallback(url.Values{"state": {s.state}, "code": {"synthetic-code"}})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful callbacks = %d, want 1", success)
	}
}

func TestAuthorizationRejectsUnsafeEndpoints(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ endpoint, redirect string }{
		{"http://identity.example/authorize", "http://127.0.0.1:12345/callback"},
		{"https://identity.example/authorize?state=attacker", "http://127.0.0.1:12345/callback"},
		{"https://identity.example/authorize", "http://0.0.0.0:12345/callback"},
		{"https://identity.example/authorize", "http://localhost:12345/callback"},
		{"https://identity.example/authorize", "http://127.0.0.1/callback"},
	} {
		if _, err := s.AuthorizationURL(tc.endpoint, "client", tc.redirect, nil); err == nil {
			t.Fatalf("accepted %q %q", tc.endpoint, tc.redirect)
		}
	}
	if _, err := s.AuthorizationURL("https://identity.example/authorize", "client", "http://[::1]:12345/callback", nil); err != nil {
		t.Fatalf("valid IPv6 loopback: %v", err)
	}
}

func TestAuthorizationRejectsProviderParamsThatOverridePKCEFields(t *testing.T) {
	for _, extra := range []map[string]string{
		{"state": "attacker"},
		{"redirect_uri": "http://attacker.invalid/"},
		{"originator": "unsafe\r\nHeader: value"},
		{"bad key": "value"},
	} {
		session, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.AuthorizationURLWithParams("https://identity.example/authorize", "client", "http://127.0.0.1:12345/callback", nil, extra); err == nil {
			t.Fatalf("accepted unsafe provider authorization parameters: %#v", extra)
		}
	}
}
