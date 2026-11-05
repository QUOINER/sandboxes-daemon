package oauthsession

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func TestInterceptTokenResponseReplacesGuestTokensAndKeepsHostTokens(t *testing.T) {
	body := []byte(`{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"synthetic-id","expires_in":3600,"scope":"read write","token_type":"Bearer","metadata":{"safe":true}}`)
	filtered, tokens, err := InterceptTokenResponse(body, ResponseFields{}, Sentinels{
		AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-access", "synthetic-refresh", "synthetic-id"} {
		if bytes.Contains(filtered, []byte(secret)) {
			t.Fatalf("guest response leaked %s: %s", secret, filtered)
		}
	}
	for _, expected := range []string{`"access_token":"access-sentinel"`, `"refresh_token":"refresh-sentinel"`, `"metadata":{"safe":true}`} {
		if !bytes.Contains(filtered, []byte(expected)) {
			t.Errorf("sanitized response lacks %s: %s", expected, filtered)
		}
	}
	if tokens.AccessToken != "synthetic-access" || tokens.RefreshToken != "synthetic-refresh" || tokens.IDToken != "synthetic-id" ||
		tokens.ExpiresIn != 3600 || strings.Join(tokens.Scopes, ",") != "read,write" {
		t.Fatalf("host token response fields were not preserved: %#v", tokens)
	}
}

func TestInterceptTokenResponseUsesConfiguredFieldNames(t *testing.T) {
	fields := ResponseFields{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: "ttl", Scope: "permissions", IDToken: "identity"}
	filtered, tokens, err := InterceptTokenResponse([]byte(`{"access":"a","refresh":"r","ttl":12,"permissions":"models:read","identity":"id"}`), fields, Sentinels{
		AccessToken: "a-sentinel", RefreshToken: "r-sentinel",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "a" || tokens.RefreshToken != "r" || tokens.ExpiresIn != 12 || len(tokens.Scopes) != 1 || tokens.Scopes[0] != "models:read" {
		t.Fatalf("configured fields not parsed: %#v", tokens)
	}
	if !bytes.Contains(filtered, []byte(`"access":"a-sentinel"`)) || bytes.Contains(filtered, []byte(`"identity"`)) {
		t.Fatalf("configured token fields not masked: %s", filtered)
	}
}

func TestInterceptTokenResponseRejectsDuplicateMalformedAndOversizedData(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"access_token":"first","access_token":"second"}`),
		[]byte(`{"access_token":"a"} {}`),
		[]byte(`{"access_token":"a","expires_in":-1}`),
		[]byte(`{"access_token":"a","token_type":"MAC"}`),
		bytes.Repeat([]byte("x"), maxInterceptedTokenResponse+1),
	}
	for i, body := range tests {
		if _, _, err := InterceptTokenResponse(body, ResponseFields{}, Sentinels{AccessToken: "a", RefreshToken: "r"}); err == nil {
			t.Errorf("case %d unexpectedly accepted", i)
		}
	}
	if _, _, err := InterceptTokenResponse([]byte(`{"access_token":"a"}`), ResponseFields{Scope: "access_token"}, Sentinels{AccessToken: "a", RefreshToken: "r"}); err == nil {
		t.Fatal("accepted overlapping configured response fields")
	}
}

func TestRestoreRefreshTokenOnlyRewritesConfiguredSentinel(t *testing.T) {
	body := []byte("grant_type=refresh_token&refresh_token=guest-sentinel&client_id=public-client")
	restored, changed, err := RestoreRefreshToken(body, "guest-sentinel", "synthetic-host-refresh")
	if err != nil || !changed {
		t.Fatalf("restore changed=%t err=%v", changed, err)
	}
	values, err := url.ParseQuery(string(restored))
	if err != nil || values.Get("refresh_token") != "synthetic-host-refresh" || values.Get("client_id") != "public-client" {
		t.Fatalf("restored form=%q err=%v", restored, err)
	}
	if bytes.Contains(restored, []byte("guest-sentinel")) || bytes.Contains(body, []byte("synthetic-host-refresh")) {
		t.Fatal("refresh body mutation leaked across buffers")
	}
}

func TestRestoreRefreshTokenRejectsDuplicateAndLeavesNonRefreshGrantAlone(t *testing.T) {
	for _, body := range [][]byte{
		[]byte("grant_type=refresh_token&refresh_token=a&refresh_token=b"),
		[]byte("grant_type=refresh_token&grant_type=authorization_code&refresh_token=a"),
	} {
		if _, _, err := RestoreRefreshToken(body, "sentinel", "host-token"); err == nil {
			t.Errorf("accepted duplicate form fields %q", body)
		}
	}
	body := []byte("grant_type=authorization_code&code=synthetic-code")
	restored, changed, err := RestoreRefreshToken(body, "sentinel", "host-token")
	if err != nil || changed || !bytes.Equal(restored, body) {
		t.Fatalf("non-refresh grant changed=%t body=%q err=%v", changed, restored, err)
	}
}
