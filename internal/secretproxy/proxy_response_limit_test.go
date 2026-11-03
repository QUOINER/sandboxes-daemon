package secretproxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestEnforceResponseLimitAllowsResponseAtLimit(t *testing.T) {
	response := &http.Response{ContentLength: maxResponseBody, Body: io.NopCloser(strings.NewReader("ok"))}

	if err := enforceResponseLimit(response); err != nil {
		t.Fatalf("enforce response limit: %v", err)
	}
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read bounded response: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("response = %q, want %q", got, "ok")
	}
}

func TestEnforceResponseLimitRejectsOversizedContentLength(t *testing.T) {
	response := &http.Response{ContentLength: maxResponseBody + 1, Body: io.NopCloser(strings.NewReader("unused"))}

	if err := enforceResponseLimit(response); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("enforce response limit error = %v, want %v", err, errResponseTooLarge)
	}
}

func TestBoundedResponseBodyAllowsPayloadAtLimit(t *testing.T) {
	body := &boundedResponseBody{body: io.NopCloser(strings.NewReader("abc")), remaining: 3}

	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read response at limit: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("response = %q, want %q", got, "abc")
	}
}

func TestBoundedResponseBodyRejectsPayloadOverLimit(t *testing.T) {
	body := &boundedResponseBody{body: io.NopCloser(strings.NewReader("abcd")), remaining: 3}

	got, err := io.ReadAll(body)
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("read error = %v, want %v", err, errResponseTooLarge)
	}
	if string(got) != "abc" {
		t.Fatalf("response bytes before rejection = %q, want %q", got, "abc")
	}
}
