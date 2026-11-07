package servicesecrets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateSourceRequiresExactlyOneSource(t *testing.T) {
	for name, source := range map[string]Source{
		"empty":                 {},
		"blank command":         {Command: " \t "},
		"reference and command": {Reference: "op://Work/Item/credential", Command: "gh auth token"},
		"profile on command":    {Command: "gh auth token", AWSProfile: "work"},
		"invalid refresh":       {Command: "gh auth token", Refresh: "0s"},
		"verification conflict": {Command: "gh auth token", NoVerify: true, ShowError: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSource(source); err == nil {
				t.Fatalf("validateSource(%+v) unexpectedly succeeded", source)
			}
		})
	}
}

func TestReferenceSourceCapturesProviderSelection(t *testing.T) {
	got, err := validateSource(Source{
		Reference: "op://Work/Anthropic/credential",
		OPAccount: "work-account",
		Refresh:   "on-demand",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Refresh != "on-demand" || got.OPAccount != "work-account" {
		t.Fatalf("normalized source = %+v", got)
	}
	if _, err := validateSource(Source{
		Reference: "arn:aws:secretsmanager:us-west-2:123456789012:secret:synthetic",
		OPAccount: "wrong-provider",
	}); err == nil {
		t.Fatal("accepted a 1Password account selector for an AWS reference")
	}
}

func TestCommandSourceIsStoredAndResolvedOnHost(t *testing.T) {
	backend := &fakeBackend{items: make(map[string]string)}
	store, err := NewStore(NativeVault{Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Command: testPrintCommand(), NoVerify: true, Refresh: "on-demand"}
	if _, err := store.SaveSource(context.Background(), "github", ScopeGlobal, "", source); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Load(context.Background(), "github", ScopeGlobal, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, dynamic, err := decodeSource(stored)
	if err != nil || !dynamic || decoded.Command != source.Command {
		t.Fatalf("stored source = %+v dynamic=%v err=%v", decoded, dynamic, err)
	}
	clear(stored)
	value, err := store.Resolve(context.Background(), "github", ScopeGlobal, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "synthetic-value" {
		t.Fatalf("resolved value = %q", value)
	}
}

func TestCommandSourceHidesProviderErrorsUnlessRequested(t *testing.T) {
	for i := range 20 {
		_, err := resolveSource(context.Background(), Source{Command: testFailCommand()})
		if err == nil || strings.Contains(err.Error(), "synthetic-provider-error") {
			t.Fatalf("iteration %d default error = %v, want generic error without provider output", i, err)
		}
		_, err = resolveSource(context.Background(), Source{Command: testFailCommand(), ShowError: true})
		if err == nil || !strings.Contains(err.Error(), "synthetic-provider-error") {
			t.Fatalf("iteration %d show-error result = %v, want explicit provider stderr", i, err)
		}
	}
}

func TestBoundedCommandCaptureEnforcesLimit(t *testing.T) {
	var signals int
	capture := &boundedCommandCapture{
		limit: 4,
		signalLimit: func() {
			signals++
		},
	}
	if n, err := capture.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatalf("write at limit = (%d, %v), want (4, nil)", n, err)
	}
	if n, err := capture.Write([]byte("5")); n != 0 || !errors.Is(err, errResolverOutputLimit) {
		t.Fatalf("write beyond limit = (%d, %v), want (0, output limit)", n, err)
	}
	if n, err := capture.Write([]byte("6")); n != 0 || !errors.Is(err, errResolverOutputLimit) {
		t.Fatalf("write after limit = (%d, %v), want (0, output limit)", n, err)
	}
	data, exceeded := capture.take()
	if string(data) != "1234" || !exceeded {
		t.Fatalf("captured data = %q, exceeded = %v; want bounded prefix and exceeded", data, exceeded)
	}
	if signals != 1 {
		t.Fatalf("limit signal count = %d, want 1", signals)
	}
	clear(data)
}

func TestBoundedCommandCaptureTruncatesOverflowingWrite(t *testing.T) {
	capture := &boundedCommandCapture{limit: 4}
	if n, err := capture.Write([]byte("12345")); n != 4 || !errors.Is(err, errResolverOutputLimit) {
		t.Fatalf("overflowing write = (%d, %v), want (4, output limit)", n, err)
	}
	data, exceeded := capture.take()
	if string(data) != "1234" || !exceeded {
		t.Fatalf("captured data = %q, exceeded = %v; want bounded prefix and exceeded", data, exceeded)
	}
	clear(data)
}

func TestCommandSourceCancellationCleansUpProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := resolveSource(ctx, Source{Command: testWaitCommand()})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolveSource error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("resolver did not terminate promptly after cancellation: %s", elapsed)
	}
}

func TestSourceResolverCacheModesAndInvalidation(t *testing.T) {
	resolver := newSourceResolver()
	key := "github/global"
	source := Source{Command: testFailCommand()}
	cacheKey, err := sourceCacheKey(key, source)
	if err != nil {
		t.Fatal(err)
	}
	resolver.cache(cacheKey, []byte("cached-value"), time.Now().Add(time.Minute))
	value, err := resolver.resolve(context.Background(), key, source)
	if err != nil || string(value) != "cached-value" {
		t.Fatalf("cache hit value=%q err=%v", value, err)
	}
	clear(value)

	onDemandKey := "github/on-demand"
	value, err = resolver.resolve(context.Background(), onDemandKey, Source{Command: testPrintCommand(), Refresh: "on-demand"})
	if err != nil || string(value) != "synthetic-value" {
		t.Fatalf("on-demand value=%q err=%v", value, err)
	}
	clear(value)
	resolver.mu.Lock()
	if len(resolver.entries) != 1 {
		resolver.mu.Unlock()
		t.Fatalf("on-demand resolution unexpectedly populated cache: %d entries", len(resolver.entries))
	}
	resolver.mu.Unlock()

	resolver.invalidate(key)
	resolver.invalidate(onDemandKey)
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if len(resolver.entries) != 0 {
		t.Fatalf("invalidate left %d cache entries", len(resolver.entries))
	}
}

func TestSourceCacheDoesNotReuseCredentialAfterSourceChanges(t *testing.T) {
	resolver := newSourceResolver()
	account := "github/global"
	oldSource := Source{Command: "old-source", Refresh: "55m"}
	oldKey, err := sourceCacheKey(account, oldSource)
	if err != nil {
		t.Fatal(err)
	}
	resolver.cache(oldKey, []byte("old-synthetic-token"), time.Now().Add(time.Hour))

	newSource := Source{Command: testPrintCommand(), Refresh: "55m"}
	value, err := resolver.resolve(context.Background(), account, newSource)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "synthetic-value" {
		t.Fatalf("new source resolved to %q; old-source cache was reused", value)
	}

	resolver.invalidate(account)
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if len(resolver.entries) != 0 {
		t.Fatalf("source rotation invalidation left %d cached credentials", len(resolver.entries))
	}
}

func FuzzDecodeSecretSource(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(secretSourcePrefix + `{}`))
	f.Add([]byte(secretSourcePrefix + `{"reference":"op://Work/Item/key","refresh":"55m"}`))
	f.Add([]byte(secretSourcePrefix + `not-json`))
	f.Fuzz(func(t *testing.T, value []byte) {
		decoded, dynamic, err := decodeSource(value)
		if dynamic && err == nil {
			if _, validateErr := validateSource(decoded); validateErr != nil {
				t.Fatalf("decoded invalid source without error: %+v", decoded)
			}
		}
	})
}

func FuzzValidateSourceReference(f *testing.F) {
	f.Add("op://Work/Item/key")
	f.Add("arn:aws:secretsmanager:us-west-2:123456789012:secret:synthetic")
	f.Add("not-a-reference")
	f.Fuzz(func(t *testing.T, reference string) {
		_, _ = validateSource(Source{Reference: reference})
	})
}
