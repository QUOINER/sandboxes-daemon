package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	core "github.com/rheic/sandboxes-core"
	"github.com/rheic/sandboxes-core/sandbox"
	gatewaypolicy "github.com/rheic/sandboxes-gateway/policy"
	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
	"github.com/rheic/sandboxes-daemon/internal/orgpolicy"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

var orgPolicyTestNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func orgPolicySigningKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x5a
	}
	return ed25519.NewKeyFromSeed(seed)
}

// signedBundle builds a synthetic bundle using the same canonical encoding the
// control plane and policy sync client use. The daemon never re-fetches it.
func signedBundle(t *testing.T, payload controlplane.PolicyPayload) store.StoredPolicyBundle {
	t.Helper()
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		t.Fatalf("canonical policy encoding: %v", err)
	}
	signature := ed25519.Sign(orgPolicySigningKey(), canonical)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return store.StoredPolicyBundle{
		OrgID:     payload.OrgID,
		Revision:  payload.Revision,
		Payload:   encoded,
		Signature: base64.StdEncoding.EncodeToString(signature),
		IssuedAt:  payload.IssuedAt.UTC(),
		ExpiresAt: payload.ExpiresAt.UTC(),
		SyncedAt:  orgPolicyTestNow,
	}
}

func testPolicyPayload(org string, rules ...controlplane.PolicyRule) controlplane.PolicyPayload {
	return controlplane.PolicyPayload{
		SchemaVersion: 1,
		OrgID:         org,
		Revision:      7,
		IssuedAt:      orgPolicyTestNow.Add(-time.Hour),
		ExpiresAt:     orgPolicyTestNow.Add(time.Hour),
		Rules:         rules,
	}
}

func saveBundle(t *testing.T, st *store.Store, bundle store.StoredPolicyBundle) {
	t.Helper()
	if err := st.SavePolicyBundle(context.Background(), bundle); err != nil {
		t.Fatalf("save synthetic bundle: %v", err)
	}
}

func openOrgPolicyService(t *testing.T, backend runtime.Backend) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "org-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, backend)
	svc.now = func() time.Time { return orgPolicyTestNow }
	return svc, st
}

func enableOrgPolicy(svc *Service, org string) {
	svc.OrgPolicyEnforce = true
	svc.OrgPolicyOrg = org
}

func TestOrgPolicyEnforcementRequiresStoredBundle(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{}
	svc, _ := openOrgPolicyService(t, backend)
	enableOrgPolicy(svc, "acme")

	if _, err := svc.Create(ctx, CreateRequest{Name: "blocked"}); !errors.Is(err, orgpolicy.ErrBundleMissing) || !errors.Is(err, core.ErrConflict) {
		t.Fatalf("create error = %v; want missing bundle and conflict", err)
	}
	if backend.created != 0 {
		t.Fatalf("create reached runtime without a stored bundle: %d", backend.created)
	}

	// A sandbox created before enforcement was enabled must still fail to start.
	svc.OrgPolicyEnforce = false
	op, err := svc.Create(ctx, CreateRequest{Name: "existing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	enableOrgPolicy(svc, "acme")
	if _, err := svc.Start(ctx, op.SandboxID); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("start error = %v; want missing bundle", err)
	}
	if backend.started != 0 {
		t.Fatalf("start reached runtime without a stored bundle: %d", backend.started)
	}

	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 443}); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("sandbox policy mutation error = %v; want missing bundle", err)
	}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 443}); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("global policy mutation error = %v; want missing bundle", err)
	}
	if _, err := svc.SetPolicyProfile(ctx, "allow-all"); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("profile mutation error = %v; want missing bundle", err)
	}
	if _, err := svc.RefreshPolicies(ctx); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("refresh error = %v; want missing bundle", err)
	}
}

func TestOrgPolicyRejectsExpiredCrossOrgAndInvalidBundles(t *testing.T) {
	ctx := context.Background()
	validRule := controlplane.PolicyRule{Resource: "network:203.0.113.0/24:443", Action: "deny", RuleID: "rule-001"}

	t.Run("expired", func(t *testing.T) {
		svc, st := openOrgPolicyService(t, &fakeRuntime{})
		payload := testPolicyPayload("acme", validRule)
		payload.IssuedAt = orgPolicyTestNow.Add(-2 * time.Hour)
		payload.ExpiresAt = orgPolicyTestNow.Add(-time.Hour)
		saveBundle(t, st, signedBundle(t, payload))
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "expired"}); !errors.Is(err, orgpolicy.ErrBundleExpired) {
			t.Fatalf("create error = %v; want expired bundle", err)
		}
	})

	t.Run("cross org settings", func(t *testing.T) {
		svc, st := openOrgPolicyService(t, &fakeRuntime{})
		saveBundle(t, st, signedBundle(t, testPolicyPayload("other", validRule)))
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "cross-org"}); !errors.Is(err, orgpolicy.ErrBundleMissing) {
			t.Fatalf("create error = %v; want missing bundle for the enforced org", err)
		}
	})

	t.Run("cross org payload", func(t *testing.T) {
		svc, st := openOrgPolicyService(t, &fakeRuntime{})
		bundle := signedBundle(t, testPolicyPayload("other", validRule))
		bundle.OrgID = "acme"
		saveBundle(t, st, bundle)
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "cross-org-payload"}); !errors.Is(err, orgpolicy.ErrBundleOrgMismatch) {
			t.Fatalf("create error = %v; want cross-org mismatch", err)
		}
	})

	t.Run("revision mismatch", func(t *testing.T) {
		svc, st := openOrgPolicyService(t, &fakeRuntime{})
		bundle := signedBundle(t, testPolicyPayload("acme", validRule))
		bundle.Revision = 6
		saveBundle(t, st, bundle)
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "revision"}); !errors.Is(err, orgpolicy.ErrBundleInvalid) {
			t.Fatalf("create error = %v; want invalid bundle", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		svc, st := openOrgPolicyService(t, &fakeRuntime{})
		saveBundle(t, st, store.StoredPolicyBundle{
			OrgID: "acme", Revision: 1, Payload: []byte("not json"), Signature: "synthetic",
			IssuedAt: orgPolicyTestNow.Add(-time.Hour), ExpiresAt: orgPolicyTestNow.Add(time.Hour), SyncedAt: orgPolicyTestNow,
		})
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "invalid-json"}); !errors.Is(err, orgpolicy.ErrBundleInvalid) {
			t.Fatalf("create error = %v; want invalid bundle", err)
		}
	})
}

func TestOrgPolicyDenyBlocksMatchingAllow(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{}
	svc, st := openOrgPolicyService(t, backend)
	rule := controlplane.PolicyRule{Resource: "network:203.0.113.7:443", Action: "deny", RuleID: "rule-001"}
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	enableOrgPolicy(svc, "acme")

	op, err := svc.Create(ctx, CreateRequest{Name: "deny-wins",
		Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "203.0.113.7/32", Port: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Allow) != 1 {
		t.Fatalf("runtime allow = %+v", backend.lastConfig.Allow)
	}
	if len(backend.lastConfig.Deny) != 2 {
		t.Fatalf("runtime deny = %+v; want tcp and udp expansion", backend.lastConfig.Deny)
	}
	for _, deny := range backend.lastConfig.Deny {
		if deny.Port != 443 || deny.CIDR != "203.0.113.7/32" || deny.ID != "rule-001" {
			t.Fatalf("expanded deny = %+v", deny)
		}
	}
	if backend.lastConfig.Deny[0].Protocol != "tcp" || backend.lastConfig.Deny[1].Protocol != "udp" {
		t.Fatalf("protocols = %q/%q", backend.lastConfig.Deny[0].Protocol, backend.lastConfig.Deny[1].Protocol)
	}

	// Start must re-apply the same organization deny from the stored bundle.
	if _, err := svc.Stop(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastHandle.Deny) != 2 || backend.lastHandle.Deny[0].ID != "rule-001" {
		t.Fatalf("start handle deny = %+v", backend.lastHandle.Deny)
	}

	allow := toGatewayTestRules(backend.lastConfig.Allow, gatewaypolicy.Allow)
	deny := toGatewayTestRules(backend.lastConfig.Deny, gatewaypolicy.Deny)
	decision := gatewaypolicy.Check(allow, deny, gatewaypolicy.Request{Protocol: "tcp", Address: "203.0.113.7", Port: 443})
	if decision.Allow || decision.RuleID != "rule-001" {
		t.Fatalf("gateway decision = %+v; want org deny", decision)
	}
	if decision := gatewaypolicy.Check(allow, deny, gatewaypolicy.Request{Protocol: "udp", Address: "203.0.113.7", Port: 443}); decision.Allow {
		t.Fatalf("udp decision = %+v; want org deny", decision)
	}

	// The check path must use the same organization deny.
	policyDecision, err := svc.CheckPolicy(ctx, op.SandboxID, "tcp", "203.0.113.7", "", 443)
	if err != nil || policyDecision.Allowed || policyDecision.RuleID != "rule-001" {
		t.Fatalf("CheckPolicy = %+v, %v", policyDecision, err)
	}
}

func TestOrgPolicyExpandsEveryDenyToTCPAndUDP(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{}
	svc, st := openOrgPolicyService(t, backend)
	rule := controlplane.PolicyRule{Resource: "network:198.51.100.0/24:8443", Action: "deny", RuleID: "rule-001"}
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	enableOrgPolicy(svc, "acme")

	if _, err := svc.Create(ctx, CreateRequest{Name: "expanded"}); err != nil {
		t.Fatal(err)
	}
	protocols := map[string]bool{}
	for _, deny := range backend.lastConfig.Deny {
		protocols[deny.Protocol] = true
	}
	if !protocols["tcp"] || !protocols["udp"] || len(backend.lastConfig.Deny) != 2 {
		t.Fatalf("deny expansion = %+v", backend.lastConfig.Deny)
	}
}

func TestOrgPolicyDomainDenyRequiresQUICCapability(t *testing.T) {
	ctx := context.Background()
	rule := controlplane.PolicyRule{Resource: "network:api.example.test:443", Action: "deny", RuleID: "rule-001"}

	backend := &fakeRuntime{}
	svc, st := openOrgPolicyService(t, backend)
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	enableOrgPolicy(svc, "acme")
	if _, err := svc.Create(ctx, CreateRequest{Name: "domain-no-quic"}); !errors.Is(err, orgpolicy.ErrPolicyConflict) {
		t.Fatalf("create error = %v; want fail-closed conflict without QUIC", err)
	}
	if backend.created != 0 {
		t.Fatal("un-enforceable domain deny reached the runtime")
	}

	svc.QUICEnabled = true
	if _, err := svc.Create(ctx, CreateRequest{Name: "domain-quic"}); err != nil {
		t.Fatalf("create with QUIC capability: %v", err)
	}
	if len(backend.lastConfig.Deny) != 2 || backend.lastConfig.Deny[0].Domain != "api.example.test" || backend.lastConfig.Deny[0].ID != "rule-001" {
		t.Fatalf("domain deny expansion = %+v", backend.lastConfig.Deny)
	}
}

func TestOrgPolicyConflictWithLocalIPAllowFailsClosed(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{}
	svc, st := openOrgPolicyService(t, backend)
	rule := controlplane.PolicyRule{Resource: "network:api.example.test:443", Action: "deny", RuleID: "rule-001"}
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	enableOrgPolicy(svc, "acme")
	svc.QUICEnabled = true

	_, err := svc.Create(ctx, CreateRequest{Name: "conflict",
		Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 443}},
	})
	if !errors.Is(err, orgpolicy.ErrPolicyConflict) || !errors.Is(err, core.ErrConflict) {
		t.Fatalf("create error = %v; want typed policy conflict", err)
	}
	if backend.created != 0 {
		t.Fatal("conflicting policy reached the runtime")
	}
}

func TestOrgPolicyMalformedResourcesFailClosed(t *testing.T) {
	ctx := context.Background()
	for name, resource := range map[string]string{
		"missing port":   "network:api.example.test",
		"empty host":     "network::443",
		"whitespace":     "network:api example.test:443",
		"zero port":      "network:api.example.test:0",
		"port too large": "network:api.example.test:70000",
		"bad cidr":       "network:203.0.113.0/33:443",
		"not network":    "network:api.example.test:443/extra",
	} {
		t.Run(name, func(t *testing.T) {
			svc, st := openOrgPolicyService(t, &fakeRuntime{})
			rule := controlplane.PolicyRule{Resource: resource, Action: "deny", RuleID: "rule-001"}
			saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
			enableOrgPolicy(svc, "acme")
			if _, err := svc.Create(ctx, CreateRequest{Name: "malformed"}); !errors.Is(err, orgpolicy.ErrMalformedDeny) {
				t.Fatalf("create error = %v; want malformed deny", err)
			}
		})
	}

	t.Run("unsupported and advisory rules are ignored", func(t *testing.T) {
		backend := &fakeRuntime{}
		svc, st := openOrgPolicyService(t, backend)
		rules := []controlplane.PolicyRule{
			{Resource: "filesystem:/work", Action: "deny", RuleID: "rule-001"},
			{Resource: "network:bad host:443", Action: "allow", RuleID: "rule-002"},
			{Resource: "network:198.51.100.0/24:8443", Action: "deny", RuleID: "rule-003"},
			{Resource: "mcp:server", Action: "allow", RuleID: "rule-004"},
		}
		saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rules...)))
		enableOrgPolicy(svc, "acme")
		if _, err := svc.Create(ctx, CreateRequest{Name: "mixed"}); err != nil {
			t.Fatalf("create with ignored rules: %v", err)
		}
		if len(backend.lastConfig.Deny) != 2 || backend.lastConfig.Deny[0].ID != "rule-003" {
			t.Fatalf("runtime deny = %+v", backend.lastConfig.Deny)
		}
		if len(backend.lastConfig.Allow) != 0 {
			t.Fatalf("org allow rules granted access: %+v", backend.lastConfig.Allow)
		}
	})
}

func TestOrgPolicyEnforcementOffChangesNothing(t *testing.T) {
	ctx := context.Background()
	backend := &fakeRuntime{}
	svc, _ := openOrgPolicyService(t, backend)
	if svc.OrgPolicyEnforce {
		t.Fatal("enforcement must default off")
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "off",
		Allow: []sandbox.NetworkRule{{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 443}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Deny) != 0 || len(backend.lastConfig.Allow) != 1 {
		t.Fatalf("runtime policy changed with enforcement off: allow=%+v deny=%+v", backend.lastConfig.Allow, backend.lastConfig.Deny)
	}
}

func TestOrgPolicyPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restart.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	rule := controlplane.PolicyRule{Resource: "network:192.0.2.10:443", Action: "deny", RuleID: "rule-001"}
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	backend := &fakeRuntime{}
	svc := New(reopened, backend)
	svc.now = func() time.Time { return orgPolicyTestNow }
	enableOrgPolicy(svc, "acme")
	if _, err := svc.Create(ctx, CreateRequest{Name: "after-restart"}); err != nil {
		t.Fatal(err)
	}
	if len(backend.lastConfig.Deny) != 2 || backend.lastConfig.Deny[0].ID != "rule-001" {
		t.Fatalf("deny after restart = %+v", backend.lastConfig.Deny)
	}
}

func TestOrgPolicyMutatePathsKeepOrganizationDeny(t *testing.T) {
	ctx := context.Background()
	backend := &fakePolicyRuntime{}
	svc, st := openOrgPolicyService(t, backend)
	rule := controlplane.PolicyRule{Resource: "network:203.0.113.0/24:443", Action: "deny", RuleID: "rule-001"}
	saveBundle(t, st, signedBundle(t, testPolicyPayload("acme", rule)))
	enableOrgPolicy(svc, "acme")

	op, err := svc.Create(ctx, CreateRequest{Name: "mutations"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 8443}); err != nil {
		t.Fatal(err)
	}
	if len(backend.deny) != 2 || backend.deny[0].ID != "rule-001" {
		t.Fatalf("sandbox mutation deny = %+v", backend.deny)
	}
	if _, _, err := svc.MutateGlobalPolicy(ctx, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 9443}); err != nil {
		t.Fatal(err)
	}
	if len(backend.deny) != 2 || backend.deny[0].ID != "rule-001" {
		t.Fatalf("global mutation deny = %+v", backend.deny)
	}

	// A later enforcement switch without a stored bundle must block mutations.
	svc.OrgPolicyOrg = "other"
	if _, err := svc.MutatePolicy(ctx, op.SandboxID, "allow", sandbox.NetworkRule{Protocol: "tcp", CIDR: "198.51.100.0/24", Port: 10443}); !errors.Is(err, orgpolicy.ErrBundleMissing) {
		t.Fatalf("mutation error = %v; want missing bundle", err)
	}
}

func toGatewayTestRules(rules []runtime.Rule, action gatewaypolicy.Action) []gatewaypolicy.Rule {
	out := make([]gatewaypolicy.Rule, 0, len(rules))
	for i := range rules {
		out = append(out, gatewaypolicy.Rule{ID: rules[i].ID, Action: action, Protocol: rules[i].Protocol, CIDR: rules[i].CIDR, Domain: rules[i].Domain, Port: rules[i].Port})
	}
	return out
}
