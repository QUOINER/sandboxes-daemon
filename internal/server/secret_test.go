package server

import (
	"context"
	"path/filepath"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rheic/sandboxes-daemon/internal/service"
	"github.com/rheic/sandboxes-daemon/internal/servicesecrets"
	"github.com/rheic/sandboxes-daemon/internal/store"
)

type secretTestVault struct{ values map[string]string }

func (v *secretTestVault) Set(_ context.Context, serviceName, account, value string) error {
	v.values[serviceName+"/"+account] = value
	return nil
}

func (v *secretTestVault) Get(_ context.Context, serviceName, account string) (string, error) {
	value, ok := v.values[serviceName+"/"+account]
	if !ok {
		return "", servicesecrets.ErrNotFound
	}
	return value, nil
}

func (v *secretTestVault) Delete(_ context.Context, serviceName, account string) error {
	key := serviceName + "/" + account
	if _, ok := v.values[key]; !ok {
		return servicesecrets.ErrNotFound
	}
	delete(v.values, key)
	return nil
}

func TestSecretCreateReturnsAlreadyExistsWithoutReplacingValue(t *testing.T) {
	ctx := context.Background()
	state, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	svc := service.New(state, nil)
	vault := &secretTestVault{values: make(map[string]string)}
	secretStore, err := servicesecrets.NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetServiceSecretStore(secretStore)
	server := NewSecret(svc)

	first := &localv1.SecretServiceCreateRequest{Service: "openai", Scope: "global", Value: []byte("synthetic-original")}
	if _, err := server.Create(ctx, first); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	second := &localv1.SecretServiceCreateRequest{Service: "openai", Scope: "global", Value: []byte("synthetic-replacement")}
	_, err = server.Create(ctx, second)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate create status=%s err=%v", status.Code(err), err)
	}
	if got := vault.values; len(got) != 1 {
		t.Fatalf("vault entries=%d, want 1", len(got))
	}
	for _, value := range vault.values {
		if value != "synthetic-original" {
			t.Fatalf("duplicate create changed stored value to %q", value)
		}
	}
	if status.Convert(err).Message() != "service secret already exists; pass --force to replace it" {
		t.Fatalf("unexpected duplicate-create error: %v", err)
	}
}
