package oauthsession

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
)

const oauthVaultService = "com.klorq.oauth.v1"

var ErrNoTokens = errors.New("OAuth tokens are not stored")
var ErrNoCredentialFingerprint = errors.New("OAuth credential fingerprint is not stored")

// Vault is the host credential store. No file fallback is provided here.
type Vault interface {
	Set(context.Context, string, string, string) error
	Get(context.Context, string, string) (string, error)
	Delete(context.Context, string, string) error
}

// VaultSink stores a single host-selected provider's token record.
type VaultSink struct {
	vault   Vault
	account string
}

type tokenRecord struct {
	Tokens    Tokens    `json:"tokens"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewVaultSink binds storage to a trusted host-selected provider identifier.
func NewVaultSink(vault Vault, provider string) (*VaultSink, error) {
	if vault == nil || provider == "" || len(provider) > 128 || strings.ContainsAny(provider, "\x00\r\n/\\") {
		return nil, errors.New("invalid OAuth vault configuration")
	}
	return &VaultSink{vault: vault, account: provider}, nil
}

// Save stores a token record as one keychain item.
func (s *VaultSink) Save(ctx context.Context, tokens Tokens) error {
	if tokens.AccessToken == "" || !strings.EqualFold(tokens.TokenType, "bearer") || tokens.ExpiresIn < 0 || tokens.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return errors.New("invalid OAuth tokens")
	}
	record := tokenRecord{Tokens: tokens}
	if tokens.ExpiresIn > 0 {
		record.ExpiresAt = time.Now().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return errors.New("encode OAuth tokens failed")
	}
	defer clear(payload)
	if err := s.vault.Set(ctx, oauthVaultService, s.account, string(payload)); err != nil {
		return errors.New("store OAuth tokens failed")
	}
	return nil
}

// Load retrieves the exact record from the host vault.
func (s *VaultSink) Load(ctx context.Context) (Tokens, time.Time, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account)
	if err != nil {
		if errors.Is(err, registrycredentials.ErrNotFound) {
			return Tokens{}, time.Time{}, ErrNoTokens
		}
		return Tokens{}, time.Time{}, errors.New("read OAuth tokens failed")
	}
	var record tokenRecord
	if json.Unmarshal([]byte(value), &record) != nil || record.Tokens.AccessToken == "" || !strings.EqualFold(record.Tokens.TokenType, "bearer") {
		return Tokens{}, time.Time{}, errors.New("invalid stored OAuth tokens")
	}
	return record.Tokens, record.ExpiresAt, nil
}

// Delete removes only this provider's vault record.
func (s *VaultSink) Delete(ctx context.Context) error {
	if err := s.vault.Delete(ctx, oauthVaultService, s.account); err != nil {
		return errors.New("delete OAuth tokens failed")
	}
	return nil
}

// SaveDockerHubPATFingerprint records ownership metadata for the PAT created
// by this OAuth session. The fingerprint is not sufficient to authenticate.
func (s *VaultSink) SaveDockerHubPATFingerprint(ctx context.Context, fingerprint string) error {
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid OAuth credential fingerprint")
	}
	clear(decoded)
	if err := s.vault.Set(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256", fingerprint); err != nil {
		return errors.New("store OAuth credential ownership failed")
	}
	return nil
}

// DockerHubPATFingerprint retrieves local ownership metadata for cleanup.
func (s *VaultSink) DockerHubPATFingerprint(ctx context.Context) (string, error) {
	value, err := s.vault.Get(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return "", ErrNoCredentialFingerprint
	}
	if err != nil {
		return "", errors.New("read OAuth credential ownership failed")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return "", errors.New("invalid OAuth credential ownership record")
	}
	clear(decoded)
	return value, nil
}

// DeleteDockerHubPATFingerprint clears only this provider's ownership marker.
func (s *VaultSink) DeleteDockerHubPATFingerprint(ctx context.Context) error {
	err := s.vault.Delete(ctx, oauthVaultService, s.account+":docker-hub-pat-sha256")
	if errors.Is(err, registrycredentials.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.New("delete OAuth credential ownership failed")
	}
	return nil
}
