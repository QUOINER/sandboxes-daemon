package oauthsession

import "github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"

// NewNativeVaultSink binds OAuth storage to the OS credential vault. It does
// not perform I/O until the returned sink is used and never falls back to a file.
func NewNativeVaultSink(provider string) (*VaultSink, error) {
	return NewVaultSink(registrycredentials.NativeVault{}, provider)
}
