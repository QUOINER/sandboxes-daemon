package controlplane

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
)

// Role is the authorization role granted by a control-plane credential.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleReader Role = "reader"

	minCredentialTokenBytes = 32
	maxCredentialTokenBytes = 4096
	maxCredentials          = 64
	// MaxCredentialFileBytes bounds the protected credentials file read by the
	// server. The parser applies the same bound to callers that pass raw bytes.
	MaxCredentialFileBytes = 64 << 10
)

var credentialNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Credential is one named bearer credential with exactly one role. Token
// values are secret material and are never logged or echoed in errors.
type Credential struct {
	Name  string `json:"name"`
	Role  Role   `json:"role"`
	Token string `json:"token"`
}

type credentialFile struct {
	Credentials []Credential `json:"credentials"`
}

// CredentialSet authenticates bearer tokens against the configured roles. It
// stores only SHA-256 digests of tokens, so token material is retained only for
// as long as the caller keeps the decoded configuration.
type CredentialSet struct {
	hashes [][sha256.Size]byte
	roles  []Role
}

// ParseCredentials decodes and validates the protected role file. The file is a
// strict JSON object with a non-empty "credentials" array; unknown fields,
// duplicate members, empty files and malformed entries are rejected.
func ParseCredentials(raw []byte) (*CredentialSet, error) {
	if len(raw) == 0 {
		return nil, errors.New("credential file is empty")
	}
	if len(raw) > MaxCredentialFileBytes {
		return nil, errors.New("credential file exceeds size limit")
	}
	var decoded credentialFile
	if err := decodeStrictJSON(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode credential file: %w", err)
	}
	return NewCredentialSet(decoded.Credentials)
}

// NewCredentialSet validates credentials and builds a lookup set. It fails
// closed on an empty set, unknown roles, short or oversized tokens, duplicate
// names and duplicate token digests.
func NewCredentialSet(credentials []Credential) (*CredentialSet, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one credential is required")
	}
	if len(credentials) > maxCredentials {
		return nil, errors.New("credential count exceeds limit")
	}
	set := &CredentialSet{
		hashes: make([][sha256.Size]byte, 0, len(credentials)),
		roles:  make([]Role, 0, len(credentials)),
	}
	seenNames := make(map[string]struct{}, len(credentials))
	seenTokens := make(map[[sha256.Size]byte]struct{}, len(credentials))
	for _, credential := range credentials {
		if !credentialNamePattern.MatchString(credential.Name) {
			return nil, errors.New("credential name is missing or malformed")
		}
		if !validRole(credential.Role) {
			return nil, fmt.Errorf("credential %q has an unknown role", credential.Name)
		}
		if len(credential.Token) < minCredentialTokenBytes || len(credential.Token) > maxCredentialTokenBytes {
			return nil, fmt.Errorf("credential %q token length is outside the allowed bounds", credential.Name)
		}
		if _, exists := seenNames[credential.Name]; exists {
			return nil, fmt.Errorf("credential name %q is duplicated", credential.Name)
		}
		seenNames[credential.Name] = struct{}{}
		digest := sha256.Sum256([]byte(credential.Token))
		if _, exists := seenTokens[digest]; exists {
			return nil, errors.New("duplicate credential token")
		}
		seenTokens[digest] = struct{}{}
		set.hashes = append(set.hashes, digest)
		set.roles = append(set.roles, credential.Role)
	}
	return set, nil
}

// Authenticate returns the role for a bearer token. It compares the digest of
// the supplied token against every configured digest without short-circuiting,
// so the comparison time does not depend on the matched entry.
func (s *CredentialSet) Authenticate(token string) (Role, bool) {
	if s == nil || token == "" || len(s.hashes) != len(s.roles) {
		return "", false
	}
	provided := sha256.Sum256([]byte(token))
	var role Role
	var matched int
	for index := range s.hashes {
		equal := subtle.ConstantTimeCompare(provided[:], s.hashes[index][:])
		if equal == 1 {
			role = s.roles[index]
		}
		matched |= equal
	}
	if matched != 1 {
		return "", false
	}
	return role, true
}

func validRole(role Role) bool {
	return role == RoleAdmin || role == RoleReader
}
