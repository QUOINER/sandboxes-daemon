package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxJWKSBytes = 1 << 20
	maxJWKSKeys  = 32
	maxJWKValue  = 16 << 10
)

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	X         string `json:"x"`
}

type jwksCache struct {
	url                string
	client             *http.Client
	clock              func() time.Time
	refreshInterval    time.Duration
	maxCacheAge        time.Duration
	minRefreshInterval time.Duration

	mu          sync.Mutex
	keySet      map[string][]crypto.PublicKey
	lastAttempt time.Time
	lastSuccess time.Time
}

func (c *jwksCache) lookup(ctx context.Context, kid string) ([]crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if c.keySet == nil || now.Sub(c.lastSuccess) > c.maxCacheAge {
		if err := c.refreshLocked(ctx); err != nil {
			return nil, fmt.Errorf("refresh JWKS: %w", err)
		}
		now = c.clock()
	} else if now.Sub(c.lastSuccess) >= c.refreshInterval {
		// A scheduled refresh is best effort while the cached set is still
		// inside maxCacheAge; a failure does not extend the stale bound.
		_ = c.refreshLocked(ctx)
		now = c.clock()
	}
	if candidates, found := c.keySet[kid]; found {
		return candidates, nil
	}
	if now.Sub(c.lastAttempt) >= c.minRefreshInterval {
		if err := c.refreshLocked(ctx); err != nil {
			return nil, fmt.Errorf("refresh JWKS for unknown key: %w", err)
		}
		if candidates, found := c.keySet[kid]; found {
			return candidates, nil
		}
	}
	return nil, errors.New("token signing key is unknown")
}

func (c *jwksCache) refreshLocked(ctx context.Context) error {
	c.lastAttempt = c.clock()
	keys, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	c.keySet = keys
	c.lastSuccess = c.lastAttempt
	return nil
}

func (c *jwksCache) fetch(ctx context.Context) (map[string][]crypto.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("JWKS exceeds size limit")
	}
	var document jwksDocument
	if err := decodeLenientJSON(body, &document); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	return parseJWKS(document)
}

func parseJWKS(document jwksDocument) (map[string][]crypto.PublicKey, error) {
	if len(document.Keys) == 0 || len(document.Keys) > maxJWKSKeys {
		return nil, errors.New("JWKS key count is outside bounds")
	}
	keys := make(map[string][]crypto.PublicKey, len(document.Keys))
	for index := range document.Keys {
		raw := &document.Keys[index]
		if raw.Use != "" && raw.Use != "sig" {
			continue
		}
		if raw.KeyID == "" || len(raw.KeyID) > 256 {
			continue
		}
		key, err := parseJWK(*raw)
		if err != nil {
			continue
		}
		keys[raw.KeyID] = append(keys[raw.KeyID], key)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signing keys")
	}
	return keys, nil
}

func parseJWK(raw jwkKey) (crypto.PublicKey, error) {
	switch raw.KeyType {
	case "RSA":
		return parseRSAJWK(raw)
	case "OKP":
		return parseOKPJWK(raw)
	default:
		return nil, errors.New("unsupported JWK key type")
	}
}

func parseRSAJWK(raw jwkKey) (crypto.PublicKey, error) {
	if raw.Algorithm != "" && raw.Algorithm != jwtAlgorithmRS256 {
		return nil, errors.New("RSA JWK algorithm is not RS256")
	}
	modulus, err := decodeJWKValue(raw.Modulus)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := decodeJWKValue(raw.Exponent)
	if err != nil {
		return nil, err
	}
	modulusInt := new(big.Int).SetBytes(modulus)
	if modulusInt.BitLen() < 2048 || modulusInt.BitLen() > 16384 {
		return nil, errors.New("RSA JWK modulus size is outside bounds")
	}
	exponentInt := new(big.Int).SetBytes(exponentBytes)
	if !exponentInt.IsInt64() {
		return nil, errors.New("RSA JWK exponent is too large")
	}
	exponent := exponentInt.Int64()
	if exponent < 3 || exponent > math.MaxInt32 || exponent%2 == 0 {
		return nil, errors.New("RSA JWK exponent is invalid")
	}
	return &rsa.PublicKey{N: modulusInt, E: int(exponent)}, nil
}

func parseOKPJWK(raw jwkKey) (crypto.PublicKey, error) {
	if raw.Curve != "Ed25519" {
		return nil, errors.New("OKP JWK curve is not Ed25519")
	}
	if raw.Algorithm != "" && raw.Algorithm != jwtAlgorithmEdDSA {
		return nil, errors.New("OKP JWK algorithm is not EdDSA")
	}
	key, err := decodeJWKValue(raw.X)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 JWK key size is invalid")
	}
	return ed25519.PublicKey(key), nil
}

func decodeJWKValue(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > maxJWKValue {
		return nil, errors.New("JWK value size is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("JWK value is not valid base64url")
	}
	return decoded, nil
}

// decodeLenientJSON rejects duplicate members, invalid UTF-8, trailing data and
// oversized values while allowing JWKS/JWT extension members.
func decodeLenientJSON(raw []byte, dst any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
