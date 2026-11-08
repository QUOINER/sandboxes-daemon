package controlplane

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxJWTBytes          = 64 << 10
	maxJWTPartBytes      = 32 << 10
	defaultOIDCRefresh   = 5 * time.Minute
	defaultOIDCMaxAge    = 15 * time.Minute
	defaultOIDCMinResync = 30 * time.Second
	defaultOIDCLeeway    = 60 * time.Second
)

const (
	jwtAlgorithmRS256 = "RS256"
	jwtAlgorithmEdDSA = "EdDSA"
)

var jwtAlgorithms = map[string]struct{}{jwtAlgorithmRS256: {}, jwtAlgorithmEdDSA: {}}

// OIDCConfig configures optional OIDC bearer-token validation. Issuer,
// Audience and JWKSURL must all be set; the server keeps static credentials
// enabled alongside OIDC.
type OIDCConfig struct {
	Issuer             string
	Audience           string
	JWKSURL            string
	HTTPClient         *http.Client
	Clock              func() time.Time
	RefreshInterval    time.Duration
	MaxCacheAge        time.Duration
	MinRefreshInterval time.Duration
	Leeway             time.Duration
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type oidcClaims struct {
	Issuer    string        `json:"iss"`
	Audience  audienceClaim `json:"aud"`
	Subject   string        `json:"sub"`
	Expiry    json.Number   `json:"exp"`
	NotBefore json.Number   `json:"nbf"`
	Org       string        `json:"org"`
	Role      string        `json:"role"`
}

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = audienceClaim{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil {
		return errors.New("audience claim must be a string or string array")
	}
	*a = audienceClaim(multiple)
	return nil
}

func (a audienceClaim) contains(want string) bool {
	for _, candidate := range a {
		if candidate == want {
			return true
		}
	}
	return false
}

// OIDCValidator verifies asymmetric JWT bearer tokens against a cached JWKS and
// maps org/role claims to a Principal.
type OIDCValidator struct {
	issuer   string
	audience string
	keys     *jwksCache
	clock    func() time.Time
	leeway   time.Duration
}

// NewOIDCValidator validates the OIDC configuration and builds a validator.
func NewOIDCValidator(config OIDCConfig) (*OIDCValidator, error) {
	if err := validateOIDCConfig(config); err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	refresh := config.RefreshInterval
	if refresh <= 0 {
		refresh = defaultOIDCRefresh
	}
	maxAge := config.MaxCacheAge
	if maxAge <= 0 {
		maxAge = defaultOIDCMaxAge
	}
	minResync := config.MinRefreshInterval
	if minResync <= 0 {
		minResync = defaultOIDCMinResync
	}
	if maxAge < refresh || minResync > refresh {
		return nil, errors.New("OIDC cache bounds are inconsistent")
	}
	leeway := config.Leeway
	if leeway == 0 {
		leeway = defaultOIDCLeeway
	}
	if leeway < 0 {
		return nil, errors.New("OIDC clock leeway must not be negative")
	}
	client := config.HTTPClient
	if client == nil {
		client = newOIDCClient()
	}
	return &OIDCValidator{
		issuer:   config.Issuer,
		audience: config.Audience,
		clock:    clock,
		leeway:   leeway,
		keys: &jwksCache{
			url: config.JWKSURL, client: client, clock: clock,
			refreshInterval: refresh, maxCacheAge: maxAge, minRefreshInterval: minResync,
		},
	}, nil
}

func validateOIDCConfig(config OIDCConfig) error {
	if config.Issuer == "" || config.Audience == "" || config.JWKSURL == "" {
		return errors.New("OIDC issuer, audience and JWKS URL are all required")
	}
	for name, raw := range map[string]string{"issuer": config.Issuer, "JWKS URL": config.JWKSURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("OIDC %s must be an absolute HTTPS URL", name)
		}
	}
	return nil
}

func newOIDCClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Scheme != "https" {
				return errors.New("refusing non-HTTPS JWKS redirect")
			}
			if len(via) >= 3 {
				return errors.New("too many JWKS redirects")
			}
			return nil
		},
	}
}

// Authenticate validates a JWT and returns the org/role principal. Errors are
// deliberately generic and never contain the token or its signature.
func (v *OIDCValidator) Authenticate(ctx context.Context, token string) (Principal, error) {
	if token == "" || len(token) > maxJWTBytes {
		return Principal{}, errors.New("token size is invalid")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, errors.New("token is not a compact JWS")
	}
	var header jwtHeader
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return Principal{}, fmt.Errorf("decode token header: %w", err)
	}
	if _, allowed := jwtAlgorithms[header.Algorithm]; !allowed {
		return Principal{}, errors.New("token algorithm is not allowed")
	}
	if header.KeyID == "" || len(header.KeyID) > 256 {
		return Principal{}, errors.New("token key ID is missing or invalid")
	}
	keys, err := v.keys.lookup(ctx, header.KeyID)
	if err != nil {
		return Principal{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		return Principal{}, errors.New("token signature is not valid base64url")
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyJWTSignature(header.Algorithm, keys, signingInput, signature) {
		return Principal{}, errors.New("token signature is invalid")
	}
	var claims oidcClaims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return Principal{}, fmt.Errorf("decode token claims: %w", err)
	}
	if err := v.validateClaims(claims); err != nil {
		return Principal{}, err
	}
	return Principal{Role: Role(claims.Role), Org: claims.Org, Subject: claims.Subject}, nil
}

func (v *OIDCValidator) validateClaims(claims oidcClaims) error {
	now := v.clock()
	if claims.Issuer != v.issuer {
		return errors.New("token issuer mismatch")
	}
	if !claims.Audience.contains(v.audience) {
		return errors.New("token audience mismatch")
	}
	if claims.Subject == "" || len(claims.Subject) > 512 {
		return errors.New("token subject is missing or invalid")
	}
	expiry, err := claims.Expiry.Int64()
	if err != nil {
		return errors.New("token expiry is missing or invalid")
	}
	if !now.Before(time.Unix(expiry, 0).Add(v.leeway)) {
		return errors.New("token is expired")
	}
	if claims.NotBefore != "" {
		notBefore, err := claims.NotBefore.Int64()
		if err != nil {
			return errors.New("token not-before claim is invalid")
		}
		if now.Add(v.leeway).Before(time.Unix(notBefore, 0)) {
			return errors.New("token is not yet valid")
		}
	}
	if !validOrgID(claims.Org) {
		return errors.New("token org claim is missing or invalid")
	}
	if !validRole(Role(claims.Role)) {
		return errors.New("token role claim is missing or invalid")
	}
	return nil
}

func verifyJWTSignature(algorithm string, keys []crypto.PublicKey, signingInput string, signature []byte) bool {
	for _, key := range keys {
		if verifyJWTKey(algorithm, key, signingInput, signature) {
			return true
		}
	}
	return false
}

func verifyJWTKey(algorithm string, key crypto.PublicKey, signingInput string, signature []byte) bool {
	switch algorithm {
	case jwtAlgorithmRS256:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok || len(signature) != rsaKey.Size() {
			return false
		}
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature) == nil
	case jwtAlgorithmEdDSA:
		edKey, ok := key.(ed25519.PublicKey)
		if !ok || len(signature) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(edKey, []byte(signingInput), signature)
	default:
		return false
	}
}

func decodeJWTPart(encoded string, dst any) error {
	if encoded == "" || len(encoded) > maxJWTPartBytes {
		return errors.New("encoded part size is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("encoded part is not valid base64url")
	}
	if !utf8.Valid(raw) {
		return errors.New("encoded part is not valid UTF-8")
	}
	return decodeLenientJSON(raw, dst)
}
