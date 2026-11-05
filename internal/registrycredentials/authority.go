package registrycredentials

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const proxyAuthorityService = "com.rheic.registry-proxy-authority.v1"
const proxyAuthorityAccount = "host-forward-proxy"
const certificatePEMType = "CERTIFICATE"
const privateKeyPEMType = "PRIVATE KEY"

// ProxyAuthority is a host-side signing authority. Only its public certificate
// may cross into a guest; the private signer is loaded from the native vault.
type ProxyAuthority struct {
	certificate *x509.Certificate
	signer      *ecdsa.PrivateKey
	pem         []byte
}

// ProxyCA returns a stable host signing authority, generating and saving one
// only when the native vault has no existing key.
func (s *Store) ProxyCA(ctx context.Context) (*ProxyAuthority, error) {
	if s == nil || s.vault == nil {
		return nil, errors.New("registry credential vault is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := s.vault.Get(ctx, proxyAuthorityService, proxyAuthorityAccount)
	if err == nil {
		ca, parseErr := parseProxyAuthority(payload)
		if parseErr != nil {
			return nil, errors.New("stored registry proxy authority is invalid")
		}
		return ca, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, errors.New("read registry proxy authority from native vault")
	}
	ca, err := generateProxyAuthority()
	if err != nil {
		return nil, fmt.Errorf("generate registry proxy authority: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.signer)
	if err != nil {
		return nil, errors.New("encode registry proxy authority private key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: keyDER})
	clear(keyDER)
	serialized, err := json.Marshal(struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}{Certificate: string(ca.pem), PrivateKey: string(keyPEM)})
	clear(keyPEM)
	if err != nil {
		return nil, errors.New("encode registry proxy authority")
	}
	defer clear(serialized)
	if err := s.vault.Set(ctx, proxyAuthorityService, proxyAuthorityAccount, string(serialized)); err != nil {
		return nil, errors.New("store registry proxy authority in native vault")
	}
	return ca, nil
}

func generateProxyAuthority() (*ProxyAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Rheic Sandbox Registry Proxy"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &ProxyAuthority{certificate: cert, signer: key, pem: pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: der})}, nil
}

func parseProxyAuthority(payload string) (*ProxyAuthority, error) {
	if payload == "" || len(payload) > 64<<10 {
		return nil, errors.New("stored proxy authority has an invalid size")
	}
	var stored struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(payload), &stored); err != nil {
		return nil, err
	}
	cert, key, certPEM, err := parseAuthorityMaterial(stored.Certificate, stored.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &ProxyAuthority{certificate: cert, signer: key, pem: certPEM}, nil
}

func parseAuthorityMaterial(certificatePEM, privateKeyPEM string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certBlock, certRest := pem.Decode([]byte(certificatePEM))
	keyBlock, keyRest := pem.Decode([]byte(privateKeyPEM))
	if certBlock == nil || certBlock.Type != certificatePEMType || len(bytes.TrimSpace(certRest)) != 0 ||
		keyBlock == nil || keyBlock.Type != privateKeyPEMType || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, nil, nil, errors.New("invalid PEM data")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !validProxyAuthorityPair(cert, key) {
		return nil, nil, nil, errors.New("key does not match a CA certificate")
	}
	return cert, key, []byte(certificatePEM), nil
}

func validProxyAuthorityPair(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	return cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 && cert.NotAfter.After(time.Now()) &&
		cert.CheckSignatureFrom(cert) == nil && key.PublicKey.Equal(cert.PublicKey)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return nil, errors.New("generated an empty certificate serial")
	}
	return serial, nil
}

// Certificate returns a copy of the public root certificate in PEM form.
func (a *ProxyAuthority) Certificate() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.pem...)
}

// Leaf creates a short-lived server certificate signed by the host authority.
func (a *ProxyAuthority) Leaf(host string, now time.Time) (tlsCertificate tls.Certificate, err error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if a == nil || a.certificate == nil || a.signer == nil || !trustedProxyHostname(host) {
		return tls.Certificate{}, errors.New("invalid registry proxy certificate request")
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now = now.UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &leafKey.PublicKey, a.signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: keyDER})
	tlsCertificate, err = tls.X509KeyPair(append(leafPEM, a.pem...), keyPEM)
	clear(keyDER)
	clear(keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCertificate, nil
}

func trustedProxyHostname(host string) bool {
	switch host {
	case "registry-1.docker.io", dockerHubAuthAuthority, dockerHubBlobAuthority:
		return true
	default:
		return false
	}
}
