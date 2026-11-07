package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
)

func TestGenerateAndSignPolicyOffline(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "org-key")
	if err := generatePolicyKey([]string{"--prefix", prefix}); err != nil {
		t.Fatal(err)
	}
	privatePath := prefix + ".private"
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if goruntime.GOOS != "windows" && privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions=%#o, want 0600", privateInfo.Mode().Perm())
	}
	privateKey, err := os.ReadFile(privatePath)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key size=%d err=%v", len(privateKey), err)
	}
	publicBytes, err := os.ReadFile(prefix + ".public")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(publicBytes)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size=%d err=%v", len(publicKey), err)
	}
	payload := controlplane.PolicyPayload{SchemaVersion: 1, OrgID: "acme", Revision: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(inputPath, payloadBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "signed.json")
	if err := signPolicy([]string{"--input", inputPath, "--private-key", privatePath, "--output", outputPath}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle controlplane.SignedPolicyBundle
	if err := json.Unmarshal(encoded, &bundle); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(bundle.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		t.Fatal("offline signature did not verify with the generated public key")
	}
	if err := generatePolicyKey([]string{"--prefix", prefix}); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

func TestLoadTLSCertificateRequiresPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "control.example.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"control.example.test"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTLSCertificate(certificatePath, keyPath); err != nil {
		t.Fatalf("secure certificate pair rejected: %v", err)
	}
	if goruntime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTLSCertificate(certificatePath, keyPath); err == nil {
			t.Fatal("TLS private key with group/world permissions was accepted")
		}
	}
}
