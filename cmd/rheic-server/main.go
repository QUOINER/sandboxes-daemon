package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rheic/sandboxes-daemon/internal/controlplane"
)

func main() {
	if err := run(); err != nil {
		slog.Error("self-hosted control plane stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if goruntime.GOOS != "darwin" && goruntime.GOOS != "linux" {
		return errors.New("self-hosted control-plane preview currently supports macOS and Linux only")
	}
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		return generatePolicyKey(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "sign-policy" {
		return signPolicy(os.Args[2:])
	}
	return runServer(os.Args[1:])
}

type serverOptions struct {
	listen          string
	dbPath          string
	credentialsPath string
	publicKey       string
	certPath        string
	privateKey      string
}

func runServer(args []string) error {
	flags := flag.NewFlagSet("rheic-server", flag.ContinueOnError)
	defaultDBPath, err := defaultDatabasePath()
	if err != nil {
		return err
	}
	listen := flags.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	dbPath := flags.String("db", defaultDBPath, "SQLite database path")
	credentialsPath := flags.String("credentials-file", "", "protected role-scoped bearer credentials file (mode 0600)")
	publicKeyPath := flags.String("policy-public-key", "", "base64 Ed25519 policy-signing public key file")
	certPath := flags.String("tls-cert", "", "TLS certificate PEM")
	keyPath := flags.String("tls-key", "", "TLS private key PEM")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *credentialsPath == "" || *publicKeyPath == "" || *certPath == "" || *keyPath == "" {
		return errors.New("--credentials-file, --policy-public-key, --tls-cert, and --tls-key are required")
	}
	return serve(serverOptions{listen: *listen, dbPath: *dbPath, credentialsPath: *credentialsPath, publicKey: *publicKeyPath, certPath: *certPath, privateKey: *keyPath})
}

func defaultDatabasePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return databasePathInConfigDir(configDir), nil
}

func databasePathInConfigDir(configDir string) string {
	return filepath.Join(configDir, "rheic", "rheic-server.db")
}

func serve(options serverOptions) error {
	credentialsRaw, err := readProtectedFile(options.credentialsPath, controlplane.MaxCredentialFileBytes)
	if err != nil {
		return fmt.Errorf("read credentials file: %w", err)
	}
	credentials, err := controlplane.ParseCredentials(credentialsRaw)
	if err != nil {
		return fmt.Errorf("parse credentials file: %w", err)
	}
	encodedKey, err := os.ReadFile(options.publicKey)
	if err != nil {
		return fmt.Errorf("read policy public key: %w", err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("policy public key must be a base64 Ed25519 public key")
	}
	certificate, err := loadTLSCertificate(options.certPath, options.privateKey)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	if err := prepareDatabasePath(options.dbPath); err != nil {
		return err
	}
	service, err := controlplane.New(controlplane.Config{DBPath: options.dbPath, Credentials: credentials, PolicyKey: ed25519.PublicKey(publicKey)})
	if err != nil {
		return err
	}
	defer func() {
		if err := service.Close(); err != nil {
			slog.Error("close control-plane database", "error", err)
		}
	}()
	server := &http.Server{
		Addr:              options.listen,
		Handler:           secureHeaders(service.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("self-hosted control plane listening", "address", options.listen)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTPS: %w", err)
	}
	return nil
}

func loadTLSCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certInfo, err := os.Lstat(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("inspect certificate file: %w", err)
	}
	if !certInfo.Mode().IsRegular() || certInfo.Mode()&os.ModeSymlink != 0 {
		return tls.Certificate{}, errors.New("certificate must be a regular file")
	}
	//nolint:gosec // The operator configures this public certificate path; it is not secret material.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate file: %w", err)
	}
	keyPEM, err := readPrivateFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate pair: %w", err)
	}
	return pair, nil
}

func generatePolicyKey(args []string) error {
	flags := flag.NewFlagSet("rheic-server keygen", flag.ContinueOnError)
	prefix := flags.String("prefix", "", "output prefix for .private and .public files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *prefix == "" || flags.NArg() != 0 {
		return errors.New("keygen requires --prefix PATH")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate policy key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(*prefix), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := writeNewFile(*prefix+".private", privateKey, 0o600); err != nil {
		return err
	}
	encodedPublic := []byte(base64.StdEncoding.EncodeToString(publicKey) + "\n")
	if err := writeNewFile(*prefix+".public", encodedPublic, 0o644); err != nil {
		_ = os.Remove(*prefix + ".private")
		return err
	}
	fmt.Printf("Created %s.private (keep offline) and %s.public\n", *prefix, *prefix)
	return nil
}

func signPolicy(args []string) error {
	flags := flag.NewFlagSet("rheic-server sign-policy", flag.ContinueOnError)
	inputPath := flags.String("input", "", "unsigned policy payload JSON")
	keyPath := flags.String("private-key", "", "offline Ed25519 private key file (mode 0600)")
	outputPath := flags.String("output", "", "signed bundle output file; stdout when omitted")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *keyPath == "" || flags.NArg() != 0 {
		return errors.New("sign-policy requires --input FILE and --private-key FILE")
	}
	privateKey, err := readPrivateFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read policy private key: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("policy private key has invalid size")
	}
	payload, err := readPolicyPayload(*inputPath)
	if err != nil {
		return err
	}
	canonical, err := controlplane.PolicySigningBytes(payload)
	if err != nil {
		return fmt.Errorf("canonicalize policy payload: %w", err)
	}
	bundle := controlplane.SignedPolicyBundle{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(privateKey), canonical))}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed policy: %w", err)
	}
	encoded = append(encoded, '\n')
	if *outputPath == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return writeNewFile(*outputPath, encoded, 0o600)
}

func readPolicyPayload(path string) (controlplane.PolicyPayload, error) {
	//nolint:gosec // --input is an operator-supplied local policy file, not a request-controlled path.
	input, err := os.Open(path)
	if err != nil {
		return controlplane.PolicyPayload{}, fmt.Errorf("open policy payload: %w", err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			slog.Error("close policy payload", "error", err)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil {
		return controlplane.PolicyPayload{}, fmt.Errorf("read policy payload: %w", err)
	}
	if len(raw) > 1<<20 {
		return controlplane.PolicyPayload{}, errors.New("policy payload exceeds 1 MiB")
	}
	payload, err := controlplane.DecodePolicyPayloadJSON(raw)
	if err != nil {
		return controlplane.PolicyPayload{}, fmt.Errorf("decode policy payload: %w", err)
	}
	if err := controlplane.ValidatePolicyPayload(payload, payload.OrgID, time.Now()); err != nil {
		return controlplane.PolicyPayload{}, fmt.Errorf("validate policy payload: %w", err)
	}
	payload.IssuedAt = payload.IssuedAt.UTC()
	payload.ExpiresAt = payload.ExpiresAt.UTC()
	return payload, nil
}

func writeNewFile(path string, content []byte, mode os.FileMode) error {
	//nolint:gosec // The operator supplies the output path for generated local key and bundle files.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func readPrivateFile(path string) ([]byte, error) {
	return readProtectedFile(path, 4096)
}

func readProtectedFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("must be a regular file accessible only by its owner")
	}
	//nolint:gosec // The operator supplies this path for a locally protected key or token file.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errors.New("private file changed while opening")
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Error("close private input file", "error", err)
		}
	}()
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > limit {
		return nil, fmt.Errorf("protected file exceeds %d-byte limit", limit)
	}
	return content, nil
}

func prepareDatabasePath(path string) error {
	if path == ":memory:" {
		return errors.New("persistent SQLite path is required")
	}
	if err := ensurePrivateDatabaseDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return secureDatabaseFile(path)
}

func ensurePrivateDatabaseDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	dirInfo, err := os.Lstat(path)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("database directory must be a private directory with mode 0700")
	}
	return nil
}

func secureDatabaseFile(path string) error {
	priorInfo, statErr := os.Lstat(path)
	if statErr == nil && (!priorInfo.Mode().IsRegular() || priorInfo.Mode()&os.ModeSymlink != 0) {
		return errors.New("database path must be a regular file, not a symlink or special file")
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect database path: %w", statErr)
	}
	//nolint:gosec // This is the operator-configured local SQLite database path.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	return secureOpenDatabaseFile(file, priorInfo, statErr)
}

func secureOpenDatabaseFile(file *os.File, priorInfo os.FileInfo, statErr error) error {
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure database file: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil || (statErr == nil && !os.SameFile(priorInfo, openedInfo)) {
		_ = file.Close()
		return errors.New("database file changed while opening")
	}
	return file.Close()
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
