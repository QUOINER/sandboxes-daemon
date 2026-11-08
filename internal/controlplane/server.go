package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxBundleBytes = 1 << 20
	maxAuditBytes  = 1 << 20
	maxAuditEvents = 1000
	maxBundleAge   = 30 * 24 * time.Hour
)

var (
	orgIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}$`)
	decisionNames  = map[string]struct{}{"allow": {}, "deny": {}}
	auditResources = map[string]struct{}{"sandbox": {}, "network": {}, "filesystem": {}, "registry": {}, "mcp": {}, "secret": {}}
)

type PolicyRule struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	RuleID   string `json:"ruleId"`
}

type PolicyPayload struct {
	SchemaVersion int          `json:"schemaVersion"`
	OrgID         string       `json:"orgId"`
	Revision      uint64       `json:"revision"`
	IssuedAt      time.Time    `json:"issuedAt"`
	ExpiresAt     time.Time    `json:"expiresAt"`
	Rules         []PolicyRule `json:"rules"`
}

type SignedPolicyBundle struct {
	Payload   PolicyPayload `json:"payload"`
	Signature string        `json:"signature"`
}

type AuditEvent struct {
	OccurredAt  time.Time `json:"occurredAt"`
	SandboxID   string    `json:"sandboxId"`
	OperationID string    `json:"operationId"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Decision    string    `json:"decision"`
	RuleID      string    `json:"ruleId,omitempty"`
}

type Config struct {
	DBPath     string
	AdminToken []byte
	PolicyKey  ed25519.PublicKey
	Clock      func() time.Time
}

type Server struct {
	db         *sql.DB
	token      []byte
	policyKey  ed25519.PublicKey
	clock      func() time.Time
	httpServer *http.ServeMux
}

func New(config Config) (*Server, error) {
	if config.DBPath == "" || len(config.AdminToken) < 32 || len(config.PolicyKey) != ed25519.PublicKeySize {
		return nil, errors.New("database path, 32-byte admin token, and Ed25519 policy public key are required")
	}
	db, err := sql.Open("sqlite", config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure control-plane database: %w", err)
	}
	if err := migrate(db, config.DBPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &Server{db: db, token: append([]byte(nil), config.AdminToken...), policyKey: append(ed25519.PublicKey(nil), config.PolicyKey...), clock: clock, httpServer: http.NewServeMux()}
	s.httpServer.HandleFunc("GET /healthz", s.health)
	s.httpServer.HandleFunc("GET /v1/orgs/{org}/policy", s.getPolicy)
	s.httpServer.HandleFunc("PUT /v1/orgs/{org}/policy", s.putPolicy)
	s.httpServer.HandleFunc("POST /v1/orgs/{org}/audit", s.ingestAudit)
	return s, nil
}

func migrate(db *sql.DB, dbPath string) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read control-plane schema version: %w", err)
	}
	if version > 1 {
		return fmt.Errorf("control-plane schema version %d is newer than this server supports", version)
	}
	if version == 1 {
		return nil
	}
	var existingTables int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&existingTables); err != nil {
		return fmt.Errorf("inspect control-plane database before migration: %w", err)
	}
	if existingTables > 0 {
		if err := backupDatabase(db, dbPath); err != nil {
			return err
		}
	}
	const schema = `
CREATE TABLE IF NOT EXISTS policy_bundles (
	org_id TEXT PRIMARY KEY,
	revision INTEGER NOT NULL,
	payload BLOB NOT NULL,
	signature TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY,
	org_id TEXT NOT NULL,
	occurred_at TEXT NOT NULL,
	sandbox_id TEXT NOT NULL,
	operation_id TEXT NOT NULL,
	action TEXT NOT NULL,
	resource TEXT NOT NULL,
	decision TEXT NOT NULL,
	rule_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_events_org_time ON audit_events(org_id, occurred_at, id);
PRAGMA user_version=1;`
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin control-plane schema migration: %w", err)
	}
	if _, err := tx.Exec(schema); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migrate control-plane database: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit control-plane schema migration: %w", err)
	}
	return nil
}

func backupDatabase(db *sql.DB, dbPath string) error {
	backupDir, err := os.MkdirTemp(filepath.Dir(dbPath), ".rheic-server-backup-")
	if err != nil {
		return fmt.Errorf("create migration backup directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(backupDir) }()
	snapshot := filepath.Join(backupDir, "snapshot.db")
	if _, err := db.Exec(`VACUUM INTO ?`, snapshot); err != nil {
		return fmt.Errorf("backup control-plane database before migration: %w", err)
	}
	if err := os.Chmod(snapshot, 0o600); err != nil {
		return fmt.Errorf("secure control-plane database backup: %w", err)
	}
	backupPath := fmt.Sprintf("%s.backup-%s", dbPath, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Rename(snapshot, backupPath); err != nil {
		return fmt.Errorf("publish control-plane database backup: %w", err)
	}
	return nil
}

func (s *Server) Handler() http.Handler { return s.httpServer }

func (s *Server) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	if err := s.db.Ping(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	org := r.PathValue("org")
	if !validOrgID(org) {
		writeError(w, http.StatusBadRequest, "invalid_org_id")
		return
	}
	var raw []byte
	var signature string
	err := s.db.QueryRowContext(r.Context(), `SELECT payload, signature FROM policy_bundles WHERE org_id=?`, org).Scan(&raw, &signature)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "policy_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	payload, decodeErr := DecodePolicyPayloadJSON(raw)
	if decodeErr != nil || validatePayload(payload, org, s.clock()) != nil || !verifySignature(payload, signature, s.policyKey) {
		writeError(w, http.StatusServiceUnavailable, "stored_policy_invalid")
		return
	}
	payload = normalizePolicyTimes(payload)
	writeJSON(w, http.StatusOK, SignedPolicyBundle{Payload: payload, Signature: signature})
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	org := r.PathValue("org")
	if !validOrgID(org) {
		writeError(w, http.StatusBadRequest, "invalid_org_id")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBundleBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_bundle")
		return
	}
	bundle, err := DecodeSignedPolicyBundleJSON(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_bundle")
		return
	}
	if err := validatePayload(bundle.Payload, org, s.clock()); err != nil || !verifySignature(bundle.Payload, bundle.Signature, s.policyKey) {
		writeError(w, http.StatusUnprocessableEntity, "bundle_signature_or_policy_invalid")
		return
	}
	bundle.Payload = normalizePolicyTimes(bundle.Payload)
	payload, err := json.Marshal(bundle.Payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding_failed")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `INSERT INTO policy_bundles(org_id, revision, payload, signature, expires_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(org_id) DO UPDATE SET revision=excluded.revision, payload=excluded.payload, signature=excluded.signature, expires_at=excluded.expires_at, updated_at=excluded.updated_at
WHERE excluded.revision > policy_bundles.revision`, org, bundle.Payload.Revision, payload, bundle.Signature, bundle.Payload.ExpiresAt.UTC().Format(time.RFC3339Nano), s.clock().UTC().Format(time.RFC3339Nano))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		writeError(w, http.StatusConflict, "revision_not_newer")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) ingestAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	org := r.PathValue("org")
	if !validOrgID(org) {
		writeError(w, http.StatusBadRequest, "invalid_org_id")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAuditBytes))
	if err != nil || len(body) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_audit_batch")
		return
	}
	events, err := decodeAuditBatch(body, s.clock())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_audit_batch")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(r.Context(), `INSERT INTO audit_events(org_id, occurred_at, sandbox_id, operation_id, action, resource, decision, rule_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	defer func() { _ = stmt.Close() }()
	for _, event := range events {
		if _, err := stmt.ExecContext(r.Context(), org, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.SandboxID, event.OperationID, event.Action, event.Resource, event.Decision, event.RuleID); err != nil {
			writeError(w, http.StatusInternalServerError, "database_error")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	header := r.Header.Get("Authorization")
	value := strings.TrimPrefix(header, "Bearer ")
	providedHash := sha256.Sum256([]byte(value))
	configuredHash := sha256.Sum256(s.token)
	if value == header || subtle.ConstantTimeCompare(providedHash[:], configuredHash[:]) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func validatePayload(payload PolicyPayload, org string, now time.Time) error {
	if err := validatePayloadMetadata(payload, org, now); err != nil {
		return err
	}
	return validatePolicyRules(payload.Rules)
}

// ValidatePolicyPayload applies the control-plane policy constraints to a
// payload at the supplied time.
func ValidatePolicyPayload(payload PolicyPayload, org string, now time.Time) error {
	return validatePayload(payload, org, now)
}

func validatePolicyRules(rules []PolicyRule) error {
	previousRuleID := ""
	for index, rule := range rules {
		if !idPattern.MatchString(rule.RuleID) || rule.Resource == "" || len(rule.Resource) > 512 {
			return errors.New("invalid policy rule")
		}
		if _, ok := decisionNames[rule.Action]; !ok {
			return errors.New("invalid policy action")
		}
		if index > 0 && rule.RuleID <= previousRuleID {
			return errors.New("policy rules must be strictly ordered by ruleId")
		}
		previousRuleID = rule.RuleID
	}
	return nil
}

func validatePayloadMetadata(payload PolicyPayload, org string, now time.Time) error {
	if payload.SchemaVersion != 1 || payload.OrgID != org || payload.Revision == 0 || payload.Revision > math.MaxInt64 {
		return errors.New("invalid policy bundle metadata")
	}
	if payload.IssuedAt.IsZero() || payload.IssuedAt.After(now.Add(5*time.Minute)) || !payload.ExpiresAt.After(now) || !payload.ExpiresAt.After(payload.IssuedAt) || payload.ExpiresAt.Sub(payload.IssuedAt) > maxBundleAge {
		return errors.New("invalid policy bundle lifetime")
	}
	if len(payload.Rules) > 10000 {
		return errors.New("policy bundle has too many rules")
	}
	return nil
}

func verifySignature(payload PolicyPayload, encoded string, key ed25519.PublicKey) bool {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != encoded {
		return false
	}
	canonical, err := PolicySigningBytes(payload)
	return err == nil && ed25519.Verify(key, canonical, signature)
}

func normalizePolicyTimes(payload PolicyPayload) PolicyPayload {
	payload.IssuedAt = payload.IssuedAt.UTC()
	payload.ExpiresAt = payload.ExpiresAt.UTC()
	return payload
}

func decodeAuditBatch(raw []byte, now time.Time) ([]AuditEvent, error) {
	if len(raw) > maxAuditBytes {
		return nil, errors.New("audit batch too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	events := make([]AuditEvent, 0)
	for len(events) <= maxAuditEvents {
		var event AuditEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !validAuditEvent(event, now) {
			return nil, errors.New("invalid audit event")
		}
		events = append(events, event)
	}
	if len(events) == 0 || len(events) > maxAuditEvents {
		return nil, errors.New("audit event count outside bounds")
	}
	return events, nil
}

func validAuditEvent(event AuditEvent, now time.Time) bool {
	_, allowed := decisionNames[event.Decision]
	_, resourceAllowed := auditResources[event.Resource]
	if event.OccurredAt.IsZero() || event.OccurredAt.After(now.Add(5*time.Minute)) || event.OccurredAt.Before(now.Add(-30*24*time.Hour)) || !allowed || !resourceAllowed || !idPattern.MatchString(event.SandboxID) || !idPattern.MatchString(event.OperationID) || !idPattern.MatchString(event.Action) {
		return false
	}
	return event.RuleID == "" || idPattern.MatchString(event.RuleID)
}

func validOrgID(org string) bool { return orgIDPattern.MatchString(org) }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, struct {
		Code string `json:"code"`
	}{Code: code})
}
