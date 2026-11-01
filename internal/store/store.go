// Package store implements the SQLite persistence adapters.
package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	_ "modernc.org/sqlite"
)

// Store is the SQLite implementation of the daemon repositories.
type Store struct {
	db  *sql.DB
	ops *OperationStore
}

// OperationStore is the SQLite operation journal adapter.
type OperationStore struct {
	db *sql.DB
}

var _ sandbox.Store = (*Store)(nil)
var _ operation.Store = (*OperationStore)(nil)

// Open opens and migrates the SQLite database.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db, ops: &OperationStore{db: db}}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Operations returns the operation journal adapter.
func (s *Store) Operations() *OperationStore { return s.ops }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS sandboxes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			image TEXT NOT NULL,
			workspace TEXT NOT NULL,
			workspaces TEXT NOT NULL DEFAULT '[]',
			ports TEXT NOT NULL DEFAULT '[]',
			allow_rules TEXT NOT NULL DEFAULT '[]',
			deny_rules TEXT NOT NULL DEFAULT '[]',
			agent TEXT NOT NULL DEFAULT '',
			policy_profile TEXT NOT NULL DEFAULT '',
			detached INTEGER NOT NULL DEFAULT 0,
			last_used_at INTEGER NOT NULL DEFAULT 0,
			cpus INTEGER NOT NULL DEFAULT 2,
			memory_mib INTEGER NOT NULL DEFAULT 1024,
			stopped_at INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS operations (
			id TEXT PRIMARY KEY,
			sandbox_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			idempotency_key TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS operations_idempotency
			ON operations(idempotency_key) WHERE idempotency_key <> ''`,
		`CREATE INDEX IF NOT EXISTS operations_sandbox ON operations(sandbox_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS service_secret_index (
			service TEXT NOT NULL,
			scope TEXT NOT NULL,
			sandbox_name TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (service, scope, sandbox_name)
		)`,
		`CREATE TABLE IF NOT EXISTS registry_credential_index (
			registry TEXT NOT NULL,
			scope TEXT NOT NULL,
			sandbox_name TEXT NOT NULL DEFAULT '',
			username TEXT NOT NULL,
			PRIMARY KEY (registry, scope, sandbox_name)
		)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if err := s.ensureSandboxResourceColumns(ctx); err != nil {
		return fmt.Errorf("migrate sandbox resources: %w", err)
	}
	return nil
}

func (s *Store) ensureSandboxResourceColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(sandboxes)`)
	if err != nil {
		return err
	}
	columns := make(map[string]struct{})
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{"cpus", "cpus INTEGER NOT NULL DEFAULT 2"},
		{"memory_mib", "memory_mib INTEGER NOT NULL DEFAULT 1024"},
		{"stopped_at", "stopped_at INTEGER NOT NULL DEFAULT 0"},
		{"workspaces", "workspaces TEXT NOT NULL DEFAULT '[]'"},
		{"ports", "ports TEXT NOT NULL DEFAULT '[]'"},
		{"allow_rules", "allow_rules TEXT NOT NULL DEFAULT '[]'"},
		{"deny_rules", "deny_rules TEXT NOT NULL DEFAULT '[]'"},
		{"agent", "agent TEXT NOT NULL DEFAULT ''"},
		{"policy_profile", "policy_profile TEXT NOT NULL DEFAULT ''"},
		{"detached", "detached INTEGER NOT NULL DEFAULT 0"},
		{"last_used_at", "last_used_at INTEGER NOT NULL DEFAULT 0"},
	} {
		if _, ok := columns[column.name]; ok {
			continue
		}
		if _, err := s.db.ExecContext(ctx, "ALTER TABLE sandboxes ADD COLUMN "+column.definition); err != nil {
			return err
		}
	}
	return nil
}

// Create inserts a sandbox.
func (s *Store) Create(ctx context.Context, sb sandbox.Sandbox) error {
	workspaces, err := encodeWorkspaces(sb.Workspaces)
	if err != nil {
		return err
	}
	ports, err := encodePorts(sb.Ports)
	if err != nil {
		return err
	}
	allow, deny, err := encodePolicy(sb.Policy)
	if err != nil {
		return err
	}
	agent, profile, detached, lastUsed := metaValues(sb)
	_, err = s.db.ExecContext(ctx, `INSERT INTO sandboxes
		(id, name, state, generation, image, workspace, workspaces, ports, allow_rules, deny_rules, agent, policy_profile, detached, last_used_at, cpus, memory_mib, stopped_at, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sb.ID, sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, workspaces, ports, allow, deny, agent, profile, detached, lastUsed, sb.CPUs, sb.MemoryMiB, toUnix(sb.StoppedAt), sb.Error,
		toUnix(sb.CreatedAt), toUnix(sb.UpdatedAt))
	return mapSQLError(err)
}

// Get returns a sandbox by ID.
func (s *Store) Get(ctx context.Context, id string) (sandbox.Sandbox, error) {
	return s.getSandbox(ctx, "id = ?", id)
}

// GetByName returns a sandbox by name.
func (s *Store) GetByName(ctx context.Context, name string) (sandbox.Sandbox, error) {
	return s.getSandbox(ctx, "name = ?", name)
}

func (s *Store) getSandbox(ctx context.Context, where string, arg any) (sandbox.Sandbox, error) {
	var sb sandbox.Sandbox
	var created, updated, stoppedAt int64
	var workspaces, ports, allow, deny, agent, profile string
	var detached, lastUsed int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, state, generation, image, workspace, workspaces, ports, allow_rules, deny_rules, agent, policy_profile, detached, last_used_at, cpus, memory_mib, stopped_at, error, created_at, updated_at
		FROM sandboxes WHERE `+where, arg).Scan(
		&sb.ID, &sb.Name, &sb.State, &sb.Generation, &sb.Image, &sb.Workspace, &workspaces, &ports, &allow, &deny, &agent, &profile, &detached, &lastUsed, &sb.CPUs, &sb.MemoryMiB, &stoppedAt, &sb.Error, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return sandbox.Sandbox{}, core.ErrNotFound
	}
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	if err := decodeWorkspaces(workspaces, &sb); err != nil {
		return sandbox.Sandbox{}, err
	}
	if err := decodePorts(ports, &sb); err != nil {
		return sandbox.Sandbox{}, err
	}
	if err := decodePolicy(allow, deny, &sb); err != nil {
		return sandbox.Sandbox{}, err
	}
	decodeMeta(agent, profile, detached, lastUsed, &sb)
	sb.StoppedAt = fromUnix(stoppedAt)
	sb.CreatedAt = fromUnix(created)
	sb.UpdatedAt = fromUnix(updated)
	return sb, nil
}

// List returns one page of sandboxes.
func (s *Store) List(ctx context.Context, opts sandbox.ListOptions) ([]sandbox.Sandbox, string, error) {
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset, err := decodeOffset(opts.PageToken)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, state, generation, image, workspace, workspaces, ports, allow_rules, deny_rules, agent, policy_profile, detached, last_used_at, cpus, memory_mib, stopped_at, error, created_at, updated_at
		FROM sandboxes ORDER BY created_at, id LIMIT ? OFFSET ?`, pageSize+1, offset)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var out []sandbox.Sandbox
	for rows.Next() {
		var sb sandbox.Sandbox
		var created, updated, stoppedAt int64
		var workspaces, ports, allow, deny, agent, profile string
		var detached, lastUsed int64
		if err := rows.Scan(&sb.ID, &sb.Name, &sb.State, &sb.Generation, &sb.Image, &sb.Workspace, &workspaces, &ports, &allow, &deny, &agent, &profile, &detached, &lastUsed, &sb.CPUs, &sb.MemoryMiB, &stoppedAt, &sb.Error, &created, &updated); err != nil {
			return nil, "", err
		}
		if err := decodeWorkspaces(workspaces, &sb); err != nil {
			return nil, "", err
		}
		if err := decodePorts(ports, &sb); err != nil {
			return nil, "", err
		}
		if err := decodePolicy(allow, deny, &sb); err != nil {
			return nil, "", err
		}
		decodeMeta(agent, profile, detached, lastUsed, &sb)
		sb.StoppedAt = fromUnix(stoppedAt)
		sb.CreatedAt = fromUnix(created)
		sb.UpdatedAt = fromUnix(updated)
		out = append(out, sb)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > pageSize {
		out = out[:pageSize]
		next = encodeOffset(offset + pageSize)
	}
	return out, next, nil
}

// Update updates a sandbox.
func (s *Store) Update(ctx context.Context, sb sandbox.Sandbox) error {
	workspaces, err := encodeWorkspaces(sb.Workspaces)
	if err != nil {
		return err
	}
	ports, err := encodePorts(sb.Ports)
	if err != nil {
		return err
	}
	allow, deny, err := encodePolicy(sb.Policy)
	if err != nil {
		return err
	}
	agent, profile, detached, lastUsed := metaValues(sb)
	res, err := s.db.ExecContext(ctx, `UPDATE sandboxes SET name=?, state=?, generation=?, image=?, workspace=?, workspaces=?, ports=?, allow_rules=?, deny_rules=?, agent=?, policy_profile=?, detached=?, last_used_at=?, cpus=?, memory_mib=?, stopped_at=?, error=?, updated_at=?
		WHERE id=?`,
		sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, workspaces, ports, allow, deny, agent, profile, detached, lastUsed, sb.CPUs, sb.MemoryMiB, toUnix(sb.StoppedAt), sb.Error, toUnix(sb.UpdatedAt), sb.ID)
	if err != nil {
		return mapSQLError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Delete deletes a sandbox.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sandboxes WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Create inserts an operation.
func (s *OperationStore) Create(opCtx context.Context, op operation.Operation) error {
	_, err := s.db.ExecContext(opCtx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt))
	return mapSQLError(err)
}

// Get returns an operation by ID.
func (s *OperationStore) Get(ctx context.Context, id string) (operation.Operation, error) {
	return s.getBy(ctx, "id", id)
}

// GetByIdempotencyKey returns the operation associated with a non-empty key.
func (s *OperationStore) GetByIdempotencyKey(ctx context.Context, key string) (operation.Operation, error) {
	if key == "" {
		return operation.Operation{}, core.ErrNotFound
	}
	return s.getBy(ctx, "idempotency_key", key)
}

func (s *OperationStore) getBy(ctx context.Context, column, value string) (operation.Operation, error) {
	var op operation.Operation
	var created, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at
		FROM operations WHERE `+column+`=?`, value).Scan(
		&op.ID, &op.SandboxID, &op.Kind, &op.State, &op.Generation, &op.IdempotencyKey, &op.Error, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return operation.Operation{}, core.ErrNotFound
	}
	if err != nil {
		return operation.Operation{}, err
	}
	op.CreatedAt = fromUnix(created)
	op.UpdatedAt = fromUnix(updated)
	return op, nil
}

// ListBySandbox returns operations for a sandbox.
func (s *OperationStore) ListBySandbox(ctx context.Context, sandboxID string) ([]operation.Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at
		FROM operations WHERE sandbox_id=? ORDER BY created_at, id`, sandboxID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []operation.Operation
	for rows.Next() {
		var op operation.Operation
		var created, updated int64
		if err := rows.Scan(&op.ID, &op.SandboxID, &op.Kind, &op.State, &op.Generation, &op.IdempotencyKey, &op.Error, &created, &updated); err != nil {
			return nil, err
		}
		op.CreatedAt = fromUnix(created)
		op.UpdatedAt = fromUnix(updated)
		out = append(out, op)
	}
	return out, rows.Err()
}

// ListUnfinished returns pending and running operations.
func (s *OperationStore) ListUnfinished(ctx context.Context) ([]operation.Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at
		FROM operations WHERE state IN ('pending','running') ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []operation.Operation
	for rows.Next() {
		var op operation.Operation
		var created, updated int64
		if err := rows.Scan(&op.ID, &op.SandboxID, &op.Kind, &op.State, &op.Generation, &op.IdempotencyKey, &op.Error, &created, &updated); err != nil {
			return nil, err
		}
		op.CreatedAt = fromUnix(created)
		op.UpdatedAt = fromUnix(updated)
		out = append(out, op)
	}
	return out, rows.Err()
}

// Update updates an operation.
func (s *OperationStore) Update(ctx context.Context, op operation.Operation) error {
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET state=?, generation=?, error=?, updated_at=? WHERE id=?`,
		op.State, op.Generation, op.Error, toUnix(op.UpdatedAt), op.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// CreateSandboxWithOperation inserts a sandbox and its operation atomically.
func (s *Store) CreateSandboxWithOperation(ctx context.Context, sb sandbox.Sandbox, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	workspaces, err := encodeWorkspaces(sb.Workspaces)
	if err != nil {
		return err
	}
	ports, err := encodePorts(sb.Ports)
	if err != nil {
		return err
	}
	allow, deny, err := encodePolicy(sb.Policy)
	if err != nil {
		return err
	}
	agent, profile, detached, lastUsed := metaValues(sb)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandboxes
		(id, name, state, generation, image, workspace, workspaces, ports, allow_rules, deny_rules, agent, policy_profile, detached, last_used_at, cpus, memory_mib, stopped_at, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sb.ID, sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, workspaces, ports, allow, deny, agent, profile, detached, lastUsed, sb.CPUs, sb.MemoryMiB, toUnix(sb.StoppedAt), sb.Error,
		toUnix(sb.CreatedAt), toUnix(sb.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// ApplySandboxOperation updates a sandbox and appends an operation atomically.
func (s *Store) ApplySandboxOperation(ctx context.Context, sb sandbox.Sandbox, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	agent, _, detached, lastUsed := metaValues(sb)
	res, err := tx.ExecContext(ctx, `UPDATE sandboxes SET state=?, generation=?, agent=?, detached=?, last_used_at=?, stopped_at=?, error=?, updated_at=? WHERE id=?`,
		sb.State, sb.Generation, agent, detached, lastUsed, toUnix(sb.StoppedAt), sb.Error, toUnix(sb.UpdatedAt), sb.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// DeleteSandboxWithOperation deletes a sandbox and appends an operation atomically.
func (s *Store) DeleteSandboxWithOperation(ctx context.Context, id string, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM sandboxes WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return core.ErrConflict
	}
	return err
}

func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func toUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromUnixNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func encodeOffset(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n)))
}

func decodeOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("invalid page token: %w", err)
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid page token")
	}
	return n, nil
}

func encodeWorkspaces(workspaces []sandbox.Workspace) (string, error) {
	if len(workspaces) == 0 {
		return "[]", nil
	}
	data, err := json.Marshal(workspaces)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeWorkspaces(value string, sb *sandbox.Sandbox) error {
	if value == "" || value == "[]" {
		if sb.Workspace != "" {
			sb.Workspaces = []sandbox.Workspace{{Path: sb.Workspace}}
		}
		return nil
	}
	if err := json.Unmarshal([]byte(value), &sb.Workspaces); err != nil {
		return fmt.Errorf("decode workspaces: %w", err)
	}
	if len(sb.Workspaces) == 0 && sb.Workspace != "" {
		sb.Workspaces = []sandbox.Workspace{{Path: sb.Workspace}}
	}
	return nil
}

func encodePorts(ports []sandbox.Port) (string, error) {
	if len(ports) == 0 {
		return "[]", nil
	}
	data, err := json.Marshal(ports)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodePorts(value string, sb *sandbox.Sandbox) error {
	if value == "" || value == "[]" {
		return nil
	}
	if err := json.Unmarshal([]byte(value), &sb.Ports); err != nil {
		return fmt.Errorf("decode ports: %w", err)
	}
	return nil
}

func encodePolicy(policy *sandbox.NetworkPolicy) (string, string, error) {
	if policy == nil || (len(policy.Allow) == 0 && len(policy.Deny) == 0) {
		return "[]", "[]", nil
	}
	allow, err := json.Marshal(policy.Allow)
	if err != nil {
		return "", "", err
	}
	deny, err := json.Marshal(policy.Deny)
	if err != nil {
		return "", "", err
	}
	return string(allow), string(deny), nil
}

func decodePolicy(allow, deny string, sb *sandbox.Sandbox) error {
	var policy sandbox.NetworkPolicy
	if allow != "" && allow != "[]" {
		if err := json.Unmarshal([]byte(allow), &policy.Allow); err != nil {
			return fmt.Errorf("decode allow rules: %w", err)
		}
	}
	if deny != "" && deny != "[]" {
		if err := json.Unmarshal([]byte(deny), &policy.Deny); err != nil {
			return fmt.Errorf("decode deny rules: %w", err)
		}
	}
	if len(policy.Allow) > 0 || len(policy.Deny) > 0 {
		sb.Policy = &policy
	}
	return nil
}

func metaValues(sb sandbox.Sandbox) (string, string, int64, int64) {
	if sb.Meta == nil {
		return "", "", 0, 0
	}
	detached := int64(0)
	if sb.Meta.Detached {
		detached = 1
	}
	return sb.Meta.Agent, sb.Meta.PolicyProfile, detached, toUnixNano(sb.Meta.LastUsedAt)
}

func decodeMeta(agent, profile string, detached, lastUsed int64, sb *sandbox.Sandbox) {
	if agent == "" && profile == "" && detached == 0 && lastUsed == 0 {
		return
	}
	sb.Meta = &sandbox.Meta{Agent: agent, PolicyProfile: profile, Detached: detached != 0, LastUsedAt: fromUnixNano(lastUsed)}
}

// RegistryCredentialIndex is non-secret metadata for a stored registry login.
type RegistryCredentialIndex struct {
	Registry    string
	Username    string
	Scope       string
	SandboxName string
}

// UpsertRegistryCredentialIndex records a non-secret registry credential summary.
func (s *Store) UpsertRegistryCredentialIndex(ctx context.Context, entry RegistryCredentialIndex) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO registry_credential_index (registry, scope, sandbox_name, username)
		VALUES (?,?,?,?)
		ON CONFLICT(registry, scope, sandbox_name) DO UPDATE SET username=excluded.username`,
		entry.Registry, entry.Scope, entry.SandboxName, entry.Username)
	if err != nil {
		return fmt.Errorf("record registry credential index: %w", err)
	}
	return nil
}

// DeleteRegistryCredentialIndex removes one non-secret registry credential summary.
func (s *Store) DeleteRegistryCredentialIndex(ctx context.Context, registry, scope, sandboxName string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM registry_credential_index WHERE registry=? AND scope=? AND sandbox_name=?`,
		registry, scope, sandboxName)
	if err != nil {
		return fmt.Errorf("delete registry credential index: %w", err)
	}
	return nil
}

// ListRegistryCredentialIndex lists non-secret registry credential summaries.
func (s *Store) ListRegistryCredentialIndex(ctx context.Context) ([]RegistryCredentialIndex, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT registry, username, scope, sandbox_name FROM registry_credential_index ORDER BY registry, scope, sandbox_name`)
	if err != nil {
		return nil, fmt.Errorf("list registry credential index: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RegistryCredentialIndex
	for rows.Next() {
		var entry RegistryCredentialIndex
		if err := rows.Scan(&entry.Registry, &entry.Username, &entry.Scope, &entry.SandboxName); err != nil {
			return nil, fmt.Errorf("scan registry credential index: %w", err)
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// ServiceSecretIndex is non-secret metadata for a stored service secret.
type ServiceSecretIndex struct {
	Service     string
	Scope       string
	SandboxName string
}

// UpsertServiceSecretIndex records a non-secret service secret summary.
func (s *Store) UpsertServiceSecretIndex(ctx context.Context, entry ServiceSecretIndex) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_secret_index (service, scope, sandbox_name, updated_at)
		VALUES (?,?,?,?)
		ON CONFLICT(service, scope, sandbox_name) DO UPDATE SET updated_at=excluded.updated_at`,
		entry.Service, entry.Scope, entry.SandboxName, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("record service secret index: %w", err)
	}
	return nil
}

// DeleteServiceSecretIndex removes one non-secret service secret summary.
func (s *Store) DeleteServiceSecretIndex(ctx context.Context, service, scope, sandboxName string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_secret_index WHERE service=? AND scope=? AND sandbox_name=?`,
		service, scope, sandboxName)
	if err != nil {
		return fmt.Errorf("delete service secret index: %w", err)
	}
	return nil
}

// ListServiceSecretIndex lists non-secret service secret summaries.
func (s *Store) ListServiceSecretIndex(ctx context.Context) ([]ServiceSecretIndex, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service, scope, sandbox_name FROM service_secret_index ORDER BY service, scope, sandbox_name`)
	if err != nil {
		return nil, fmt.Errorf("list service secret index: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ServiceSecretIndex
	for rows.Next() {
		var entry ServiceSecretIndex
		if err := rows.Scan(&entry.Service, &entry.Scope, &entry.SandboxName); err != nil {
			return nil, fmt.Errorf("scan service secret index: %w", err)
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// GetSetting returns a daemon setting.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", core.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get setting: %w", err)
	}
	return value, nil
}

// SetSetting stores a daemon setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("set setting: %w", err)
	}
	return nil
}

// DeleteSetting removes a daemon setting. Missing keys are not an error.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, key); err != nil {
		return fmt.Errorf("delete setting: %w", err)
	}
	return nil
}
