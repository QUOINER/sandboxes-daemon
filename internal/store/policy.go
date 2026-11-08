package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

const maxPolicyPayloadBytes = 1 << 20

// ErrPolicyRevisionNotNewer reports an attempt to replace a stored signed
// policy bundle with the same or an older revision. The write is refused so a
// server or client bug cannot silently roll organization policy back.
var ErrPolicyRevisionNotNewer = errors.New("stored policy revision would not increase")

// StoredPolicyBundle is a locally persisted, already verified signed policy
// bundle. Payload is the normalized JSON encoding of the policy payload and is
// re-verified by the sync client as needed.
type StoredPolicyBundle struct {
	OrgID     string
	Revision  uint64
	Payload   []byte
	Signature string
	IssuedAt  time.Time
	ExpiresAt time.Time
	SyncedAt  time.Time
}

// GetPolicyBundle returns the stored verified bundle for an org. The boolean is
// false when no bundle has been synced yet.
func (s *Store) GetPolicyBundle(ctx context.Context, org string) (StoredPolicyBundle, bool, error) {
	if org == "" {
		return StoredPolicyBundle{}, false, errors.New("policy organization is required")
	}
	var (
		bundle              StoredPolicyBundle
		revision            int64
		issuedAt, expiresAt int64
		syncedAt            int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT org_id, revision, payload, signature, issued_at, expires_at, synced_at
FROM org_policy_bundles WHERE org_id=?`, org).Scan(
		&bundle.OrgID, &revision, &bundle.Payload, &bundle.Signature, &issuedAt, &expiresAt, &syncedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredPolicyBundle{}, false, nil
	}
	if err != nil {
		return StoredPolicyBundle{}, false, fmt.Errorf("read stored policy bundle: %w", err)
	}
	if revision <= 0 {
		return StoredPolicyBundle{}, false, errors.New("stored policy revision is invalid")
	}
	bundle.Revision = uint64(revision)
	bundle.IssuedAt = fromUnixNano(issuedAt)
	bundle.ExpiresAt = fromUnixNano(expiresAt)
	bundle.SyncedAt = fromUnixNano(syncedAt)
	return bundle, true, nil
}

// SavePolicyBundle persists a verified bundle if its revision is strictly newer
// than the stored one. The revision check and write are one SQL statement, so a
// concurrent writer cannot bypass it.
func (s *Store) SavePolicyBundle(ctx context.Context, bundle StoredPolicyBundle) error {
	if bundle.OrgID == "" {
		return errors.New("policy organization is required")
	}
	if bundle.Revision == 0 || bundle.Revision > math.MaxInt64 {
		return errors.New("policy revision is out of range")
	}
	if len(bundle.Payload) == 0 || len(bundle.Payload) > maxPolicyPayloadBytes {
		return errors.New("policy payload size is out of range")
	}
	if bundle.Signature == "" || len(bundle.Signature) > 1024 {
		return errors.New("policy signature is missing or oversized")
	}
	if bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero() || !bundle.ExpiresAt.After(bundle.IssuedAt) {
		return errors.New("policy bundle lifetime is invalid")
	}
	revision := int64(bundle.Revision)
	result, err := s.db.ExecContext(ctx, `INSERT INTO org_policy_bundles(org_id, revision, payload, signature, issued_at, expires_at, synced_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(org_id) DO UPDATE SET
	revision=excluded.revision, payload=excluded.payload, signature=excluded.signature,
	issued_at=excluded.issued_at, expires_at=excluded.expires_at, synced_at=excluded.synced_at
WHERE excluded.revision > org_policy_bundles.revision`,
		bundle.OrgID, revision, bundle.Payload, bundle.Signature,
		toUnixNano(bundle.IssuedAt), toUnixNano(bundle.ExpiresAt), toUnixNano(bundle.SyncedAt))
	if err != nil {
		return fmt.Errorf("save policy bundle: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("confirm policy bundle write: %w", err)
	}
	if changed != 1 {
		return ErrPolicyRevisionNotNewer
	}
	return nil
}
