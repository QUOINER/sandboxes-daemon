package controlplane

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultAuditPageLimit = 100
	maxAuditPageLimit     = 500
)

// AuditRecord is a stored audit event with its stable storage identifier. The
// identifier is the pagination cursor; it is monotonic per server.
type AuditRecord struct {
	ID int64 `json:"id"`
	AuditEvent
}

// AuditPage is the bounded JSON representation returned by the audit export
// endpoint. Events are ordered by ascending ID. NextCursor is empty on the last
// page and otherwise is the ID to pass as the next `after` query parameter.
type AuditPage struct {
	Events     []AuditRecord `json:"events"`
	NextCursor string        `json:"nextCursor"`
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRole(w, r, RoleAdmin, RoleReader)
	if !ok {
		return
	}
	org := r.PathValue("org")
	if !validOrgID(org) {
		writeError(w, http.StatusBadRequest, "invalid_org_id")
		return
	}
	if !principal.allowsOrg(org) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	limit, after, code := parseAuditPage(r)
	if code != "" {
		writeError(w, http.StatusBadRequest, code)
		return
	}
	records, more, err := s.readAuditPage(r, org, after, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}
	nextCursor := ""
	if more && len(records) > 0 {
		nextCursor = strconv.FormatInt(records[len(records)-1].ID, 10)
	}
	writeJSON(w, http.StatusOK, AuditPage{Events: records, NextCursor: nextCursor})
}

func parseAuditPage(r *http.Request) (int, int64, string) {
	query := r.URL.Query()
	limit := defaultAuditPageLimit
	if query.Has("limit") {
		parsed, err := strconv.Atoi(query.Get("limit"))
		if err != nil || parsed < 1 || parsed > maxAuditPageLimit {
			return 0, 0, "invalid_limit"
		}
		limit = parsed
	}
	var after int64
	if query.Has("after") {
		parsed, err := strconv.ParseInt(query.Get("after"), 10, 64)
		if err != nil || parsed < 0 {
			return 0, 0, "invalid_cursor"
		}
		after = parsed
	}
	return limit, after, ""
}

func (s *Server) readAuditPage(r *http.Request, org string, after int64, limit int) ([]AuditRecord, bool, error) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT id, occurred_at, sandbox_id, operation_id, action, resource, decision, rule_id
FROM audit_events WHERE org_id=? AND id>? ORDER BY id ASC LIMIT ?`, org, after, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	records := make([]AuditRecord, 0, limit)
	for rows.Next() {
		var record AuditRecord
		var occurredAt string
		if err := rows.Scan(&record.ID, &occurredAt, &record.SandboxID, &record.OperationID, &record.Action, &record.Resource, &record.Decision, &record.RuleID); err != nil {
			return nil, false, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, false, errors.New("stored audit timestamp is invalid")
		}
		record.OccurredAt = parsed.UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(records) > limit {
		return records[:limit], true, nil
	}
	return records, false, nil
}
