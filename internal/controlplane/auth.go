package controlplane

import (
	"net/http"
	"strings"
)

// Principal is the authenticated caller for one request. Org is empty for
// installation-wide static credentials and set for credentials bound to a
// single organization, such as OIDC tokens.
type Principal struct {
	Role    Role
	Org     string
	Subject string
}

func (p Principal) allowsOrg(org string) bool {
	return p.Org == "" || p.Org == org
}

func (p Principal) hasRole(allowed ...Role) bool {
	for _, role := range allowed {
		if p.Role == role {
			return true
		}
	}
	return false
}

// requireRole authenticates the request and rejects callers that do not hold
// one of the allowed roles. Authentication failures are 401; authenticated
// callers without the required role are 403.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, allowed ...Role) (Principal, bool) {
	principal, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="rheic-control-plane"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return Principal{}, false
	}
	if !principal.hasRole(allowed...) {
		writeError(w, http.StatusForbidden, "forbidden")
		return Principal{}, false
	}
	return principal, true
}

// authenticate resolves a bearer token to a principal. Static credentials are
// checked first; OIDC validation is appended by the OIDC configuration when
// enabled. Both paths fail closed.
func (s *Server) authenticate(r *http.Request) (Principal, bool) {
	token, ok := bearerToken(r)
	if !ok {
		return Principal{}, false
	}
	role, ok := s.credentials.Authenticate(token)
	if !ok {
		return Principal{}, false
	}
	return Principal{Role: role}, true
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := header[len(prefix):]
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}
