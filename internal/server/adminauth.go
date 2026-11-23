package server

import (
	"errors"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/identity"
)

// Under -iam=enforce the admin API answers only the administrator: it
// can wipe the data, read every record and mint accounts. Health and the
// CA certificate stay open, since clients need them before they have
// credentials. In accept mode nothing changes, except for requests from
// other machines (-lan), which are always checked.

// maxAdminBody bounds an admin request's body while its signature is
// checked. Admin bodies are small JSON documents.
const maxAdminBody = 1 << 20

var errNotAdmin = apierr.New(http.StatusForbidden, "WeiStack.0403",
	"under -iam=enforce the admin API answers only the administrator's credentials (-admin-access-key, or the keys in admin-credentials.json)")

// adminAuth admits only requests signed with the administrator's keys,
// or carrying a token of theirs, when credentials are enforced.
func (s *Server) adminAuth(next http.Handler) http.Handler {
	m := &mounted{maxBody: maxAdminBody}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.enforcing(r) {
			next.ServeHTTP(w, r)
			return
		}
		id, err := s.verify(m, r, []string{r.URL.Path})
		if err == nil && !s.isAdministrator(id.Principal) {
			err = errNotAdmin
		}
		if err != nil {
			var apiErr *apierr.Error
			if !errors.As(err, &apiErr) {
				s.log.ErrorContext(r.Context(), "checking admin credentials", "error", err)
				apiErr = apierr.Internal(err)
			}
			s.log.WarnContext(r.Context(), "refused an admin request without the administrator's credentials",
				"path", r.URL.Path, "code", apiErr.Code, "remote", r.RemoteAddr)
			apierr.Write(w, r, apierr.StyleFlat, apiErr)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

// isAdministrator reports whether p is the bootstrap administrator of the
// primary account, with credentials not narrowed by session policies.
func (s *Server) isAdministrator(p identity.Principal) bool {
	return p.Admin && p.Session == nil && p.AccountID == s.dir.Account().ID
}
