package server

import (
	"context"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// With -lan, other machines reach WeiStack on a listener of their own
// (internal/app), whose requests carry a network mark. Requests with the
// mark always have their credentials checked and permissions enforced,
// as under -iam=enforce, whatever -iam says; their admin API answers
// only the administrator, and never dumps or wipes the data.

type networkKey struct{}

// withNetwork marks ctx as a request from another machine.
func withNetwork(ctx context.Context) context.Context {
	return context.WithValue(ctx, networkKey{}, true)
}

// fromNetwork reports whether ctx is a request from another machine.
func fromNetwork(ctx context.Context) bool {
	v, _ := ctx.Value(networkKey{}).(bool)
	return v
}

// NetworkHandler serves the requests of other machines (-lan).
func (s *Server) NetworkHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.proxy.ServeHTTP(w, r.WithContext(withNetwork(r.Context())))
	})
}

var errLocalOnly = apierr.New(http.StatusForbidden, "WeiStack.0403",
	"this admin operation is only available from WeiStack's own machine, not over -lan")

// localOnly refuses requests from other machines.
func (s *Server) localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fromNetwork(r.Context()) {
			s.log.WarnContext(r.Context(), "refused an admin operation from another machine",
				"path", r.URL.Path, "remote", r.RemoteAddr)
			apierr.Write(w, r, apierr.StyleFlat, errLocalOnly)
			return
		}
		next.ServeHTTP(w, r)
	})
}
