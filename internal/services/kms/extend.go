package kms

import "github.com/go-chi/chi/v5"

// Extension adds routes of a service that shares the KMS endpoint (KPS).
type Extension interface {
	Routes(r chi.Router)
}

// Extend adds e's routes. Call it before the server registers routes.
func (s *Service) Extend(e Extension) {
	if e != nil {
		s.exts = append(s.exts, e)
	}
}
