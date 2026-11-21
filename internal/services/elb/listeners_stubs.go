package elb

import "net/http"

// Wave 0 stubs for W2 (listeners). W2 removes this file.

func (s *Service) handleCreateListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateListener")(w, r, t)
}

func (s *Service) handleListListeners(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListListeners")(w, r, t)
}

func (s *Service) handleShowListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowListener")(w, r, t)
}

func (s *Service) handleUpdateListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateListener")(w, r, t)
}

func (s *Service) handleDeleteListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteListener")(w, r, t)
}

func (s *Service) handleDeleteListenerForce(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteListenerForce")(w, r, t)
}
