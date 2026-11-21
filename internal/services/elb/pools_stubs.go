package elb

import "net/http"

// Wave 0 stubs for W3 (pools and health monitors). W3 removes this file.

func (s *Service) handleCreatePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreatePool")(w, r, t)
}

func (s *Service) handleListPools(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListPools")(w, r, t)
}

func (s *Service) handleShowPool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowPool")(w, r, t)
}

func (s *Service) handleUpdatePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdatePool")(w, r, t)
}

func (s *Service) handleDeletePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeletePool")(w, r, t)
}

func (s *Service) handleDeletePoolCascade(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeletePoolCascade")(w, r, t)
}

func (s *Service) handleCreateHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateHealthMonitor")(w, r, t)
}

func (s *Service) handleListHealthMonitors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListHealthMonitors")(w, r, t)
}

func (s *Service) handleShowHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowHealthMonitor")(w, r, t)
}

func (s *Service) handleUpdateHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateHealthMonitor")(w, r, t)
}

func (s *Service) handleDeleteHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteHealthMonitor")(w, r, t)
}
