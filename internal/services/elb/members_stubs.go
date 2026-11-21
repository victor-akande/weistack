package elb

import (
	"context"
	"net/http"
)

// Wave 0 stubs for W4 (members and member health). W4 removes this file.

func (s *Service) memberOperatingStatus(context.Context, Tenant, member, pool, *healthMonitor, string) (string, error) {
	return StatusNoMonitor, nil
}

func (s *Service) handleCreateMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateMember")(w, r, t)
}

func (s *Service) handleListMembers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListMembers")(w, r, t)
}

func (s *Service) handleShowMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowMember")(w, r, t)
}

func (s *Service) handleUpdateMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateMember")(w, r, t)
}

func (s *Service) handleDeleteMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteMember")(w, r, t)
}

func (s *Service) handleListAllMembers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListAllMembers")(w, r, t)
}
