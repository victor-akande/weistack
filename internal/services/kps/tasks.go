package kps

import (
	"context"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Resume reschedules any running KPS tasks found in the store after a restart.
func (s *Service) Resume(_ context.Context) error {
	return nil
}

func (s *Service) handleAssociateKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "AssociateKeypair")
}

func (s *Service) handleDisassociateKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "DisassociateKeypair")
}

func (s *Service) handleBatchAssociateKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "BatchAssociateKeypair")
}

func (s *Service) handleListKeypairTask(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ListKeypairTask")
}

func (s *Service) handleListRunningTask(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ListRunningTask")
}

func (s *Service) handleListFailedTask(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ListFailedTask")
}

func (s *Service) handleDeleteFailedTask(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "DeleteFailedTask")
}

func (s *Service) handleDeleteAllFailedTask(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "DeleteAllFailedTask")
}
