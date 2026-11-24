package kps

import (
	"context"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) createKeypair(_ context.Context, _ Tenant, _ createKeypairAction) (Keypair, string, error) {
	return Keypair{}, "", apierr.NotImplemented("kps", "CreateKeypair")
}

func (s *Service) getKeypair(_ context.Context, _ Tenant, _ string) (Keypair, error) {
	return Keypair{}, apierr.NotImplemented("kps", "ListKeypairDetail")
}

func (s *Service) listKeypairs(_ context.Context, _ Tenant, _ string, _ int) ([]Keypair, string, string, error) {
	return nil, "", "", apierr.NotImplemented("kps", "ListKeypairs")
}

func (s *Service) deleteKeypair(_ context.Context, _ Tenant, _ string) error {
	return apierr.NotImplemented("kps", "DeleteKeypair")
}

func (s *Service) handleCreateKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "CreateKeypair")
}

func (s *Service) handleListKeypairs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ListKeypairs")
}

func (s *Service) handleListKeypairDetail(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ListKeypairDetail")
}

func (s *Service) handleUpdateKeypairDescription(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "UpdateKeypairDescription")
}

func (s *Service) handleDeleteKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "DeleteKeypair")
}
