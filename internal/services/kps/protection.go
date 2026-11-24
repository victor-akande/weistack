package kps

import (
	"context"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) sealPrivateKey(_ context.Context, _ Tenant, _ *Keypair, _ string, _ *encryptionWire) error {
	return apierr.NotImplemented("kps", "sealPrivateKey")
}

func (s *Service) openPrivateKey(_ context.Context, _ Tenant, _ Keypair) (string, error) {
	return "", apierr.NotImplemented("kps", "openPrivateKey")
}

func verifyKeyPairMatch(_, _ string) error {
	return apierr.NotImplemented("kps", "verifyKeyPairMatch")
}

func (s *Service) handleImportPrivateKey(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ImportPrivateKey")
}

func (s *Service) handleExportPrivateKey(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ExportPrivateKey")
}

func (s *Service) handleClearPrivateKey(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "ClearPrivateKey")
}

func (s *Service) handleBatchImportKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "BatchImportKeypair")
}

func (s *Service) handleBatchExportPrivateKey(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("kps", "BatchExportPrivateKey")
}
