package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) handleCreateSnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateNatGatewaySnatRule")
}

func (s *Service) handleListSnatRules(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewaySnatRules")
}

func (s *Service) handleShowSnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowNatGatewaySnatRule")
}

func (s *Service) handleUpdateSnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdateNatGatewaySnatRule")
}

func (s *Service) handleDeleteSnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteNatGatewaySnatRule")
}

func (s *Service) handleCreateDnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateNatGatewayDnatRule")
}

func (s *Service) handleBatchCreateDnatRules(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "BatchCreateNatGatewayDnatRules")
}

func (s *Service) handleListDnatRules(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewayDnatRules")
}

func (s *Service) handleShowDnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowNatGatewayDnatRule")
}

func (s *Service) handleUpdateDnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdateNatGatewayDnatRule")
}

func (s *Service) handleDeleteDnatRule(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteNatGatewayDnatRule")
}
