package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) handleCreateNatGateway(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateNatGateway")
}

func (s *Service) handleListNatGateways(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGateways")
}

func (s *Service) handleShowNatGateway(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowNatGateway")
}

func (s *Service) handleUpdateNatGateway(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdateNatGateway")
}

func (s *Service) handleDeleteNatGateway(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteNatGateway")
}

func (s *Service) handleListNatGatewaySpecs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewaySpecs")
}
