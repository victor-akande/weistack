package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) handleShowNatGatewayTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowNatGatewayTag")
}

func (s *Service) handleCreateNatGatewayTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateNatGatewayTag")
}

func (s *Service) handleDeleteNatGatewayTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteNatGatewayTag")
}

func (s *Service) handleBatchNatGatewayTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "BatchCreateDeleteNatGatewayTag")
}

func (s *Service) handleListNatGatewayTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewayTag")
}

func (s *Service) handleListNatGatewayByTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewayByTag")
}
