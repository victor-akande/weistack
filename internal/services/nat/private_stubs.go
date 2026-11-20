package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Stubs for private NAT operations, implemented in the follow-up PR.

func (s *Service) handleCreatePrivateNat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreatePrivateNat")
}

func (s *Service) handleListPrivateNats(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListPrivateNats")
}

func (s *Service) handleShowPrivateNat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowPrivateNat")
}

func (s *Service) handleUpdatePrivateNat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdatePrivateNat")
}

func (s *Service) handleDeletePrivateNat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeletePrivateNat")
}

func (s *Service) handleListSpecs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListSpecs")
}

func (s *Service) handleCreateTransitSubnet(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateTransitSubnet")
}

func (s *Service) handleListTransitSubnets(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitSubnet")
}

func (s *Service) handleShowTransitSubnet(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowTransitSubnet")
}

func (s *Service) handleUpdateTransitSubnet(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdateTransitSubnet")
}

func (s *Service) handleDeleteTransitSubnet(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteTransitSubnet")
}

func (s *Service) handleCreateTransitIP(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateTransitIp")
}

func (s *Service) handleListTransitIPs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitIps")
}

func (s *Service) handleShowTransitIP(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowTransitIp")
}

func (s *Service) handleDeleteTransitIP(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteTransitIp")
}

func (s *Service) handleCreatePrivateSnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreatePrivateSnat")
}

func (s *Service) handleListPrivateSnats(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListPrivateSnats")
}

func (s *Service) handleShowPrivateSnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowPrivateSnat")
}

func (s *Service) handleUpdatePrivateSnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdatePrivateSnat")
}

func (s *Service) handleDeletePrivateSnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeletePrivateSnat")
}

func (s *Service) handleCreatePrivateDnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreatePrivateDnat")
}

func (s *Service) handleListPrivateDnats(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListPrivateDnats")
}

func (s *Service) handleShowPrivateDnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowPrivateDnat")
}

func (s *Service) handleUpdatePrivateDnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "UpdatePrivateDnat")
}

func (s *Service) handleDeletePrivateDnat(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeletePrivateDnat")
}

func (s *Service) handleShowPrivateNatTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowPrivateNatTags")
}

func (s *Service) handleCreatePrivateNatTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreatePrivateNatTag")
}

func (s *Service) handleDeletePrivateNatTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeletePrivateNatTag")
}

func (s *Service) handleBatchPrivateNatTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "BatchCreateDeletePrivateNatTags")
}

func (s *Service) handleListPrivateNatTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListPrivateNatTags")
}

func (s *Service) handleListPrivateNatsByTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListPrivateNatsByTags")
}

func (s *Service) handleShowTransitIPTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowTransitIpTags")
}

func (s *Service) handleCreateTransitIPTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateTransitIpTag")
}

func (s *Service) handleDeleteTransitIPTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteTransitIpTag")
}

func (s *Service) handleBatchTransitIPTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "BatchCreateDeleteTransitIpTags")
}

func (s *Service) handleListTransitIPTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitIpTags")
}

func (s *Service) handleListTransitIPsByTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitIpsByTags")
}

func (s *Service) handleShowTransitSubnetTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ShowTransitSubnetTags")
}

func (s *Service) handleCreateTransitSubnetTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "CreateTransitSubnetTag")
}

func (s *Service) handleDeleteTransitSubnetTag(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "DeleteTransitSubnetTag")
}

func (s *Service) handleBatchTransitSubnetTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "BatchCreateDeleteTransitSubnetTags")
}

func (s *Service) handleListTransitSubnetTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitSubnetTags")
}

func (s *Service) handleListTransitSubnetsByTags(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListTransitSubnetsByTags")
}
