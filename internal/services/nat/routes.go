package nat

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	act := authz.Action
	gw := authz.Param("gateway", "nat_gateway_id")
	pgw := authz.Param("privateGateway", "gateway_id")
	pgwTag := authz.Param("privateGateway", "resource_id")
	tip := authz.Param("privateTransitIp", "transit_ip_id")
	tipTag := authz.Param("privateTransitIp", "resource_id")
	tsn := authz.Param("transitSubnet", "transit_subnet_id")
	tsnTag := authz.Param("transitSubnet", "resource_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{
			Name:  "nat",
			Style: apierr.StyleFlatRequestID,
			Deny:  denied,
		}))

		// §3.1 Public NAT gateways, §3.2 SNAT rules, §3.3 DNAT rules.
		r.Route("/v2/{project_id}", func(r chi.Router) {
			r.With(act("nat:natGateways:create")).Post("/nat_gateways", s.handle("CreateNatGateway", s.handleCreateNatGateway))
			r.With(act("nat:natGateways:list")).Get("/nat_gateways", s.handle("ListNatGateways", s.handleListNatGateways))
			r.With(act("nat:natGateways:get", gw)).Get("/nat_gateways/{nat_gateway_id}", s.handle("ShowNatGateway", s.handleShowNatGateway))
			r.With(act("nat:natGateways:update", gw)).Put("/nat_gateways/{nat_gateway_id}", s.handle("UpdateNatGateway", s.handleUpdateNatGateway))
			r.With(act("nat:natGateways:delete", gw)).Delete("/nat_gateways/{nat_gateway_id}", s.handle("DeleteNatGateway", s.handleDeleteNatGateway))
			r.With(authz.Public()).Get("/nat_gateway_specs", s.handle("ListNatGatewaySpecs", s.handleListNatGatewaySpecs))

			r.With(act("nat:snatRules:create")).Post("/snat_rules", s.handle("CreateNatGatewaySnatRule", s.handleCreateSnatRule))
			r.With(act("nat:snatRules:list")).Get("/snat_rules", s.handle("ListNatGatewaySnatRules", s.handleListSnatRules))
			r.With(act("nat:snatRules:get")).Get("/snat_rules/{snat_rule_id}", s.handle("ShowNatGatewaySnatRule", s.handleShowSnatRule))
			r.With(act("nat:snatRules:update")).Put("/snat_rules/{snat_rule_id}", s.handle("UpdateNatGatewaySnatRule", s.handleUpdateSnatRule))
			r.With(act("nat:snatRules:delete")).Delete("/nat_gateways/{nat_gateway_id}/snat_rules/{snat_rule_id}", s.handle("DeleteNatGatewaySnatRule", s.handleDeleteSnatRule))

			r.With(act("nat:dnatRules:create")).Post("/dnat_rules", s.handle("CreateNatGatewayDnatRule", s.handleCreateDnatRule))
			r.With(act("nat:dnatRules:create")).Post("/dnat_rules/batch", s.handle("BatchCreateNatGatewayDnatRules", s.handleBatchCreateDnatRules))
			r.With(act("nat:dnatRules:list")).Get("/dnat_rules", s.handle("ListNatGatewayDnatRules", s.handleListDnatRules))
			r.With(act("nat:dnatRules:get")).Get("/dnat_rules/{dnat_rule_id}", s.handle("ShowNatGatewayDnatRule", s.handleShowDnatRule))
			r.With(act("nat:dnatRules:update")).Put("/dnat_rules/{dnat_rule_id}", s.handle("UpdateNatGatewayDnatRule", s.handleUpdateDnatRule))
			r.With(act("nat:dnatRules:delete")).Delete("/nat_gateways/{nat_gateway_id}/dnat_rules/{dnat_rule_id}", s.handle("DeleteNatGatewayDnatRule", s.handleDeleteDnatRule))
		})

		// §3.4 Public gateway tags (v2.0 prefix used by Terraform provider).
		r.Route("/v2.0/{project_id}", func(r chi.Router) {
			s.mountPublicTagRoutes(r, act, gw)
		})

		// §3.4 Public gateway tags (v3), §3.5–§3.9 Private NAT, §3.10 Private tags.
		r.Route("/v3/{project_id}", func(r chi.Router) {
			s.mountPublicTagRoutes(r, act, gw)

			r.Route("/private-nat", func(r chi.Router) {
				// §3.5 Private NAT gateways and specs.
				r.With(act("nat:privateNatGateways:create")).Post("/gateways", s.handle("CreatePrivateNat", s.handleCreatePrivateNat))
				r.With(act("nat:privateNatGateways:list")).Get("/gateways", s.handle("ListPrivateNats", s.handleListPrivateNats))
				r.With(act("nat:privateNatGateways:get", pgw)).Get("/gateways/{gateway_id}", s.handle("ShowPrivateNat", s.handleShowPrivateNat))
				r.With(act("nat:privateNatGateways:update", pgw)).Put("/gateways/{gateway_id}", s.handle("UpdatePrivateNat", s.handleUpdatePrivateNat))
				r.With(act("nat:privateNatGateways:delete", pgw)).Delete("/gateways/{gateway_id}", s.handle("DeletePrivateNat", s.handleDeletePrivateNat))
				r.With(authz.Public()).Get("/specs", s.handle("ListSpecs", s.handleListSpecs))

				// §3.6 Transit subnets.
				r.With(act("nat:transitSubnets:create")).Post("/transit-subnets", s.handle("CreateTransitSubnet", s.handleCreateTransitSubnet))
				r.With(act("nat:transitSubnets:list")).Get("/transit-subnets", s.handle("ListTransitSubnet", s.handleListTransitSubnets))
				r.With(act("nat:transitSubnets:get", tsn)).Get("/transit-subnets/{transit_subnet_id}", s.handle("ShowTransitSubnet", s.handleShowTransitSubnet))
				r.With(act("nat:transitSubnets:update", tsn)).Put("/transit-subnets/{transit_subnet_id}", s.handle("UpdateTransitSubnet", s.handleUpdateTransitSubnet))
				r.With(act("nat:transitSubnets:delete", tsn)).Delete("/transit-subnets/{transit_subnet_id}", s.handle("DeleteTransitSubnet", s.handleDeleteTransitSubnet))

				// §3.7 Transit IPs.
				r.With(act("nat:privateNatTransitIps:create")).Post("/transit-ips", s.handle("CreateTransitIp", s.handleCreateTransitIP))
				r.With(act("nat:privateNatTransitIps:list")).Get("/transit-ips", s.handle("ListTransitIps", s.handleListTransitIPs))
				r.With(act("nat:privateNatTransitIps:get", tip)).Get("/transit-ips/{transit_ip_id}", s.handle("ShowTransitIp", s.handleShowTransitIP))
				r.With(act("nat:privateNatTransitIps:delete", tip)).Delete("/transit-ips/{transit_ip_id}", s.handle("DeleteTransitIp", s.handleDeleteTransitIP))

				// §3.8 Private SNAT rules.
				r.With(act("nat:privateNatSnatRules:create")).Post("/snat-rules", s.handle("CreatePrivateSnat", s.handleCreatePrivateSnat))
				r.With(act("nat:privateNatSnatRules:list")).Get("/snat-rules", s.handle("ListPrivateSnats", s.handleListPrivateSnats))
				r.With(act("nat:privateNatSnatRules:get")).Get("/snat-rules/{snat_rule_id}", s.handle("ShowPrivateSnat", s.handleShowPrivateSnat))
				r.With(act("nat:privateNatSnatRules:update")).Put("/snat-rules/{snat_rule_id}", s.handle("UpdatePrivateSnat", s.handleUpdatePrivateSnat))
				r.With(act("nat:privateNatSnatRules:delete")).Delete("/snat-rules/{snat_rule_id}", s.handle("DeletePrivateSnat", s.handleDeletePrivateSnat))

				// §3.9 Private DNAT rules.
				r.With(act("nat:privateNatDnatRules:create")).Post("/dnat-rules", s.handle("CreatePrivateDnat", s.handleCreatePrivateDnat))
				r.With(act("nat:privateNatDnatRules:list")).Get("/dnat-rules", s.handle("ListPrivateDnats", s.handleListPrivateDnats))
				r.With(act("nat:privateNatDnatRules:get")).Get("/dnat-rules/{dnat_rule_id}", s.handle("ShowPrivateDnat", s.handleShowPrivateDnat))
				r.With(act("nat:privateNatDnatRules:update")).Put("/dnat-rules/{dnat_rule_id}", s.handle("UpdatePrivateDnat", s.handleUpdatePrivateDnat))
				r.With(act("nat:privateNatDnatRules:delete")).Delete("/dnat-rules/{dnat_rule_id}", s.handle("DeletePrivateDnat", s.handleDeletePrivateDnat))
			})

			// §3.10 Private gateway tags.
			r.With(act("nat:privateNatGateways:listTags", pgwTag)).Get("/private-nat-gateways/{resource_id}/tags", s.handle("ShowPrivateNatTags", s.handleShowPrivateNatTags))
			r.With(act("nat:privateNatGateways:createTags", pgwTag)).Post("/private-nat-gateways/{resource_id}/tags", s.handle("CreatePrivateNatTag", s.handleCreatePrivateNatTag))
			r.With(act("nat:privateNatGateways:deleteTags", pgwTag)).Delete("/private-nat-gateways/{resource_id}/tags/{key}", s.handle("DeletePrivateNatTag", s.handleDeletePrivateNatTag))
			r.With(act("nat:privateNatGateways:createTags", pgwTag)).Post("/private-nat-gateways/{resource_id}/tags/action", s.handle("BatchCreateDeletePrivateNatTags", s.handleBatchPrivateNatTags))
			r.With(act("nat:privateNatGateways:listTags")).Get("/private-nat-gateways/tags", s.handle("ListPrivateNatTags", s.handleListPrivateNatTags))
			r.With(act("nat:privateNatGateways:listTags")).Post("/private-nat-gateways/resource_instances/action", s.handle("ListPrivateNatsByTags", s.handleListPrivateNatsByTags))

			// §3.10 Transit IP tags.
			r.With(act("nat:privateNatTransitIps:listTags", tipTag)).Get("/transit-ips/{resource_id}/tags", s.handle("ShowTransitIpTags", s.handleShowTransitIPTags))
			r.With(act("nat:privateNatTransitIps:createTags", tipTag)).Post("/transit-ips/{resource_id}/tags", s.handle("CreateTransitIpTag", s.handleCreateTransitIPTag))
			r.With(act("nat:privateNatTransitIps:deleteTags", tipTag)).Delete("/transit-ips/{resource_id}/tags/{key}", s.handle("DeleteTransitIpTag", s.handleDeleteTransitIPTag))
			r.With(act("nat:privateNatTransitIps:createTags", tipTag)).Post("/transit-ips/{resource_id}/tags/action", s.handle("BatchCreateDeleteTransitIpTags", s.handleBatchTransitIPTags))
			r.With(act("nat:privateNatTransitIps:listTags")).Get("/transit-ips/tags", s.handle("ListTransitIpTags", s.handleListTransitIPTags))
			r.With(act("nat:privateNatTransitIps:listTags")).Post("/transit-ips/resource_instances/action", s.handle("ListTransitIpsByTags", s.handleListTransitIPsByTags))

			// §3.10 Transit subnet tags.
			r.With(act("nat:transitSubnets:listTags", tsnTag)).Get("/transit-subnets/{resource_id}/tags", s.handle("ShowTransitSubnetTags", s.handleShowTransitSubnetTags))
			r.With(act("nat:transitSubnets:createTags", tsnTag)).Post("/transit-subnets/{resource_id}/tags", s.handle("CreateTransitSubnetTag", s.handleCreateTransitSubnetTag))
			r.With(act("nat:transitSubnets:deleteTags", tsnTag)).Delete("/transit-subnets/{resource_id}/tags/{key}", s.handle("DeleteTransitSubnetTag", s.handleDeleteTransitSubnetTag))
			r.With(act("nat:transitSubnets:createTags", tsnTag)).Post("/transit-subnets/{resource_id}/tags/action", s.handle("BatchCreateDeleteTransitSubnetTags", s.handleBatchTransitSubnetTags))
			r.With(act("nat:transitSubnets:listTags")).Get("/transit-subnets/tags", s.handle("ListTransitSubnetTags", s.handleListTransitSubnetTags))
			r.With(act("nat:transitSubnets:listTags")).Post("/transit-subnets/resource_instances/action", s.handle("ListTransitSubnetsByTags", s.handleListTransitSubnetsByTags))
		})
	})
}

func (s *Service) mountPublicTagRoutes(r chi.Router, act func(string, ...authz.ResourceFunc) func(http.Handler) http.Handler, gw authz.ResourceFunc) {
	r.With(act("nat:natGateways:listTags", gw)).Get("/nat_gateways/{nat_gateway_id}/tags", s.handle("ShowNatGatewayTag", s.handleShowNatGatewayTag))
	r.With(act("nat:natGateways:createTags", gw)).Post("/nat_gateways/{nat_gateway_id}/tags", s.handle("CreateNatGatewayTag", s.handleCreateNatGatewayTag))
	r.With(act("nat:natGateways:deleteTags", gw)).Delete("/nat_gateways/{nat_gateway_id}/tags/{key}", s.handle("DeleteNatGatewayTag", s.handleDeleteNatGatewayTag))
	r.With(act("nat:natGateways:createTags", gw)).Post("/nat_gateways/{nat_gateway_id}/tags/action", s.handle("BatchCreateDeleteNatGatewayTag", s.handleBatchNatGatewayTag))
	r.With(act("nat:natGateways:listTags")).Get("/nat_gateways/tags", s.handle("ListNatGatewayTag", s.handleListNatGatewayTag))
	r.With(act("nat:natGateways:listTags")).Post("/nat_gateways/resource_instances/action", s.handle("ListNatGatewayByTag", s.handleListNatGatewayByTag))
}
