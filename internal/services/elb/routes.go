package elb

import (
	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	act := authz.Action
	lb := authz.Param("loadbalancer", "loadbalancer_id")
	lsn := authz.Param("listener", "listener_id")
	pl := authz.Param("pool", "pool_id")
	mem := authz.Param("member", "member_id")
	hm := authz.Param("healthmonitor", "healthmonitor_id")
	cert := authz.Param("certificate", "certificate_id")
	pol := authz.Param("l7policy", "l7policy_id")
	rule := authz.Param("l7rule", "l7rule_id")
	ipg := authz.Param("ipgroup", "ipgroup_id")
	sp := authz.Param("securityPolicy", "security_policy_id")
	flv := authz.Param("flavor", "flavor_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{
			Name:  "elb",
			Style: apierr.StyleFlatRequestID,
		}))

		r.Route("/v3/{project_id}/elb", func(r chi.Router) {
			// §3.1 Load balancers.
			r.With(act("elb:loadbalancers:create")).Post("/loadbalancers", s.handle("CreateLoadBalancer", s.handleCreateLoadBalancer))
			r.With(act("elb:loadbalancers:list")).Get("/loadbalancers", s.handle("ListLoadBalancers", s.handleListLoadBalancers))
			r.With(act("elb:loadbalancers:show", lb)).Get("/loadbalancers/{loadbalancer_id}", s.handle("ShowLoadBalancer", s.handleShowLoadBalancer))
			r.With(act("elb:loadbalancers:update", lb)).Put("/loadbalancers/{loadbalancer_id}", s.handle("UpdateLoadBalancer", s.handleUpdateLoadBalancer))
			r.With(act("elb:loadbalancers:delete", lb)).Delete("/loadbalancers/{loadbalancer_id}", s.handle("DeleteLoadBalancer", s.handleDeleteLoadBalancer))
			r.With(act("elb:loadbalancers:delete", lb)).Delete("/loadbalancers/{loadbalancer_id}/force-elb", s.handle("DeleteLoadBalancerForce", s.handleDeleteLoadBalancerForce))
			r.With(act("elb:loadbalancers:show", lb)).Get("/loadbalancers/{loadbalancer_id}/statuses", s.handle("ShowLoadBalancerStatus", s.handleShowLoadBalancerStatus))
			r.With(act("elb:loadbalancers:update", lb)).Post("/loadbalancers/{loadbalancer_id}/availability-zone/batch-add", s.handle("BatchAddAvailableZones", s.handleBatchAddAvailableZones))
			r.With(act("elb:loadbalancers:update", lb)).Post("/loadbalancers/{loadbalancer_id}/availability-zone/batch-remove", s.handle("BatchRemoveAvailableZones", s.handleBatchRemoveAvailableZones))

			// §3.2 Listeners.
			r.With(act("elb:listeners:create")).Post("/listeners", s.handle("CreateListener", s.handleCreateListener))
			r.With(act("elb:listeners:list")).Get("/listeners", s.handle("ListListeners", s.handleListListeners))
			r.With(act("elb:listeners:show", lsn)).Get("/listeners/{listener_id}", s.handle("ShowListener", s.handleShowListener))
			r.With(act("elb:listeners:update", lsn)).Put("/listeners/{listener_id}", s.handle("UpdateListener", s.handleUpdateListener))
			r.With(act("elb:listeners:delete", lsn)).Delete("/listeners/{listener_id}", s.handle("DeleteListener", s.handleDeleteListener))
			r.With(act("elb:listeners:delete", lsn)).Delete("/listeners/{listener_id}/force", s.handle("DeleteListenerForce", s.handleDeleteListenerForce))

			// §3.3 Pools.
			r.With(act("elb:pools:create")).Post("/pools", s.handle("CreatePool", s.handleCreatePool))
			r.With(act("elb:pools:list")).Get("/pools", s.handle("ListPools", s.handleListPools))
			r.With(act("elb:pools:show", pl)).Get("/pools/{pool_id}", s.handle("ShowPool", s.handleShowPool))
			r.With(act("elb:pools:update", pl)).Put("/pools/{pool_id}", s.handle("UpdatePool", s.handleUpdatePool))
			r.With(act("elb:pools:delete", pl)).Delete("/pools/{pool_id}", s.handle("DeletePool", s.handleDeletePool))
			r.With(act("elb:pools:delete", pl)).Delete("/pools/{pool_id}/delete-cascade", s.handle("DeletePoolCascade", s.handleDeletePoolCascade))

			// §3.4 Members.
			r.With(act("elb:members:create")).Post("/pools/{pool_id}/members", s.handle("CreateMember", s.handleCreateMember))
			r.With(act("elb:members:list")).Get("/pools/{pool_id}/members", s.handle("ListMembers", s.handleListMembers))
			r.With(act("elb:members:show", mem)).Get("/pools/{pool_id}/members/{member_id}", s.handle("ShowMember", s.handleShowMember))
			r.With(act("elb:members:update", mem)).Put("/pools/{pool_id}/members/{member_id}", s.handle("UpdateMember", s.handleUpdateMember))
			r.With(act("elb:members:delete", mem)).Delete("/pools/{pool_id}/members/{member_id}", s.handle("DeleteMember", s.handleDeleteMember))
			r.With(act("elb:members:list")).Get("/members", s.handle("ListAllMembers", s.handleListAllMembers))

			// §3.6 Health monitors.
			r.With(act("elb:healthmonitors:create")).Post("/healthmonitors", s.handle("CreateHealthMonitor", s.handleCreateHealthMonitor))
			r.With(act("elb:healthmonitors:list")).Get("/healthmonitors", s.handle("ListHealthMonitors", s.handleListHealthMonitors))
			r.With(act("elb:healthmonitors:show", hm)).Get("/healthmonitors/{healthmonitor_id}", s.handle("ShowHealthMonitor", s.handleShowHealthMonitor))
			r.With(act("elb:healthmonitors:update", hm)).Put("/healthmonitors/{healthmonitor_id}", s.handle("UpdateHealthMonitor", s.handleUpdateHealthMonitor))
			r.With(act("elb:healthmonitors:delete", hm)).Delete("/healthmonitors/{healthmonitor_id}", s.handle("DeleteHealthMonitor", s.handleDeleteHealthMonitor))

			// §3.7 Certificates.
			r.With(act("elb:certificates:create")).Post("/certificates", s.handle("CreateCertificate", s.handleCreateCertificate))
			r.With(act("elb:certificates:list")).Get("/certificates", s.handle("ListCertificates", s.handleListCertificates))
			r.With(act("elb:certificates:show", cert)).Get("/certificates/{certificate_id}", s.handle("ShowCertificate", s.handleShowCertificate))
			r.With(act("elb:certificates:update", cert)).Put("/certificates/{certificate_id}", s.handle("UpdateCertificate", s.handleUpdateCertificate))
			r.With(act("elb:certificates:delete", cert)).Delete("/certificates/{certificate_id}", s.handle("DeleteCertificate", s.handleDeleteCertificate))

			// §3.8 L7 policies and rules (/l7policies/rules before /l7policies/{l7policy_id}).
			r.With(act("elb:l7policies:create")).Post("/l7policies", s.handle("CreateL7Policy", s.handleCreateL7Policy))
			r.With(act("elb:l7policies:list")).Get("/l7policies", s.handle("ListL7Policies", s.handleListL7Policies))
			r.With(act("elb:l7rules:list")).Get("/l7policies/rules", s.handle("ListAllL7Rules", s.handleListAllL7Rules))
			r.With(act("elb:l7policies:show", pol)).Get("/l7policies/{l7policy_id}", s.handle("ShowL7Policy", s.handleShowL7Policy))
			r.With(act("elb:l7policies:update", pol)).Put("/l7policies/{l7policy_id}", s.handle("UpdateL7Policy", s.handleUpdateL7Policy))
			r.With(act("elb:l7policies:delete", pol)).Delete("/l7policies/{l7policy_id}", s.handle("DeleteL7Policy", s.handleDeleteL7Policy))
			r.With(act("elb:l7rules:create")).Post("/l7policies/{l7policy_id}/rules", s.handle("CreateL7Rule", s.handleCreateL7Rule))
			r.With(act("elb:l7rules:list")).Get("/l7policies/{l7policy_id}/rules", s.handle("ListL7Rules", s.handleListL7Rules))
			r.With(act("elb:l7rules:show", rule)).Get("/l7policies/{l7policy_id}/rules/{l7rule_id}", s.handle("ShowL7Rule", s.handleShowL7Rule))
			r.With(act("elb:l7rules:update", rule)).Put("/l7policies/{l7policy_id}/rules/{l7rule_id}", s.handle("UpdateL7Rule", s.handleUpdateL7Rule))
			r.With(act("elb:l7rules:delete", rule)).Delete("/l7policies/{l7policy_id}/rules/{l7rule_id}", s.handle("DeleteL7Rule", s.handleDeleteL7Rule))

			// §3.9 IP groups and security policies.
			r.With(act("elb:ipgroups:create")).Post("/ipgroups", s.handle("CreateIpGroup", s.handleCreateIPGroup))
			r.With(act("elb:ipgroups:list")).Get("/ipgroups", s.handle("ListIpGroups", s.handleListIPGroups))
			r.With(act("elb:ipgroups:show", ipg)).Get("/ipgroups/{ipgroup_id}", s.handle("ShowIpGroup", s.handleShowIPGroup))
			r.With(act("elb:ipgroups:update", ipg)).Put("/ipgroups/{ipgroup_id}", s.handle("UpdateIpGroup", s.handleUpdateIPGroup))
			r.With(act("elb:ipgroups:delete", ipg)).Delete("/ipgroups/{ipgroup_id}", s.handle("DeleteIpGroup", s.handleDeleteIPGroup))
			r.With(act("elb:security-policies:create")).Post("/security-policies", s.handle("CreateSecurityPolicy", s.handleCreateSecurityPolicy))
			r.With(act("elb:security-policies:list")).Get("/security-policies", s.handle("ListSecurityPolicies", s.handleListSecurityPolicies))
			r.With(act("elb:security-policies:show", sp)).Get("/security-policies/{security_policy_id}", s.handle("ShowSecurityPolicy", s.handleShowSecurityPolicy))
			r.With(act("elb:security-policies:update", sp)).Put("/security-policies/{security_policy_id}", s.handle("UpdateSecurityPolicy", s.handleUpdateSecurityPolicy))
			r.With(act("elb:security-policies:delete", sp)).Delete("/security-policies/{security_policy_id}", s.handle("DeleteSecurityPolicy", s.handleDeleteSecurityPolicy))
			r.With(act("elb:security-policies:list")).Get("/system-security-policies", s.handle("ListSystemSecurityPolicies", s.handleListSystemSecurityPolicies))

			// §3.10 Flavors and availability zones.
			r.With(act("elb:flavors:list")).Get("/flavors", s.handle("ListFlavors", s.handleListFlavors))
			r.With(act("elb:flavors:show", flv)).Get("/flavors/{flavor_id}", s.handle("ShowFlavor", s.handleShowFlavor))
			r.With(act("elb:availability-zones:list")).Get("/availability-zones", s.handle("ListAvailabilityZones", s.handleListAvailabilityZones))
		})

		// §3.11 Tags under /v2.0/{project_id} (used by the Terraform provider).
		r.Route("/v2.0/{project_id}", func(r chi.Router) {
			r.With(act("elb:loadbalancerTags:get", lb)).Get("/loadbalancers/{loadbalancer_id}/tags", s.handle("ShowLoadbalancerTags", s.handleShowLoadBalancerTags))
			r.With(act("elb:loadbalancerTags:create", lb)).Post("/loadbalancers/{loadbalancer_id}/tags/action", s.handle("ChangeLoadbalancerTags", s.handleChangeLoadBalancerTags))
			r.With(act("elb:loadbalancerTags:get")).Get("/loadbalancers/tags", s.handle("ListLoadbalancerTags", s.handleListLoadBalancerTags))
			r.With(act("elb:loadbalancerTags:create", lb)).Post("/loadbalancers/{loadbalancer_id}/tags", s.handle("CreateLoadbalancerTag", s.handleCreateLoadBalancerTag))
			r.With(act("elb:loadbalancerTags:delete", lb)).Delete("/loadbalancers/{loadbalancer_id}/tags/{key}", s.handle("DeleteLoadbalancerTag", s.handleDeleteLoadBalancerTag))
			r.With(act("elb:loadbalancerTags:get")).Post("/loadbalancers/resource_instances/action", s.handle("ListLoadbalancersByTags", s.handleListLoadBalancersByTags))

			r.With(act("elb:listenerTags:get", lsn)).Get("/listeners/{listener_id}/tags", s.handle("ShowListenerTags", s.handleShowListenerTags))
			r.With(act("elb:listenerTags:create", lsn)).Post("/listeners/{listener_id}/tags/action", s.handle("ChangeListenerTags", s.handleChangeListenerTags))
			r.With(act("elb:listenerTags:get")).Get("/listeners/tags", s.handle("ListListenerTags", s.handleListListenerTags))
			r.With(act("elb:listenerTags:create", lsn)).Post("/listeners/{listener_id}/tags", s.handle("CreateListenerTag", s.handleCreateListenerTag))
			r.With(act("elb:listenerTags:delete", lsn)).Delete("/listeners/{listener_id}/tags/{key}", s.handle("DeleteListenerTag", s.handleDeleteListenerTag))
			r.With(act("elb:listenerTags:get")).Post("/listeners/resource_instances/action", s.handle("ListListenersByTags", s.handleListListenersByTags))
		})

		// §3.11 Tags under /v3/{project_id}.
		r.Route("/v3/{project_id}", func(r chi.Router) {
			r.With(act("elb:loadbalancerTags:get", lb)).Get("/loadbalancers/{loadbalancer_id}/tags", s.handle("ShowLoadbalancerTags", s.handleShowLoadBalancerTags))
			r.With(act("elb:loadbalancerTags:create", lb)).Post("/loadbalancers/{loadbalancer_id}/tags/action", s.handle("ChangeLoadbalancerTags", s.handleChangeLoadBalancerTags))
			r.With(act("elb:loadbalancerTags:get")).Get("/loadbalancers/tags", s.handle("ListLoadbalancerTags", s.handleListLoadBalancerTags))

			r.With(act("elb:listenerTags:get", lsn)).Get("/listeners/{listener_id}/tags", s.handle("ShowListenerTags", s.handleShowListenerTags))
			r.With(act("elb:listenerTags:create", lsn)).Post("/listeners/{listener_id}/tags/action", s.handle("ChangeListenerTags", s.handleChangeListenerTags))
			r.With(act("elb:listenerTags:get")).Get("/listeners/tags", s.handle("ListListenerTags", s.handleListListenerTags))
		})
	})
}
