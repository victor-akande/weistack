package eip

import (
	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// RoutesV1 mounts EIP and bandwidth v1 routes inside /v1/{project_id}.
func (s *Service) RoutesV1(r chi.Router) {
	act := authz.Action
	pip := authz.Param("publicip", "publicip_id")
	bw := authz.Param("bandwidth", "bandwidth_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleCodeMessage}))

		r.With(act("eip:publicIps:create")).Post("/publicips", s.v1("CreatePublicip", s.handleCreatePublicIP))
		r.With(act("eip:publicIps:list")).Get("/publicips", s.v1("ListPublicips", s.handleListPublicIPs))
		r.With(act("eip:publicIps:get", pip)).Get("/publicips/{publicip_id}", s.v1("ShowPublicip", s.handleShowPublicIP))
		r.With(act("eip:publicIps:update", pip)).Put("/publicips/{publicip_id}", s.v1("UpdatePublicip", s.handleUpdatePublicIP))
		r.With(act("eip:publicIps:delete", pip)).Delete("/publicips/{publicip_id}", s.v1("DeletePublicip", s.handleDeletePublicIP))

		r.With(act("eip:bandwidths:list")).Get("/bandwidths", s.v1("ListBandwidths", s.handleListBandwidths))
		r.With(act("eip:bandwidths:get", bw)).Get("/bandwidths/{bandwidth_id}", s.v1("ShowBandwidth", s.handleShowBandwidth))
		r.With(act("eip:bandwidths:update", bw)).Put("/bandwidths/{bandwidth_id}", s.v1("UpdateBandwidth", s.handleUpdateBandwidth))
	})
}

// RoutesV20 mounts shared bandwidth and EIP tag v2.0 routes inside /v2.0/{project_id}.
func (s *Service) RoutesV20(r chi.Router) {
	act := authz.Action
	pip := authz.Param("publicip", "publicip_id")
	bw := authz.Param("bandwidth", "bandwidth_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleCodeMessage}))

		r.With(act("eip:bandwidths:create")).Post("/bandwidths", s.v1("CreateSharedBandwidth", s.handleCreateSharedBandwidth))
		r.With(act("eip:bandwidths:update", bw)).Put("/bandwidths/{bandwidth_id}", s.v1("UpdatePrePaidBandwidth", s.handleUpdatePrePaidBandwidth))
		r.With(act("eip:bandwidths:delete", bw)).Delete("/bandwidths/{bandwidth_id}", s.v1("DeleteSharedBandwidth", s.handleDeleteSharedBandwidth))
		r.With(act("eip:bandwidths:insertPublicIps", bw)).Post("/bandwidths/{bandwidth_id}/insert", s.v1("AddPublicipsIntoSharedBandwidth", s.handleAddPublicIPsIntoSharedBandwidth))
		r.With(act("eip:bandwidths:removePublicIps", bw)).Post("/bandwidths/{bandwidth_id}/remove", s.v1("RemovePublicipsFromSharedBandwidth", s.handleRemovePublicIPsFromSharedBandwidth))

		r.With(act("eip:publicIps:createTags", pip)).Post("/publicips/{publicip_id}/tags", s.v1("CreatePublicipTag", s.handleCreatePublicIPTag))
		r.With(act("eip:publicIps:listTags", pip)).Get("/publicips/{publicip_id}/tags", s.v1("ShowPublicipTags", s.handleShowPublicIPTags))
		r.With(act("eip:publicIps:deleteTags", pip)).Delete("/publicips/{publicip_id}/tags/{key}", s.v1("DeletePublicipTag", s.handleDeletePublicIPTag))
		r.With(authz.Defer()).Post("/publicips/{publicip_id}/tags/action", s.v1("BatchCreatePublicipTags", s.handleBatchPublicIPTags))
		r.With(act("eip:publicIps:listTags")).Post("/publicips/resource_instances/action", s.v1("ListPublicipsByTags", s.handleListPublicIPsByTags))
		r.With(act("eip:publicIps:listTags")).Get("/publicips/tags", s.v1("ListPublicipTags", s.handleListPublicIPTags))
	})
}

// Routes mounts EIP v3 routes at /v3/{project_id}/eip.
func (s *Service) Routes(r chi.Router) {
	act := authz.Action
	pip := authz.Param("publicip", "publicip_id")

	r.Route("/v3/{project_id}/eip", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleFlatRequestID}))

			r.With(act("eip:publicIps:list")).Get("/publicips", s.v3("ListPublicipsV3", s.handleListPublicIPsV3))
			r.With(act("eip:publicIps:get", pip)).Get("/publicips/{publicip_id}", s.v3("ShowPublicipV3", s.handleShowPublicIPV3))
			r.With(act("eip:publicIps:update", pip)).Put("/publicips/{publicip_id}", s.v3("UpdatePublicipV3", s.handleUpdatePublicIPV3))
			r.With(act("eip:publicIps:associateInstance", pip)).Post("/publicips/{publicip_id}/associate-instance", s.v3("AssociatePublicips", s.handleAssociatePublicIPs))
			r.With(act("eip:publicIps:disassociateInstance", pip)).Post("/publicips/{publicip_id}/disassociate-instance", s.v3("DisassociatePublicips", s.handleDisassociatePublicIPs))
		})
	})
}
