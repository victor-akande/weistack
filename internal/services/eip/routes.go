package eip

import (
	"net/http"

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

		r.With(act("eip:publicIps:create")).Post("/publicips", s.v1("CreatePublicip", s.dispatchCreatePublicIP))
		r.With(act("eip:publicIps:list")).Get("/publicips", s.v1("ListPublicips", s.dispatchListPublicIPs))
		r.With(act("eip:publicIps:get", pip)).Get("/publicips/{publicip_id}", s.v1("ShowPublicip", s.dispatchShowPublicIP))
		r.With(act("eip:publicIps:update", pip)).Put("/publicips/{publicip_id}", s.v1("UpdatePublicip", s.dispatchUpdatePublicIP))
		r.With(act("eip:publicIps:delete", pip)).Delete("/publicips/{publicip_id}", s.v1("DeletePublicip", s.dispatchDeletePublicIP))

		r.With(act("eip:bandwidths:list")).Get("/bandwidths", s.v1("ListBandwidths", s.dispatchListBandwidths))
		r.With(act("eip:bandwidths:get", bw)).Get("/bandwidths/{bandwidth_id}", s.v1("ShowBandwidth", s.dispatchShowBandwidth))
		r.With(act("eip:bandwidths:update", bw)).Put("/bandwidths/{bandwidth_id}", s.v1("UpdateBandwidth", s.dispatchUpdateBandwidth))
	})
}

// RoutesV20 mounts shared bandwidth and EIP tag v2.0 routes inside /v2.0/{project_id}.
func (s *Service) RoutesV20(r chi.Router) {
	act := authz.Action
	pip := authz.Param("publicip", "publicip_id")
	bw := authz.Param("bandwidth", "bandwidth_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleCodeMessage}))

		r.With(act("eip:bandwidths:create")).Post("/bandwidths", s.v1("CreateSharedBandwidth", s.dispatchCreateSharedBandwidth))
		r.With(act("eip:bandwidths:update", bw)).Put("/bandwidths/{bandwidth_id}", s.v1("UpdatePrePaidBandwidth", s.dispatchUpdatePrePaidBandwidth))
		r.With(act("eip:bandwidths:delete", bw)).Delete("/bandwidths/{bandwidth_id}", s.v1("DeleteSharedBandwidth", s.dispatchDeleteSharedBandwidth))
		r.With(act("eip:bandwidths:insertPublicIps", bw)).Post("/bandwidths/{bandwidth_id}/insert", s.v1("AddPublicipsIntoSharedBandwidth", s.dispatchAddPublicIPsIntoSharedBandwidth))
		r.With(act("eip:bandwidths:removePublicIps", bw)).Post("/bandwidths/{bandwidth_id}/remove", s.v1("RemovePublicipsFromSharedBandwidth", s.dispatchRemovePublicIPsFromSharedBandwidth))

		r.With(act("eip:publicIps:createTags", pip)).Post("/publicips/{publicip_id}/tags", s.v1("CreatePublicipTag", s.dispatchCreatePublicIPTag))
		r.With(act("eip:publicIps:listTags", pip)).Get("/publicips/{publicip_id}/tags", s.v1("ShowPublicipTags", s.dispatchShowPublicIPTags))
		r.With(act("eip:publicIps:deleteTags", pip)).Delete("/publicips/{publicip_id}/tags/{key}", s.v1("DeletePublicipTag", s.dispatchDeletePublicIPTag))
		r.With(authz.Defer()).Post("/publicips/{publicip_id}/tags/action", s.v1("BatchCreatePublicipTags", s.dispatchBatchPublicIPTags))
		r.With(act("eip:publicIps:listTags")).Post("/publicips/resource_instances/action", s.v1("ListPublicipsByTags", s.dispatchListPublicIPsByTags))
		r.With(act("eip:publicIps:listTags")).Get("/publicips/tags", s.v1("ListPublicipTags", s.dispatchListPublicIPTags))
	})
}

// Routes mounts EIP v3 routes at /v3/{project_id}/eip.
func (s *Service) Routes(r chi.Router) {
	act := authz.Action
	pip := authz.Param("publicip", "publicip_id")

	r.Route("/v3/{project_id}/eip", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleFlatRequestID}))

			r.With(act("eip:publicIps:list")).Get("/publicips", s.v3("ListPublicipsV3", s.dispatchListPublicIPsV3))
			r.With(act("eip:publicIps:get", pip)).Get("/publicips/{publicip_id}", s.v3("ShowPublicipV3", s.dispatchShowPublicIPV3))
			r.With(act("eip:publicIps:update", pip)).Put("/publicips/{publicip_id}", s.v3("UpdatePublicipV3", s.dispatchUpdatePublicIPV3))
			r.With(act("eip:publicIps:associateInstance", pip)).Post("/publicips/{publicip_id}/associate-instance", s.v3("AssociatePublicips", s.dispatchAssociatePublicIPs))
			r.With(act("eip:publicIps:disassociateInstance", pip)).Post("/publicips/{publicip_id}/disassociate-instance", s.v3("DisassociatePublicips", s.dispatchDisassociatePublicIPs))
		})
	})
}

func (s *Service) dispatchCreatePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleCreatePublicIP(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleCreatePublicIP(w, r, t)
	}
	return apierr.NotImplemented("eip", "CreatePublicip")
}

func (s *Service) dispatchListPublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleListPublicIPs(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleListPublicIPs(w, r, t)
	}
	return apierr.NotImplemented("eip", "ListPublicips")
}

func (s *Service) dispatchShowPublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleShowPublicIP(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleShowPublicIP(w, r, t)
	}
	return apierr.NotImplemented("eip", "ShowPublicip")
}

func (s *Service) dispatchUpdatePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleUpdatePublicIP(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleUpdatePublicIP(w, r, t)
	}
	return apierr.NotImplemented("eip", "UpdatePublicip")
}

func (s *Service) dispatchDeletePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleDeletePublicIP(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleDeletePublicIP(w, r, t)
	}
	return apierr.NotImplemented("eip", "DeletePublicip")
}

func (s *Service) dispatchListBandwidths(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleListBandwidths(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleListBandwidths(w, r, t)
	}
	return apierr.NotImplemented("eip", "ListBandwidths")
}

func (s *Service) dispatchShowBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleShowBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleShowBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "ShowBandwidth")
}

func (s *Service) dispatchUpdateBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleUpdateBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleUpdateBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "UpdateBandwidth")
}

func (s *Service) dispatchCreateSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleCreateSharedBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleCreateSharedBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "CreateSharedBandwidth")
}

func (s *Service) dispatchUpdatePrePaidBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleUpdatePrePaidBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleUpdatePrePaidBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "UpdatePrePaidBandwidth")
}

func (s *Service) dispatchDeleteSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleDeleteSharedBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleDeleteSharedBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "DeleteSharedBandwidth")
}

func (s *Service) dispatchAddPublicIPsIntoSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleAddPublicIPsIntoSharedBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleAddPublicIPsIntoSharedBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "AddPublicipsIntoSharedBandwidth")
}

func (s *Service) dispatchRemovePublicIPsFromSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleRemovePublicIPsFromSharedBandwidth(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleRemovePublicIPsFromSharedBandwidth(w, r, t)
	}
	return apierr.NotImplemented("eip", "RemovePublicipsFromSharedBandwidth")
}

func (s *Service) dispatchCreatePublicIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleCreatePublicIPTag(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleCreatePublicIPTag(w, r, t)
	}
	return apierr.NotImplemented("eip", "CreatePublicipTag")
}

func (s *Service) dispatchShowPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleShowPublicIPTags(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleShowPublicIPTags(w, r, t)
	}
	return apierr.NotImplemented("eip", "ShowPublicipTags")
}

func (s *Service) dispatchDeletePublicIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleDeletePublicIPTag(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleDeletePublicIPTag(w, r, t)
	}
	return apierr.NotImplemented("eip", "DeletePublicipTag")
}

func (s *Service) dispatchBatchPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleBatchPublicIPTags(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleBatchPublicIPTags(w, r, t)
	}
	id := chi.URLParam(r, "publicip_id")
	if err := authz.Check(r, "eip:publicIps:createTags", authz.Resource{Type: "publicip", Path: id}); err != nil {
		return err
	}
	return apierr.NotImplemented("eip", "BatchCreatePublicipTags")
}

func (s *Service) dispatchListPublicIPsByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleListPublicIPsByTags(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleListPublicIPsByTags(w, r, t)
	}
	return apierr.NotImplemented("eip", "ListPublicipsByTags")
}

func (s *Service) dispatchListPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleListPublicIPTags(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleListPublicIPTags(w, r, t)
	}
	return apierr.NotImplemented("eip", "ListPublicipTags")
}

func (s *Service) dispatchListPublicIPsV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleListPublicIPsV3(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleListPublicIPsV3(w, r, t)
	}
	return apierr.NotImplemented("eip", "ListPublicipsV3")
}

func (s *Service) dispatchShowPublicIPV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleShowPublicIPV3(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleShowPublicIPV3(w, r, t)
	}
	return apierr.NotImplemented("eip", "ShowPublicipV3")
}

func (s *Service) dispatchUpdatePublicIPV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleUpdatePublicIPV3(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleUpdatePublicIPV3(w, r, t)
	}
	return apierr.NotImplemented("eip", "UpdatePublicip")
}

func (s *Service) dispatchAssociatePublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleAssociatePublicIPs(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleAssociatePublicIPs(w, r, t)
	}
	return apierr.NotImplemented("eip", "AssociatePublicips")
}

func (s *Service) dispatchDisassociatePublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if h, ok := any(s).(interface {
		handleDisassociatePublicIPs(http.ResponseWriter, *http.Request, Tenant) error
	}); ok {
		return h.handleDisassociatePublicIPs(w, r, t)
	}
	return apierr.NotImplemented("eip", "DisassociatePublicips")
}
