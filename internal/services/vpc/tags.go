package vpc

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
)

// Resource tags, read through the v2.0 tag API that clients such as
// Terraform use after every read. VPCs and subnets keep no tags, so
// theirs are always empty; security groups report the tags they were
// created with. Changing tags is not emulated.

type tagsResponse struct {
	Tags []Tag `json:"tags"`
}

func (s *Service) handleShowVPCTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if _, err := s.GetVPC(r.Context(), t, chi.URLParam(r, "id")); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagsResponse{Tags: []Tag{}})
}

func (s *Service) handleShowSubnetTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if _, err := s.GetSubnet(r.Context(), t, chi.URLParam(r, "id")); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagsResponse{Tags: []Tag{}})
}

func (s *Service) handleShowSecurityGroupTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	g, err := s.GetSecurityGroup(r.Context(), t, chi.URLParam(r, "id"))
	if err != nil {
		return v1Error(err)
	}
	tags := g.Tags
	if tags == nil {
		tags = []Tag{}
	}
	return httpx.WriteJSON(w, http.StatusOK, tagsResponse{Tags: tags})
}
