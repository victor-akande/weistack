package nat

import (
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
)

// --- §3.4 Public gateway tags (/v3/{project_id} and /v2.0/{project_id}) ---

type createNatGatewayTagRequest struct {
	Tag *tag `json:"tag"`
}

type showNatGatewayTagsResponse struct {
	Tags []tag `json:"tags"`
}

type batchNatGatewayTagsRequest struct {
	Action string `json:"action"`
	Tags   []tag  `json:"tags"`
}

type tagFilter struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type matchFilter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type listNatGatewaysByTagRequest struct {
	Tags       []tagFilter   `json:"tags,omitempty"`
	TagsAny    []tagFilter   `json:"tags_any,omitempty"`
	NotTags    []tagFilter   `json:"not_tags,omitempty"`
	NotTagsAny []tagFilter   `json:"not_tags_any,omitempty"`
	Limit      any           `json:"limit,omitempty"`
	Offset     any           `json:"offset,omitempty"`
	Action     string        `json:"action"`
	Matches    []matchFilter `json:"matches,omitempty"`
}

type taggedResource struct {
	ResourceDetail any    `json:"resource_detail"`
	ResourceID     string `json:"resource_id"`
	ResourceName   string `json:"resource_name"`
	Tags           []tag  `json:"tags"`
}

type listNatGatewaysByTagResponse struct {
	Resources  []taggedResource `json:"resources,omitempty"`
	TotalCount int              `json:"total_count"`
}

type projectTag struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type listNatGatewayTagsResponse struct {
	Tags []projectTag `json:"tags"`
}

func (s *Service) handleShowNatGatewayTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.showNatGatewayTags(r.Context(), t, chi.URLParam(r, "nat_gateway_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showNatGatewayTagsResponse{Tags: tags})
}

func (s *Service) handleCreateNatGatewayTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createNatGatewayTagRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Tag == nil {
		return errInvalidTag()
	}
	if err := s.createNatGatewayTag(r.Context(), t, chi.URLParam(r, "nat_gateway_id"), *req.Tag); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteNatGatewayTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "nat_gateway_id")
	key := chi.URLParam(r, "key")
	if err := s.deleteNatGatewayTag(r.Context(), t, id, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleBatchNatGatewayTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchNatGatewayTagsRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.batchNatGatewayTags(r.Context(), t, chi.URLParam(r, "nat_gateway_id"), req.Action, req.Tags); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListNatGatewayTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.listNatGatewayTags(r.Context(), t)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listNatGatewayTagsResponse{Tags: tags})
}

func (s *Service) handleListNatGatewayByTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req listNatGatewaysByTagRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Action != "filter" && req.Action != "count" {
		return errInvalidParams("invalid action %q", req.Action)
	}

	limit := defaultTagFilterPage
	offset := 0
	if req.Action == "filter" {
		if req.Limit != nil {
			n, ok := parseTagInt(req.Limit)
			if !ok || n < 1 || n > maxTagFilterPage {
				return errInvalidParams("limit must be between 1 and %d", maxTagFilterPage)
			}
			limit = n
		}
		if req.Offset != nil {
			n, ok := parseTagInt(req.Offset)
			if !ok || n < 0 {
				return errInvalidParams("offset must not be negative")
			}
			offset = n
		}
	}

	gws, err := s.listNatGatewaysByTags(r.Context(), t, tagQuery{
		Tags:       req.Tags,
		TagsAny:    req.TagsAny,
		NotTags:    req.NotTags,
		NotTagsAny: req.NotTagsAny,
		Matches:    req.Matches,
	})
	if err != nil {
		return err
	}
	if req.Action == "count" {
		return httpx.WriteJSON(w, http.StatusOK, listNatGatewaysByTagResponse{TotalCount: len(gws)})
	}

	resources := []taggedResource{}
	if offset < len(gws) {
		end := min(offset+limit, len(gws))
		for _, g := range gws[offset:end] {
			tags := []tag{}
			if len(g.Tags) > 0 {
				tags = slices.Clone(g.Tags)
			}
			resources = append(resources, taggedResource{
				ResourceDetail: nil,
				ResourceID:     g.ID,
				ResourceName:   g.Name,
				Tags:           tags,
			})
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Resources  []taggedResource `json:"resources"`
		TotalCount int              `json:"total_count"`
	}{
		Resources:  resources,
		TotalCount: len(gws),
	})
}

func parseTagInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
			return 0, false
		}
		if v > float64(math.MaxInt32) || v < float64(math.MinInt32) {
			return 0, false
		}
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}
