package eip

import (
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

func (s *Service) handleCreatePublicIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPublicIPTagRequest
	if err := decode(r, &req, errInvalidPublicIP); err != nil {
		return err
	}
	if req.Tag == nil {
		return errInvalidPublicIP("tag is required")
	}
	if err := s.createPublicIPTag(r.Context(), t, chi.URLParam(r, "publicip_id"), *req.Tag); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleShowPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.showPublicIPTags(r.Context(), t, chi.URLParam(r, "publicip_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showPublicIPTagsResponse{Tags: tags})
}

func (s *Service) handleDeletePublicIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	key := chi.URLParam(r, "key")
	if err := s.deletePublicIPTag(r.Context(), t, id, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleBatchPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	var req batchPublicIPTagsRequest
	decErr := decode(r, &req, errInvalidPublicIP)
	if req.Action == "delete" {
		reqctx.From(r.Context()).SetOperation("BatchDeletePublicipTags")
		if err := authz.Check(r, "eip:publicIps:deleteTags", authz.Resource{Type: "publicip", Path: id}); err != nil {
			return err
		}
	} else {
		if err := authz.Check(r, "eip:publicIps:createTags", authz.Resource{Type: "publicip", Path: id}); err != nil {
			return err
		}
		if decErr == nil && req.Action != "create" {
			return errInvalidPublicIP("invalid action %q", req.Action)
		}
	}
	if decErr != nil {
		return decErr
	}
	if err := s.batchPublicIPTags(r.Context(), t, id, req.Action, req.Tags); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListPublicIPsByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req listPublicIPsByTagsRequest
	if err := decode(r, &req, errInvalidPublicIP); err != nil {
		return err
	}
	if req.Action != "filter" && req.Action != "count" {
		return errInvalidPublicIP("invalid action %q", req.Action)
	}

	limit := defaultTagFilterPage
	offset := 0
	if req.Action == "filter" {
		if req.Limit != nil {
			n, ok := parseTagInt(req.Limit)
			if !ok || n < 1 || n > maxTagFilterPage {
				return errInvalidPublicIP("limit must be between 1 and %d", maxTagFilterPage)
			}
			limit = n
		}
		if req.Offset != nil {
			n, ok := parseTagInt(req.Offset)
			if !ok || n < 0 {
				return errInvalidPublicIP("offset must not be negative")
			}
			offset = n
		}
	}

	pips, err := s.listPublicIPsByTags(r.Context(), t, req.Tags)
	if err != nil {
		return err
	}
	if req.Action == "count" {
		return httpx.WriteJSON(w, http.StatusOK, listPublicIPsByTagsResponse{TotalCount: len(pips)})
	}

	resources := []taggedResource{}
	if offset < len(pips) {
		end := min(offset+limit, len(pips))
		for _, pip := range pips[offset:end] {
			tags := []tag{}
			if len(pip.Tags) > 0 {
				tags = slices.Clone(pip.Tags)
			}
			resources = append(resources, taggedResource{
				ResourceDetail: nil,
				ResourceID:     pip.ID,
				ResourceName:   pip.Alias,
				Tags:           tags,
			})
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Resources  []taggedResource `json:"resources"`
		TotalCount int              `json:"total_count"`
	}{
		Resources:  resources,
		TotalCount: len(pips),
	})
}

func (s *Service) handleListPublicIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.listPublicIPTags(r.Context(), t)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listPublicIPTagsResponse{Tags: tags})
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
