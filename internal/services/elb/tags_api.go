package elb

import (
	"math"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
)

// --- §3.11 Load balancer and listener tags (/v2.0/{project_id} and /v3/{project_id}) ---

type tagCreateRequest struct {
	Tag *tag `json:"tag"`
}

type tagShowResponse struct {
	Tags []tag `json:"tags"`
}

type tagChangeRequest struct {
	Action string `json:"action"`
	Tags   []tag  `json:"tags"`
}

type tagListProjectResponse struct {
	Tags []tagProjectItem `json:"tags"`
}

type tagListByTagsRequest struct {
	Tags       []tagFilter      `json:"tags,omitempty"`
	TagsAny    []tagFilter      `json:"tags_any,omitempty"`
	NotTags    []tagFilter      `json:"not_tags,omitempty"`
	NotTagsAny []tagFilter      `json:"not_tags_any,omitempty"`
	Limit      any              `json:"limit,omitempty"`
	Offset     any              `json:"offset,omitempty"`
	Action     string           `json:"action"`
	Matches    []tagMatchFilter `json:"matches,omitempty"`
}

type tagResourceItem struct {
	ResourceDetail any    `json:"resource_detail"`
	ResourceID     string `json:"resource_id"`
	ResourceName   string `json:"resource_name"`
	Tags           []tag  `json:"tags"`
}

type tagListByTagsCountResponse struct {
	TotalCount int `json:"total_count"`
}

type tagListByTagsFilterResponse struct {
	Resources  []tagResourceItem `json:"resources"`
	TotalCount int               `json:"total_count"`
}

func tagParseInt(raw any) (int, bool) {
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

func tagParseListByTagsRequest(r *http.Request) (tagListByTagsRequest, int, int, error) {
	var req tagListByTagsRequest
	if err := decode(r, &req); err != nil {
		return tagListByTagsRequest{}, 0, 0, err
	}
	if req.Action != "filter" && req.Action != "count" {
		return tagListByTagsRequest{}, 0, 0, errInvalidInput("action")
	}

	limit := tagDefaultFilterPage
	offset := 0
	if req.Action == "filter" {
		if req.Limit != nil {
			n, ok := tagParseInt(req.Limit)
			if !ok || n < 1 || n > tagMaxFilterPage {
				return tagListByTagsRequest{}, 0, 0, errInvalidInput("limit")
			}
			limit = n
		}
		if req.Offset != nil {
			n, ok := tagParseInt(req.Offset)
			if !ok || n < 0 {
				return tagListByTagsRequest{}, 0, 0, errInvalidInput("offset")
			}
			offset = n
		}
	}
	return req, offset, limit, nil
}

func tagWriteListByTagsResponse(w http.ResponseWriter, action string, offset, limit int, all []tagResourceItem) error {
	if action == "count" {
		return httpx.WriteJSON(w, http.StatusOK, tagListByTagsCountResponse{TotalCount: len(all)})
	}
	page := []tagResourceItem{}
	if offset < len(all) {
		end := min(offset+limit, len(all))
		page = all[offset:end]
	}
	return httpx.WriteJSON(w, http.StatusOK, tagListByTagsFilterResponse{
		Resources:  page,
		TotalCount: len(all),
	})
}

func (s *Service) handleShowLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.tagShowLoadBalancer(r.Context(), t, chi.URLParam(r, "loadbalancer_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagShowResponse{Tags: tags})
}

func (s *Service) handleChangeLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req tagChangeRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.tagChangeLoadBalancer(r.Context(), t, chi.URLParam(r, "loadbalancer_id"), req.Action, req.Tags); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.tagListLoadBalancerProject(r.Context(), t)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagListProjectResponse{Tags: tags})
}

func (s *Service) handleCreateLoadBalancerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req tagCreateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Tag == nil {
		return errInvalidInput("tag")
	}
	if err := s.tagCreateLoadBalancer(r.Context(), t, chi.URLParam(r, "loadbalancer_id"), *req.Tag); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteLoadBalancerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "loadbalancer_id")
	key := chi.URLParam(r, "key")
	if err := s.tagDeleteLoadBalancer(r.Context(), t, id, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListLoadBalancersByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	req, offset, limit, err := tagParseListByTagsRequest(r)
	if err != nil {
		return err
	}
	lbs, err := s.tagListLoadBalancersByQuery(r.Context(), t, tagQuery{
		Tags:       req.Tags,
		TagsAny:    req.TagsAny,
		NotTags:    req.NotTags,
		NotTagsAny: req.NotTagsAny,
		Matches:    req.Matches,
	})
	if err != nil {
		return err
	}
	items := make([]tagResourceItem, len(lbs))
	for i, lb := range lbs {
		items[i] = tagResourceItem{
			ResourceDetail: nil,
			ResourceID:     lb.ID,
			ResourceName:   lb.Name,
			Tags:           tagCloneOrEmpty(lb.Tags),
		}
	}
	return tagWriteListByTagsResponse(w, req.Action, offset, limit, items)
}

func (s *Service) handleShowListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.tagShowListener(r.Context(), t, chi.URLParam(r, "listener_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagShowResponse{Tags: tags})
}

func (s *Service) handleChangeListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req tagChangeRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.tagChangeListener(r.Context(), t, chi.URLParam(r, "listener_id"), req.Action, req.Tags); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	tags, err := s.tagListListenerProject(r.Context(), t)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, tagListProjectResponse{Tags: tags})
}

func (s *Service) handleCreateListenerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req tagCreateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Tag == nil {
		return errInvalidInput("tag")
	}
	if err := s.tagCreateListener(r.Context(), t, chi.URLParam(r, "listener_id"), *req.Tag); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteListenerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "listener_id")
	key := chi.URLParam(r, "key")
	if err := s.tagDeleteListener(r.Context(), t, id, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListListenersByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	req, offset, limit, err := tagParseListByTagsRequest(r)
	if err != nil {
		return err
	}
	lsns, err := s.tagListListenersByQuery(r.Context(), t, tagQuery{
		Tags:       req.Tags,
		TagsAny:    req.TagsAny,
		NotTags:    req.NotTags,
		NotTagsAny: req.NotTagsAny,
		Matches:    req.Matches,
	})
	if err != nil {
		return err
	}
	items := make([]tagResourceItem, len(lsns))
	for i, lsn := range lsns {
		items[i] = tagResourceItem{
			ResourceDetail: nil,
			ResourceID:     lsn.ID,
			ResourceName:   lsn.Name,
			Tags:           tagCloneOrEmpty(lsn.Tags),
		}
	}
	return tagWriteListByTagsResponse(w, req.Action, offset, limit, items)
}
