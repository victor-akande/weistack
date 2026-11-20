package nat

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// --- §3.10 Private tags (/v3/{project_id}) ---

type showPrivateTagsResponse struct {
	RequestID string `json:"request_id"`
	Tags      []tag  `json:"tags"`
}

type listPrivateTagsResponse struct {
	RequestID string       `json:"request_id"`
	Tags      []projectTag `json:"tags"`
}

type listPrivateByTagsCountResponse struct {
	RequestID  string `json:"request_id"`
	TotalCount int    `json:"total_count"`
}

type listPrivateByTagsFilterResponse struct {
	Resources  []taggedResource `json:"resources"`
	RequestID  string           `json:"request_id"`
	TotalCount int              `json:"total_count"`
}

func handleShowPrivateResourceTags[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	tags, err := showPrivateResourceTags(r.Context(), s, t, res, chi.URLParam(r, "resource_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showPrivateTagsResponse{
		RequestID: reqctx.From(r.Context()).RequestID,
		Tags:      tags,
	})
}

func handleCreatePrivateResourceTag[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	var req createNatGatewayTagRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Tag == nil {
		return errInvalidTag()
	}
	if err := createPrivateResourceTag(r.Context(), s, t, res, chi.URLParam(r, "resource_id"), *req.Tag); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func handleDeletePrivateResourceTag[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	id := chi.URLParam(r, "resource_id")
	key := chi.URLParam(r, "key")
	if err := deletePrivateResourceTag(r.Context(), s, t, res, id, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func handleBatchPrivateResourceTags[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	var req batchNatGatewayTagsRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := batchPrivateResourceTags(r.Context(), s, t, res, chi.URLParam(r, "resource_id"), req.Action, req.Tags); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func handleListPrivateResourceTags[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	tags, err := listPrivateResourceTags(r.Context(), s, t, res)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listPrivateTagsResponse{
		RequestID: reqctx.From(r.Context()).RequestID,
		Tags:      tags,
	})
}

func handleListPrivateResourcesByTags[T any](w http.ResponseWriter, r *http.Request, s *Service, t Tenant, res privateTagResource[T]) error {
	var req listNatGatewaysByTagRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Action != "filter" && req.Action != "count" {
		return errBadJSON("invalid action %q", req.Action)
	}

	limit := defaultTagFilterPage
	offset := 0
	if req.Action == "filter" {
		if req.Limit != nil {
			n, ok := parseTagInt(req.Limit)
			if !ok || n < 1 || n > maxTagFilterPage {
				return errBadJSON("limit must be between 1 and %d", maxTagFilterPage)
			}
			limit = n
		}
		if req.Offset != nil {
			n, ok := parseTagInt(req.Offset)
			if !ok || n < 0 {
				return errBadJSON("offset must not be negative")
			}
			offset = n
		}
	}

	matched, err := listPrivateResourcesByTags(r.Context(), s, t, res, tagQuery{
		Tags:       req.Tags,
		TagsAny:    req.TagsAny,
		NotTags:    req.NotTags,
		NotTagsAny: req.NotTagsAny,
		Matches:    req.Matches,
	})
	if err != nil {
		return err
	}

	reqID := reqctx.From(r.Context()).RequestID
	if req.Action == "count" {
		return httpx.WriteJSON(w, http.StatusOK, listPrivateByTagsCountResponse{
			RequestID:  reqID,
			TotalCount: len(matched),
		})
	}

	resources := []taggedResource{}
	if offset < len(matched) {
		end := min(offset+limit, len(matched))
		resources = matched[offset:end]
	}
	return httpx.WriteJSON(w, http.StatusOK, listPrivateByTagsFilterResponse{
		Resources:  resources,
		RequestID:  reqID,
		TotalCount: len(matched),
	})
}

// Private NAT gateway tag handlers.

func (s *Service) handleShowPrivateNatTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleShowPrivateResourceTags(w, r, s, t, privateGatewayTagResource)
}

func (s *Service) handleCreatePrivateNatTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleCreatePrivateResourceTag(w, r, s, t, privateGatewayTagResource)
}

func (s *Service) handleDeletePrivateNatTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleDeletePrivateResourceTag(w, r, s, t, privateGatewayTagResource)
}

func (s *Service) handleBatchPrivateNatTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleBatchPrivateResourceTags(w, r, s, t, privateGatewayTagResource)
}

func (s *Service) handleListPrivateNatTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourceTags(w, r, s, t, privateGatewayTagResource)
}

func (s *Service) handleListPrivateNatsByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourcesByTags(w, r, s, t, privateGatewayTagResource)
}

// Transit IP tag handlers.

func (s *Service) handleShowTransitIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleShowPrivateResourceTags(w, r, s, t, transitIPTagResource)
}

func (s *Service) handleCreateTransitIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleCreatePrivateResourceTag(w, r, s, t, transitIPTagResource)
}

func (s *Service) handleDeleteTransitIPTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleDeletePrivateResourceTag(w, r, s, t, transitIPTagResource)
}

func (s *Service) handleBatchTransitIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleBatchPrivateResourceTags(w, r, s, t, transitIPTagResource)
}

func (s *Service) handleListTransitIPTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourceTags(w, r, s, t, transitIPTagResource)
}

func (s *Service) handleListTransitIPsByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourcesByTags(w, r, s, t, transitIPTagResource)
}

// Transit subnet tag handlers.

func (s *Service) handleShowTransitSubnetTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleShowPrivateResourceTags(w, r, s, t, transitSubnetTagResource)
}

func (s *Service) handleCreateTransitSubnetTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleCreatePrivateResourceTag(w, r, s, t, transitSubnetTagResource)
}

func (s *Service) handleDeleteTransitSubnetTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleDeletePrivateResourceTag(w, r, s, t, transitSubnetTagResource)
}

func (s *Service) handleBatchTransitSubnetTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleBatchPrivateResourceTags(w, r, s, t, transitSubnetTagResource)
}

func (s *Service) handleListTransitSubnetTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourceTags(w, r, s, t, transitSubnetTagResource)
}

func (s *Service) handleListTransitSubnetsByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return handleListPrivateResourcesByTags(w, r, s, t, transitSubnetTagResource)
}
