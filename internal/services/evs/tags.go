package evs

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxVolumeTags  = 10
	maxTagKeyLen   = 36
	maxTagValueLen = 43
)

// volumeTag mirrors the SDK model evs/v2 Tag.
type volumeTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type batchVolumeTagsRequest struct {
	Action string      `json:"action"`
	Tags   []volumeTag `json:"tags"`
}

type showVolumeTagsResponse struct {
	Tags []volumeTag `json:"tags"`
}

type listVolumeTagsResponse struct {
	Tags map[string][]string `json:"tags"`
}

func isValidTagKeyRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' ||
		(r >= '\u4E00' && r <= '\u9FFF')
}

func isValidTagValueRune(r rune) bool {
	return isValidTagKeyRune(r) || r == '.'
}

func checkTagKey(key string) error {
	n := utf8.RuneCountInString(key)
	if n == 0 || n > maxTagKeyLen {
		return errInvalidTag
	}
	for _, r := range key {
		if !isValidTagKeyRune(r) {
			return errInvalidTag
		}
	}
	return nil
}

func checkTagValue(val string) error {
	if utf8.RuneCountInString(val) > maxTagValueLen {
		return errInvalidTag
	}
	for _, r := range val {
		if !isValidTagValueRune(r) {
			return errInvalidTag
		}
	}
	return nil
}

func (s *Service) handleBatchVolumeTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchVolumeTagsRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return errInvalidRequest
	}
	id := chi.URLParam(r, "volume_id")
	vol := authz.Resource{Type: "volume", Path: id}
	info := reqctx.From(r.Context())

	var err error
	switch req.Action {
	case "create":
		info.SetOperation("BatchCreateVolumeTags")
		if err := authz.Check(r, "evs:volumes:tagResource", vol); err != nil {
			return err
		}
		err = s.batchCreateVolumeTags(r.Context(), t, id, req.Tags)
	case "delete":
		info.SetOperation("BatchDeleteVolumeTags")
		if err := authz.Check(r, "evs:volumes:unTagResource", vol); err != nil {
			return err
		}
		err = s.batchDeleteVolumeTags(r.Context(), t, id, req.Tags)
	default:
		return errInvalidRequest
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) batchCreateVolumeTags(ctx context.Context, t Tenant, volumeID string, tags []volumeTag) error {
	if len(tags) == 0 {
		return errInvalidRequest
	}
	for _, tag := range tags {
		if err := checkTagKey(tag.Key); err != nil {
			return err
		}
		if err := checkTagValue(tag.Value); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
		merged := maps.Clone(v.Tags)
		if merged == nil {
			merged = make(map[string]string, len(tags))
		}
		for _, tag := range tags {
			merged[tag.Key] = tag.Value
		}
		if len(merged) > maxVolumeTags {
			return errTooManyTags
		}
		v.Tags = merged
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	return err
}

func (s *Service) batchDeleteVolumeTags(ctx context.Context, t Tenant, volumeID string, tags []volumeTag) error {
	if len(tags) == 0 {
		return errInvalidRequest
	}
	for _, tag := range tags {
		if err := checkTagKey(tag.Key); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
		if len(v.Tags) == 0 {
			return nil
		}
		updated := maps.Clone(v.Tags)
		for _, tag := range tags {
			delete(updated, tag.Key)
		}
		if len(updated) == 0 {
			v.Tags = nil
		} else {
			v.Tags = updated
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	return err
}

func (s *Service) handleShowVolumeTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "volume_id")
	v, err := s.volumes(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	if err != nil {
		return err
	}
	out := make([]volumeTag, 0, len(v.Tags))
	for k, val := range v.Tags {
		out = append(out, volumeTag{Key: k, Value: val})
	}
	slices.SortFunc(out, func(a, b volumeTag) int {
		return strings.Compare(a.Key, b.Key)
	})
	return httpx.WriteJSON(w, http.StatusOK, showVolumeTagsResponse{Tags: out})
}

func (s *Service) handleListVolumeTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	all, err := s.volumes(t).List(r.Context(), nil)
	if err != nil {
		return err
	}
	sets := make(map[string]map[string]struct{})
	for _, v := range all {
		for k, val := range v.Tags {
			if sets[k] == nil {
				sets[k] = make(map[string]struct{})
			}
			sets[k][val] = struct{}{}
		}
	}
	out := make(map[string][]string, len(sets))
	for k, set := range sets {
		vals := make([]string, 0, len(set))
		for val := range set {
			vals = append(vals, val)
		}
		slices.Sort(vals)
		out[k] = vals
	}
	return httpx.WriteJSON(w, http.StatusOK, listVolumeTagsResponse{Tags: out})
}
