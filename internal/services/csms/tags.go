package csms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxFilterTags      = 10
	maxFilterTagValues = 10
)

type tagItem struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

type tagView struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type sysTagView struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type listSecretTagsResponse struct {
	Tags    []tagView    `json:"tags"`
	SysTags []sysTagView `json:"sys_tags"`
}

type tagResponseView struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type listProjectTagsResponse struct {
	Tags []tagResponseView `json:"tags"`
}

type tagFilter struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type tagMatch struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// tagNumber decodes a non-negative integer sent as either a JSON string ("10")
// or a JSON number (10), matching SDK and raw REST callers.
type tagNumber struct {
	set bool
	v   int
	bad bool
}

func (n *tagNumber) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	n.set = true
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := strconv.Atoi(s)
		n.v, n.bad = v, err != nil
		return nil
	}
	var v int
	n.bad = json.Unmarshal(b, &v) != nil
	n.v = v
	return nil
}

type listResourceInstancesRequest struct {
	Limit    tagNumber   `json:"limit"`
	Offset   tagNumber   `json:"offset"`
	Action   string      `json:"action"`
	Tags     []tagFilter `json:"tags"`
	Matches  []tagMatch  `json:"matches"`
	Sequence *string     `json:"sequence"`
}

type actionResourceView struct {
	ResourceID     string       `json:"resource_id"`
	ResourceDetail secretView   `json:"resource_detail"`
	ResourceName   string       `json:"resource_name"`
	Tags           []tagView    `json:"tags"`
	SysTags        []sysTagView `json:"sys_tags"`
}

type listResourceInstancesResponse struct {
	Resources  []actionResourceView `json:"resources"`
	TotalCount int                  `json:"total_count"`
}

func validTagRune(r rune, allowed string) bool {
	if r < 32 {
		return false
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune(allowed, r)
}

func validTagKey(k string) bool {
	n := utf8.RuneCountInString(k)
	if n < 1 || n > maxTagKeyLen {
		return false
	}
	if strings.TrimSpace(k) != k || strings.HasPrefix(k, "_sys_") {
		return false
	}
	for _, r := range k {
		if !validTagRune(r, "_.:=+-@") {
			return false
		}
	}
	return true
}

func validTagValue(v string) bool {
	if utf8.RuneCountInString(v) > maxTagValueLen {
		return false
	}
	for _, r := range v {
		if !validTagRune(r, "_.:/=+-@") {
			return false
		}
	}
	return true
}

func checkTagItem(it tagItem) (string, error) {
	if !validTagKey(it.Key) {
		return "", errParam
	}
	v := ""
	if it.Value != nil {
		v = *it.Value
	}
	if !validTagValue(v) {
		return "", errParam
	}
	return v, nil
}

func setSecretTags(sec *Secret, add []Tag) error {
	for _, tg := range add {
		i := slices.IndexFunc(sec.Tags, func(o Tag) bool { return o.Key == tg.Key })
		if i >= 0 {
			sec.Tags[i].Value = tg.Value
			continue
		}
		sec.Tags = append(sec.Tags, tg)
	}
	if len(sec.Tags) > maxTagsPerSecret {
		return errParam
	}
	return nil
}

func tagViews(tags []Tag) []tagView {
	out := make([]tagView, 0, len(tags))
	for _, tg := range tags {
		out = append(out, tagView(tg))
	}
	return out
}

func (s *Service) updateSecretByID(ctx context.Context, t Tenant, secretID string, fn func(*Secret) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec, ok, err := s.findSecretByID(ctx, t, secretID)
	if err != nil {
		return err
	}
	if !ok {
		return errNotFound
	}
	_, err = s.secrets(t).Update(ctx, sec.Name, fn)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	return err
}

func (s *Service) handleCreateSecretTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var b struct {
		Tag *tagItem `json:"tag"`
	}
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if b.Tag == nil {
		return errParam
	}
	v, err := checkTagItem(*b.Tag)
	if err != nil {
		return err
	}
	if err := s.updateSecretByID(r.Context(), t, chi.URLParam(r, "secret_id"), func(sec *Secret) error {
		return setSecretTags(sec, []Tag{{Key: b.Tag.Key, Value: v}})
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListSecretTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	sec, ok, err := s.findSecretByID(r.Context(), t, chi.URLParam(r, "secret_id"))
	if err != nil {
		return err
	}
	if !ok {
		return errNotFound
	}
	return httpx.WriteJSON(w, http.StatusOK, listSecretTagsResponse{
		Tags:    tagViews(sec.Tags),
		SysTags: []sysTagView{},
	})
}

func (s *Service) handleBatchCreateOrDeleteTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var b struct {
		Tags     []tagItem `json:"tags"`
		Action   string    `json:"action"`
		Sequence *string   `json:"sequence"`
	}
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if b.Action != "create" && b.Action != "delete" {
		return errParam
	}
	if len(b.Tags) == 0 {
		return errParam
	}

	seen := make(map[string]struct{}, len(b.Tags))
	tags := make([]Tag, 0, len(b.Tags))
	for _, it := range b.Tags {
		if _, dup := seen[it.Key]; dup {
			return errParam
		}
		seen[it.Key] = struct{}{}
		if b.Action == "delete" {
			if !validTagKey(it.Key) {
				return errParam
			}
			if it.Value != nil && !validTagValue(*it.Value) {
				return errParam
			}
			tags = append(tags, Tag{Key: it.Key})
			continue
		}
		v, err := checkTagItem(it)
		if err != nil {
			return err
		}
		tags = append(tags, Tag{Key: it.Key, Value: v})
	}

	if err := s.updateSecretByID(r.Context(), t, chi.URLParam(r, "secret_id"), func(sec *Secret) error {
		if b.Action == "create" {
			return setSecretTags(sec, tags)
		}
		sec.Tags = slices.DeleteFunc(sec.Tags, func(o Tag) bool {
			return slices.ContainsFunc(tags, func(d Tag) bool { return d.Key == o.Key })
		})
		return nil
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteSecretTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	key := chi.URLParam(r, "key")
	if unescaped, err := url.PathUnescape(key); err == nil {
		key = unescaped
	}
	if !validTagKey(key) {
		return errParam
	}
	if err := s.updateSecretByID(r.Context(), t, chi.URLParam(r, "secret_id"), func(sec *Secret) error {
		i := slices.IndexFunc(sec.Tags, func(o Tag) bool { return o.Key == key })
		if i < 0 {
			return errNotFound
		}
		sec.Tags = slices.Delete(sec.Tags, i, i+1)
		return nil
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListProjectSecretsTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	all, err := s.secrets(t).List(r.Context(), nil)
	if err != nil {
		return err
	}
	values := map[string][]string{}
	for _, sec := range all {
		for _, tg := range sec.Tags {
			if !slices.Contains(values[tg.Key], tg.Value) {
				values[tg.Key] = append(values[tg.Key], tg.Value)
			}
		}
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]tagResponseView, 0, len(keys))
	for _, k := range keys {
		out = append(out, tagResponseView{Key: k, Values: values[k]})
	}
	return httpx.WriteJSON(w, http.StatusOK, listProjectTagsResponse{Tags: out})
}

func matchesSecretFilters(sec Secret, filters []tagFilter, matches []tagMatch, emptyMatch bool) bool {
	if emptyMatch {
		return false
	}
	for _, f := range filters {
		i := slices.IndexFunc(sec.Tags, func(tg Tag) bool { return tg.Key == f.Key })
		if i < 0 {
			return false
		}
		if len(f.Values) > 0 && !slices.Contains(f.Values, sec.Tags[i].Value) {
			return false
		}
	}
	for _, m := range matches {
		if !strings.Contains(sec.Name, *m.Value) {
			return false
		}
	}
	return true
}

func (s *Service) handleListResourceInstances(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var b listResourceInstancesRequest
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if b.Action != "filter" && b.Action != "count" {
		return errParam
	}

	limit, offset := defaultTagLimit, 0
	if b.Limit.set {
		if b.Limit.bad || b.Limit.v < 1 || b.Limit.v > maxTagLimit {
			return errParam
		}
		limit = b.Limit.v
	}
	if b.Offset.set {
		if b.Offset.bad || b.Offset.v < 0 {
			return errParam
		}
		offset = b.Offset.v
	}

	if len(b.Tags) > maxFilterTags {
		return errParam
	}
	for _, f := range b.Tags {
		if !validTagKey(f.Key) || len(f.Values) > maxFilterTagValues {
			return errParam
		}
		seenVals := make(map[string]struct{}, len(f.Values))
		for _, v := range f.Values {
			if !validTagValue(v) {
				return errParam
			}
			if _, dup := seenVals[v]; dup {
				return errParam
			}
			seenVals[v] = struct{}{}
		}
	}

	emptyMatch := false
	for _, m := range b.Matches {
		if m.Key != "resource_name" || m.Value == nil || !validTagValue(*m.Value) {
			return errParam
		}
		if *m.Value == "" {
			emptyMatch = true
		}
	}

	all, err := s.secrets(t).List(r.Context(), nil)
	if err != nil {
		return err
	}

	var hits []Secret
	for _, sec := range all {
		if matchesSecretFilters(sec, b.Tags, b.Matches, emptyMatch) {
			hits = append(hits, sec)
		}
	}

	if b.Action == "count" {
		return httpx.WriteJSON(w, http.StatusOK, struct {
			TotalCount int `json:"total_count"`
		}{TotalCount: len(hits)})
	}

	acctID := s.accountID(r.Context())
	res := make([]actionResourceView, 0)
	if offset < len(hits) {
		end := min(offset+limit, len(hits))
		res = make([]actionResourceView, 0, end-offset)
		for _, sec := range hits[offset:end] {
			res = append(res, actionResourceView{
				ResourceID:     sec.ID,
				ResourceDetail: toSecretView(sec, acctID),
				ResourceName:   sec.Name,
				Tags:           tagViews(sec.Tags),
				SysTags:        []sysTagView{},
			})
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, listResourceInstancesResponse{
		Resources:  res,
		TotalCount: len(hits),
	})
}
