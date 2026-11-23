package kms

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/quota"
)

// Key tags (api-dew "Tag Management"): at most 20 per key, keys of 1 to
// 36 characters and values of up to 43, without control characters or
// *<>\=.

const (
	maxTagKey   = 36
	maxTagValue = 43
)

func validTagText(s string, limit int, empty bool) bool {
	n := utf8.RuneCountInString(s)
	if n > limit || n == 0 && !empty {
		return false
	}
	for _, c := range s {
		if c < 32 || strings.ContainsRune(`*<>\=`, c) {
			return false
		}
	}
	return true
}

// checkTag validates a tag and returns its value.
func checkTag(it tagItem) (string, error) {
	if !validTagText(it.Key, maxTagKey, false) {
		return "", errTagKey
	}
	v := ""
	if it.Value != nil {
		v = *it.Value
	}
	if !validTagText(v, maxTagValue, true) {
		return "", errTagValue
	}
	return v, nil
}

// setTags adds or replaces tags on a key.
func setTags(k *key, add []tag) error {
	for _, t := range add {
		i := slices.IndexFunc(k.Tags, func(o tag) bool { return o.Key == t.Key })
		if i >= 0 {
			k.Tags[i].Value = t.Value
			continue
		}
		k.Tags = append(k.Tags, t)
	}
	if len(k.Tags) > maxTags {
		return errTooManyTags
	}
	return nil
}

func tagViews(tags []tag) []tagView {
	out := make([]tagView, 0, len(tags))
	for _, t := range tags {
		out = append(out, tagView(t))
	}
	return out
}

func (s *Service) handleKeyTags(w http.ResponseWriter, r *http.Request, t tenant) error {
	k, err := s.find(r.Context(), t, chi.URLParam(r, "key_id"))
	if err != nil {
		return err
	}
	return write(w, struct {
		Tags         []tagView `json:"tags"`
		ExistTagsNum int       `json:"existTagsNum"`
	}{tagViews(k.Tags), len(k.Tags)})
}

func (s *Service) handleCreateTag(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b struct {
		Tag *tagItem `json:"tag"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.Tag == nil {
		return errMissing
	}
	v, err := checkTag(*b.Tag)
	if err != nil {
		return err
	}
	if _, err := s.update(r.Context(), t, chi.URLParam(r, "key_id"), func(k *key) error {
		return setTags(k, []tag{{Key: b.Tag.Key, Value: v}})
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteTag(w http.ResponseWriter, r *http.Request, t tenant) error {
	name := chi.URLParam(r, "key")
	if _, err := s.update(r.Context(), t, chi.URLParam(r, "key_id"), func(k *key) error {
		i := slices.IndexFunc(k.Tags, func(o tag) bool { return o.Key == name })
		if i < 0 {
			return errNoTag
		}
		k.Tags = slices.Delete(k.Tags, i, i+1)
		return nil
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleBatchTags(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b struct {
		Tags   []tagItem `json:"tags"`
		Action string    `json:"action"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.Action != "create" && b.Action != "delete" {
		return errAction
	}
	if len(b.Tags) == 0 {
		return errTagList
	}
	tags := make([]tag, 0, len(b.Tags))
	for _, it := range b.Tags {
		if b.Action == "delete" {
			if !validTagText(it.Key, maxTagKey, false) {
				return errTagKey
			}
			tags = append(tags, tag{Key: it.Key})
			continue
		}
		v, err := checkTag(it)
		if err != nil {
			return err
		}
		tags = append(tags, tag{Key: it.Key, Value: v})
	}
	if _, err := s.update(r.Context(), t, chi.URLParam(r, "key_id"), func(k *key) error {
		if b.Action == "create" {
			return setTags(k, tags)
		}
		// Deleting tags a key does not have is not an error.
		k.Tags = slices.DeleteFunc(k.Tags, func(o tag) bool {
			return slices.ContainsFunc(tags, func(d tag) bool { return d.Key == o.Key })
		})
		return nil
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListAllTags(w http.ResponseWriter, r *http.Request, t tenant) error {
	keys, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	values := map[string][]string{}
	for _, k := range keys {
		for _, tg := range k.Tags {
			if !slices.Contains(values[tg.Key], tg.Value) {
				values[tg.Key] = append(values[tg.Key], tg.Value)
			}
		}
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]tagFilter, 0, len(names))
	for _, n := range names {
		out = append(out, tagFilter{Key: n, Values: values[n]})
	}
	return write(w, struct {
		Tags []tagFilter `json:"tags"`
	}{out})
}

// Paging of resource_instances/action.
const (
	defaultTagLimit = 10
	maxTagLimit     = 1000
)

var (
	errTagLimit  = errLimit
	errOffset    = kmsErr(http.StatusBadRequest, "KMS.0417", "Invalid offset.")
	errMatches   = kmsErr(http.StatusBadRequest, "KMS.0415", "Invalid matches.")
	errTagFilter = kmsErr(http.StatusBadRequest, "KMS.0414", "Invalid tags.")
)

// matchesFilter reports whether a key has every tag the filter names,
// with one of its values (any value when it lists none).
func matchesFilter(k key, filters []tagFilter) bool {
	for _, f := range filters {
		i := slices.IndexFunc(k.Tags, func(t tag) bool { return t.Key == f.Key })
		if i < 0 || len(f.Values) > 0 && !slices.Contains(f.Values, k.Tags[i].Value) {
			return false
		}
	}
	return true
}

func (s *Service) handleListByTags(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b listByTagsRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.Action != "filter" && b.Action != "count" {
		return errAction
	}
	limit, offset := defaultTagLimit, 0
	if b.Limit.set {
		if b.Limit.bad || b.Limit.v < 1 || b.Limit.v > maxTagLimit {
			return errTagLimit
		}
		limit = b.Limit.v
	}
	if b.Offset.set {
		if b.Offset.bad || b.Offset.v < 0 {
			return errOffset
		}
		offset = b.Offset.v
	}
	for _, f := range b.Tags {
		if !validTagText(f.Key, maxTagKey, false) {
			return errTagFilter
		}
	}
	name := ""
	for _, m := range b.Matches {
		if m.Key != "resource_name" || m.Value == nil {
			return errMatches
		}
		name = *m.Value
	}
	keys, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	var hits []key
	for _, k := range keys {
		if matchesFilter(k, b.Tags) && (name == "" || strings.Contains(k.Alias, name)) {
			hits = append(hits, k)
		}
	}
	if b.Action == "count" {
		return write(w, struct {
			TotalCount int `json:"total_count"`
		}{len(hits)})
	}
	res := []taggedResource{}
	if offset < len(hits) {
		for _, k := range hits[offset:min(offset+limit, len(hits))] {
			res = append(res, taggedResource{ResourceID: k.ID, ResourceDetail: details(k), ResourceName: k.Alias, Tags: tagViews(k.Tags)})
		}
	}
	return write(w, struct {
		Resources  []taggedResource `json:"resources"`
		TotalCount int              `json:"total_count"`
	}{res, len(hits)})
}

func (s *Service) handleUserInstances(w http.ResponseWriter, r *http.Request, t tenant) error {
	keys, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	return write(w, struct {
		InstanceNum int `json:"instance_num"`
	}{customCount(keys)})
}

func customCount(keys []key) int {
	n := 0
	for _, k := range keys {
		if !k.Default {
			n++
		}
	}
	return n
}

// maxGrantsPerKey is the documented grant quota of a key.
const maxGrantsPerKey = 100

func (s *Service) handleUserQuotas(w http.ResponseWriter, r *http.Request, t tenant) error {
	keys, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	type resource struct {
		Type  string `json:"type"`
		Used  int    `json:"used"`
		Quota int    `json:"quota"`
	}
	type quotas struct {
		Resources []resource `json:"resources"`
	}
	return write(w, struct {
		Quotas quotas `json:"quotas"`
	}{quotas{[]resource{
		{Type: "CMK", Used: customCount(keys), Quota: s.quotas.Get(quota.KMSCMK)},
		{Type: "grant_per_CMK", Used: 0, Quota: maxGrantsPerKey},
	}}})
}
