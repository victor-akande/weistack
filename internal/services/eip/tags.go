package eip

import (
	"context"
	"errors"
	"slices"
	"sort"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxTagKeyLen         = 36
	maxTagValueLen       = 43
	maxFilterTags        = 10
	maxFilterTagValues   = 10
	maxFilterTagKeyLen   = 127
	maxFilterTagValueLen = 255
	defaultTagFilterPage = 1000
	maxTagFilterPage     = 1000
)

func validateTag(t tag) error {
	keyLen := utf8.RuneCountInString(t.Key)
	if keyLen < 1 || keyLen > maxTagKeyLen {
		return errInvalidPublicIP("tag key must be between 1 and %d characters", maxTagKeyLen)
	}
	if utf8.RuneCountInString(t.Value) > maxTagValueLen {
		return errInvalidPublicIP("tag value must not exceed %d characters", maxTagValueLen)
	}
	return nil
}

func validateTagFilters(filters []tagFilter) error {
	if len(filters) > maxFilterTags {
		return errInvalidPublicIP("tags filter must not exceed %d keys", maxFilterTags)
	}
	seenKeys := make(map[string]bool, len(filters))
	for _, f := range filters {
		keyLen := utf8.RuneCountInString(f.Key)
		if keyLen < 1 || keyLen > maxFilterTagKeyLen {
			return errInvalidPublicIP("tag filter key must be between 1 and %d characters", maxFilterTagKeyLen)
		}
		if seenKeys[f.Key] {
			return errInvalidPublicIP("duplicate tag filter key %q", f.Key)
		}
		seenKeys[f.Key] = true

		if len(f.Values) > maxFilterTagValues {
			return errInvalidPublicIP("tag filter values for %q must not exceed %d items", f.Key, maxFilterTagValues)
		}
		seenVals := make(map[string]bool, len(f.Values))
		for _, v := range f.Values {
			if utf8.RuneCountInString(v) > maxFilterTagValueLen {
				return errInvalidPublicIP("tag filter value must not exceed %d characters", maxFilterTagValueLen)
			}
			if seenVals[v] {
				return errInvalidPublicIP("duplicate tag filter value %q for key %q", v, f.Key)
			}
			seenVals[v] = true
		}
	}
	return nil
}

func upsertTags(pip *publicIP, add []tag) {
	for _, tg := range add {
		i := slices.IndexFunc(pip.Tags, func(existing tag) bool {
			return existing.Key == tg.Key
		})
		if i >= 0 {
			pip.Tags[i].Value = tg.Value
			continue
		}
		pip.Tags = append(pip.Tags, tg)
	}
}

func matchesTagFilters(tags []tag, filters []tagFilter) bool {
	for _, f := range filters {
		i := slices.IndexFunc(tags, func(tg tag) bool {
			return tg.Key == f.Key
		})
		if i < 0 {
			return false
		}
		if len(f.Values) > 0 && !slices.Contains(f.Values, tags[i].Value) {
			return false
		}
	}
	return true
}

func (s *Service) createPublicIPTag(ctx context.Context, t Tenant, id string, tg tag) error {
	if err := validateTag(tg); err != nil {
		return err
	}
	_, err := s.publicips(t).Update(ctx, id, func(pip *publicIP) error {
		upsertTags(pip, []tag{tg})
		pip.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPublicIPNotFound()
	}
	return err
}

func (s *Service) showPublicIPTags(ctx context.Context, t Tenant, id string) ([]tag, error) {
	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errPublicIPNotFound()
	}
	if err != nil {
		return nil, err
	}
	if len(pip.Tags) == 0 {
		return []tag{}, nil
	}
	return slices.Clone(pip.Tags), nil
}

func (s *Service) deletePublicIPTag(ctx context.Context, t Tenant, id, key string) error {
	_, err := s.publicips(t).Update(ctx, id, func(pip *publicIP) error {
		pip.Tags = slices.DeleteFunc(pip.Tags, func(existing tag) bool {
			return existing.Key == key
		})
		pip.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPublicIPNotFound()
	}
	return err
}

func (s *Service) batchPublicIPTags(ctx context.Context, t Tenant, id, action string, tags []tag) error {
	if len(tags) == 0 {
		return errInvalidPublicIP("tags must not be empty")
	}
	for _, tg := range tags {
		if err := validateTag(tg); err != nil {
			return err
		}
	}
	_, err := s.publicips(t).Update(ctx, id, func(pip *publicIP) error {
		if action == "create" {
			upsertTags(pip, tags)
		} else {
			pip.Tags = slices.DeleteFunc(pip.Tags, func(existing tag) bool {
				return slices.ContainsFunc(tags, func(d tag) bool {
					return d.Key == existing.Key
				})
			})
		}
		pip.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPublicIPNotFound()
	}
	return err
}

func (s *Service) listPublicIPsByTags(ctx context.Context, t Tenant, filters []tagFilter) ([]publicIP, error) {
	if err := validateTagFilters(filters); err != nil {
		return nil, err
	}
	return s.publicips(t).List(ctx, func(pip publicIP) bool {
		return matchesTagFilters(pip.Tags, filters)
	})
}

func (s *Service) listPublicIPTags(ctx context.Context, t Tenant) ([]projectTag, error) {
	pips, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	byKey := map[string][]string{}
	for _, pip := range pips {
		for _, tg := range pip.Tags {
			if !slices.Contains(byKey[tg.Key], tg.Value) {
				byKey[tg.Key] = append(byKey[tg.Key], tg.Value)
			}
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]projectTag, 0, len(keys))
	for _, k := range keys {
		out = append(out, projectTag{Key: k, Values: byKey[k]})
	}
	return out, nil
}
