package nat

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxTagFilterKeys     = 20
	maxTagFilterValues   = 20
	maxTagFilterKeyLen   = 128
	maxTagFilterValueLen = 255
	maxMatchValueLen     = 255
	defaultTagFilterPage = 1000
	maxTagFilterPage     = 1000
)

type tagQuery struct {
	Tags       []tagFilter
	TagsAny    []tagFilter
	NotTags    []tagFilter
	NotTagsAny []tagFilter
	Matches    []matchFilter
}

func validateTagFilters(filters []tagFilter) error {
	if len(filters) > maxTagFilterKeys {
		return errInvalidTag()
	}
	seenKeys := make(map[string]bool, len(filters))
	for _, f := range filters {
		key := strings.TrimSpace(f.Key)
		keyLen := utf8.RuneCountInString(key)
		if keyLen < 1 || keyLen > maxTagFilterKeyLen {
			return errInvalidTag()
		}
		if seenKeys[key] {
			return errInvalidTag()
		}
		seenKeys[key] = true

		if len(f.Values) > maxTagFilterValues {
			return errInvalidTag()
		}
		seenVals := make(map[string]bool, len(f.Values))
		for _, v := range f.Values {
			if utf8.RuneCountInString(v) > maxTagFilterValueLen {
				return errInvalidTag()
			}
			if seenVals[v] {
				return errInvalidTag()
			}
			seenVals[v] = true
		}
	}
	return nil
}

func validateMatchFilters(matches []matchFilter) error {
	for _, m := range matches {
		if m.Key != "resource_name" {
			return errInvalidParams("unsupported match key %q", m.Key)
		}
		if utf8.RuneCountInString(m.Value) > maxMatchValueLen {
			return errInvalidParams("match value must not exceed %d characters", maxMatchValueLen)
		}
	}
	return nil
}

func upsertGatewayTags(g *gateway, add []tag) error {
	for _, tg := range add {
		i := slices.IndexFunc(g.Tags, func(existing tag) bool {
			return existing.Key == tg.Key
		})
		if i >= 0 {
			g.Tags[i].Value = tg.Value
			continue
		}
		g.Tags = append(g.Tags, tg)
	}
	if len(g.Tags) > maxTags {
		return errTooManyTags(maxTags)
	}
	return nil
}

func matchesTagValue(val string, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if after, ok := strings.CutPrefix(w, "*"); ok {
			if strings.Contains(val, after) {
				return true
			}
		} else if val == w {
			return true
		}
	}
	return false
}

func matchesSingleTag(tags []tag, f tagFilter) bool {
	key := strings.TrimSpace(f.Key)
	i := slices.IndexFunc(tags, func(tg tag) bool {
		return tg.Key == key
	})
	if i < 0 {
		return false
	}
	return matchesTagValue(tags[i].Value, f.Values)
}

func matchesAllTags(tags []tag, filters []tagFilter) bool {
	for _, f := range filters {
		if !matchesSingleTag(tags, f) {
			return false
		}
	}
	return true
}

func matchesAnyTag(tags []tag, filters []tagFilter) bool {
	for _, f := range filters {
		if matchesSingleTag(tags, f) {
			return true
		}
	}
	return false
}

func matchesGatewayQuery(g gateway, q tagQuery) bool {
	if len(q.Tags) > 0 && !matchesAllTags(g.Tags, q.Tags) {
		return false
	}
	if len(q.TagsAny) > 0 && !matchesAnyTag(g.Tags, q.TagsAny) {
		return false
	}
	if len(q.NotTags) > 0 && matchesAllTags(g.Tags, q.NotTags) {
		return false
	}
	if len(q.NotTagsAny) > 0 && matchesAnyTag(g.Tags, q.NotTagsAny) {
		return false
	}
	for _, m := range q.Matches {
		if m.Value == "" {
			if g.Name != "" {
				return false
			}
		} else if !strings.Contains(strings.ToLower(g.Name), strings.ToLower(m.Value)) {
			return false
		}
	}
	return true
}

func (s *Service) createNatGatewayTag(ctx context.Context, t Tenant, id string, tg tag) error {
	if !validTag(tg.Key, tg.Value) {
		return errInvalidTag()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.gateways(t).Update(ctx, id, func(g *gateway) error {
		return upsertGatewayTags(g, []tag{tg})
	})
	if errors.Is(err, store.ErrNotFound) {
		return errGatewayNotFound(id)
	}
	return err
}

func (s *Service) showNatGatewayTags(ctx context.Context, t Tenant, id string) ([]tag, error) {
	g, err := s.gateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errGatewayNotFound(id)
	}
	if err != nil {
		return nil, err
	}
	if len(g.Tags) == 0 {
		return []tag{}, nil
	}
	return slices.Clone(g.Tags), nil
}

func (s *Service) deleteNatGatewayTag(ctx context.Context, t Tenant, id, key string) error {
	if key == "" {
		return errInvalidParams("tag key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.gateways(t).Update(ctx, id, func(g *gateway) error {
		i := slices.IndexFunc(g.Tags, func(existing tag) bool {
			return existing.Key == key
		})
		if i < 0 {
			return errInvalidParams("tag %q does not exist", key)
		}
		g.Tags = slices.Delete(g.Tags, i, i+1)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errGatewayNotFound(id)
	}
	return err
}

func (s *Service) batchNatGatewayTags(ctx context.Context, t Tenant, id, action string, tags []tag) error {
	if action != "create" && action != "delete" {
		return errInvalidParams("invalid action %q", action)
	}
	if len(tags) == 0 {
		return errInvalidTag()
	}
	seen := make(map[string]bool, len(tags))
	for _, tg := range tags {
		if !validTag(tg.Key, tg.Value) {
			return errInvalidTag()
		}
		if action == "create" {
			if seen[tg.Key] {
				return errInvalidTag()
			}
			seen[tg.Key] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.gateways(t).Update(ctx, id, func(g *gateway) error {
		if action == "create" {
			return upsertGatewayTags(g, tags)
		}
		g.Tags = slices.DeleteFunc(g.Tags, func(existing tag) bool {
			return slices.ContainsFunc(tags, func(d tag) bool {
				return d.Key == existing.Key
			})
		})
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errGatewayNotFound(id)
	}
	return err
}

func (s *Service) listNatGatewaysByTags(ctx context.Context, t Tenant, q tagQuery) ([]gateway, error) {
	if err := validateTagFilters(q.Tags); err != nil {
		return nil, err
	}
	if err := validateTagFilters(q.TagsAny); err != nil {
		return nil, err
	}
	if err := validateTagFilters(q.NotTags); err != nil {
		return nil, err
	}
	if err := validateTagFilters(q.NotTagsAny); err != nil {
		return nil, err
	}
	if err := validateMatchFilters(q.Matches); err != nil {
		return nil, err
	}
	return s.gateways(t).List(ctx, func(g gateway) bool {
		return matchesGatewayQuery(g, q)
	})
}

func (s *Service) listNatGatewayTags(ctx context.Context, t Tenant) ([]projectTag, error) {
	gws, err := s.gateways(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	byKey := map[string][]string{}
	for _, g := range gws {
		for _, tg := range g.Tags {
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
