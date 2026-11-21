package nat

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/store"
)

// privateTagResource adapts one of the three taggable private NAT resource
// collections to the shared tag operations in §3.10.
type privateTagResource[T any] struct {
	kind       string
	collection func(*Service, Tenant) store.Collection[T]
	id         func(T) string
	name       func(T) string
	tags       func(*T) *[]tag
	updatedAt  func(*T) *time.Time
}

var (
	privateGatewayTagResource = privateTagResource[privateGateway]{
		kind:       "Gateway",
		collection: (*Service).privateGateways,
		id:         func(g privateGateway) string { return g.ID },
		name:       func(g privateGateway) string { return g.Name },
		tags:       func(g *privateGateway) *[]tag { return &g.Tags },
		updatedAt:  func(g *privateGateway) *time.Time { return &g.UpdatedAt },
	}
	transitIPTagResource = privateTagResource[transitIP]{
		kind:       "TransitIp",
		collection: (*Service).transitIPs,
		id:         func(ip transitIP) string { return ip.ID },
		name:       func(transitIP) string { return "" },
		tags:       func(ip *transitIP) *[]tag { return &ip.Tags },
		updatedAt:  func(ip *transitIP) *time.Time { return &ip.UpdatedAt },
	}
	transitSubnetTagResource = privateTagResource[transitSubnet]{
		kind:       "TransitSubnet",
		collection: (*Service).transitSubnets,
		id:         func(ts transitSubnet) string { return ts.ID },
		name:       func(ts transitSubnet) string { return ts.Name },
		tags:       func(ts *transitSubnet) *[]tag { return &ts.Tags },
		updatedAt:  func(ts *transitSubnet) *time.Time { return &ts.UpdatedAt },
	}
)

func validatePrivateMatchFilters(matches []matchFilter) error {
	for _, m := range matches {
		if m.Key != "resource_name" {
			return errBadJSON("unsupported match key %q", m.Key)
		}
		if utf8.RuneCountInString(m.Value) > maxMatchValueLen {
			return errBadJSON("match value must not exceed %d characters", maxMatchValueLen)
		}
	}
	return nil
}

func upsertPrivateTags(dst *[]tag, add []tag) error {
	for _, tg := range add {
		i := slices.IndexFunc(*dst, func(existing tag) bool {
			return existing.Key == tg.Key
		})
		if i >= 0 {
			(*dst)[i].Value = tg.Value
			continue
		}
		*dst = append(*dst, tg)
	}
	if len(*dst) > maxTags {
		return errTooManyTags()
	}
	return nil
}

func matchesPrivateTagQuery(tags []tag, name string, q tagQuery) bool {
	if len(q.Tags) > 0 && !matchesAllTags(tags, q.Tags) {
		return false
	}
	if len(q.TagsAny) > 0 && !matchesAnyTag(tags, q.TagsAny) {
		return false
	}
	if len(q.NotTags) > 0 && matchesAllTags(tags, q.NotTags) {
		return false
	}
	if len(q.NotTagsAny) > 0 && matchesAnyTag(tags, q.NotTagsAny) {
		return false
	}
	for _, m := range q.Matches {
		if m.Value == "" {
			if name != "" {
				return false
			}
		} else if !strings.Contains(strings.ToLower(name), strings.ToLower(m.Value)) {
			return false
		}
	}
	return true
}

func createPrivateResourceTag[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T], id string, tg tag) error {
	if !validTag(tg.Key, tg.Value) {
		return errInvalidTag()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := res.collection(s, t).Update(ctx, id, func(rec *T) error {
		if err := upsertPrivateTags(res.tags(rec), []tag{tg}); err != nil {
			return err
		}
		*res.updatedAt(rec) = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound(res.kind, id)
	}
	return err
}

func showPrivateResourceTags[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T], id string) ([]tag, error) {
	rec, err := res.collection(s, t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errPrivateNotFound(res.kind, id)
	}
	if err != nil {
		return nil, err
	}
	tags := *res.tags(&rec)
	if len(tags) == 0 {
		return []tag{}, nil
	}
	return slices.Clone(tags), nil
}

func deletePrivateResourceTag[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T], id, key string) error {
	if key == "" {
		return errBadJSON("tag key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := res.collection(s, t).Update(ctx, id, func(rec *T) error {
		tags := res.tags(rec)
		i := slices.IndexFunc(*tags, func(existing tag) bool {
			return existing.Key == key
		})
		if i < 0 {
			return errBadJSON("tag %q does not exist", key)
		}
		*tags = slices.Delete(*tags, i, i+1)
		*res.updatedAt(rec) = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound(res.kind, id)
	}
	return err
}

func batchPrivateResourceTags[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T], id, action string, tags []tag) error {
	if action != "create" && action != "delete" {
		return errBadJSON("invalid action %q", action)
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
	_, err := res.collection(s, t).Update(ctx, id, func(rec *T) error {
		dst := res.tags(rec)
		if action == "create" {
			if err := upsertPrivateTags(dst, tags); err != nil {
				return err
			}
		} else {
			*dst = slices.DeleteFunc(*dst, func(existing tag) bool {
				return slices.ContainsFunc(tags, func(d tag) bool {
					return d.Key == existing.Key
				})
			})
		}
		*res.updatedAt(rec) = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound(res.kind, id)
	}
	return err
}

func listPrivateResourcesByTags[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T], q tagQuery) ([]taggedResource, error) {
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
	if err := validatePrivateMatchFilters(q.Matches); err != nil {
		return nil, err
	}
	recs, err := res.collection(s, t).List(ctx, func(rec T) bool {
		return matchesPrivateTagQuery(*res.tags(&rec), res.name(rec), q)
	})
	if err != nil {
		return nil, err
	}
	out := make([]taggedResource, 0, len(recs))
	for i := range recs {
		tags := []tag{}
		if raw := *res.tags(&recs[i]); len(raw) > 0 {
			tags = slices.Clone(raw)
		}
		out = append(out, taggedResource{
			ResourceDetail: nil,
			ResourceID:     res.id(recs[i]),
			ResourceName:   res.name(recs[i]),
			Tags:           tags,
		})
	}
	return out, nil
}

func listPrivateResourceTags[T any](ctx context.Context, s *Service, t Tenant, res privateTagResource[T]) ([]projectTag, error) {
	recs, err := res.collection(s, t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	byKey := map[string][]string{}
	for i := range recs {
		for _, tg := range *res.tags(&recs[i]) {
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
