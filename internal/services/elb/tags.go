package elb

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
	tagMaxFilterKeys     = 20
	tagMaxFilterValues   = 20
	tagMaxFilterKeyLen   = 128
	tagMaxFilterValueLen = 255
	tagMaxMatchValueLen  = 255
	tagDefaultFilterPage = 1000
	tagMaxFilterPage     = 1000
)

type tagFilter struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type tagMatchFilter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type tagQuery struct {
	Tags       []tagFilter
	TagsAny    []tagFilter
	NotTags    []tagFilter
	NotTagsAny []tagFilter
	Matches    []tagMatchFilter
}

type tagProjectItem struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

func tagValidateFilters(filters []tagFilter) error {
	if len(filters) > tagMaxFilterKeys {
		return errInvalidInput("tags")
	}
	seenKeys := make(map[string]struct{}, len(filters))
	for _, f := range filters {
		key := strings.TrimSpace(f.Key)
		keyLen := utf8.RuneCountInString(key)
		if keyLen < 1 || keyLen > tagMaxFilterKeyLen {
			return errInvalidInput("tags")
		}
		if _, dup := seenKeys[key]; dup {
			return errInvalidInput("tags")
		}
		seenKeys[key] = struct{}{}

		if len(f.Values) > tagMaxFilterValues {
			return errInvalidInput("tags")
		}
		seenVals := make(map[string]struct{}, len(f.Values))
		for _, v := range f.Values {
			if utf8.RuneCountInString(v) > tagMaxFilterValueLen {
				return errInvalidInput("tags")
			}
			if _, dup := seenVals[v]; dup {
				return errInvalidInput("tags")
			}
			seenVals[v] = struct{}{}
		}
	}
	return nil
}

func tagValidateMatches(matches []tagMatchFilter) error {
	for _, m := range matches {
		if m.Key != "resource_name" && m.Key != "resource_id" {
			return errInvalidInput("matches")
		}
		if utf8.RuneCountInString(m.Value) > tagMaxMatchValueLen {
			return errInvalidInput("matches")
		}
	}
	return nil
}

func tagValidateQuery(q tagQuery) error {
	if err := tagValidateFilters(q.Tags); err != nil {
		return err
	}
	if err := tagValidateFilters(q.TagsAny); err != nil {
		return err
	}
	if err := tagValidateFilters(q.NotTags); err != nil {
		return err
	}
	if err := tagValidateFilters(q.NotTagsAny); err != nil {
		return err
	}
	return tagValidateMatches(q.Matches)
}

func tagValidateBatch(action string, tags []tag) error {
	if action != "create" && action != "delete" {
		return errInvalidInput("action")
	}
	if len(tags) == 0 {
		return errInvalidInput("tags")
	}
	seen := make(map[string]struct{}, len(tags))
	for _, tg := range tags {
		if !validTag(tg.Key, tg.Value) {
			return errInvalidInput("tags")
		}
		if action == "create" {
			if _, dup := seen[tg.Key]; dup {
				return errInvalidInput("tags")
			}
			seen[tg.Key] = struct{}{}
		}
	}
	return nil
}

func tagUpsert(existing, add []tag) ([]tag, error) {
	out := slices.Clone(existing)
	for _, tg := range add {
		i := slices.IndexFunc(out, func(cur tag) bool {
			return cur.Key == tg.Key
		})
		if i >= 0 {
			out[i].Value = tg.Value
			continue
		}
		out = append(out, tg)
	}
	if len(out) > maxTags {
		return nil, errInvalidInput("tags")
	}
	return out, nil
}

func tagDeleteKeys(existing, del []tag) []tag {
	out := slices.Clone(existing)
	return slices.DeleteFunc(out, func(cur tag) bool {
		return slices.ContainsFunc(del, func(d tag) bool {
			return d.Key == cur.Key
		})
	})
}

func tagMatchesValue(val string, want []string) bool {
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

func tagMatchesSingle(tags []tag, f tagFilter) bool {
	key := strings.TrimSpace(f.Key)
	i := slices.IndexFunc(tags, func(tg tag) bool {
		return tg.Key == key
	})
	if i < 0 {
		return false
	}
	return tagMatchesValue(tags[i].Value, f.Values)
}

func tagMatchesAll(tags []tag, filters []tagFilter) bool {
	for _, f := range filters {
		if !tagMatchesSingle(tags, f) {
			return false
		}
	}
	return true
}

func tagMatchesAny(tags []tag, filters []tagFilter) bool {
	for _, f := range filters {
		if tagMatchesSingle(tags, f) {
			return true
		}
	}
	return false
}

func tagMatchesQuery(id, name string, tags []tag, q tagQuery) bool {
	if len(q.Tags) > 0 && !tagMatchesAll(tags, q.Tags) {
		return false
	}
	if len(q.TagsAny) > 0 && !tagMatchesAny(tags, q.TagsAny) {
		return false
	}
	if len(q.NotTags) > 0 && tagMatchesAll(tags, q.NotTags) {
		return false
	}
	if len(q.NotTagsAny) > 0 && tagMatchesAny(tags, q.NotTagsAny) {
		return false
	}
	for _, m := range q.Matches {
		switch m.Key {
		case "resource_name":
			if m.Value == "" {
				if name != "" {
					return false
				}
			} else if !strings.Contains(strings.ToLower(name), strings.ToLower(m.Value)) {
				return false
			}
		case "resource_id":
			if id != m.Value {
				return false
			}
		}
	}
	return true
}

func tagAggregateProject(groups [][]tag) []tagProjectItem {
	byKey := map[string][]string{}
	for _, tags := range groups {
		for _, tg := range tags {
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
	out := make([]tagProjectItem, 0, len(keys))
	for _, k := range keys {
		vals := byKey[k]
		sort.Strings(vals)
		out = append(out, tagProjectItem{Key: k, Values: vals})
	}
	return out
}

func tagCloneOrEmpty(tags []tag) []tag {
	if len(tags) == 0 {
		return []tag{}
	}
	return slices.Clone(tags)
}

func (s *Service) tagShowLoadBalancer(ctx context.Context, t Tenant, id string) ([]tag, error) {
	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("loadbalancer", id)
	}
	if err != nil {
		return nil, err
	}
	return tagCloneOrEmpty(lb.Tags), nil
}

func (s *Service) tagCreateLoadBalancer(ctx context.Context, t Tenant, id string, tg tag) error {
	if !validTag(tg.Key, tg.Value) {
		return errInvalidInput("tag")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadBalancers(t).Update(ctx, id, func(lb *loadBalancer) error {
		updated, err := tagUpsert(lb.Tags, []tag{tg})
		if err != nil {
			return err
		}
		lb.Tags = updated
		lb.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("loadbalancer", id)
	}
	return err
}

func (s *Service) tagDeleteLoadBalancer(ctx context.Context, t Tenant, id, key string) error {
	if key == "" {
		return errInvalidInput("key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadBalancers(t).Update(ctx, id, func(lb *loadBalancer) error {
		i := slices.IndexFunc(lb.Tags, func(existing tag) bool {
			return existing.Key == key
		})
		if i < 0 {
			return errInvalidInput("key")
		}
		lb.Tags = slices.Delete(slices.Clone(lb.Tags), i, i+1)
		lb.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("loadbalancer", id)
	}
	return err
}

func (s *Service) tagChangeLoadBalancer(ctx context.Context, t Tenant, id, action string, tags []tag) error {
	if err := tagValidateBatch(action, tags); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadBalancers(t).Update(ctx, id, func(lb *loadBalancer) error {
		if action == "create" {
			updated, err := tagUpsert(lb.Tags, tags)
			if err != nil {
				return err
			}
			lb.Tags = updated
		} else {
			lb.Tags = tagDeleteKeys(lb.Tags, tags)
		}
		lb.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("loadbalancer", id)
	}
	return err
}

func (s *Service) tagListLoadBalancerProject(ctx context.Context, t Tenant) ([]tagProjectItem, error) {
	lbs, err := s.loadBalancers(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	groups := make([][]tag, len(lbs))
	for i, lb := range lbs {
		groups[i] = lb.Tags
	}
	return tagAggregateProject(groups), nil
}

func (s *Service) tagListLoadBalancersByQuery(ctx context.Context, t Tenant, q tagQuery) ([]loadBalancer, error) {
	if err := tagValidateQuery(q); err != nil {
		return nil, err
	}
	return s.loadBalancers(t).List(ctx, func(lb loadBalancer) bool {
		return tagMatchesQuery(lb.ID, lb.Name, lb.Tags, q)
	})
}

func (s *Service) tagShowListener(ctx context.Context, t Tenant, id string) ([]tag, error) {
	lsn, err := s.listeners(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("listener", id)
	}
	if err != nil {
		return nil, err
	}
	return tagCloneOrEmpty(lsn.Tags), nil
}

func (s *Service) tagCreateListener(ctx context.Context, t Tenant, id string, tg tag) error {
	if !validTag(tg.Key, tg.Value) {
		return errInvalidInput("tag")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.listeners(t).Update(ctx, id, func(lsn *listener) error {
		updated, err := tagUpsert(lsn.Tags, []tag{tg})
		if err != nil {
			return err
		}
		lsn.Tags = updated
		lsn.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", id)
	}
	return err
}

func (s *Service) tagDeleteListener(ctx context.Context, t Tenant, id, key string) error {
	if key == "" {
		return errInvalidInput("key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.listeners(t).Update(ctx, id, func(lsn *listener) error {
		i := slices.IndexFunc(lsn.Tags, func(existing tag) bool {
			return existing.Key == key
		})
		if i < 0 {
			return errInvalidInput("key")
		}
		lsn.Tags = slices.Delete(slices.Clone(lsn.Tags), i, i+1)
		lsn.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", id)
	}
	return err
}

func (s *Service) tagChangeListener(ctx context.Context, t Tenant, id, action string, tags []tag) error {
	if err := tagValidateBatch(action, tags); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.listeners(t).Update(ctx, id, func(lsn *listener) error {
		if action == "create" {
			updated, err := tagUpsert(lsn.Tags, tags)
			if err != nil {
				return err
			}
			lsn.Tags = updated
		} else {
			lsn.Tags = tagDeleteKeys(lsn.Tags, tags)
		}
		lsn.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", id)
	}
	return err
}

func (s *Service) tagListListenerProject(ctx context.Context, t Tenant) ([]tagProjectItem, error) {
	lsns, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	groups := make([][]tag, len(lsns))
	for i, lsn := range lsns {
		groups[i] = lsn.Tags
	}
	return tagAggregateProject(groups), nil
}

func (s *Service) tagListListenersByQuery(ctx context.Context, t Tenant, q tagQuery) ([]listener, error) {
	if err := tagValidateQuery(q); err != nil {
		return nil, err
	}
	return s.listeners(t).List(ctx, func(lsn listener) bool {
		return tagMatchesQuery(lsn.ID, lsn.Name, lsn.Tags, q)
	})
}
