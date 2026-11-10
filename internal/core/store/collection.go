package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// Collection is a typed, JSON-encoded view of one Scope. It is a small
// value: build one per request with Of.
type Collection[T any] struct {
	s     Store
	scope Scope
}

// Of returns the typed view of scope in s.
func Of[T any](s Store, scope Scope) Collection[T] {
	return Collection[T]{s: s, scope: scope}
}

func (c Collection[T]) decode(rec Record) (T, error) {
	var v T
	if err := json.Unmarshal(rec.Data, &v); err != nil {
		return v, fmt.Errorf("store: decoding %s/%s: %w", c.scope, rec.ID, err)
	}
	return v, nil
}

func (c Collection[T]) encode(id string, v T) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("store: encoding %s/%s: %w", c.scope, id, err)
	}
	return data, nil
}

// Get returns the value with the given ID or ErrNotFound.
func (c Collection[T]) Get(ctx context.Context, id string) (T, error) {
	rec, err := c.s.Get(ctx, c.scope, id)
	if err != nil {
		var zero T
		return zero, err
	}
	return c.decode(rec)
}

// List returns the values for which keep returns true, in creation order.
// A nil keep returns everything. The result is never nil.
func (c Collection[T]) List(ctx context.Context, keep func(T) bool) ([]T, error) {
	recs, err := c.s.List(ctx, c.scope)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(recs))
	for _, rec := range recs {
		v, err := c.decode(rec)
		if err != nil {
			return nil, err
		}
		if keep == nil || keep(v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// Create stores a new value or returns ErrExists.
func (c Collection[T]) Create(ctx context.Context, id string, v T) error {
	data, err := c.encode(id, v)
	if err != nil {
		return err
	}
	_, err = c.s.Create(ctx, c.scope, id, data)
	return err
}

// Put stores v, replacing any existing value.
func (c Collection[T]) Put(ctx context.Context, id string, v T) error {
	data, err := c.encode(id, v)
	if err != nil {
		return err
	}
	_, err = c.s.Put(ctx, c.scope, id, data)
	return err
}

// Update atomically applies fn to the stored value and returns the
// result. fn may run more than once (see the package-level Update) and
// must not have side effects. An error from fn aborts the update.
func (c Collection[T]) Update(ctx context.Context, id string, fn func(*T) error) (T, error) {
	var result T
	_, err := Update(ctx, c.s, c.scope, id, func(data []byte) ([]byte, error) {
		v, err := c.decode(Record{ID: id, Data: data})
		if err != nil {
			return nil, err
		}
		if err := fn(&v); err != nil {
			return nil, err
		}
		result = v
		return c.encode(id, v)
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

// Delete removes the value or returns ErrNotFound.
func (c Collection[T]) Delete(ctx context.Context, id string) error {
	return c.s.Delete(ctx, c.scope, id)
}
