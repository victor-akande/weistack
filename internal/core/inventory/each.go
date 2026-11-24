package inventory

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Each calls fn with every record of kind in st, in every region and
// project, with the scope it is in: scopes in the order of
// store.Store.Scopes, and records in creation order. It stops at fn's
// first error, and returns it.
func Each[T any](ctx context.Context, st store.Store, kind string, fn func(store.Scope, T) error) error {
	scopes, err := st.Scopes(ctx, kind)
	if err != nil {
		return err
	}
	for _, sc := range scopes {
		items, err := store.Of[T](st, sc).List(ctx, nil)
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := fn(sc, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// Filter selects resources. An empty field selects every value.
type Filter struct {
	AccountID           string
	Type                Type // a zero Type selects every type
	RegionID            string
	ProjectID           string
	EnterpriseProjectID string
	ID                  string
}

// Match reports whether r is selected.
func (f Filter) Match(r Resource) bool {
	return (f.AccountID == "" || f.AccountID == r.AccountID) &&
		(f.Type == Type{} || f.Type == r.Type) &&
		(f.RegionID == "" || f.RegionID == r.RegionID) &&
		(f.ProjectID == "" || f.ProjectID == r.ProjectID) &&
		(f.EnterpriseProjectID == "" || f.EnterpriseProjectID == r.EnterpriseProjectID) &&
		(f.ID == "" || f.ID == r.ID)
}

// Select returns the resources f selects, in the snapshot's order.
func (s Snapshot) Select(f Filter) []Resource {
	out := []Resource{}
	for _, r := range s.Resources {
		if f.Match(r) {
			out = append(out, r)
		}
	}
	return out
}
