package kms

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: customer master keys,
// including service default keys. Grants are permissions on a key and
// are not reported.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindKey, func(_ store.Scope, k key) error {
		if s.gone(k) {
			return nil
		}
		return emit(resourceOf(k))
	})
}

func resourceOf(k key) inventory.Resource {
	return inventory.Resource{
		Type:                inventory.KMSKeys,
		ID:                  k.ID,
		Name:                k.Alias,
		AccountID:           k.AccountID,
		RegionID:            k.Region,
		ProjectID:           k.ProjectID,
		EnterpriseProjectID: k.EP,
		Created:             k.CreatedAt,
		State:               inventory.Succeeded,
		Tags:                tagMap(k.Tags),
	}
}

func tagMap(tags []tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}
