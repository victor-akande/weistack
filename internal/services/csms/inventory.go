package csms

import (
	"context"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter for CSMS secrets. Secret
// values, versions, stages, and cryptographic material are never reported.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindSecret, func(sc store.Scope, sec Secret) error {
		return emit(resourceOf(sc, sec))
	})
}

func resourceOf(sc store.Scope, sec Secret) inventory.Resource {
	return inventory.Resource{
		Type:                inventory.CSMSSecrets,
		ID:                  sec.ID,
		Name:                sec.Name,
		RegionID:            sc.Region,
		ProjectID:           sc.ProjectID,
		EnterpriseProjectID: sec.EnterpriseProjectID,
		Created:             unixMilli(sec.CreatedAt),
		Updated:             unixMilli(sec.UpdatedAt),
		State:               inventory.Succeeded,
		Tags:                tagMap(sec.Tags),
	}
}

func unixMilli(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func tagMap(tags []Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}
