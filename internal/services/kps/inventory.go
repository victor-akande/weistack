package kps

import (
	"context"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter for SSH key pairs. Public keys,
// sealed private keys, and asynchronous bind or unbind tasks are never reported.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindKeypair, func(sc store.Scope, kp Keypair) error {
		return emit(inventory.Resource{
			Type:      inventory.KPSKeypairs,
			ID:        kp.Name,
			Name:      kp.Name,
			RegionID:  sc.Region,
			ProjectID: sc.ProjectID,
			Created:   unixMilli(kp.CreatedAt),
			Updated:   unixMilli(kp.UpdatedAt),
		})
	})
}

func unixMilli(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
