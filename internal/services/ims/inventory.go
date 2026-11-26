package ims

import (
	"context"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: private images only. Public
// images live under store.Global and belong to no account; ECS reports which
// image a server uses.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindImage, func(sc store.Scope, img Image) error {
		if sc.ProjectID == store.Global {
			return nil
		}
		return emit(inventory.Resource{
			Type: inventory.IMSImages, ID: img.ID, Name: img.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: img.EnterpriseProjectID,
			Created: time.Time(img.CreatedAt), Updated: time.Time(img.UpdatedAt),
			State: imageState(img.Status),
			Tags:  tagMap(img.Tags),
		})
	})
}

func imageState(status string) inventory.State {
	switch status {
	case StatusQueued, StatusSaving:
		return inventory.Processing
	case StatusKilled:
		return inventory.Failed
	default:
		return inventory.Succeeded
	}
}

func tagMap(tags []string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		k, v, _ := strings.Cut(t, "=")
		m[k] = v
	}
	return m
}
