package evs

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: volumes and snapshots.
// Volumes report their server attachments; Config relates no snapshot to
// its volume.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindVolume, func(sc store.Scope, v volume) error {
		return emit(inventory.Resource{
			Type: inventory.EVSVolumes, ID: v.ID, Name: v.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: v.EnterpriseProjectID,
			Created: parseTime(v.CreatedAt), Updated: parseTime(v.UpdatedAt),
			State:     evsState(v.Status),
			Tags:      volumeTags(v.Tags),
			Relations: volumeRelations(v.Attachments),
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindSnapshot, func(sc store.Scope, sn snapshot) error {
		return emit(inventory.Resource{
			Type: inventory.EVSSnapshots, ID: sn.ID, Name: sn.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: sn.EnterpriseProjectID,
			Created: parseTime(sn.CreatedAt), Updated: parseTime(sn.UpdatedAt),
			State: evsState(sn.Status),
		})
	})
}

func evsState(status string) inventory.State {
	switch status {
	case statusCreating, statusExtending, statusDeleting, statusAttaching, statusDetaching, statusRollbacking:
		return inventory.Processing
	case statusError, statusErrorExtending, statusErrorDeleting, statusErrorRestoring, statusErrorRollbacking:
		return inventory.Failed
	case statusAvailable, statusInUse:
		return inventory.Succeeded
	default:
		if strings.HasPrefix(status, "error") {
			return inventory.Failed
		}
		return inventory.Succeeded
	}
}

func volumeTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	return maps.Clone(tags)
}

func volumeRelations(atts []attachment) []inventory.Ref {
	if len(atts) == 0 {
		return nil
	}
	var rels []inventory.Ref
	for _, a := range atts {
		if a.ServerID != "" {
			rels = append(rels, inventory.Ref{
				Relation: inventory.IsAttachedTo,
				Type:     inventory.ECSServers,
				ID:       a.ServerID,
			})
		}
	}
	return rels
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(volumeTimeLayout, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}
