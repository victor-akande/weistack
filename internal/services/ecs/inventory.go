package ecs

import (
	"context"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: cloud servers and their
// VPC, security group and image relationships.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindServer, func(sc store.Scope, srv Server) error {
		return emit(inventory.Resource{
			Type:                inventory.ECSServers,
			ID:                  srv.ID,
			Name:                srv.Name,
			RegionID:            sc.Region,
			ProjectID:           sc.ProjectID,
			EnterpriseProjectID: srv.EnterpriseProjectID,
			Created:             parseTime(srv.Created),
			Updated:             parseTime(srv.Updated),
			State:               serverState(srv.Status, srv.Pending),
			Tags:                tagMap(srv.Tags),
			Relations:           serverRelations(srv),
		})
	})
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func serverState(status string, pending *PendingOp) inventory.State {
	if pending != nil {
		return inventory.Processing
	}
	switch status {
	case StatusBuild, StatusReboot, StatusHardReboot, StatusResize:
		return inventory.Processing
	case StatusError:
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
	for _, raw := range tags {
		t := splitTag(raw)
		m[t.Key] = t.Value
	}
	return m
}

func serverRelations(srv Server) []inventory.Ref {
	var refs []inventory.Ref
	if srv.VPCID != "" {
		refs = append(refs, inventory.Ref{
			Relation: inventory.IsContainedIn,
			Type:     inventory.VPCs,
			ID:       srv.VPCID,
		})
	}
	for _, sgID := range srv.SecurityGroups {
		if sgID != "" {
			refs = append(refs, inventory.Ref{
				Relation: inventory.IsAssociatedWith,
				Type:     inventory.VPCSecurityGroups,
				ID:       sgID,
			})
		}
	}
	if srv.ImageID != "" {
		refs = append(refs, inventory.Ref{
			Relation: inventory.IsAssociatedWith,
			Type:     inventory.IMSImages,
			ID:       srv.ImageID,
		})
	}
	return refs
}
