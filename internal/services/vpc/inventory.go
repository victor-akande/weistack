package vpc

import (
	"context"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: VPCs, subnets, security
// groups and their rules. Config relates none of them to each other; the
// EIP service reports which VPC contains an EIP.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindVPC, func(sc store.Scope, v VPC) error {
		return emit(inventory.Resource{
			Type: inventory.VPCs, ID: v.ID, Name: v.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: v.EnterpriseProjectID,
			Created: time.Time(v.CreatedAt), Updated: time.Time(v.UpdatedAt),
			State: vpcState(v.Status),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindSubnet, func(sc store.Scope, r subnetRecord) error {
		return emit(inventory.Resource{
			Type: inventory.VPCSubnets, ID: r.ID, Name: r.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: time.Time(r.CreatedAt), Updated: time.Time(r.UpdatedAt),
			State: subnetState(r.Status),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindSecGroup, func(sc store.Scope, g SecurityGroup) error {
		return emit(inventory.Resource{
			Type: inventory.VPCSecurityGroups, ID: g.ID, Name: g.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: g.EnterpriseProjectID,
			Created: time.Time(g.CreatedAt), Updated: time.Time(g.UpdatedAt),
			Tags: tagMap(g.Tags),
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindSecGroupRule, func(sc store.Scope, r SecurityGroupRule) error {
		return emit(inventory.Resource{
			Type: inventory.VPCSecurityGroupRules, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: time.Time(r.CreatedAt), Updated: time.Time(r.UpdatedAt),
		})
	})
}

func vpcState(status string) inventory.State {
	switch status {
	case VPCStatusCreating:
		return inventory.Processing
	case VPCStatusError:
		return inventory.Failed
	default:
		return inventory.Succeeded
	}
}

// subnetState: a subnet is UNKNOWN while it is being created.
func subnetState(status string) inventory.State {
	switch status {
	case SubnetStatusUnknown:
		return inventory.Processing
	case SubnetStatusError:
		return inventory.Failed
	default:
		return inventory.Succeeded
	}
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
