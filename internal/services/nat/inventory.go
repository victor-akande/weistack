package nat

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: public NAT gateways and rules,
// private NAT gateways and rules, transit subnets and transit IPs. The EIP
// service reports which public IPs are attached to a public NAT gateway.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindGateway, func(sc store.Scope, g gateway) error {
		return emit(inventory.Resource{
			Type: inventory.NATGateways, ID: g.ID, Name: g.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: g.EnterpriseProjectID,
			Created: g.CreatedAt,
			State:   natState(g.Status),
			Tags:    tagMap(g.Tags),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindSnat, func(sc store.Scope, r snatRule) error {
		return emit(inventory.Resource{
			Type: inventory.NATSNATRules, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: r.CreatedAt,
			State:   natState(r.Status),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindDnat, func(sc store.Scope, r dnatRule) error {
		return emit(inventory.Resource{
			Type: inventory.NATDNATRules, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: r.CreatedAt,
			State:   natState(r.Status),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindPrivateGateway, func(sc store.Scope, g privateGateway) error {
		return emit(inventory.Resource{
			Type: inventory.NATPrivateGateways, ID: g.ID, Name: g.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: g.EnterpriseProjectID,
			Created: g.CreatedAt, Updated: g.UpdatedAt,
			Tags: tagMap(g.Tags),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindPrivateSnat, func(sc store.Scope, r privateSnat) error {
		return emit(inventory.Resource{
			Type: inventory.NATPrivateSNATRules, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: r.CreatedAt, Updated: r.UpdatedAt,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindPrivateDnat, func(sc store.Scope, r privateDnat) error {
		return emit(inventory.Resource{
			Type: inventory.NATPrivateDNATRules, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: r.CreatedAt, Updated: r.UpdatedAt,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindTransitSubnet, func(sc store.Scope, r transitSubnet) error {
		return emit(inventory.Resource{
			Type: inventory.NATTransitSubnets, ID: r.ID, Name: r.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: r.CreatedAt, Updated: r.UpdatedAt,
			Tags: tagMap(r.Tags),
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindTransitIP, func(sc store.Scope, r transitIP) error {
		return emit(inventory.Resource{
			Type: inventory.NATTransitIPs, ID: r.ID,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: r.EnterpriseProjectID,
			Created: r.CreatedAt, Updated: r.UpdatedAt,
			Tags: tagMap(r.Tags),
		})
	})
}

func natState(status string) inventory.State {
	switch status {
	case StatusPendingCreate:
		return inventory.Processing
	case StatusActive, StatusInactive:
		return inventory.Succeeded
	default:
		return inventory.Succeeded
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
