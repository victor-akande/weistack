package elb

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: load balancers, listeners,
// pools, members, health monitors, L7 policies, certificates, IP groups and
// security policies. L7 rules are not standalone Config resources and are not
// reported; EIP reports the load balancer's public IPs.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindLoadBalancer, func(sc store.Scope, lb loadBalancer) error {
		return emit(inventory.Resource{
			Type: inventory.ELBLoadBalancers, ID: lb.ID, Name: lb.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: lb.EnterpriseProjectID,
			Created: lb.CreatedAt, Updated: lb.UpdatedAt,
			State: inventory.Succeeded,
			Tags:  tagMap(lb.Tags),
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindListener, func(sc store.Scope, l listener) error {
		rels := []inventory.Ref{{Relation: inventory.IsContainedIn, Type: inventory.ELBLoadBalancers, ID: l.LoadBalancerID}}
		if l.DefaultPoolID != "" {
			rels = append(rels, inventory.Ref{Relation: inventory.IsAttachedTo, Type: inventory.ELBPools, ID: l.DefaultPoolID})
		}
		return emit(inventory.Resource{
			Type: inventory.ELBListeners, ID: l.ID, Name: l.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: l.EnterpriseProjectID,
			Created: l.CreatedAt, Updated: l.UpdatedAt,
			State:     inventory.Succeeded,
			Tags:      tagMap(l.Tags),
			Relations: rels,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindPool, func(sc store.Scope, p pool) error {
		var rels []inventory.Ref
		if p.LoadBalancerID != "" {
			rels = []inventory.Ref{{Relation: inventory.IsAttachedTo, Type: inventory.ELBLoadBalancers, ID: p.LoadBalancerID}}
		}
		return emit(inventory.Resource{
			Type: inventory.ELBPools, ID: p.ID, Name: p.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: p.EnterpriseProjectID,
			Created: p.CreatedAt, Updated: p.UpdatedAt,
			State:     inventory.Succeeded,
			Relations: rels,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindMember, func(sc store.Scope, m member) error {
		return emit(inventory.Resource{
			Type: inventory.ELBMembers, ID: m.ID, Name: m.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: m.CreatedAt, Updated: m.UpdatedAt,
			State:     inventory.Succeeded,
			Relations: []inventory.Ref{{Relation: inventory.IsContainedIn, Type: inventory.ELBPools, ID: m.PoolID}},
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindHealthMonitor, func(sc store.Scope, hm healthMonitor) error {
		return emit(inventory.Resource{
			Type: inventory.ELBHealthMonitors, ID: hm.ID, Name: hm.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: hm.CreatedAt, Updated: hm.UpdatedAt,
			State: inventory.Succeeded,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindL7Policy, func(sc store.Scope, p l7Policy) error {
		return emit(inventory.Resource{
			Type: inventory.ELBL7Policies, ID: p.ID, Name: p.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: p.EnterpriseProjectID,
			Created: p.CreatedAt, Updated: p.UpdatedAt,
			State:     inventory.Succeeded,
			Relations: []inventory.Ref{{Relation: inventory.IsContainedIn, Type: inventory.ELBListeners, ID: p.ListenerID}},
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindCertificate, func(sc store.Scope, c certificate) error {
		return emit(inventory.Resource{
			Type: inventory.ELBCertificates, ID: c.ID, Name: c.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: c.EnterpriseProjectID,
			Created: c.CreatedAt, Updated: c.UpdatedAt,
			State: inventory.Succeeded,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindIPGroup, func(sc store.Scope, g ipGroup) error {
		return emit(inventory.Resource{
			Type: inventory.ELBIPGroups, ID: g.ID, Name: g.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: g.EnterpriseProjectID,
			Created: g.CreatedAt, Updated: g.UpdatedAt,
			State: inventory.Succeeded,
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindSecurityPolicy, func(sc store.Scope, sp securityPolicy) error {
		return emit(inventory.Resource{
			Type: inventory.ELBSecurityPolicies, ID: sp.ID, Name: sp.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: sp.EnterpriseProjectID,
			Created: sp.CreatedAt, Updated: sp.UpdatedAt,
			State: inventory.Succeeded,
		})
	})
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
