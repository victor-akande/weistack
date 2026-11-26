package eip

import (
	"context"
	"errors"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: elastic IPs and bandwidths.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindPublicIP, func(sc store.Scope, ip publicIP) error {
		rels, err := s.publicIPRelations(ctx, Tenant{Region: sc.Region, ProjectID: sc.ProjectID}, ip)
		if err != nil {
			return err
		}
		return emit(inventory.Resource{
			Type:                inventory.EIPPublicIPs,
			ID:                  ip.ID,
			Name:                ip.Alias,
			RegionID:            sc.Region,
			ProjectID:           sc.ProjectID,
			EnterpriseProjectID: ip.EnterpriseProjectID,
			Created:             ip.CreatedAt,
			Updated:             ip.UpdatedAt,
			State:               publicIPState(ip.Status),
			Tags:                tagMap(ip.Tags),
			Relations:           rels,
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindBandwidth, func(sc store.Scope, bw bandwidth) error {
		return emit(inventory.Resource{
			Type:                inventory.EIPBandwidths,
			ID:                  bw.ID,
			Name:                bw.Name,
			RegionID:            sc.Region,
			ProjectID:           sc.ProjectID,
			EnterpriseProjectID: bw.EnterpriseProjectID,
			Created:             bw.CreatedAt,
			Updated:             bw.UpdatedAt,
		})
	})
}

func (s *Service) publicIPRelations(ctx context.Context, t Tenant, ip publicIP) ([]inventory.Ref, error) {
	var rels []inventory.Ref
	if ip.BandwidthID != "" {
		rels = append(rels, inventory.Ref{
			Relation: inventory.IsContainedIn,
			Type:     inventory.EIPBandwidths,
			ID:       ip.BandwidthID,
		})
	}
	if ip.NATGatewayID != "" {
		rels = append(rels, inventory.Ref{
			Relation: inventory.IsAttachedTo,
			Type:     inventory.NATGateways,
			ID:       ip.NATGatewayID,
		})
	}
	if ip.ELBLoadBalancerID != "" {
		rels = append(rels, inventory.Ref{
			Relation: inventory.IsAttachedTo,
			Type:     inventory.ELBLoadBalancers,
			ID:       ip.ELBLoadBalancerID,
		})
	}
	if ip.PortID != "" && s.ports != nil {
		port, ok, err := s.ports.Port(ctx, t, ip.PortID)
		if err != nil {
			return nil, err
		}
		if ok {
			if strings.HasPrefix(port.DeviceOwner, "compute:") && port.DeviceID != "" {
				rels = append(rels, inventory.Ref{
					Relation: inventory.IsAttachedTo,
					Type:     inventory.ECSServers,
					ID:       port.DeviceID,
				})
			}
			if port.SubnetID != "" {
				if sl, hasSubnet := s.ports.(subnetLookup); hasSubnet {
					sn, snErr := sl.GetSubnet(ctx, t, port.SubnetID)
					var apiErr *apierr.Error
					switch {
					case snErr == nil:
						if sn.VPCID != "" {
							rels = append(rels, inventory.Ref{
								Relation: inventory.IsContainedIn,
								Type:     inventory.VPCs,
								ID:       sn.VPCID,
							})
						}
					case !errors.As(snErr, &apiErr):
						return nil, snErr
					}
				}
			}
		}
	}
	return rels, nil
}

func publicIPState(status string) inventory.State {
	switch status {
	case StatusPendingCreate:
		return inventory.Processing
	case "ERROR":
		return inventory.Failed
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
