package eip

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Quotas implements vpc.Extension, returning EIP's publicIp, shareBandwidth,
// and shareBandwidthIP quota items for GET /v1/{project_id}/quotas.
func (s *Service) Quotas(ctx context.Context, t vpc.Tenant) ([]vpc.QuotaResource, error) {
	pips, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	bws, err := s.bandwidths(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	sharedCount := 0
	maxSharedIPs := 0
	for _, bw := range bws {
		if bw.ShareType != ShareTypeWhole {
			continue
		}
		sharedCount++
		if n := len(bw.PublicIPIDs); n > maxSharedIPs {
			maxSharedIPs = n
		}
	}
	return []vpc.QuotaResource{
		{Type: "publicIp", Used: len(pips), Quota: s.quotas.Get(quota.VPCPublicIP), Min: 0},
		{Type: "shareBandwidth", Used: sharedCount, Quota: s.quotas.Get(quota.VPCShareBandwidth), Min: 0},
		{Type: "shareBandwidthIP", Used: maxSharedIPs, Quota: s.quotas.Get(quota.VPCShareBandwidthIP), Min: 0},
	}, nil
}

// CountPublicIPs returns the number of elastic IPs in the tenant.
func (s *Service) CountPublicIPs(ctx context.Context, t vpc.Tenant) (int, error) {
	pips, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return 0, err
	}
	return len(pips), nil
}
