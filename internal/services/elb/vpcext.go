package elb

import (
	"context"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// VPCExtension returns a vpc.Extension that reports ELB's loadbalancer and
// listener quotas through VPC's GET /v1/{project_id}/quotas endpoint.
func (s *Service) VPCExtension() vpc.Extension {
	return vpcExtension{s: s}
}

type vpcExtension struct {
	s *Service
}

func (vpcExtension) RoutesV1(chi.Router)  {}
func (vpcExtension) RoutesV20(chi.Router) {}
func (vpcExtension) Routes(chi.Router)    {}

func (e vpcExtension) Quotas(ctx context.Context, t vpc.Tenant) ([]vpc.QuotaResource, error) {
	lbs, err := e.s.loadBalancers(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	lsns, err := e.s.listeners(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	return []vpc.QuotaResource{
		{Type: "loadbalancer", Used: len(lbs), Quota: e.s.quotas.Get(quota.ELBLoadBalancer), Min: 0},
		{Type: "listener", Used: len(lsns), Quota: e.s.quotas.Get(quota.ELBListener), Min: 0},
	}, nil
}
