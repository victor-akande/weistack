package rds

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/quota"
)

type showQuotasResponse struct {
	Quotas quotaList `json:"quotas"`
}

type quotaList struct {
	Resources []QuotaResource `json:"resources"`
}

// QuotaResource mirrors the SDK model rds/v3 Resources.
type QuotaResource struct {
	Type  string `json:"type"`
	Used  int    `json:"used"`
	Quota int    `json:"quota"`
}

// ShowQuotas returns the project's RDS resource quotas and current usage.
func (s *Service) ShowQuotas(ctx context.Context, t Tenant) ([]QuotaResource, error) {
	existing, err := s.instances(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	return []QuotaResource{
		{
			Type:  "instance",
			Used:  len(existing),
			Quota: s.quotas.Get(quota.RDSInstance),
		},
	}, nil
}
