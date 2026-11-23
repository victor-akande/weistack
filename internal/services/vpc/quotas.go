package vpc

import (
	"context"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
)

// v1QuotaResponse mirrors the SDK model vpc/v2 ShowQuotaResponse (and eip/v2 ListQuotasResponse).
type v1QuotaResponse struct {
	Quotas v1QuotaBody `json:"quotas"`
}

type v1QuotaBody struct {
	Resources []QuotaResource `json:"resources"`
}

// v3QuotaResponse mirrors the SDK model vpc/v3 ShowQuotaResponse.
type v3QuotaResponse struct {
	RequestID string   `json:"request_id"`
	Quota     v3Quotas `json:"quota"`
}

// v3Quotas mirrors the SDK model vpc/v3 VpcQuotas for the resources WeiStack emulates;
// unemulated fields of the SDK model are omitempty and omitted here.
type v3Quotas struct {
	VPC               int `json:"vpc"`
	Virsubnet         int `json:"virsubnet"`
	SecurityGroup     int `json:"security_group"`
	SecurityGroupRule int `json:"security_group_rule"`
}

// listQuotas returns all v1 quota resources for tenant t in the documented order:
// vpc, subnet, securityGroup, securityGroupRule, followed by items from registered
// extensions (EIP, ELB). Usage is counted directly from the store without holding s.mu.
func (s *Service) listQuotas(ctx context.Context, t Tenant) ([]QuotaResource, error) {
	vpcs, err := s.vpcs(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	subnets, err := s.subnets(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	groups, err := s.secGroups(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	rules, err := s.secGroupRules(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}

	resources := []QuotaResource{
		{Type: "vpc", Used: len(vpcs), Quota: s.quotas.Get(quota.VPCVPC), Min: 0},
		{Type: "subnet", Used: len(subnets), Quota: s.quotas.Get(quota.VPCSubnet), Min: 0},
		{Type: "securityGroup", Used: len(groups), Quota: s.quotas.Get(quota.VPCSecurityGroup), Min: 0},
		{Type: "securityGroupRule", Used: len(rules), Quota: s.quotas.Get(quota.VPCSecurityGroupRule), Min: 0},
	}
	for _, ext := range s.exts {
		extra, err := ext.Quotas(ctx, t)
		if err != nil {
			return nil, err
		}
		resources = append(resources, extra...)
	}
	return resources, nil
}

func (s *Service) handleShowQuotaV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	resources, err := s.listQuotas(r.Context(), t)
	if err != nil {
		return err
	}
	if typ := r.URL.Query().Get("type"); typ != "" {
		var filtered []QuotaResource
		for _, res := range resources {
			if res.Type == typ {
				filtered = append(filtered, res)
			}
		}
		if len(filtered) == 0 {
			return errInvalidQuotaType()
		}
		resources = filtered
	}
	return httpx.WriteJSON(w, http.StatusOK, v1QuotaResponse{
		Quotas: v1QuotaBody{Resources: resources},
	})
}

func (s *Service) handleShowQuotaV3(w http.ResponseWriter, r *http.Request, _ Tenant) error {
	return httpx.WriteJSON(w, http.StatusOK, v3QuotaResponse{
		RequestID: requestID(r),
		Quota: v3Quotas{
			VPC:               s.quotas.Get(quota.VPCVPC),
			Virsubnet:         s.quotas.Get(quota.VPCSubnet),
			SecurityGroup:     s.quotas.Get(quota.VPCSecurityGroup),
			SecurityGroupRule: s.quotas.Get(quota.VPCSecurityGroupRule),
		},
	})
}
