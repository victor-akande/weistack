package ecs

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Fixed limit values reported by ShowServerLimits for resources WeiStack does
// not emulate, taken from Huawei Cloud's API example response.
const (
	limitMaxServerMeta         = 128
	limitMaxPersonality        = 5
	limitMaxPersonalitySize    = 10240
	limitMaxImageMeta          = 128
	limitMaxSecurityGroupRules = 20
	limitMaxServerGroups       = 10
	limitMaxServerGroupMembers = 16
)

type showServerLimitsResponse struct {
	Absolute ServerLimits `json:"absolute"`
}

// ServerLimits mirrors the SDK model ecs/v2 ServerLimits.
type ServerLimits struct {
	MaxImageMeta            int   `json:"maxImageMeta"`
	MaxPersonality          int   `json:"maxPersonality"`
	MaxPersonalitySize      int   `json:"maxPersonalitySize"`
	MaxSecurityGroupRules   int   `json:"maxSecurityGroupRules"`
	MaxSecurityGroups       int   `json:"maxSecurityGroups"`
	MaxServerGroupMembers   int   `json:"maxServerGroupMembers"`
	MaxServerGroups         int   `json:"maxServerGroups"`
	MaxServerMeta           int   `json:"maxServerMeta"`
	MaxTotalCores           int   `json:"maxTotalCores"`
	MaxTotalFloatingIps     int   `json:"maxTotalFloatingIps"`
	MaxTotalInstances       int   `json:"maxTotalInstances"`
	MaxTotalKeypairs        int   `json:"maxTotalKeypairs"`
	MaxTotalRAMSize         int   `json:"maxTotalRAMSize"`
	TotalCoresUsed          int   `json:"totalCoresUsed"`
	TotalFloatingIpsUsed    int   `json:"totalFloatingIpsUsed"`
	TotalInstancesUsed      int   `json:"totalInstancesUsed"`
	TotalRAMUsed            int64 `json:"totalRAMUsed"`
	TotalSecurityGroupsUsed int   `json:"totalSecurityGroupsUsed"`
	TotalServerGroupsUsed   int   `json:"totalServerGroupsUsed"`
}

// ShowLimits returns the tenant's ECS resource quotas and current usage.
func (s *Service) ShowLimits(ctx context.Context, t Tenant) (ServerLimits, error) {
	all, err := s.servers(t).List(ctx, nil)
	if err != nil {
		return ServerLimits{}, err
	}
	var (
		coresUsed int
		ramUsed   int64
	)
	for _, srv := range all {
		if f, ok := s.FlavorByName(srv.Flavor); ok {
			coresUsed += f.VCPUs
			ramUsed += int64(f.RAM)
		}
	}

	var floatingIPsUsed int
	if s.eips != nil {
		floatingIPsUsed, err = s.eips.CountPublicIPs(ctx, t.vpc())
		if err != nil {
			return ServerLimits{}, err
		}
	}

	sgs, err := s.network.ListSecurityGroups(ctx, t.vpc(), vpc.ListSecurityGroupsFilter{})
	if err != nil {
		return ServerLimits{}, err
	}

	return ServerLimits{
		MaxImageMeta:            limitMaxImageMeta,
		MaxPersonality:          limitMaxPersonality,
		MaxPersonalitySize:      limitMaxPersonalitySize,
		MaxSecurityGroupRules:   limitMaxSecurityGroupRules,
		MaxSecurityGroups:       s.quotas.Get(quota.VPCSecurityGroup),
		MaxServerGroupMembers:   limitMaxServerGroupMembers,
		MaxServerGroups:         limitMaxServerGroups,
		MaxServerMeta:           limitMaxServerMeta,
		MaxTotalCores:           s.quotas.Get(quota.ECSCores),
		MaxTotalFloatingIps:     s.quotas.Get(quota.VPCPublicIP),
		MaxTotalInstances:       s.quotas.Get(quota.ECSInstances),
		MaxTotalKeypairs:        quota.Unlimited,
		MaxTotalRAMSize:         quota.Unlimited,
		TotalCoresUsed:          coresUsed,
		TotalFloatingIpsUsed:    floatingIPsUsed,
		TotalInstancesUsed:      len(all),
		TotalRAMUsed:            ramUsed,
		TotalSecurityGroupsUsed: len(sgs),
		TotalServerGroupsUsed:   0,
	}, nil
}
