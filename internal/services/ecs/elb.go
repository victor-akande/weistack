package ecs

import (
	"context"

	"github.com/victor-akande/weistack/internal/services/vpc"
)

// ServerAt returns the status of the project's server with a NIC in
// subnetID (the subnet's ID; "" means any subnet of vpcID) at ip.
func (s *Service) ServerAt(ctx context.Context, t vpc.Tenant, vpcID, subnetID, ip string) (string, bool, error) {
	if ip == "" {
		return "", false, nil
	}
	servers, err := s.servers(Tenant{Region: t.Region, ProjectID: t.ProjectID}).List(ctx, nil)
	if err != nil {
		return "", false, err
	}
	for _, srv := range servers {
		if vpcID != "" && srv.VPCID != vpcID {
			continue
		}
		for _, nic := range srv.NICs {
			if nic.IP != ip {
				continue
			}
			if subnetID != "" && nic.SubnetID != subnetID {
				continue
			}
			return srv.Status, true, nil
		}
	}
	return "", false, nil
}
