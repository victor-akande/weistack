package ecs

import (
	"context"

	"github.com/victor-akande/weistack/internal/services/vpc"
)

// ServerAt returns the status of the project's server with a NIC in
// subnetID (the subnet's ID; "" means any subnet of vpcID) at ip.
func (s *Service) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}
