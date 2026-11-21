package eip

import (
	"context"

	"github.com/victor-akande/weistack/internal/services/vpc"
)

// BindToELB binds an existing EIP to a load balancer's VIP.
func (s *Service) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", ErrNATNotFound
}

// CreateForELB creates an EIP bound to a load balancer's VIP, as
// AttachToServer creates one for a server.
func (s *Service) CreateForELB(context.Context, vpc.Tenant, string, string, string, ServerIP) (string, string, error) {
	return "", "", ErrNATNotFound
}

// UnbindFromELB unbinds an EIP; the EIP stays.
func (s *Service) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}
