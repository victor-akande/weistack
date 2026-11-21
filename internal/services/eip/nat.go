package eip

import (
	"context"
	"errors"
	"fmt"

	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// NAT reports why an EIP cannot be used by a NAT gateway.
var (
	ErrNATNotFound = errors.New("eip: not found")
	ErrNATBound    = errors.New("eip: bound to a port")       // wrapped with the port ID
	ErrNATHeld     = errors.New("eip: used by a NAT gateway") // wrapped with the gateway ID
	ErrNATNotReady = errors.New("eip: not ready")             // PENDING_CREATE
)

// HoldForNAT marks an EIP as used by a NAT gateway and returns its
// address. Holding an EIP the same gateway already holds is a no-op.
func (s *Service) HoldForNAT(ctx context.Context, t vpc.Tenant, eipID, gatewayID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, eipID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNATNotFound
	}
	if err != nil {
		return "", err
	}
	if pip.Status == StatusPendingCreate {
		return "", ErrNATNotReady
	}
	if pip.PortID != "" {
		return "", fmt.Errorf("%w: %s", ErrNATBound, pip.PortID)
	}
	if pip.ELBLoadBalancerID != "" {
		return "", fmt.Errorf("%w: %s", ErrNATBound, pip.ELBLoadBalancerID)
	}
	if pip.NATGatewayID != "" {
		if pip.NATGatewayID == gatewayID {
			return pip.Address, nil
		}
		return "", fmt.Errorf("%w: %s", ErrNATHeld, pip.NATGatewayID)
	}

	pip.NATGatewayID = gatewayID
	pip.Status = StatusActive
	pip.UpdatedAt = s.nowUTC()
	if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
		return "", err
	}
	return pip.Address, nil
}

// ReleaseFromNAT ends the gateway's hold; NAT calls it when no rule of the
// gateway uses the EIP any more. Releasing an EIP the gateway does not
// hold, or one that is gone, is a no-op.
func (s *Service) ReleaseFromNAT(ctx context.Context, t vpc.Tenant, eipID, gatewayID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, eipID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if pip.NATGatewayID == "" || pip.NATGatewayID != gatewayID {
		return nil
	}

	pip.NATGatewayID = ""
	pip.Status = StatusDown
	pip.UpdatedAt = s.nowUTC()
	return s.publicips(t).Put(ctx, pip.ID, pip)
}

// PublicIPByAddress finds an EIP of the project by its address.
func (s *Service) PublicIPByAddress(ctx context.Context, t vpc.Tenant, address string) (id string, ok bool, err error) {
	if address == "" {
		return "", false, nil
	}
	items, err := s.publicips(t).List(ctx, func(p publicIP) bool {
		return p.Address == address
	})
	if err != nil {
		return "", false, err
	}
	if len(items) == 0 {
		return "", false, nil
	}
	return items[0].ID, true, nil
}

// PublicIPAddress returns an EIP's address.
func (s *Service) PublicIPAddress(ctx context.Context, t vpc.Tenant, eipID string) (string, bool, error) {
	pip, err := s.publicips(t).Get(ctx, eipID)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return pip.Address, true, nil
}
