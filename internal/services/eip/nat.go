package eip

import (
	"context"
	"errors"

	"github.com/victor-akande/weistack/internal/core/apierr"
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
func (s *Service) HoldForNAT(_ context.Context, _ vpc.Tenant, _, _ string) (string, error) {
	return "", apierr.NotImplemented("eip", "HoldForNAT")
}

// ReleaseFromNAT ends the gateway's hold; NAT calls it when no rule of the
// gateway uses the EIP any more. Releasing an EIP the gateway does not
// hold, or one that is gone, is a no-op.
func (s *Service) ReleaseFromNAT(_ context.Context, _ vpc.Tenant, _, _ string) error {
	return apierr.NotImplemented("eip", "ReleaseFromNAT")
}

// PublicIPByAddress finds an EIP of the project by its address.
func (s *Service) PublicIPByAddress(_ context.Context, _ vpc.Tenant, _ string) (id string, ok bool, err error) {
	return "", false, apierr.NotImplemented("eip", "PublicIPByAddress")
}

// PublicIPAddress returns an EIP's address.
func (s *Service) PublicIPAddress(_ context.Context, _ vpc.Tenant, _ string) (string, bool, error) {
	return "", false, apierr.NotImplemented("eip", "PublicIPAddress")
}
