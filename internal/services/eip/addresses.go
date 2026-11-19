package eip

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/victor-akande/weistack/internal/core/store"
)

var addressPrefixes = [...]string{
	"192.0.2",
	"198.51.100",
	"203.0.113",
}

var (
	defaultAddressPool []string
	defaultAddressSet  map[string]struct{}
)

func init() {
	defaultAddressPool = make([]string, 0, len(addressPrefixes)*254)
	defaultAddressSet = make(map[string]struct{}, len(addressPrefixes)*254)
	for _, prefix := range addressPrefixes {
		for host := 1; host <= 254; host++ {
			addr := fmt.Sprintf("%s.%d", prefix, host)
			defaultAddressPool = append(defaultAddressPool, addr)
			defaultAddressSet[addr] = struct{}{}
		}
	}
}

func (s *Service) candidatePool() []string {
	if s.pool != nil {
		return s.pool
	}
	return defaultAddressPool
}

func (s *Service) inAddressPool(addr string) bool {
	if s.pool != nil {
		return slices.Contains(s.pool, addr)
	}
	_, ok := defaultAddressSet[addr]
	return ok
}

// claimAddress claims a specific or the next available IPv4 address in the
// region's pool. Uniqueness is enforced across all projects and accounts in
// the region through the store.Global eip.address collection.
func (s *Service) claimAddress(ctx context.Context, t Tenant, publicIPID, requested string) (string, error) {
	col := s.addresses(t.Region)
	claim := addressClaim{
		ProjectID:  t.ProjectID,
		PublicIPID: publicIPID,
	}

	if requested != "" {
		if !s.inAddressPool(requested) {
			return "", errIPAddressInUse()
		}
		if err := col.Create(ctx, requested, claim); err != nil {
			if errors.Is(err, store.ErrExists) {
				return "", errIPAddressInUse()
			}
			return "", err
		}
		return requested, nil
	}

	for _, addr := range s.candidatePool() {
		err := col.Create(ctx, addr, claim)
		if err == nil {
			return addr, nil
		}
		if errors.Is(err, store.ErrExists) {
			continue
		}
		return "", err
	}
	return "", errAddressPoolExhausted()
}

// releaseAddress deletes the claim for address in region, ignoring ErrNotFound.
func (s *Service) releaseAddress(ctx context.Context, region, address string) error {
	if address == "" {
		return nil
	}
	err := s.addresses(region).Delete(ctx, address)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}
