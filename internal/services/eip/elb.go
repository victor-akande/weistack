package eip

import (
	"context"
	"errors"
	"fmt"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// BindToELB binds an existing EIP to a load balancer's VIP and returns its
// IPv4 address. Binding an EIP already bound to the same load balancer is a
// no-op.
func (s *Service) BindToELB(ctx context.Context, t vpc.Tenant, eipID, lbID, vipPortID, vipAddress string) (string, error) {
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
	if pip.NATGatewayID != "" {
		return "", fmt.Errorf("%w: %s", ErrNATHeld, pip.NATGatewayID)
	}
	if pip.ELBLoadBalancerID != "" {
		if pip.ELBLoadBalancerID == lbID {
			return pip.Address, nil
		}
		return "", fmt.Errorf("%w: %s", ErrNATBound, pip.PortID)
	}
	if pip.PortID != "" {
		return "", fmt.Errorf("%w: %s", ErrNATBound, pip.PortID)
	}
	if vipPortID != "" {
		existing, err := s.publicips(t).List(ctx, nil)
		if err != nil {
			return "", err
		}
		for _, other := range existing {
			if other.ID != pip.ID && other.PortID == vipPortID {
				return "", fmt.Errorf("%w: %s", ErrNATBound, vipPortID)
			}
		}
	}

	pip.PortID = vipPortID
	pip.PrivateIP = vipAddress
	pip.ELBLoadBalancerID = lbID
	pip.Status = StatusActive
	pip.UpdatedAt = s.nowUTC()
	if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
		return "", err
	}
	return pip.Address, nil
}

// CreateForELB creates an EIP immediately ACTIVE and bound to a load balancer's
// VIP, as AttachToServer creates one for a server.
func (s *Service) CreateForELB(ctx context.Context, t vpc.Tenant, lbID, vipPortID, vipAddress string, ip ServerIP) (string, string, error) {
	if !validPublicIPType(t.Region, ip.Type) {
		return "", "", errInvalidPublicIP("publicip type is invalid")
	}
	if ip.ShareType != ShareTypePer && ip.ShareType != ShareTypeWhole {
		return "", "", errInvalidPublicIP("Bandwidth share_type is invalid.")
	}
	chargeMode := ChargeModeBandwidth
	switch ip.ShareType {
	case ShareTypePer:
		if ip.Size < 1 || ip.Size > 2000 {
			return "", "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
		if ip.BandwidthName != "" && !validName(ip.BandwidthName) {
			return "", "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
		if ip.ChargeMode != "" {
			if ip.ChargeMode != ChargeModeBandwidth && ip.ChargeMode != ChargeModeTraffic {
				return "", "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
			}
			chargeMode = ip.ChargeMode
		}
	case ShareTypeWhole:
		if ip.BandwidthID == "" {
			return "", "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
	}

	epID := ip.EnterpriseProjectID
	if epID == "" {
		epID = defaultEnterpriseProjectID
	}
	if !validEnterpriseProjectID(epID) {
		return "", "", errInvalidEnterpriseProjectID()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return "", "", err
	}
	if vipPortID != "" {
		for _, p := range existing {
			if p.PortID == vipPortID {
				return "", "", errPortAlreadyBound()
			}
		}
	}

	if ip.ShareType == ShareTypeWhole {
		bw, err := s.bandwidths(t).Get(ctx, ip.BandwidthID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && bw.ShareType != ShareTypeWhole) {
			return "", "", errBandwidthNotFound()
		}
		if err != nil {
			return "", "", err
		}
	}

	if !s.quotas.Allows(quota.VPCPublicIP, len(existing), 1) {
		return "", "", errPublicIPQuota()
	}

	pipID := s.ids.UUID()
	bwID := ip.BandwidthID
	if ip.ShareType == ShareTypePer {
		bwID = s.ids.UUID()
	}

	addr, err := s.claimAddress(ctx, t, pipID, "")
	if err != nil {
		return "", "", err
	}

	now := s.nowUTC()
	if ip.ShareType == ShareTypePer {
		bwName := ip.BandwidthName
		if bwName == "" {
			lbPrefix := lbID
			if len(lbPrefix) > 8 {
				lbPrefix = lbPrefix[:8]
			}
			pipPrefix := pipID
			if len(pipPrefix) > 4 {
				pipPrefix = pipPrefix[:4]
			}
			bwName = fmt.Sprintf("elb-%s-bandwidth-%s", lbPrefix, pipPrefix)
		}
		bw := bandwidth{
			ID:                  bwID,
			Name:                bwName,
			Size:                ip.Size,
			ShareType:           ShareTypePer,
			ChargeMode:          chargeMode,
			EnterpriseProjectID: epID,
			PublicIPIDs:         []string{pipID},
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.bandwidths(t).Create(ctx, bw.ID, bw); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return "", "", err
		}
	} else {
		if _, err := s.bandwidths(t).Update(ctx, bwID, func(b *bandwidth) error {
			b.PublicIPIDs = append(b.PublicIPIDs, pipID)
			b.UpdatedAt = now
			return nil
		}); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return "", "", err
		}
	}

	pip := publicIP{
		ID:                  pipID,
		Description:         ip.Description,
		Type:                ip.Type,
		Address:             addr,
		Status:              StatusActive,
		PortID:              vipPortID,
		PrivateIP:           vipAddress,
		ELBLoadBalancerID:   lbID,
		BandwidthID:         bwID,
		EnterpriseProjectID: epID,
		Tags:                []tag{},
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.publicips(t).Create(ctx, pip.ID, pip); err != nil {
		_ = s.releaseAddress(ctx, t.Region, addr)
		if ip.ShareType == ShareTypePer {
			_ = s.bandwidths(t).Delete(ctx, bwID)
		} else {
			_, _ = s.bandwidths(t).Update(ctx, bwID, func(b *bandwidth) error {
				b.PublicIPIDs = removePublicIPID(b.PublicIPIDs, pipID)
				b.UpdatedAt = now
				return nil
			})
		}
		return "", "", err
	}

	return pip.ID, pip.Address, nil
}

// UnbindFromELB unbinds an EIP from a load balancer; the EIP stays in DOWN
// status. Unbinding an EIP the load balancer does not own, or one that is
// gone, is a no-op.
func (s *Service) UnbindFromELB(ctx context.Context, t vpc.Tenant, eipID, lbID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, eipID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if pip.ELBLoadBalancerID == "" || pip.ELBLoadBalancerID != lbID {
		return nil
	}

	pip.ELBLoadBalancerID = ""
	pip.PortID = ""
	pip.PrivateIP = ""
	pip.Status = StatusDown
	pip.UpdatedAt = s.nowUTC()
	return s.publicips(t).Put(ctx, pip.ID, pip)
}
