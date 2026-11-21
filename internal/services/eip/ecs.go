package eip

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// ServerIP is what ECS and ELB ask for when attaching or creating an EIP.
type ServerIP struct {
	ID                  string // publicip.id: bind this existing EIP
	Type                string // publicip.eip.iptype / network_type
	ShareType           string // publicip.eip.bandwidth.sharetype
	Size                int    // publicip.eip.bandwidth.size
	ChargeMode          string // publicip.eip.bandwidth.chargemode
	BandwidthID         string // publicip.eip.bandwidth.id (WHOLE)
	BandwidthName       string // optional PER bandwidth name (ELB)
	Description         string // optional EIP description (ELB)
	EnterpriseProjectID string // optional enterprise project ID (ELB)
	ReleaseWithServer   bool   // publicip.delete_on_termination
}

// AttachToServer binds an existing EIP (when ip.ID is set) or creates a new
// bound EIP (when ip.ID is empty) for portID, returning its IPv4 address.
func (s *Service) AttachToServer(ctx context.Context, t vpc.Tenant, portID, serverName string, ip ServerIP) (string, error) {
	if ip.ID != "" {
		if portID == "" {
			return "", errInvalidPublicIP("Port id is invalid.")
		}
		pip, err := s.updatePublicIP(ctx, t, ip.ID, updatePublicIPSpec{
			PortIDPresent: true,
			PortID:        &portID,
		})
		if err != nil {
			return "", err
		}
		return pip.Address, nil
	}

	if !validPublicIPType(t.Region, ip.Type) {
		return "", errInvalidPublicIP("publicip type is invalid")
	}
	if ip.ShareType != ShareTypePer && ip.ShareType != ShareTypeWhole {
		return "", errInvalidPublicIP("Bandwidth share_type is invalid.")
	}
	chargeMode := ChargeModeBandwidth
	switch ip.ShareType {
	case ShareTypePer:
		if ip.Size < 1 || ip.Size > 300 {
			return "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
		if ip.ChargeMode != "" {
			if ip.ChargeMode != ChargeModeBandwidth && ip.ChargeMode != ChargeModeTraffic {
				return "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
			}
			chargeMode = ip.ChargeMode
		}
	case ShareTypeWhole:
		if ip.BandwidthID == "" {
			return "", errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
	}
	if portID == "" {
		return "", errInvalidPort()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	port, ok, err := s.ports.Port(ctx, t, portID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errInvalidPort()
	}

	existing, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return "", err
	}
	for _, p := range existing {
		if p.PortID == port.ID {
			return "", errPortAlreadyBound()
		}
	}

	if ip.ShareType == ShareTypeWhole {
		bw, err := s.bandwidths(t).Get(ctx, ip.BandwidthID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && bw.ShareType != ShareTypeWhole) {
			return "", errBandwidthNotFound()
		}
		if err != nil {
			return "", err
		}
	}

	if len(existing) >= s.maxPerProject {
		return "", errPublicIPQuota()
	}

	pipID := s.ids.UUID()
	bwID := ip.BandwidthID
	if ip.ShareType == ShareTypePer {
		bwID = s.ids.UUID()
	}

	addr, err := s.claimAddress(ctx, t, pipID, "")
	if err != nil {
		return "", err
	}

	now := s.nowUTC()
	if ip.ShareType == ShareTypePer {
		prefix := pipID
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		bw := bandwidth{
			ID:                  bwID,
			Name:                fmt.Sprintf("%s-bandwidth-%s", serverName, prefix),
			Size:                ip.Size,
			ShareType:           ShareTypePer,
			ChargeMode:          chargeMode,
			EnterpriseProjectID: defaultEnterpriseProjectID,
			PublicIPIDs:         []string{pipID},
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.bandwidths(t).Create(ctx, bw.ID, bw); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return "", err
		}
	} else {
		if _, err := s.bandwidths(t).Update(ctx, bwID, func(b *bandwidth) error {
			b.PublicIPIDs = append(b.PublicIPIDs, pipID)
			b.UpdatedAt = now
			return nil
		}); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return "", err
		}
	}

	pip := publicIP{
		ID:                  pipID,
		Type:                ip.Type,
		Address:             addr,
		Status:              StatusPendingCreate,
		PortID:              port.ID,
		PrivateIP:           port.IP,
		BandwidthID:         bwID,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                []tag{},
		CreatedAt:           now,
		UpdatedAt:           now,
		ReleaseWithPort:     ip.ReleaseWithServer,
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
		return "", err
	}

	s.schedulePublicIPActivation(t, pip.ID)
	return pip.Address, nil
}

// PortsRemoved releases or unbinds every EIP attached to one of portIDs.
// An EIP is released when release is true or its ReleaseWithPort flag is set;
// otherwise it is unbound and transitions to DOWN.
func (s *Service) PortsRemoved(ctx context.Context, t vpc.Tenant, portIDs []string, release bool) {
	if len(portIDs) == 0 {
		return
	}
	targets := make(map[string]struct{}, len(portIDs))
	for _, id := range portIDs {
		if id != "" {
			targets[id] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		s.log.ErrorContext(ctx, "listing EIPs for removed ports failed", "error", err)
		return
	}
	now := s.nowUTC()
	for _, pip := range all {
		if pip.PortID == "" || pip.ELBLoadBalancerID != "" {
			continue
		}
		if _, ok := targets[pip.PortID]; !ok {
			continue
		}
		if release || pip.ReleaseWithPort {
			s.forceReleasePublicIP(ctx, t, pip, now)
			continue
		}
		if pip.Status == StatusPendingCreate {
			s.engine.Cancel(pip.ID)
		}
		pip.PortID = ""
		pip.PrivateIP = ""
		pip.Status = StatusDown
		pip.ReleaseWithPort = false
		pip.UpdatedAt = now
		if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
			s.log.ErrorContext(ctx, "unbinding EIP for removed port failed", "publicip_id", pip.ID, "error", err)
		}
	}
}

// AddressesByPort returns a map of port ID to public IPv4 address for every
// bound EIP in the tenant.
func (s *Service) AddressesByPort(ctx context.Context, t vpc.Tenant) (map[string]string, error) {
	all, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, pip := range all {
		if pip.PortID != "" {
			out[pip.PortID] = pip.Address
		}
	}
	return out, nil
}

func (s *Service) forceReleasePublicIP(ctx context.Context, t Tenant, pip publicIP, now time.Time) {
	s.engine.Cancel(pip.ID)
	if err := s.publicips(t).Delete(ctx, pip.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "deleting EIP for removed port failed", "publicip_id", pip.ID, "error", err)
		return
	}
	if err := s.releaseAddress(ctx, t.Region, pip.Address); err != nil {
		s.log.ErrorContext(ctx, "releasing EIP address for removed port failed", "publicip_id", pip.ID, "error", err)
	}
	if pip.BandwidthID == "" {
		return
	}
	bw, err := s.bandwidths(t).Get(ctx, pip.BandwidthID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "reading EIP bandwidth for removed port failed", "publicip_id", pip.ID, "bandwidth_id", pip.BandwidthID, "error", err)
		}
		return
	}
	switch bw.ShareType {
	case ShareTypePer:
		if err := s.bandwidths(t).Delete(ctx, bw.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "deleting PER bandwidth for removed port failed", "bandwidth_id", bw.ID, "error", err)
		}
	case ShareTypeWhole:
		if _, err := s.bandwidths(t).Update(ctx, bw.ID, func(b *bandwidth) error {
			b.PublicIPIDs = removePublicIPID(b.PublicIPIDs, pip.ID)
			b.UpdatedAt = now
			return nil
		}); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "removing EIP from WHOLE bandwidth failed", "bandwidth_id", bw.ID, "publicip_id", pip.ID, "error", err)
		}
	}
}

func removePublicIPID(ids []string, target string) []string {
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != target {
			kept = append(kept, id)
		}
	}
	return kept
}
