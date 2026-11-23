package eip

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

func validPublicIPType(region, typ string) bool {
	switch typ {
	case "5_bgp":
		return region != "cn-southwest-2"
	case "5_sbgp":
		switch region {
		case "cn-south-1", "cn-east-3", "cn-east-2", "cn-north-1", "cn-north-4", "cn-southwest-2":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func (s *Service) createPublicIP(ctx context.Context, t Tenant, req createPublicIPRequest) (publicIP, error) {
	if req.PublicIP == nil {
		return publicIP{}, errInvalidPublicIP("publicip is required")
	}
	opt := req.PublicIP
	if !validPublicIPType(t.Region, opt.Type) {
		return publicIP{}, errInvalidPublicIP("publicip type is invalid")
	}
	if opt.IPVersion != nil {
		switch *opt.IPVersion {
		case 4:
		case 6:
			return publicIP{}, apierr.NotImplemented("eip", "IPv6 EIPs")
		default:
			return publicIP{}, errInvalidPublicIP("ip_version is invalid")
		}
	}
	alias := ""
	if opt.Alias != nil {
		if !validName(*opt.Alias) {
			return publicIP{}, errInvalidPublicIP("alias is invalid")
		}
		alias = *opt.Alias
	}

	if req.Bandwidth == nil || (req.Bandwidth.ShareType != ShareTypePer && req.Bandwidth.ShareType != ShareTypeWhole) {
		return publicIP{}, errInvalidPublicIP("Bandwidth share_type is invalid.")
	}
	bwOpt := req.Bandwidth
	chargeMode := ChargeModeBandwidth
	switch bwOpt.ShareType {
	case ShareTypePer:
		if bwOpt.Name == nil || !validName(*bwOpt.Name) {
			return publicIP{}, errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
		if bwOpt.Size == nil || *bwOpt.Size < 1 || *bwOpt.Size > 300 {
			return publicIP{}, errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
		if bwOpt.ChargeMode != nil {
			if *bwOpt.ChargeMode != ChargeModeBandwidth && *bwOpt.ChargeMode != ChargeModeTraffic {
				return publicIP{}, errInvalidBandwidth("Bandwidth name or share_type is invalid.")
			}
			chargeMode = *bwOpt.ChargeMode
		}
	case ShareTypeWhole:
		if bwOpt.ID == nil || *bwOpt.ID == "" {
			return publicIP{}, errInvalidBandwidth("Bandwidth name or share_type is invalid.")
		}
	}

	epID := defaultEnterpriseProjectID
	if req.EnterpriseProjectID != nil {
		if *req.EnterpriseProjectID == "" || !validEnterpriseProjectID(*req.EnterpriseProjectID) {
			return publicIP{}, errInvalidEnterpriseProjectID()
		}
		epID = *req.EnterpriseProjectID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	portID := ""
	privateIP := ""
	if opt.PortID != nil && *opt.PortID != "" {
		port, ok, err := s.ports.Port(ctx, t, *opt.PortID)
		if err != nil {
			return publicIP{}, err
		}
		if !ok {
			return publicIP{}, errInvalidPort()
		}
		portID = port.ID
		privateIP = port.IP
	}

	existing, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return publicIP{}, err
	}
	if portID != "" {
		for _, p := range existing {
			if p.PortID == portID {
				return publicIP{}, errPortAlreadyBound()
			}
		}
	}

	if bwOpt.ShareType == ShareTypeWhole {
		bw, err := s.bandwidths(t).Get(ctx, *bwOpt.ID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && bw.ShareType != ShareTypeWhole) {
			return publicIP{}, errBandwidthNotFound()
		}
		if err != nil {
			return publicIP{}, err
		}
	}

	if !s.quotas.Allows(quota.VPCPublicIP, len(existing), 1) {
		return publicIP{}, errPublicIPQuota()
	}

	pipID := s.ids.UUID()
	bwID := ""
	if bwOpt.ShareType == ShareTypePer {
		bwID = s.ids.UUID()
	} else {
		bwID = *bwOpt.ID
	}

	requestedIP := ""
	if opt.IPAddress != nil {
		requestedIP = *opt.IPAddress
	}
	addr, err := s.claimAddress(ctx, t, pipID, requestedIP)
	if err != nil {
		return publicIP{}, err
	}

	now := s.nowUTC()
	if bwOpt.ShareType == ShareTypePer {
		bw := bandwidth{
			ID:                  bwID,
			Name:                *bwOpt.Name,
			Size:                *bwOpt.Size,
			ShareType:           ShareTypePer,
			ChargeMode:          chargeMode,
			EnterpriseProjectID: epID,
			PublicIPIDs:         []string{pipID},
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.bandwidths(t).Create(ctx, bw.ID, bw); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return publicIP{}, err
		}
	} else {
		if _, err := s.bandwidths(t).Update(ctx, bwID, func(b *bandwidth) error {
			b.PublicIPIDs = append(b.PublicIPIDs, pipID)
			b.UpdatedAt = now
			return nil
		}); err != nil {
			_ = s.releaseAddress(ctx, t.Region, addr)
			return publicIP{}, err
		}
	}

	pip := publicIP{
		ID:                  pipID,
		Alias:               alias,
		Type:                opt.Type,
		Address:             addr,
		Status:              StatusPendingCreate,
		PortID:              portID,
		PrivateIP:           privateIP,
		BandwidthID:         bwID,
		EnterpriseProjectID: epID,
		Tags:                []tag{},
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.publicips(t).Create(ctx, pip.ID, pip); err != nil {
		_ = s.releaseAddress(ctx, t.Region, addr)
		if bwOpt.ShareType == ShareTypePer {
			_ = s.bandwidths(t).Delete(ctx, bwID)
		}
		return publicIP{}, err
	}

	s.schedulePublicIPActivation(t, pip.ID)
	return pip, nil
}

func (s *Service) schedulePublicIPActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskPublicIPCreate,
		Run: func(ctx context.Context, fault error) {
			failed := fault != nil
			_, err := s.publicips(t).Update(ctx, id, func(p *publicIP) error {
				switch {
				case failed:
					p.Status = "ERROR"
				case p.PortID != "" || p.NATGatewayID != "" || p.ELBLoadBalancerID != "":
					p.Status = StatusActive
				default:
					p.Status = StatusDown
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "publicip activation failed", "publicip_id", id, "error", err)
			}
		},
	})
}

func (s *Service) getPublicIP(ctx context.Context, t Tenant, id string) (publicIP, error) {
	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return publicIP{}, errPublicIPNotFound()
	}
	return pip, err
}

type listPublicIPsFilter struct {
	IDs                 []string
	PortIDs             []string
	PublicIPAddresses   []string
	PrivateIPAddresses  []string
	IPVersion           string
	EnterpriseProjectID string
	Page                pagination.Marker
}

func matchFilterSlice(want []string, got string) bool {
	if len(want) == 0 {
		return true
	}
	return slices.Contains(want, got)
}

func (s *Service) listPublicIPs(ctx context.Context, t Tenant, f listPublicIPsFilter) ([]publicIP, error) {
	items, err := s.publicips(t).List(ctx, func(p publicIP) bool {
		if !matchFilterSlice(f.IDs, p.ID) {
			return false
		}
		if !matchFilterSlice(f.PortIDs, p.PortID) {
			return false
		}
		if !matchFilterSlice(f.PublicIPAddresses, p.Address) {
			return false
		}
		if !matchFilterSlice(f.PrivateIPAddresses, p.PrivateIP) {
			return false
		}
		if f.IPVersion != "" && f.IPVersion != "4" {
			return false
		}
		return inEP(f.EnterpriseProjectID, p.EnterpriseProjectID)
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(items, func(a, b publicIP) int {
		return strings.Compare(a.ID, b.ID)
	})
	paged, err := pagination.ByMarker(items, func(p publicIP) string { return p.ID }, f.Page)
	if err != nil {
		return nil, errPublicIPNotFound()
	}
	return paged, nil
}

type updatePublicIPSpec struct {
	PortIDPresent bool
	PortID        *string
	IPVersion     *int
	Alias         *string
}

func (s *Service) updatePublicIP(ctx context.Context, t Tenant, id string, spec updatePublicIPSpec) (publicIP, error) {
	if (spec.PortIDPresent || spec.PortID != nil) && spec.IPVersion != nil {
		return publicIP{}, errInvalidPublicIP("port_id and ip_version cannot be set at the same time")
	}
	if spec.IPVersion != nil && *spec.IPVersion != 4 {
		return publicIP{}, errInvalidPublicIP("ip_version is invalid")
	}
	if spec.Alias != nil && !validName(*spec.Alias) {
		return publicIP{}, errInvalidPublicIP("alias is invalid")
	}

	var (
		bindPortID string
		doBind     bool
		doUnbind   bool
	)
	switch {
	case spec.PortID != nil && *spec.PortID != "":
		doBind = true
		bindPortID = *spec.PortID
	case spec.PortID != nil && *spec.PortID == "":
		doUnbind = true
	case spec.PortIDPresent && spec.PortID == nil:
		doUnbind = true
	case !spec.PortIDPresent && spec.PortID == nil && spec.Alias == nil && spec.IPVersion == nil:
		doUnbind = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return publicIP{}, errPublicIPNotFound()
	}
	if err != nil {
		return publicIP{}, err
	}

	if doBind {
		port, ok, err := s.ports.Port(ctx, t, bindPortID)
		if err != nil {
			return publicIP{}, err
		}
		if !ok {
			return publicIP{}, errInvalidPublicIP("Port id is invalid.")
		}
		if pip.Status == StatusPendingCreate {
			return publicIP{}, errPublicIPBusy()
		}
		existing, err := s.publicips(t).List(ctx, nil)
		if err != nil {
			return publicIP{}, err
		}
		for _, other := range existing {
			if other.ID != pip.ID && other.PortID == bindPortID {
				return publicIP{}, errPortAlreadyBound()
			}
		}
		if pip.NATGatewayID != "" || pip.ELBLoadBalancerID != "" || (pip.PortID != "" && pip.PortID != bindPortID) {
			return publicIP{}, errPublicIPAlreadyBound()
		}
		if pip.PortID == "" {
			pip.PortID = port.ID
			pip.PrivateIP = port.IP
			pip.Status = StatusActive
		}
	} else if doUnbind {
		if pip.Status == StatusPendingCreate {
			return publicIP{}, errPublicIPBusy()
		}
		if pip.PortID != "" && pip.ELBLoadBalancerID == "" {
			pip.PortID = ""
			pip.PrivateIP = ""
			pip.Status = StatusDown
		}
	}

	if spec.Alias != nil {
		pip.Alias = *spec.Alias
	}
	pip.UpdatedAt = s.nowUTC()
	if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
		return publicIP{}, err
	}
	return pip, nil
}

func (s *Service) deletePublicIP(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPublicIPNotFound()
	}
	if err != nil {
		return err
	}
	if pip.PortID != "" || pip.NATGatewayID != "" || pip.ELBLoadBalancerID != "" {
		return errPublicIPBound()
	}
	if pip.Status == StatusPendingCreate {
		return errPublicIPBusy()
	}

	s.engine.Cancel(pip.ID)
	if err := s.publicips(t).Delete(ctx, pip.ID); err != nil {
		return err
	}
	if err := s.releaseAddress(ctx, t.Region, pip.Address); err != nil {
		return err
	}
	if pip.BandwidthID != "" {
		bw, err := s.bandwidths(t).Get(ctx, pip.BandwidthID)
		if err == nil {
			switch bw.ShareType {
			case ShareTypePer:
				_ = s.bandwidths(t).Delete(ctx, bw.ID)
			case ShareTypeWhole:
				now := s.nowUTC()
				_, _ = s.bandwidths(t).Update(ctx, bw.ID, func(b *bandwidth) error {
					kept := make([]string, 0, len(b.PublicIPIDs))
					for _, pid := range b.PublicIPIDs {
						if pid != pip.ID {
							kept = append(kept, pid)
						}
					}
					b.PublicIPIDs = kept
					b.UpdatedAt = now
					return nil
				})
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}
