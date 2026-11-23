package eip

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ListBandwidthsFilter narrows ListBandwidths.
type ListBandwidthsFilter struct {
	ShareType           string
	EnterpriseProjectID string
}

// ListBandwidths returns the project's bandwidths ordered by ascending ID.
func (s *Service) ListBandwidths(ctx context.Context, t Tenant, f ListBandwidthsFilter) ([]bandwidth, error) {
	items, err := s.bandwidths(t).List(ctx, func(bw bandwidth) bool {
		return (f.ShareType == "" || bw.ShareType == f.ShareType) &&
			inEP(f.EnterpriseProjectID, bw.EnterpriseProjectID)
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(items, func(a, b bandwidth) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return items, nil
}

// GetBandwidth returns one bandwidth by ID.
func (s *Service) GetBandwidth(ctx context.Context, t Tenant, id string) (bandwidth, error) {
	bw, err := s.bandwidths(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return bandwidth{}, errBandwidthNotFound()
	}
	return bw, err
}

// UpdateBandwidth updates a dedicated or shared bandwidth's name, size or charge_mode.
func (s *Service) UpdateBandwidth(ctx context.Context, t Tenant, id string, opt updateBandwidthOption) (bandwidth, error) {
	now := s.nowUTC()
	bw, err := s.bandwidths(t).Update(ctx, id, func(bw *bandwidth) error {
		if opt.Name != nil {
			if !validName(*opt.Name) {
				return errInvalidBandwidth("updateBandwidth input param is invalid.")
			}
			bw.Name = *opt.Name
		}
		if opt.ChargeMode != nil {
			if *opt.ChargeMode != ChargeModeBandwidth && *opt.ChargeMode != ChargeModeTraffic {
				return errInvalidBandwidth("updateBandwidth input param is invalid.")
			}
			bw.ChargeMode = *opt.ChargeMode
		}
		if opt.Size != nil {
			sz := *opt.Size
			if bw.ShareType == ShareTypeWhole {
				if sz < 5 || sz > 2000 {
					return errInvalidBandwidth("updateBandwidth input param is invalid.")
				}
			} else {
				if sz < 1 || sz > 300 {
					return errInvalidBandwidth("updateBandwidth input param is invalid.")
				}
			}
			bw.Size = sz
		}
		bw.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return bandwidth{}, errBandwidthNotFound()
	}
	return bw, err
}

// CreateSharedBandwidth creates a new WHOLE bandwidth in the project.
func (s *Service) CreateSharedBandwidth(ctx context.Context, t Tenant, opt createSharedBandwidthOption) (bandwidth, error) {
	if !validName(opt.Name) {
		return bandwidth{}, errInvalidBandwidth("Bandwidth name or share_type is invalid.")
	}
	if opt.Size < 5 || opt.Size > 2000 {
		return bandwidth{}, errInvalidBandwidth("Bandwidth size is invalid.")
	}
	chargeMode := ChargeModeBandwidth
	if opt.ChargeMode != nil && *opt.ChargeMode != "" {
		chargeMode = *opt.ChargeMode
	}
	if chargeMode != ChargeModeBandwidth && chargeMode != ChargeModeTraffic {
		return bandwidth{}, errInvalidBandwidth("Bandwidth charge_mode is invalid.")
	}
	ep := defaultEnterpriseProjectID
	if opt.EnterpriseProjectID != nil && *opt.EnterpriseProjectID != "" {
		ep = *opt.EnterpriseProjectID
	}
	if !validEnterpriseProjectID(ep) {
		return bandwidth{}, errInvalidBandwidth("Invalid enterprise project ID.")
	}
	if opt.PublicBorderGroup != nil && *opt.PublicBorderGroup != PublicBorderGroupCenter {
		return bandwidth{}, errInvalidBandwidth("Invalid public_border_group.")
	}
	if opt.BandwidthType != nil && *opt.BandwidthType != BandwidthTypeShare {
		return bandwidth{}, errInvalidBandwidth("Invalid bandwidth_type.")
	}

	id := s.ids.UUID()
	now := s.nowUTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	shared, err := s.bandwidths(t).List(ctx, func(b bandwidth) bool {
		return b.ShareType == ShareTypeWhole
	})
	if err != nil {
		return bandwidth{}, err
	}
	if !s.quotas.Allows(quota.VPCShareBandwidth, len(shared), 1) {
		return bandwidth{}, errSharedBandwidthQuota()
	}

	bw := bandwidth{
		ID:                  id,
		Name:                opt.Name,
		Size:                opt.Size,
		ShareType:           ShareTypeWhole,
		ChargeMode:          chargeMode,
		EnterpriseProjectID: ep,
		PublicIPIDs:         []string{},
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.bandwidths(t).Create(ctx, bw.ID, bw); err != nil {
		return bandwidth{}, err
	}
	return bw, nil
}

// DeleteSharedBandwidth deletes an empty WHOLE bandwidth.
func (s *Service) DeleteSharedBandwidth(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bw, err := s.bandwidths(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errBandwidthNotFound()
	}
	if err != nil {
		return err
	}
	if bw.ShareType != ShareTypeWhole {
		return errSharedBandwidthModify()
	}
	if len(bw.PublicIPIDs) > 0 {
		return errBandwidthInUse()
	}
	if err := s.bandwidths(t).Delete(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errBandwidthNotFound()
		}
		return err
	}
	return nil
}

// AddPublicIPsIntoSharedBandwidth moves one or more EIPs from their PER
// bandwidths into a WHOLE bandwidth, deleting each old PER bandwidth.
func (s *Service) AddPublicIPsIntoSharedBandwidth(ctx context.Context, t Tenant, id string, opt addPublicIPsIntoSharedBandwidthOption) (bandwidth, error) {
	if len(opt.PublicIPInfo) == 0 {
		return bandwidth{}, errInvalidBandwidth("Invalid publicip_id")
	}
	for _, info := range opt.PublicIPInfo {
		if info.PublicIPID == "" {
			return bandwidth{}, errInvalidBandwidth("Invalid publicip_id")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bw, err := s.bandwidths(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return bandwidth{}, errBandwidthNotFound()
	}
	if err != nil {
		return bandwidth{}, err
	}
	if bw.ShareType != ShareTypeWhole {
		return bandwidth{}, errSharedBandwidthModify()
	}

	seen := make(map[string]bool, len(opt.PublicIPInfo))
	pips := make([]publicIP, 0, len(opt.PublicIPInfo))
	for _, info := range opt.PublicIPInfo {
		pip, err := s.publicips(t).Get(ctx, info.PublicIPID)
		if errors.Is(err, store.ErrNotFound) {
			return bandwidth{}, errInvalidBandwidth("Invalid publicip_id")
		}
		if err != nil {
			return bandwidth{}, err
		}
		oldBW, err := s.bandwidths(t).Get(ctx, pip.BandwidthID)
		if errors.Is(err, store.ErrNotFound) || oldBW.ShareType != ShareTypePer {
			return bandwidth{}, errSharedBandwidthModify()
		}
		if err != nil {
			return bandwidth{}, err
		}
		if seen[pip.ID] {
			return bandwidth{}, errSharedBandwidthModify()
		}
		seen[pip.ID] = true
		pips = append(pips, pip)
	}

	if !s.quotas.Allows(quota.VPCShareBandwidthIP, len(bw.PublicIPIDs), len(pips)) {
		return bandwidth{}, errSharedBandwidthModify()
	}

	now := s.nowUTC()
	for _, pip := range pips {
		if err := s.bandwidths(t).Delete(ctx, pip.BandwidthID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return bandwidth{}, err
		}
		if _, err := s.publicips(t).Update(ctx, pip.ID, func(p *publicIP) error {
			p.BandwidthID = bw.ID
			p.UpdatedAt = now
			return nil
		}); err != nil {
			return bandwidth{}, err
		}
	}

	updated, err := s.bandwidths(t).Update(ctx, bw.ID, func(b *bandwidth) error {
		for _, pip := range pips {
			b.PublicIPIDs = append(b.PublicIPIDs, pip.ID)
		}
		b.UpdatedAt = now
		return nil
	})
	if err != nil {
		return bandwidth{}, err
	}
	return updated, nil
}

// RemovePublicIPsFromSharedBandwidth removes one or more EIPs from a WHOLE
// bandwidth and gives each a new dedicated PER bandwidth.
func (s *Service) RemovePublicIPsFromSharedBandwidth(ctx context.Context, t Tenant, id string, opt removeFromSharedBandwidthOption) error {
	if opt.ChargeMode != ChargeModeBandwidth && opt.ChargeMode != ChargeModeTraffic {
		return errInvalidBandwidth("Bandwidth charge_mode is invalid.")
	}
	if opt.Size < 1 || opt.Size > 300 {
		return errInvalidBandwidth("Bandwidth size is invalid.")
	}
	if len(opt.PublicIPInfo) == 0 {
		return errInvalidBandwidth("Invalid publicip_id")
	}
	for _, info := range opt.PublicIPInfo {
		if info.PublicIPID == "" {
			return errInvalidBandwidth("Invalid publicip_id")
		}
	}

	newBWIDs := make([]string, len(opt.PublicIPInfo))
	for i := range newBWIDs {
		newBWIDs[i] = s.ids.UUID()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bw, err := s.bandwidths(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errBandwidthNotFound()
	}
	if err != nil {
		return err
	}
	if bw.ShareType != ShareTypeWhole {
		return errSharedBandwidthModify()
	}

	inBW := make(map[string]bool, len(bw.PublicIPIDs))
	for _, pipID := range bw.PublicIPIDs {
		inBW[pipID] = true
	}

	seen := make(map[string]bool, len(opt.PublicIPInfo))
	pips := make([]publicIP, 0, len(opt.PublicIPInfo))
	for _, info := range opt.PublicIPInfo {
		if !inBW[info.PublicIPID] || seen[info.PublicIPID] {
			return errSharedBandwidthModify()
		}
		pip, err := s.publicips(t).Get(ctx, info.PublicIPID)
		if errors.Is(err, store.ErrNotFound) || pip.BandwidthID != bw.ID {
			return errSharedBandwidthModify()
		}
		if err != nil {
			return err
		}
		seen[pip.ID] = true
		pips = append(pips, pip)
	}

	now := s.nowUTC()
	for i, pip := range pips {
		prefix := pip.ID
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		ep := pip.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		newBW := bandwidth{
			ID:                  newBWIDs[i],
			Name:                "bandwidth-" + prefix,
			Size:                opt.Size,
			ShareType:           ShareTypePer,
			ChargeMode:          opt.ChargeMode,
			EnterpriseProjectID: ep,
			PublicIPIDs:         []string{pip.ID},
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := s.bandwidths(t).Create(ctx, newBW.ID, newBW); err != nil {
			return err
		}
		if _, err := s.publicips(t).Update(ctx, pip.ID, func(p *publicIP) error {
			p.BandwidthID = newBW.ID
			p.UpdatedAt = now
			return nil
		}); err != nil {
			return err
		}
	}

	_, err = s.bandwidths(t).Update(ctx, bw.ID, func(b *bandwidth) error {
		remaining := make([]string, 0, len(b.PublicIPIDs))
		for _, pipID := range b.PublicIPIDs {
			if !seen[pipID] {
				remaining = append(remaining, pipID)
			}
		}
		b.PublicIPIDs = remaining
		b.UpdatedAt = now
		return nil
	})
	return err
}

func (s *Service) toBandwidthResp(ctx context.Context, t Tenant, bw bandwidth) (bandwidthResp, error) {
	bwType := BandwidthTypeBGP
	if bw.ShareType == ShareTypeWhole {
		bwType = BandwidthTypeShare
	}
	chargeMode := bw.ChargeMode
	if chargeMode == "" {
		chargeMode = ChargeModeBandwidth
	}
	ep := bw.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	pipInfos := make([]bandwidthPublicIPInfo, 0, len(bw.PublicIPIDs))
	for _, pipID := range bw.PublicIPIDs {
		pip, err := s.publicips(t).Get(ctx, pipID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return bandwidthResp{}, err
		}
		pipInfos = append(pipInfos, bandwidthPublicIPInfo{
			PublicIPAddress: pip.Address,
			PublicIPID:      pip.ID,
			PublicIPType:    pip.Type,
			IPVersion:       4,
		})
	}

	return bandwidthResp{
		BandwidthType:        bwType,
		BillingInfo:          "",
		ChargeMode:           chargeMode,
		ID:                   bw.ID,
		Name:                 bw.Name,
		PublicIPInfo:         pipInfos,
		ShareType:            bw.ShareType,
		Size:                 bw.Size,
		TenantID:             t.ProjectID,
		EnterpriseProjectID:  ep,
		Status:               BandwidthStatusNormal,
		EnableBandwidthRules: false,
		RuleQuota:            0,
		BandwidthRules:       []bandwidthRule{},
		CreatedAt:            bw.CreatedAt.UTC().Format(v3TimeFormat),
		UpdatedAt:            bw.UpdatedAt.UTC().Format(v3TimeFormat),
		PublicBorderGroup:    PublicBorderGroupCenter,
	}, nil
}
