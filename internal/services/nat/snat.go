package nat

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// listSnatRulesFilter selects public SNAT rules in listSnatRules (§3.2).
type listSnatRulesFilter struct {
	AdminStateUp      *bool
	CIDR              string
	FloatingIPAddress string
	GlobalEIPAddress  string
	FloatingIPID      string
	GlobalEIPID       string
	ID                string
	Description       string
	CreatedAt         string
	NatGatewayIDs     []string
	NetworkID         string
	SourceType        *int
	Status            string
	Page              pagination.Marker
}

func (s *Service) createSnatRule(ctx context.Context, t Tenant, opt createSnatRuleOption) (snatRule, []string, error) {
	if opt.GlobalEIPID != nil && *opt.GlobalEIPID != "" {
		return snatRule{}, nil, apierr.NotImplemented("nat", "global_eip_id")
	}
	if opt.NatGatewayID == "" {
		return snatRule{}, nil, errInvalidParams("nat_gateway_id is required")
	}
	desc := ruleDeref(opt.Description)
	if !validDescription(desc) {
		return snatRule{}, nil, errInvalidDescription()
	}

	sourceType := 0
	if opt.SourceType != nil {
		if *opt.SourceType != 0 && *opt.SourceType != 1 {
			return snatRule{}, nil, errInvalidParams("source_type must be 0 or 1")
		}
		sourceType = *opt.SourceType
	}

	networkID := ruleDeref(opt.NetworkID)
	cidr := ruleDeref(opt.CIDR)
	if (networkID == "") == (cidr == "") {
		return snatRule{}, nil, errSnatNetworkOrCIDR()
	}
	if networkID != "" && sourceType == 1 {
		return snatRule{}, nil, errSnatSourceTypeMismatch()
	}

	var cidrPrefix netip.Prefix
	if cidr != "" {
		var ok bool
		cidrPrefix, ok = parseCanonicalIPv4CIDR(cidr)
		if !ok {
			return snatRule{}, nil, errSnatInvalidCIDR()
		}
	}

	if opt.FloatingIPID == "" {
		return snatRule{}, nil, errInvalidParams("floating_ip_id is required")
	}
	eipIDs, err := parseSnatFloatingIPIDs(opt.FloatingIPID)
	if err != nil {
		return snatRule{}, nil, err
	}

	ruleID := s.ids.UUID()

	s.mu.Lock()
	defer s.mu.Unlock()

	gw, err := s.gateways(t).Get(ctx, opt.NatGatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return snatRule{}, nil, errGatewayNotFound(opt.NatGatewayID)
	}
	if err != nil {
		return snatRule{}, nil, err
	}
	if gw.Status != StatusActive {
		return snatRule{}, nil, errGatewayNotActive(opt.NatGatewayID)
	}

	// Resolve subnets of the gateway's VPC for containment and overlap checks.
	vpcSubnets, err := s.vpc.ListSubnets(ctx, t, vpc.ListSubnetsFilter{VPCID: gw.RouterID})
	if err != nil {
		return snatRule{}, nil, err
	}
	subnetPrefixes := make(map[string]netip.Prefix, len(vpcSubnets))
	for _, sn := range vpcSubnets {
		if p, ok := parseCanonicalIPv4CIDR(sn.CIDR); ok {
			subnetPrefixes[sn.ID] = p
		}
	}

	var rulePrefix netip.Prefix
	if networkID != "" {
		sn, err := s.vpc.GetSubnet(ctx, t, networkID)
		if err != nil {
			var apiErr *apierr.Error
			if errors.As(err, &apiErr) || errors.Is(err, store.ErrNotFound) {
				return snatRule{}, nil, errSnatNetworkNotFound(networkID)
			}
			return snatRule{}, nil, err
		}
		if sn.VPCID != gw.RouterID {
			return snatRule{}, nil, errSubnetNotInRouter(gw.RouterID, networkID)
		}
		if p, ok := parseCanonicalIPv4CIDR(sn.CIDR); ok {
			rulePrefix = p
			subnetPrefixes[sn.ID] = p
		}
	} else {
		rulePrefix = cidrPrefix
		if sourceType == 0 {
			inside := false
			for _, sp := range subnetPrefixes {
				if prefixContains(sp, cidrPrefix) {
					inside = true
					break
				}
			}
			if !inside {
				return snatRule{}, nil, errSnatCIDRNotInSubnet()
			}
		}
	}

	existingSnats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return snatRule{}, nil, err
	}
	for _, ex := range existingSnats {
		if networkID != "" && ex.NetworkID == networkID {
			return snatRule{}, nil, errSnatNetworkExists(networkID)
		}
		exPrefix, ok, err := s.snatRulePrefix(ctx, t, ex, subnetPrefixes)
		if err != nil {
			return snatRule{}, nil, err
		}
		if ok && rulePrefix.IsValid() && exPrefix.Overlaps(rulePrefix) {
			return snatRule{}, nil, errSnatCIDRConflict()
		}
	}

	if err := s.checkSnatDnatAnyConflictLocked(ctx, t, gw.ID, eipIDs); err != nil {
		return snatRule{}, nil, err
	}

	addrs := make([]string, 0, len(eipIDs))
	held := make([]string, 0, len(eipIDs))
	for _, id := range eipIDs {
		addr, err := s.eips.HoldForNAT(ctx, t, id, gw.ID)
		if err != nil {
			_ = s.releaseUnusedEIPsLocked(ctx, t, gw.ID, held)
			return snatRule{}, nil, mapEIPHoldError(id, err)
		}
		held = append(held, id)
		addrs = append(addrs, addr)
	}

	rule := snatRule{
		ID:            ruleID,
		GatewayID:     gw.ID,
		NetworkID:     networkID,
		CIDR:          cidr,
		SourceType:    sourceType,
		FloatingIPIDs: eipIDs,
		Description:   desc,
		Status:        StatusPendingCreate,
		CreatedAt:     s.nowUTC(),
	}
	if err := s.snatRules(t).Create(ctx, rule.ID, rule); err != nil {
		_ = s.releaseUnusedEIPsLocked(ctx, t, gw.ID, held)
		return snatRule{}, nil, err
	}

	s.scheduleSnatActivation(t, rule.ID)
	return rule, addrs, nil
}

func (s *Service) getSnatRule(ctx context.Context, t Tenant, id string) (snatRule, []string, error) {
	r, err := s.snatRules(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return snatRule{}, nil, errSnatRuleNotFound(id)
	}
	if err != nil {
		return snatRule{}, nil, err
	}
	addrs, err := s.resolveEIPAddresses(ctx, t, r.FloatingIPIDs)
	if err != nil {
		return snatRule{}, nil, err
	}
	return r, addrs, nil
}

func (s *Service) listSnatRules(ctx context.Context, t Tenant, f listSnatRulesFilter) ([]snatRule, [][]string, error) {
	all, err := s.snatRules(t).List(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	slices.SortFunc(all, func(a, b snatRule) int {
		return cmp.Compare(a.ID, b.ID)
	})

	type pair struct {
		rule  snatRule
		addrs []string
	}
	matched := make([]pair, 0, len(all))
	for _, r := range all {
		if f.AdminStateUp != nil && !*f.AdminStateUp {
			continue
		}
		if f.ID != "" && r.ID != f.ID {
			continue
		}
		if f.CIDR != "" && r.CIDR != f.CIDR {
			continue
		}
		if f.NetworkID != "" && r.NetworkID != f.NetworkID {
			continue
		}
		if f.Description != "" && r.Description != f.Description {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		if f.SourceType != nil && r.SourceType != *f.SourceType {
			continue
		}
		if len(f.NatGatewayIDs) > 0 && !slices.Contains(f.NatGatewayIDs, r.GatewayID) {
			continue
		}
		if f.GlobalEIPID != "" || f.GlobalEIPAddress != "" {
			continue
		}
		if f.CreatedAt != "" && !matchRuleCreatedAt(f.CreatedAt, r.CreatedAt) {
			continue
		}
		if f.FloatingIPID != "" && !slices.Contains(r.FloatingIPIDs, f.FloatingIPID) && strings.Join(r.FloatingIPIDs, ",") != f.FloatingIPID {
			continue
		}
		addrs, err := s.resolveEIPAddresses(ctx, t, r.FloatingIPIDs)
		if err != nil {
			return nil, nil, err
		}
		if f.FloatingIPAddress != "" && strings.Join(addrs, ",") != f.FloatingIPAddress {
			continue
		}
		matched = append(matched, pair{rule: r, addrs: addrs})
	}

	window, err := pagination.ByMarker(matched, func(p pair) string { return p.rule.ID }, f.Page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return nil, nil, errInvalidParams("%s", err)
	}
	if err != nil {
		return nil, nil, err
	}

	rules := make([]snatRule, len(window))
	addrList := make([][]string, len(window))
	for i, p := range window {
		rules[i] = p.rule
		addrList[i] = p.addrs
	}
	return rules, addrList, nil
}

func (s *Service) updateSnatRule(ctx context.Context, t Tenant, id string, opt updateSnatRuleOption) (snatRule, []string, error) {
	if opt.GlobalEIPID != nil && *opt.GlobalEIPID != "" {
		return snatRule{}, nil, apierr.NotImplemented("nat", "global_eip_id")
	}
	if opt.Description != nil && !validDescription(*opt.Description) {
		return snatRule{}, nil, errInvalidDescription()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.snatRules(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return snatRule{}, nil, errSnatRuleNotFound(id)
	}
	if err != nil {
		return snatRule{}, nil, err
	}
	if opt.NatGatewayID == "" || opt.NatGatewayID != r.GatewayID {
		return snatRule{}, nil, errInvalidParams("nat_gateway_id does not match SNAT rule")
	}

	oldEIPIDs := r.FloatingIPIDs
	var (
		newEIPIDs []string
		newAddrs  []string
		held      []string
	)

	if opt.PublicIPAddress != nil {
		if *opt.PublicIPAddress == "" {
			return snatRule{}, nil, errInvalidParams("public_ip_address must not be empty")
		}
		rawAddrs := strings.Split(*opt.PublicIPAddress, ",")
		if len(rawAddrs) > maxSnatEIPs {
			return snatRule{}, nil, errSnatFloatingIPLimit(maxSnatEIPs)
		}
		seen := make(map[string]bool, len(rawAddrs))
		newEIPIDs = make([]string, 0, len(rawAddrs))
		for _, addr := range rawAddrs {
			eipID, ok, err := s.eips.PublicIPByAddress(ctx, t, addr)
			if err != nil {
				return snatRule{}, nil, err
			}
			if !ok {
				return snatRule{}, nil, errFloatingIPNotFound(addr)
			}
			if seen[eipID] {
				return snatRule{}, nil, errDuplicateSnatFloatingIP(eipID)
			}
			seen[eipID] = true
			newEIPIDs = append(newEIPIDs, eipID)
		}

		if err := s.checkSnatDnatAnyConflictLocked(ctx, t, r.GatewayID, newEIPIDs); err != nil {
			return snatRule{}, nil, err
		}

		newAddrs = make([]string, 0, len(newEIPIDs))
		held = make([]string, 0, len(newEIPIDs))
		for _, eipID := range newEIPIDs {
			addr, err := s.eips.HoldForNAT(ctx, t, eipID, r.GatewayID)
			if err != nil {
				_ = s.releaseUnusedEIPsLocked(ctx, t, r.GatewayID, held)
				return snatRule{}, nil, mapEIPHoldError(eipID, err)
			}
			held = append(held, eipID)
			newAddrs = append(newAddrs, addr)
		}
		r.FloatingIPIDs = newEIPIDs
	}

	if opt.Description != nil {
		r.Description = *opt.Description
	}

	if err := s.snatRules(t).Put(ctx, r.ID, r); err != nil {
		if len(held) > 0 {
			_ = s.releaseUnusedEIPsLocked(ctx, t, r.GatewayID, held)
		}
		return snatRule{}, nil, err
	}

	if opt.PublicIPAddress != nil {
		if err := s.releaseUnusedEIPsLocked(ctx, t, r.GatewayID, oldEIPIDs); err != nil {
			return snatRule{}, nil, err
		}
		return r, newAddrs, nil
	}

	addrs, err := s.resolveEIPAddresses(ctx, t, r.FloatingIPIDs)
	if err != nil {
		return snatRule{}, nil, err
	}
	return r, addrs, nil
}

func (s *Service) deleteSnatRule(ctx context.Context, t Tenant, gatewayID, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.snatRules(t).Get(ctx, ruleID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && r.GatewayID != gatewayID) {
		return errSnatRuleNotFound(ruleID)
	}
	if err != nil {
		return err
	}
	if err := s.snatRules(t).Delete(ctx, ruleID); err != nil {
		return err
	}
	s.engine.Cancel(ruleID)
	return s.releaseUnusedEIPsLocked(ctx, t, r.GatewayID, r.FloatingIPIDs)
}

func parseSnatFloatingIPIDs(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	if len(parts) > maxSnatEIPs {
		return nil, errSnatFloatingIPLimit(maxSnatEIPs)
	}
	seen := make(map[string]bool, len(parts))
	out := make([]string, 0, len(parts))
	for _, id := range parts {
		if !isUUID(id) {
			return nil, errSnatInvalidFloatingIPID(id)
		}
		if seen[id] {
			return nil, errDuplicateSnatFloatingIP(id)
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

func (s *Service) snatRulePrefix(ctx context.Context, t Tenant, r snatRule, cache map[string]netip.Prefix) (netip.Prefix, bool, error) {
	if r.CIDR != "" {
		p, ok := parseCanonicalIPv4CIDR(r.CIDR)
		return p, ok, nil
	}
	if r.NetworkID == "" {
		return netip.Prefix{}, false, nil
	}
	if p, ok := cache[r.NetworkID]; ok {
		return p, true, nil
	}
	sn, err := s.vpc.GetSubnet(ctx, t, r.NetworkID)
	if err != nil {
		var apiErr *apierr.Error
		if errors.As(err, &apiErr) || errors.Is(err, store.ErrNotFound) {
			return netip.Prefix{}, false, nil
		}
		return netip.Prefix{}, false, err
	}
	p, ok := parseCanonicalIPv4CIDR(sn.CIDR)
	if ok {
		cache[r.NetworkID] = p
	}
	return p, ok, nil
}

func (s *Service) checkSnatDnatAnyConflictLocked(ctx context.Context, t Tenant, gatewayID string, eipIDs []string) error {
	dnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
		return r.GatewayID == gatewayID && r.Protocol == "any"
	})
	if err != nil {
		return err
	}
	if len(dnats) == 0 {
		return nil
	}
	anyEIPs := make(map[string]bool, len(dnats))
	for _, d := range dnats {
		anyEIPs[d.FloatingIPID] = true
	}
	for _, id := range eipIDs {
		if anyEIPs[id] {
			return errFloatingIPSnatDnatAllPortConflict(id)
		}
	}
	return nil
}

// releaseUnusedEIPsLocked releases each EIP in eipIDs from gatewayID when no
// remaining SNAT or DNAT rule on that gateway references it (§4.2).
func (s *Service) releaseUnusedEIPsLocked(ctx context.Context, t Tenant, gatewayID string, eipIDs []string) error {
	if len(eipIDs) == 0 {
		return nil
	}
	snats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return err
	}
	dnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return err
	}
	used := make(map[string]bool)
	for _, r := range snats {
		for _, id := range r.FloatingIPIDs {
			used[id] = true
		}
	}
	for _, r := range dnats {
		if r.FloatingIPID != "" {
			used[r.FloatingIPID] = true
		}
	}
	released := make(map[string]bool, len(eipIDs))
	for _, id := range eipIDs {
		if id == "" || released[id] || used[id] {
			continue
		}
		released[id] = true
		if err := s.eips.ReleaseFromNAT(ctx, t, id, gatewayID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) resolveEIPAddresses(ctx context.Context, t Tenant, eipIDs []string) ([]string, error) {
	addrs := make([]string, 0, len(eipIDs))
	for _, id := range eipIDs {
		addr, ok, err := s.eips.PublicIPAddress(ctx, t, id)
		if err != nil {
			return nil, err
		}
		if ok {
			addrs = append(addrs, addr)
		} else {
			addrs = append(addrs, "")
		}
	}
	return addrs, nil
}

func mapEIPHoldError(eipID string, err error) error {
	switch {
	case errors.Is(err, eip.ErrNATNotFound):
		return errFloatingIPNotFound(eipID)
	case errors.Is(err, eip.ErrNATBound):
		portID := strings.TrimPrefix(err.Error(), eip.ErrNATBound.Error()+": ")
		return errFloatingIPBoundToPort(eipID, portID)
	case errors.Is(err, eip.ErrNATHeld):
		gatewayID := strings.TrimPrefix(err.Error(), eip.ErrNATHeld.Error()+": ")
		return errFloatingIPUsedByGateway(eipID, gatewayID)
	case errors.Is(err, eip.ErrNATNotReady):
		return errFloatingIPOccupied(eipID)
	default:
		return err
	}
}

func parseCanonicalIPv4CIDR(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Masked() != p {
		return netip.Prefix{}, false
	}
	return p, true
}

func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func ruleDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func matchRuleCreatedAt(want string, got time.Time) bool {
	utc := got.UTC().Truncate(time.Microsecond)
	if want == utc.Format(publicTimeFormat) {
		return true
	}
	if parsed, err := time.Parse(time.RFC3339Nano, want); err == nil {
		return parsed.UTC().Truncate(time.Microsecond).Equal(utc)
	}
	return false
}
