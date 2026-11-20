package nat

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

// listDnatRulesFilter selects public DNAT rules in listDnatRules (§3.3).
type listDnatRulesFilter struct {
	AdminStateUp        *bool
	ExternalServicePort *int
	FloatingIPAddress   string
	GlobalEIPAddress    string
	Statuses            []string
	FloatingIPID        string
	GlobalEIPID         string
	InternalServicePort *int
	ID                  string
	Description         string
	CreatedAt           string
	NatGatewayIDs       []string
	PortID              string
	PrivateIP           string
	Protocols           []string
	Page                pagination.Marker
}

type portInterval struct {
	start int
	end   int
}

func (p portInterval) overlaps(other portInterval) bool {
	return p.start <= other.end && other.start <= p.end
}

type validatedDnat struct {
	gatewayID     string
	portID        string
	privateIP     string
	protocol      string
	internalPort  int
	externalPort  int
	internalRange string
	externalRange string
	floatingIPID  string
	description   string
}

func (v validatedDnat) toRule(id string) dnatRule {
	return dnatRule{
		ID:            id,
		GatewayID:     v.gatewayID,
		PortID:        v.portID,
		PrivateIP:     v.privateIP,
		Protocol:      v.protocol,
		InternalPort:  v.internalPort,
		ExternalPort:  v.externalPort,
		InternalRange: v.internalRange,
		ExternalRange: v.externalRange,
		FloatingIPID:  v.floatingIPID,
		Description:   v.description,
		Status:        StatusPendingCreate,
	}
}

func (s *Service) createDnatRule(ctx context.Context, t Tenant, opt createDnatRuleOption) (dnatRule, string, error) {
	cand, err := validateCreateDnatOption(opt)
	if err != nil {
		return dnatRule{}, "", err
	}

	ruleID := s.ids.UUID()

	s.mu.Lock()
	defer s.mu.Unlock()

	gw, err := s.requireActiveGatewayLocked(ctx, t, cand.gatewayID)
	if err != nil {
		return dnatRule{}, "", err
	}
	if err := s.validateDnatPortInVPCLocked(ctx, t, gw, cand.portID); err != nil {
		return dnatRule{}, "", err
	}

	existingDnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return dnatRule{}, "", err
	}
	if len(existingDnats) >= publicDnatRulesLimit {
		return dnatRule{}, "", errDnatLimitExceeded(publicDnatRulesLimit)
	}

	existingSnats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return dnatRule{}, "", err
	}

	rule := cand.toRule(ruleID)
	if err := checkDnatConflicts(rule, existingDnats, existingSnats); err != nil {
		return dnatRule{}, "", err
	}

	addr, err := s.eips.HoldForNAT(ctx, t, rule.FloatingIPID, gw.ID)
	if err != nil {
		return dnatRule{}, "", mapEIPHoldError(rule.FloatingIPID, err)
	}

	rule.CreatedAt = s.nowUTC()
	if err := s.dnatRules(t).Create(ctx, rule.ID, rule); err != nil {
		_ = s.releaseUnusedEIPsLocked(ctx, t, gw.ID, []string{rule.FloatingIPID})
		return dnatRule{}, "", err
	}

	s.scheduleDnatActivation(t, rule.ID)
	return rule, addr, nil
}

func (s *Service) batchCreateDnatRules(ctx context.Context, t Tenant, opts []createDnatRuleOption) ([]dnatRule, []string, error) {
	if len(opts) == 0 {
		return nil, nil, errInvalidParams("dnat_rules must not be empty")
	}

	cands := make([]validatedDnat, len(opts))
	ruleIDs := make([]string, len(opts))
	for i, opt := range opts {
		cand, err := validateCreateDnatOption(opt)
		if err != nil {
			return nil, nil, err
		}
		cands[i] = cand
		ruleIDs[i] = s.ids.UUID()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Cache per-gateway state so multi-gateway batches validate cleanly and atomically.
	gws := make(map[string]gateway)
	dnatsByGW := make(map[string][]dnatRule)
	snatsByGW := make(map[string][]snatRule)
	batchCountByGW := make(map[string]int)

	for _, cand := range cands {
		if _, seen := gws[cand.gatewayID]; !seen {
			gw, err := s.requireActiveGatewayLocked(ctx, t, cand.gatewayID)
			if err != nil {
				return nil, nil, err
			}
			existingDnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
				return r.GatewayID == gw.ID
			})
			if err != nil {
				return nil, nil, err
			}
			existingSnats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
				return r.GatewayID == gw.ID
			})
			if err != nil {
				return nil, nil, err
			}
			gws[gw.ID] = gw
			dnatsByGW[gw.ID] = existingDnats
			snatsByGW[gw.ID] = existingSnats
		}
		batchCountByGW[cand.gatewayID]++
	}

	for gwID, addCount := range batchCountByGW {
		remaining := max(0, publicDnatRulesLimit-len(dnatsByGW[gwID]))
		if addCount > remaining {
			return nil, nil, errDnatBatchLimit(remaining)
		}
	}

	rules := make([]dnatRule, len(cands))
	for i, cand := range cands {
		gw := gws[cand.gatewayID]
		if err := s.validateDnatPortInVPCLocked(ctx, t, gw, cand.portID); err != nil {
			return nil, nil, err
		}
		rule := cand.toRule(ruleIDs[i])
		if err := checkDnatConflicts(rule, dnatsByGW[gw.ID], snatsByGW[gw.ID]); err != nil {
			return nil, nil, err
		}
		// Include this rule for subsequent intra-batch conflict checks on the same gateway.
		dnatsByGW[gw.ID] = append(dnatsByGW[gw.ID], rule)
		rules[i] = rule
	}

	// Hold every EIP before persisting any rule so failures roll back cleanly.
	addrs := make([]string, len(rules))
	heldByGW := make(map[string][]string)
	rollbackHolds := func() {
		for gwID, ids := range heldByGW {
			_ = s.releaseUnusedEIPsLocked(ctx, t, gwID, ids)
		}
	}

	for i, rule := range rules {
		addr, err := s.eips.HoldForNAT(ctx, t, rule.FloatingIPID, rule.GatewayID)
		if err != nil {
			rollbackHolds()
			return nil, nil, mapEIPHoldError(rule.FloatingIPID, err)
		}
		heldByGW[rule.GatewayID] = append(heldByGW[rule.GatewayID], rule.FloatingIPID)
		addrs[i] = addr
	}

	now := s.nowUTC()
	stored := make([]string, 0, len(rules))
	for i := range rules {
		rules[i].CreatedAt = now
		if err := s.dnatRules(t).Create(ctx, rules[i].ID, rules[i]); err != nil {
			for _, id := range stored {
				_ = s.dnatRules(t).Delete(ctx, id)
			}
			rollbackHolds()
			return nil, nil, err
		}
		stored = append(stored, rules[i].ID)
	}

	for _, r := range rules {
		s.scheduleDnatActivation(t, r.ID)
	}
	return rules, addrs, nil
}

func (s *Service) getDnatRule(ctx context.Context, t Tenant, id string) (dnatRule, string, error) {
	r, err := s.dnatRules(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return dnatRule{}, "", errDnatRuleNotFound(id)
	}
	if err != nil {
		return dnatRule{}, "", err
	}
	addr, _, err := s.eips.PublicIPAddress(ctx, t, r.FloatingIPID)
	if err != nil {
		return dnatRule{}, "", err
	}
	return r, addr, nil
}

func (s *Service) listDnatRules(ctx context.Context, t Tenant, f listDnatRulesFilter) ([]dnatRule, []string, error) {
	all, err := s.dnatRules(t).List(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	slices.SortFunc(all, func(a, b dnatRule) int {
		return cmp.Compare(a.ID, b.ID)
	})

	wantProtos := make([]string, 0, len(f.Protocols))
	for _, p := range f.Protocols {
		if norm, ok := normalizeDnatProtocol(p); ok {
			wantProtos = append(wantProtos, norm)
		} else {
			wantProtos = append(wantProtos, strings.ToLower(p))
		}
	}

	type pair struct {
		rule dnatRule
		addr string
	}
	matched := make([]pair, 0, len(all))
	for _, r := range all {
		if f.AdminStateUp != nil && !*f.AdminStateUp {
			continue
		}
		if f.ID != "" && r.ID != f.ID {
			continue
		}
		if f.Description != "" && r.Description != f.Description {
			continue
		}
		if f.FloatingIPID != "" && r.FloatingIPID != f.FloatingIPID {
			continue
		}
		if f.PortID != "" && r.PortID != f.PortID {
			continue
		}
		if f.PrivateIP != "" && r.PrivateIP != f.PrivateIP {
			continue
		}
		if f.InternalServicePort != nil && r.InternalPort != *f.InternalServicePort {
			continue
		}
		if f.ExternalServicePort != nil && r.ExternalPort != *f.ExternalServicePort {
			continue
		}
		if len(f.NatGatewayIDs) > 0 && !slices.Contains(f.NatGatewayIDs, r.GatewayID) {
			continue
		}
		if len(f.Statuses) > 0 && !slices.Contains(f.Statuses, r.Status) {
			continue
		}
		if len(wantProtos) > 0 && !slices.Contains(wantProtos, r.Protocol) {
			continue
		}
		if f.GlobalEIPID != "" || f.GlobalEIPAddress != "" {
			continue
		}
		if f.CreatedAt != "" && !matchRuleCreatedAt(f.CreatedAt, r.CreatedAt) {
			continue
		}
		addr, _, err := s.eips.PublicIPAddress(ctx, t, r.FloatingIPID)
		if err != nil {
			return nil, nil, err
		}
		if f.FloatingIPAddress != "" && addr != f.FloatingIPAddress {
			continue
		}
		matched = append(matched, pair{rule: r, addr: addr})
	}

	window, err := pagination.ByMarker(matched, func(p pair) string { return p.rule.ID }, f.Page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return nil, nil, errInvalidParams("%s", err)
	}
	if err != nil {
		return nil, nil, err
	}

	rules := make([]dnatRule, len(window))
	addrs := make([]string, len(window))
	for i, p := range window {
		rules[i] = p.rule
		addrs[i] = p.addr
	}
	return rules, addrs, nil
}

func (s *Service) updateDnatRule(ctx context.Context, t Tenant, id string, opt updateDnatRuleOption) (dnatRule, string, error) {
	if opt.GlobalEIPID != nil && *opt.GlobalEIPID != "" {
		return dnatRule{}, "", apierr.NotImplemented("nat", "global_eip_id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.dnatRules(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return dnatRule{}, "", errDnatRuleNotFound(id)
	}
	if err != nil {
		return dnatRule{}, "", err
	}
	if opt.NatGatewayID == "" || opt.NatGatewayID != cur.GatewayID {
		return dnatRule{}, "", errInvalidParams("nat_gateway_id does not match DNAT rule")
	}

	merged, err := mergeDnatUpdate(cur, opt)
	if err != nil {
		return dnatRule{}, "", err
	}

	gw, err := s.gateways(t).Get(ctx, cur.GatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return dnatRule{}, "", errGatewayNotFound(cur.GatewayID)
	}
	if err != nil {
		return dnatRule{}, "", err
	}
	if err := s.validateDnatPortInVPCLocked(ctx, t, gw, merged.PortID); err != nil {
		return dnatRule{}, "", err
	}

	existingDnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
		return r.GatewayID == cur.GatewayID && r.ID != cur.ID
	})
	if err != nil {
		return dnatRule{}, "", err
	}
	existingSnats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
		return r.GatewayID == cur.GatewayID
	})
	if err != nil {
		return dnatRule{}, "", err
	}
	if err := checkDnatConflicts(merged, existingDnats, existingSnats); err != nil {
		return dnatRule{}, "", err
	}

	oldEIP := cur.FloatingIPID
	newEIP := merged.FloatingIPID
	var addr string
	if newEIP != oldEIP {
		addr, err = s.eips.HoldForNAT(ctx, t, newEIP, cur.GatewayID)
		if err != nil {
			return dnatRule{}, "", mapEIPHoldError(newEIP, err)
		}
	}

	if err := s.dnatRules(t).Put(ctx, merged.ID, merged); err != nil {
		if newEIP != oldEIP {
			_ = s.releaseUnusedEIPsLocked(ctx, t, cur.GatewayID, []string{newEIP})
		}
		return dnatRule{}, "", err
	}

	if newEIP != oldEIP {
		if err := s.releaseUnusedEIPsLocked(ctx, t, cur.GatewayID, []string{oldEIP}); err != nil {
			return dnatRule{}, "", err
		}
		return merged, addr, nil
	}

	addr, _, err = s.eips.PublicIPAddress(ctx, t, merged.FloatingIPID)
	if err != nil {
		return dnatRule{}, "", err
	}
	return merged, addr, nil
}

func (s *Service) deleteDnatRule(ctx context.Context, t Tenant, gatewayID, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.dnatRules(t).Get(ctx, ruleID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && r.GatewayID != gatewayID) {
		return errDnatRuleNotFound(ruleID)
	}
	if err != nil {
		return err
	}
	if err := s.dnatRules(t).Delete(ctx, ruleID); err != nil {
		return err
	}
	s.engine.Cancel(ruleID)
	return s.releaseUnusedEIPsLocked(ctx, t, r.GatewayID, []string{r.FloatingIPID})
}

func (s *Service) requireActiveGatewayLocked(ctx context.Context, t Tenant, gwID string) (gateway, error) {
	gw, err := s.gateways(t).Get(ctx, gwID)
	if errors.Is(err, store.ErrNotFound) {
		return gateway{}, errGatewayNotFound(gwID)
	}
	if err != nil {
		return gateway{}, err
	}
	if gw.Status != StatusActive {
		return gateway{}, errGatewayNotActive(gwID)
	}
	return gw, nil
}

func (s *Service) validateDnatPortInVPCLocked(ctx context.Context, t Tenant, gw gateway, portID string) error {
	if portID == "" {
		return nil
	}
	port, ok, err := s.vpc.Port(ctx, t, portID)
	if err != nil {
		return err
	}
	if !ok {
		return errPortNotFound(portID)
	}
	sn, err := s.vpc.GetSubnet(ctx, t, port.SubnetID)
	if err != nil {
		var apiErr *apierr.Error
		if errors.As(err, &apiErr) || errors.Is(err, store.ErrNotFound) {
			return errDnatInvalidPortVPC(portID)
		}
		return err
	}
	if sn.VPCID != gw.RouterID {
		return errDnatInvalidPortVPC(portID)
	}
	return nil
}

func validateCreateDnatOption(opt createDnatRuleOption) (validatedDnat, error) {
	if opt.GlobalEIPID != nil && *opt.GlobalEIPID != "" {
		return validatedDnat{}, apierr.NotImplemented("nat", "global_eip_id")
	}
	if opt.NatGatewayID == "" {
		return validatedDnat{}, errInvalidParams("nat_gateway_id is required")
	}
	if opt.FloatingIPID == "" {
		return validatedDnat{}, errInvalidParams("floating_ip_id is required")
	}
	intPort := 0
	if opt.InternalServicePort != nil {
		intPort = *opt.InternalServicePort
	}
	extPort := 0
	if opt.ExternalServicePort != nil {
		extPort = *opt.ExternalServicePort
	}
	return validateDnatFields(
		opt.NatGatewayID,
		opt.FloatingIPID,
		ruleDeref(opt.PortID),
		ruleDeref(opt.PrivateIP),
		opt.Protocol,
		intPort,
		extPort,
		ruleDeref(opt.InternalServicePortRange),
		ruleDeref(opt.ExternalServicePortRange),
		ruleDeref(opt.Description),
	)
}

func mergeDnatUpdate(cur dnatRule, opt updateDnatRuleOption) (dnatRule, error) {
	portID := cur.PortID
	privateIP := cur.PrivateIP
	switch {
	case opt.PortID != nil && opt.PrivateIP != nil:
		portID = *opt.PortID
		privateIP = *opt.PrivateIP
	case opt.PortID != nil:
		portID = *opt.PortID
		if portID != "" {
			privateIP = ""
		}
	case opt.PrivateIP != nil:
		privateIP = *opt.PrivateIP
		if privateIP != "" {
			portID = ""
		}
	}

	proto := cur.Protocol
	if opt.Protocol != nil {
		proto = *opt.Protocol
	}

	fipID := cur.FloatingIPID
	if opt.FloatingIPID != nil {
		if *opt.FloatingIPID == "" {
			return dnatRule{}, errInvalidParams("floating_ip_id must not be empty")
		}
		fipID = *opt.FloatingIPID
	}

	desc := cur.Description
	if opt.Description != nil {
		desc = *opt.Description
	}

	intPort := cur.InternalPort
	extPort := cur.ExternalPort
	intRange := cur.InternalRange
	extRange := cur.ExternalRange

	if opt.InternalServicePortRange != nil || opt.ExternalServicePortRange != nil {
		if opt.InternalServicePortRange != nil {
			intRange = *opt.InternalServicePortRange
		}
		if opt.ExternalServicePortRange != nil {
			extRange = *opt.ExternalServicePortRange
		}
		if intRange == "" && extRange == "" {
			if opt.InternalServicePort != nil {
				intPort = *opt.InternalServicePort
			}
			if opt.ExternalServicePort != nil {
				extPort = *opt.ExternalServicePort
			}
		}
	} else if opt.InternalServicePort != nil || opt.ExternalServicePort != nil {
		if opt.InternalServicePort != nil {
			intPort = *opt.InternalServicePort
		}
		if opt.ExternalServicePort != nil {
			extPort = *opt.ExternalServicePort
		}
		intRange = ""
		extRange = ""
	}

	v, err := validateDnatFields(cur.GatewayID, fipID, portID, privateIP, proto, intPort, extPort, intRange, extRange, desc)
	if err != nil {
		return dnatRule{}, err
	}

	out := cur
	out.PortID = v.portID
	out.PrivateIP = v.privateIP
	out.Protocol = v.protocol
	out.InternalPort = v.internalPort
	out.ExternalPort = v.externalPort
	out.InternalRange = v.internalRange
	out.ExternalRange = v.externalRange
	out.FloatingIPID = v.floatingIPID
	out.Description = v.description
	return out, nil
}

func validateDnatFields(
	gatewayID, floatingIPID, portID, privateIP, rawProto string,
	internalPort, externalPort int,
	internalRange, externalRange, desc string,
) (validatedDnat, error) {
	if !validDescription(desc) {
		return validatedDnat{}, errInvalidDescription()
	}
	if portID != "" && privateIP != "" {
		return validatedDnat{}, errDnatBothTargets()
	}
	if portID == "" && privateIP == "" {
		return validatedDnat{}, errDnatTargetMissing()
	}
	if privateIP != "" {
		addr, err := netip.ParseAddr(privateIP)
		if err != nil || !addr.Is4() {
			return validatedDnat{}, errDnatInvalidPrivateIP()
		}
	}

	proto, ok := normalizeDnatProtocol(rawProto)
	if !ok {
		return validatedDnat{}, errDnatInvalidProtocol(rawProto)
	}

	if internalRange != "" || externalRange != "" {
		if proto == "any" {
			return validatedDnat{}, errDnatAnyPortMismatch()
		}
		if internalRange == "" {
			return validatedDnat{}, errDnatInvalidPort(internalRange)
		}
		if externalRange == "" {
			return validatedDnat{}, errDnatInvalidPort(externalRange)
		}
		ir, ok := parsePortRange(internalRange)
		if !ok {
			return validatedDnat{}, errDnatInvalidPort(internalRange)
		}
		er, ok := parsePortRange(externalRange)
		if !ok {
			return validatedDnat{}, errDnatInvalidPort(externalRange)
		}
		if (ir.end - ir.start) != (er.end - er.start) {
			return validatedDnat{}, errDnatInvalidPort(externalRange)
		}
		internalPort = 0
		externalPort = 0
	} else {
		if internalPort < 0 || internalPort > 65535 {
			return validatedDnat{}, errDnatInvalidPort(internalPort)
		}
		if externalPort < 0 || externalPort > 65535 {
			return validatedDnat{}, errDnatInvalidPort(externalPort)
		}
		if proto == "any" {
			if internalPort != 0 || externalPort != 0 {
				return validatedDnat{}, errDnatAnyPortMismatch()
			}
		} else {
			if internalPort == 0 || externalPort == 0 {
				return validatedDnat{}, errDnatAnyPortMismatch()
			}
		}
	}

	return validatedDnat{
		gatewayID:     gatewayID,
		portID:        portID,
		privateIP:     privateIP,
		protocol:      proto,
		internalPort:  internalPort,
		externalPort:  externalPort,
		internalRange: internalRange,
		externalRange: externalRange,
		floatingIPID:  floatingIPID,
		description:   desc,
	}, nil
}

// checkDnatConflicts enforces all five DNAT conflict rules on one gateway (§3.3).
func checkDnatConflicts(cand dnatRule, existingDnats []dnatRule, existingSnats []snatRule) error {
	if cand.Protocol == "any" {
		for _, sn := range existingSnats {
			if slices.Contains(sn.FloatingIPIDs, cand.FloatingIPID) {
				return errFloatingIPSnatDnatAllPortConflict(cand.FloatingIPID)
			}
		}
	}

	candInt := dnatInternalInterval(cand)
	candExt := dnatExternalInterval(cand)

	for _, other := range existingDnats {
		// External EIP + port + protocol conflicts (NAT.0408, NAT.0305).
		if cand.FloatingIPID == other.FloatingIPID {
			switch {
			case cand.Protocol == "any" && other.Protocol == "any":
				return errDnatExternalConflict()
			case cand.Protocol == "any" || other.Protocol == "any":
				return errFloatingIPDnatAllPortConflict(cand.FloatingIPID)
			case cand.Protocol == other.Protocol && candExt.overlaps(dnatExternalInterval(other)):
				return errDnatExternalConflict()
			}
		}

		// Internal port_id conflicts (NAT.0307, NAT.0304).
		if cand.PortID != "" && cand.PortID == other.PortID {
			if cand.Protocol == "any" || other.Protocol == "any" {
				return errDnatPortAllPortConflict()
			}
			if cand.Protocol == other.Protocol && candInt.overlaps(dnatInternalInterval(other)) {
				return errDnatInternalConflict()
			}
		}

		// Internal private_ip conflicts (NAT.0308, NAT.0304).
		if cand.PrivateIP != "" && cand.PrivateIP == other.PrivateIP {
			if cand.Protocol == "any" || other.Protocol == "any" {
				return errDnatPrivateIPAllPortConflict()
			}
			if cand.Protocol == other.Protocol && candInt.overlaps(dnatInternalInterval(other)) {
				return errDnatInternalConflict()
			}
		}
	}
	return nil
}

func dnatInternalInterval(r dnatRule) portInterval {
	if r.InternalRange != "" {
		if iv, ok := parsePortRange(r.InternalRange); ok {
			return iv
		}
	}
	return portInterval{start: r.InternalPort, end: r.InternalPort}
}

func dnatExternalInterval(r dnatRule) portInterval {
	if r.ExternalRange != "" {
		if iv, ok := parsePortRange(r.ExternalRange); ok {
			return iv
		}
	}
	return portInterval{start: r.ExternalPort, end: r.ExternalPort}
}

func normalizeDnatProtocol(raw string) (string, bool) {
	switch strings.ToLower(raw) {
	case "tcp", "6":
		return "tcp", true
	case "udp", "17":
		return "udp", true
	case "any", "0":
		return "any", true
	default:
		return "", false
	}
}

func parsePortRange(raw string) (portInterval, bool) {
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return portInterval{}, false
	}
	a, okA := parsePortNumber(parts[0])
	b, okB := parsePortNumber(parts[1])
	if !okA || !okB || a < 1 || b > 65535 || a > b {
		return portInterval{}, false
	}
	return portInterval{start: a, end: b}, true
}

func parsePortNumber(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}
