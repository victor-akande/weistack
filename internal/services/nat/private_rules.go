package nat

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// --- Inputs and filters (§3.7–§3.9) ---

type createTransitIPInput struct {
	VirsubnetID         string
	IPAddress           string
	EnterpriseProjectID string
	Tags                []tag
}

type listTransitIPsFilter struct {
	IDs                  []string
	ProjectIDs           []string
	NetworkInterfaceIDs  []string
	IPAddresses          []string
	GatewayIDs           []string
	EnterpriseProjectIDs []string
	VirsubnetIDs         []string
	TransitSubnetIDs     []string
	Page                 pagination.Marker
}

type createPrivateSnatInput struct {
	GatewayID    string
	CIDR         string
	VirsubnetID  string
	Description  string
	TransitIPIDs []string
}

type updatePrivateSnatInput struct {
	TransitIPIDs *[]string
	Description  *string
}

type listPrivateSnatsFilter struct {
	IDs                  []string
	ProjectIDs           []string
	Descriptions         []string
	GatewayIDs           []string
	CIDRs                []string
	VirsubnetIDs         []string
	TransitIPIDs         []string
	TransitIPAddresses   []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
}

type createPrivateDnatInput struct {
	Description         string
	TransitIPID         string
	NetworkInterfaceID  string
	GatewayID           string
	Protocol            *string
	PrivateIPAddress    string
	InternalServicePort *string
	TransitServicePort  *string
}

type updatePrivateDnatInput struct {
	Description         *string
	TransitIPID         *string
	NetworkInterfaceID  *string
	PrivateIPAddress    *string
	Protocol            *string
	InternalServicePort *string
	TransitServicePort  *string
}

type listPrivateDnatsFilter struct {
	IDs                  []string
	ProjectIDs           []string
	EnterpriseProjectIDs []string
	Descriptions         []string
	GatewayIDs           []string
	TransitIPIDs         []string
	NetworkInterfaceIDs  []string
	Types                []string
	PrivateIPAddresses   []string
	Protocols            []string
	InternalServicePorts []string
	TransitServicePorts  []string
	TransitIPAddresses   []string
	Page                 pagination.Marker
}

type privateSnatView struct {
	Rule                privateSnat
	Associations        []transitIPAssociation
	EnterpriseProjectID string
}

type privateDnatView struct {
	Rule                privateDnat
	EnterpriseProjectID string
}

// --- §3.7 Transit IPs ---

func validateCreateTags(raw []tag) ([]tag, error) {
	if len(raw) > maxTags {
		return nil, errTooManyTags()
	}
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]tag, 0, len(raw))
	for _, tg := range raw {
		if !validTag(tg.Key, tg.Value) {
			return nil, errInvalidTag()
		}
		if i := slices.IndexFunc(out, func(existing tag) bool { return existing.Key == tg.Key }); i >= 0 {
			out[i].Value = tg.Value
			continue
		}
		out = append(out, tg)
	}
	return out, nil
}

func (s *Service) createTransitIP(ctx context.Context, t Tenant, in createTransitIPInput) (transitIP, error) {
	if in.VirsubnetID == "" {
		return transitIP{}, errBadJSON("virsubnet_id is required")
	}
	ep := in.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	if !validEnterpriseProjectID(ep) {
		return transitIP{}, errInvalidEnterpriseProjectID()
	}
	tags, err := validateCreateTags(in.Tags)
	if err != nil {
		return transitIP{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tsMatches, err := s.transitSubnets(t).List(ctx, func(ts transitSubnet) bool {
		return ts.SubnetID == in.VirsubnetID
	})
	if err != nil {
		return transitIP{}, err
	}
	if len(tsMatches) == 0 {
		if _, err := s.vpc.GetSubnet(ctx, t, in.VirsubnetID); err != nil {
			if isAPIError(err) || errors.Is(err, vpc.ErrSubnetNotFound) || errors.Is(err, store.ErrNotFound) {
				return transitIP{}, errPrivateNotFound("Subnet", in.VirsubnetID)
			}
			return transitIP{}, err
		}
		return transitIP{}, errTransitSubnetUnavailable(in.VirsubnetID)
	}

	id := s.ids.UUID()
	nicID := s.ids.UUID()
	addr, err := s.vpc.AllocateIP(ctx, t, in.VirsubnetID, "nat-transit:"+id, in.IPAddress)
	if err != nil {
		switch {
		case errors.Is(err, vpc.ErrSubnetNotFound):
			return transitIP{}, errPrivateNotFound("Subnet", in.VirsubnetID)
		case errors.Is(err, vpc.ErrIPNotUsable):
			return transitIP{}, errInvalidIP(in.IPAddress)
		case errors.Is(err, vpc.ErrIPInUse):
			return transitIP{}, errIPInUse(in.VirsubnetID, in.IPAddress)
		case errors.Is(err, vpc.ErrSubnetFull):
			return transitIP{}, errSubnetFull(in.VirsubnetID)
		default:
			return transitIP{}, err
		}
	}

	now := s.nowUTC()
	ti := transitIP{
		ID:                  id,
		SubnetID:            in.VirsubnetID,
		Address:             addr,
		NetworkInterfaceID:  nicID,
		GatewayID:           "",
		EnterpriseProjectID: ep,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.transitIPs(t).Create(ctx, ti.ID, ti); err != nil {
		_ = s.vpc.ReleaseIP(ctx, t, ti.SubnetID, ti.Address)
		return transitIP{}, err
	}
	return ti, nil
}

func (s *Service) getTransitIP(ctx context.Context, t Tenant, id string) (transitIP, error) {
	ti, err := s.transitIPs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return transitIP{}, errPrivateNotFound("TransitIp", id)
	}
	if err != nil {
		return transitIP{}, err
	}
	return ti, nil
}

func (s *Service) listTransitIPs(ctx context.Context, t Tenant, f listTransitIPsFilter) ([]transitIP, []transitIP, error) {
	if len(f.ProjectIDs) > 0 && !slices.Contains(f.ProjectIDs, t.ProjectID) {
		return nil, nil, nil
	}

	var subnetToTransitID map[string]string
	if len(f.TransitSubnetIDs) > 0 {
		subnets, err := s.transitSubnets(t).List(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		subnetToTransitID = make(map[string]string, len(subnets))
		for _, ts := range subnets {
			subnetToTransitID[ts.SubnetID] = ts.ID
		}
	}

	all, err := s.transitIPs(t).List(ctx, func(ti transitIP) bool {
		if len(f.IDs) > 0 && !slices.Contains(f.IDs, ti.ID) {
			return false
		}
		if len(f.NetworkInterfaceIDs) > 0 && !slices.Contains(f.NetworkInterfaceIDs, ti.NetworkInterfaceID) {
			return false
		}
		if len(f.IPAddresses) > 0 && !slices.Contains(f.IPAddresses, ti.Address) {
			return false
		}
		if len(f.GatewayIDs) > 0 && !slices.Contains(f.GatewayIDs, ti.GatewayID) {
			return false
		}
		if !matchPrivateEP(f.EnterpriseProjectIDs, ti.EnterpriseProjectID) {
			return false
		}
		if len(f.VirsubnetIDs) > 0 && !slices.Contains(f.VirsubnetIDs, ti.SubnetID) {
			return false
		}
		if len(f.TransitSubnetIDs) > 0 {
			tsID, ok := subnetToTransitID[ti.SubnetID]
			if !ok || !slices.Contains(f.TransitSubnetIDs, tsID) {
				return false
			}
		}
		return true
	})
	if err != nil {
		return nil, nil, err
	}
	slices.SortFunc(all, func(a, b transitIP) int {
		return cmp.Compare(a.ID, b.ID)
	})

	window, err := pagination.ByMarker(all, func(ti transitIP) string { return ti.ID }, f.Page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return nil, nil, errBadJSON("%s", err)
	}
	if err != nil {
		return nil, nil, err
	}
	return window, all, nil
}

func (s *Service) deleteTransitIP(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ti, err := s.transitIPs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound("TransitIp", id)
	}
	if err != nil {
		return err
	}

	snats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return slices.Contains(r.TransitIPIDs, id)
	})
	if err != nil {
		return err
	}
	if len(snats) > 0 {
		return errTransitIPUsedByRules(id)
	}

	dnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.TransitIPID == id
	})
	if err != nil {
		return err
	}
	if len(dnats) > 0 {
		return errTransitIPUsedByRules(id)
	}

	if err := s.transitIPs(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.vpc.ReleaseIP(ctx, t, ti.SubnetID, ti.Address)
}

// --- §3.8 Private SNAT rules ---

func (s *Service) createPrivateSnat(ctx context.Context, t Tenant, in createPrivateSnatInput) (privateSnatView, error) {
	if in.GatewayID == "" {
		return privateSnatView{}, errBadJSON("gateway_id is required")
	}
	if !validDescription(in.Description) {
		return privateSnatView{}, errBadJSON("description is invalid")
	}
	if (in.CIDR == "") == (in.VirsubnetID == "") {
		return privateSnatView{}, errPrivateSnatSubnetOrCIDR()
	}
	if in.CIDR != "" {
		if _, ok := parseCanonicalIPv4CIDR(in.CIDR); !ok {
			return privateSnatView{}, errPrivateSnatInvalidCIDR()
		}
	}
	if err := validatePrivateSnatTransitIPIDList(in.TransitIPIDs); err != nil {
		return privateSnatView{}, err
	}

	ruleID := s.ids.UUID()

	s.mu.Lock()
	defer s.mu.Unlock()

	gw, err := s.privateGateways(t).Get(ctx, in.GatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return privateSnatView{}, errPrivateNotFound("Gateway", in.GatewayID)
	}
	if err != nil {
		return privateSnatView{}, err
	}

	if in.VirsubnetID != "" {
		sn, err := s.vpc.GetSubnet(ctx, t, in.VirsubnetID)
		if err != nil {
			if isAPIError(err) || errors.Is(err, vpc.ErrSubnetNotFound) || errors.Is(err, store.ErrNotFound) {
				return privateSnatView{}, errPrivateSubnetNotInVPC(in.VirsubnetID, gw.ID)
			}
			return privateSnatView{}, err
		}
		if sn.VPCID != gw.VPCID {
			return privateSnatView{}, errPrivateSubnetNotInVPC(in.VirsubnetID, gw.ID)
		}
	}

	existingSnats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return privateSnatView{}, err
	}
	for _, ex := range existingSnats {
		if in.VirsubnetID != "" && ex.SubnetID == in.VirsubnetID {
			return privateSnatView{}, errPrivateSnatNetworkExists(in.VirsubnetID)
		}
		if in.CIDR != "" && ex.CIDR == in.CIDR {
			return privateSnatView{}, errPrivateSnatCIDRExists(in.CIDR)
		}
	}

	existingDnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return privateSnatView{}, err
	}
	ruleMax := privateRuleMax(gw.Spec)
	if len(existingSnats)+len(existingDnats) >= ruleMax {
		return privateSnatView{}, errPrivateRuleLimit(ruleMax)
	}

	tips, err := s.validateSnatTransitIPsLocked(ctx, t, gw, in.TransitIPIDs)
	if err != nil {
		return privateSnatView{}, err
	}

	now := s.nowUTC()
	rule := privateSnat{
		ID:           ruleID,
		GatewayID:    gw.ID,
		CIDR:         in.CIDR,
		SubnetID:     in.VirsubnetID,
		TransitIPIDs: slices.Clone(in.TransitIPIDs),
		Description:  in.Description,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	linked, err := s.linkTransitIPsLocked(ctx, t, gw.ID, tips, now)
	if err != nil {
		return privateSnatView{}, err
	}
	if err := s.privateSnats(t).Create(ctx, rule.ID, rule); err != nil {
		_ = s.unlinkTransitIPsByIDLocked(ctx, t, gw.ID, linked, now)
		return privateSnatView{}, err
	}

	return privateSnatView{
		Rule:                rule,
		Associations:        toTransitIPAssociations(tips),
		EnterpriseProjectID: gw.EnterpriseProjectID,
	}, nil
}

func (s *Service) getPrivateSnat(ctx context.Context, t Tenant, id string) (privateSnatView, error) {
	r, err := s.privateSnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateSnatView{}, errPrivateNotFound("SnatRule", id)
	}
	if err != nil {
		return privateSnatView{}, err
	}
	return s.buildPrivateSnatView(ctx, t, r)
}

func (s *Service) listPrivateSnats(ctx context.Context, t Tenant, f listPrivateSnatsFilter) ([]privateSnatView, []privateSnatView, error) {
	if len(f.ProjectIDs) > 0 && !slices.Contains(f.ProjectIDs, t.ProjectID) {
		return nil, nil, nil
	}

	all, err := s.privateSnats(t).List(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	slices.SortFunc(all, func(a, b privateSnat) int {
		return cmp.Compare(a.ID, b.ID)
	})

	gwEP := make(map[string]string)
	tipAddr := make(map[string]string)

	matched := make([]privateSnatView, 0, len(all))
	for _, r := range all {
		if len(f.IDs) > 0 && !slices.Contains(f.IDs, r.ID) {
			continue
		}
		if len(f.Descriptions) > 0 && !slices.Contains(f.Descriptions, r.Description) {
			continue
		}
		if len(f.GatewayIDs) > 0 && !slices.Contains(f.GatewayIDs, r.GatewayID) {
			continue
		}
		if len(f.CIDRs) > 0 && !slices.Contains(f.CIDRs, r.CIDR) {
			continue
		}
		if len(f.VirsubnetIDs) > 0 && !slices.Contains(f.VirsubnetIDs, r.SubnetID) {
			continue
		}
		if len(f.TransitIPIDs) > 0 && !hasAnyMatch(r.TransitIPIDs, f.TransitIPIDs) {
			continue
		}

		ep, err := s.resolvePrivateGatewayEP(ctx, t, r.GatewayID, gwEP)
		if err != nil {
			return nil, nil, err
		}
		if !matchPrivateEP(f.EnterpriseProjectIDs, ep) {
			continue
		}

		assocs, err := s.resolveTransitIPAssociations(ctx, t, r.TransitIPIDs, tipAddr)
		if err != nil {
			return nil, nil, err
		}
		if len(f.TransitIPAddresses) > 0 {
			found := false
			for _, a := range assocs {
				if slices.Contains(f.TransitIPAddresses, a.TransitIPAddress) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		matched = append(matched, privateSnatView{
			Rule:                r,
			Associations:        assocs,
			EnterpriseProjectID: ep,
		})
	}

	window, err := pagination.ByMarker(matched, func(v privateSnatView) string { return v.Rule.ID }, f.Page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return nil, nil, errBadJSON("%s", err)
	}
	if err != nil {
		return nil, nil, err
	}
	return window, matched, nil
}

func (s *Service) updatePrivateSnat(ctx context.Context, t Tenant, id string, in updatePrivateSnatInput) (privateSnatView, error) {
	if in.Description != nil && !validDescription(*in.Description) {
		return privateSnatView{}, errBadJSON("description is invalid")
	}
	if in.TransitIPIDs != nil {
		if err := validatePrivateSnatTransitIPIDList(*in.TransitIPIDs); err != nil {
			return privateSnatView{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.privateSnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateSnatView{}, errPrivateNotFound("SnatRule", id)
	}
	if err != nil {
		return privateSnatView{}, err
	}

	gw, err := s.privateGateways(t).Get(ctx, cur.GatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return privateSnatView{}, errPrivateNotFound("Gateway", cur.GatewayID)
	}
	if err != nil {
		return privateSnatView{}, err
	}

	oldTransitIPIDs := cur.TransitIPIDs
	now := s.nowUTC()
	var (
		tips   []transitIP
		linked []string
	)
	if in.TransitIPIDs != nil {
		tips, err = s.validateSnatTransitIPsLocked(ctx, t, gw, *in.TransitIPIDs)
		if err != nil {
			return privateSnatView{}, err
		}
		linked, err = s.linkTransitIPsLocked(ctx, t, gw.ID, tips, now)
		if err != nil {
			return privateSnatView{}, err
		}
		cur.TransitIPIDs = slices.Clone(*in.TransitIPIDs)
	}

	if in.Description != nil {
		cur.Description = *in.Description
	}
	cur.UpdatedAt = now

	if err := s.privateSnats(t).Put(ctx, cur.ID, cur); err != nil {
		if len(linked) > 0 {
			_ = s.unlinkTransitIPsByIDLocked(ctx, t, gw.ID, linked, now)
		}
		return privateSnatView{}, err
	}

	if in.TransitIPIDs != nil {
		if err := s.unlinkUnusedTransitIPsLocked(ctx, t, gw.ID, oldTransitIPIDs, now); err != nil {
			return privateSnatView{}, err
		}
		return privateSnatView{
			Rule:                cur,
			Associations:        toTransitIPAssociations(tips),
			EnterpriseProjectID: gw.EnterpriseProjectID,
		}, nil
	}

	assocs, err := s.resolveTransitIPAssociations(ctx, t, cur.TransitIPIDs, nil)
	if err != nil {
		return privateSnatView{}, err
	}
	return privateSnatView{
		Rule:                cur,
		Associations:        assocs,
		EnterpriseProjectID: gw.EnterpriseProjectID,
	}, nil
}

func (s *Service) deletePrivateSnat(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.privateSnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound("SnatRule", id)
	}
	if err != nil {
		return err
	}
	if err := s.privateSnats(t).Delete(ctx, id); err != nil {
		return err
	}
	return s.unlinkUnusedTransitIPsLocked(ctx, t, r.GatewayID, r.TransitIPIDs, s.nowUTC())
}

// --- §3.9 Private DNAT rules ---

func (s *Service) createPrivateDnat(ctx context.Context, t Tenant, in createPrivateDnatInput) (privateDnatView, error) {
	if in.GatewayID == "" {
		return privateDnatView{}, errBadJSON("gateway_id is required")
	}
	if in.TransitIPID == "" {
		return privateDnatView{}, errBadJSON("transit_ip_id is required")
	}
	if !isUUID(in.TransitIPID) {
		return privateDnatView{}, errPrivateSnatInvalidTransitIPID()
	}
	if !validDescription(in.Description) {
		return privateDnatView{}, errBadJSON("description is invalid")
	}

	proto := "any"
	if in.Protocol != nil && *in.Protocol != "" {
		var ok bool
		proto, ok = normalizeDnatProtocol(*in.Protocol)
		if !ok {
			return privateDnatView{}, errBadJSON("protocol %q is invalid", *in.Protocol)
		}
	}

	intPort, err := parsePrivateDnatPort(in.InternalServicePort)
	if err != nil {
		return privateDnatView{}, err
	}
	transitPort, err := parsePrivateDnatPort(in.TransitServicePort)
	if err != nil {
		return privateDnatView{}, err
	}

	cand, err := validatePrivateDnatFields(
		in.GatewayID,
		in.TransitIPID,
		in.NetworkInterfaceID,
		in.PrivateIPAddress,
		proto,
		intPort,
		transitPort,
		in.Description,
	)
	if err != nil {
		return privateDnatView{}, err
	}

	cand.ID = s.ids.UUID()

	s.mu.Lock()
	defer s.mu.Unlock()

	gw, err := s.privateGateways(t).Get(ctx, cand.GatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return privateDnatView{}, errPrivateNotFound("Gateway", cand.GatewayID)
	}
	if err != nil {
		return privateDnatView{}, err
	}

	ti, err := s.validateDnatTransitIPLocked(ctx, t, gw, cand.TransitIPID)
	if err != nil {
		return privateDnatView{}, err
	}

	if err := s.resolveAndValidatePrivateDnatBackendLocked(ctx, t, gw, &cand); err != nil {
		return privateDnatView{}, err
	}

	existingSnats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return privateDnatView{}, err
	}
	existingDnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.GatewayID == gw.ID
	})
	if err != nil {
		return privateDnatView{}, err
	}
	ruleMax := privateRuleMax(gw.Spec)
	if len(existingSnats)+len(existingDnats) >= ruleMax {
		return privateDnatView{}, errPrivateRuleLimit(ruleMax)
	}

	if err := checkPrivateDnatConflicts(cand, existingDnats); err != nil {
		return privateDnatView{}, err
	}

	now := s.nowUTC()
	cand.CreatedAt = now
	cand.UpdatedAt = now

	linked, err := s.linkTransitIPsLocked(ctx, t, gw.ID, []transitIP{ti}, now)
	if err != nil {
		return privateDnatView{}, err
	}
	if err := s.privateDnats(t).Create(ctx, cand.ID, cand); err != nil {
		_ = s.unlinkTransitIPsByIDLocked(ctx, t, gw.ID, linked, now)
		return privateDnatView{}, err
	}

	return privateDnatView{
		Rule:                cand,
		EnterpriseProjectID: gw.EnterpriseProjectID,
	}, nil
}

func (s *Service) getPrivateDnat(ctx context.Context, t Tenant, id string) (privateDnatView, error) {
	r, err := s.privateDnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateDnatView{}, errPrivateNotFound("DnatRule", id)
	}
	if err != nil {
		return privateDnatView{}, err
	}
	ep, err := s.resolvePrivateGatewayEP(ctx, t, r.GatewayID, nil)
	if err != nil {
		return privateDnatView{}, err
	}
	return privateDnatView{Rule: r, EnterpriseProjectID: ep}, nil
}

func (s *Service) listPrivateDnats(ctx context.Context, t Tenant, f listPrivateDnatsFilter) ([]privateDnatView, []privateDnatView, error) {
	if len(f.ProjectIDs) > 0 && !slices.Contains(f.ProjectIDs, t.ProjectID) {
		return nil, nil, nil
	}

	all, err := s.privateDnats(t).List(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	slices.SortFunc(all, func(a, b privateDnat) int {
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

	gwEP := make(map[string]string)
	tipAddr := make(map[string]string)

	matched := make([]privateDnatView, 0, len(all))
	for _, r := range all {
		if len(f.IDs) > 0 && !slices.Contains(f.IDs, r.ID) {
			continue
		}
		if len(f.Descriptions) > 0 && !slices.Contains(f.Descriptions, r.Description) {
			continue
		}
		if len(f.GatewayIDs) > 0 && !slices.Contains(f.GatewayIDs, r.GatewayID) {
			continue
		}
		if len(f.TransitIPIDs) > 0 && !slices.Contains(f.TransitIPIDs, r.TransitIPID) {
			continue
		}
		if len(f.NetworkInterfaceIDs) > 0 && !slices.Contains(f.NetworkInterfaceIDs, r.NetworkInterfaceID) {
			continue
		}
		if len(f.Types) > 0 && !slices.Contains(f.Types, r.Type) {
			continue
		}
		if len(f.PrivateIPAddresses) > 0 && !slices.Contains(f.PrivateIPAddresses, r.PrivateIP) {
			continue
		}
		if len(wantProtos) > 0 && !slices.Contains(wantProtos, r.Protocol) {
			continue
		}
		if len(f.InternalServicePorts) > 0 && !slices.Contains(f.InternalServicePorts, r.InternalPort) {
			continue
		}
		if len(f.TransitServicePorts) > 0 && !slices.Contains(f.TransitServicePorts, r.TransitPort) {
			continue
		}

		ep, err := s.resolvePrivateGatewayEP(ctx, t, r.GatewayID, gwEP)
		if err != nil {
			return nil, nil, err
		}
		if !matchPrivateEP(f.EnterpriseProjectIDs, ep) {
			continue
		}

		if len(f.TransitIPAddresses) > 0 {
			addr, err := s.resolveTransitIPAddress(ctx, t, r.TransitIPID, tipAddr)
			if err != nil {
				return nil, nil, err
			}
			if !slices.Contains(f.TransitIPAddresses, addr) {
				continue
			}
		}

		matched = append(matched, privateDnatView{
			Rule:                r,
			EnterpriseProjectID: ep,
		})
	}

	window, err := pagination.ByMarker(matched, func(v privateDnatView) string { return v.Rule.ID }, f.Page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return nil, nil, errBadJSON("%s", err)
	}
	if err != nil {
		return nil, nil, err
	}
	return window, matched, nil
}

func (s *Service) updatePrivateDnat(ctx context.Context, t Tenant, id string, in updatePrivateDnatInput) (privateDnatView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.privateDnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateDnatView{}, errPrivateNotFound("DnatRule", id)
	}
	if err != nil {
		return privateDnatView{}, err
	}

	merged, err := mergePrivateDnatUpdate(cur, in)
	if err != nil {
		return privateDnatView{}, err
	}

	gw, err := s.privateGateways(t).Get(ctx, cur.GatewayID)
	if errors.Is(err, store.ErrNotFound) {
		return privateDnatView{}, errPrivateNotFound("Gateway", cur.GatewayID)
	}
	if err != nil {
		return privateDnatView{}, err
	}

	ti, err := s.validateDnatTransitIPLocked(ctx, t, gw, merged.TransitIPID)
	if err != nil {
		return privateDnatView{}, err
	}

	if err := s.resolveAndValidatePrivateDnatBackendLocked(ctx, t, gw, &merged); err != nil {
		return privateDnatView{}, err
	}

	existingDnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.GatewayID == gw.ID && r.ID != cur.ID
	})
	if err != nil {
		return privateDnatView{}, err
	}
	if err := checkPrivateDnatConflicts(merged, existingDnats); err != nil {
		return privateDnatView{}, err
	}

	now := s.nowUTC()
	merged.UpdatedAt = now

	oldTransitIPID := cur.TransitIPID
	newTransitIPID := merged.TransitIPID
	var linked []string
	if newTransitIPID != oldTransitIPID {
		linked, err = s.linkTransitIPsLocked(ctx, t, gw.ID, []transitIP{ti}, now)
		if err != nil {
			return privateDnatView{}, err
		}
	}

	if err := s.privateDnats(t).Put(ctx, merged.ID, merged); err != nil {
		if len(linked) > 0 {
			_ = s.unlinkTransitIPsByIDLocked(ctx, t, gw.ID, linked, now)
		}
		return privateDnatView{}, err
	}

	if newTransitIPID != oldTransitIPID {
		if err := s.unlinkUnusedTransitIPsLocked(ctx, t, gw.ID, []string{oldTransitIPID}, now); err != nil {
			return privateDnatView{}, err
		}
	}

	return privateDnatView{
		Rule:                merged,
		EnterpriseProjectID: gw.EnterpriseProjectID,
	}, nil
}

func (s *Service) deletePrivateDnat(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, err := s.privateDnats(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound("DnatRule", id)
	}
	if err != nil {
		return err
	}
	if err := s.privateDnats(t).Delete(ctx, id); err != nil {
		return err
	}
	return s.unlinkUnusedTransitIPsLocked(ctx, t, r.GatewayID, []string{r.TransitIPID}, s.nowUTC())
}

// --- Shared private rule helpers ---

func privateRuleMax(spec string) int {
	for _, sp := range privateSpecs {
		if sp.Name == spec {
			return sp.RuleMax
		}
	}
	return privateSpecs[0].RuleMax
}

func matchPrivateEP(want []string, ep string) bool {
	if len(want) == 0 || slices.Contains(want, allGrantedEPs) {
		return true
	}
	return slices.Contains(want, ep)
}

func hasAnyMatch(have, want []string) bool {
	for _, w := range want {
		if slices.Contains(have, w) {
			return true
		}
	}
	return false
}

func validatePrivateSnatTransitIPIDList(ids []string) error {
	if len(ids) == 0 {
		return errBadJSON("transit_ip_ids is required")
	}
	if len(ids) > maxSnatEIPs {
		return errPrivateSnatTransitIPLimit(maxSnatEIPs)
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !isUUID(id) {
			return errPrivateSnatInvalidTransitIPID()
		}
		if seen[id] {
			return errBadJSON("duplicate transit_ip_id %s", id)
		}
		seen[id] = true
	}
	return nil
}

func (s *Service) validateSnatTransitIPsLocked(ctx context.Context, t Tenant, gw privateGateway, ids []string) ([]transitIP, error) {
	allDnats, err := s.privateDnats(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	dnatUsed := make(map[string]bool, len(allDnats))
	for _, d := range allDnats {
		dnatUsed[d.TransitIPID] = true
	}

	tips := make([]transitIP, 0, len(ids))
	for _, id := range ids {
		ti, err := s.transitIPs(t).Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errPrivateNotFound("TransitIp", id)
		}
		if err != nil {
			return nil, err
		}
		if err := s.checkTransitIPNotInGatewayVPCLocked(ctx, t, gw, ti); err != nil {
			return nil, err
		}
		if ti.GatewayID != "" && ti.GatewayID != gw.ID {
			return nil, errTransitIPUsedByOtherGateway(ti.ID, ti.GatewayID)
		}
		if dnatUsed[ti.ID] {
			return nil, errTransitIPUsedByDnat(ti.ID)
		}
		tips = append(tips, ti)
	}
	return tips, nil
}

func (s *Service) validateDnatTransitIPLocked(ctx context.Context, t Tenant, gw privateGateway, transitIPID string) (transitIP, error) {
	ti, err := s.transitIPs(t).Get(ctx, transitIPID)
	if errors.Is(err, store.ErrNotFound) {
		return transitIP{}, errPrivateNotFound("TransitIp", transitIPID)
	}
	if err != nil {
		return transitIP{}, err
	}
	if err := s.checkTransitIPNotInGatewayVPCLocked(ctx, t, gw, ti); err != nil {
		return transitIP{}, err
	}
	if ti.GatewayID != "" && ti.GatewayID != gw.ID {
		return transitIP{}, errTransitIPUsedByOtherGateway(ti.ID, ti.GatewayID)
	}

	snats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return slices.Contains(r.TransitIPIDs, ti.ID)
	})
	if err != nil {
		return transitIP{}, err
	}
	if len(snats) > 0 {
		return transitIP{}, errTransitIPUsedBySnat(ti.ID)
	}
	return ti, nil
}

func (s *Service) checkTransitIPNotInGatewayVPCLocked(ctx context.Context, t Tenant, gw privateGateway, ti transitIP) error {
	sn, err := s.vpc.GetSubnet(ctx, t, ti.SubnetID)
	if err != nil {
		if isAPIError(err) || errors.Is(err, vpc.ErrSubnetNotFound) || errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if sn.VPCID == gw.VPCID {
		return errTransitIPInGatewayVPC(ti.ID)
	}
	return nil
}

func (s *Service) linkTransitIPsLocked(ctx context.Context, t Tenant, gatewayID string, tips []transitIP, now time.Time) ([]string, error) {
	linked := make([]string, 0, len(tips))
	for _, ti := range tips {
		if ti.GatewayID == gatewayID {
			continue
		}
		ti.GatewayID = gatewayID
		ti.UpdatedAt = now
		if err := s.transitIPs(t).Put(ctx, ti.ID, ti); err != nil {
			_ = s.unlinkTransitIPsByIDLocked(ctx, t, gatewayID, linked, now)
			return nil, err
		}
		linked = append(linked, ti.ID)
	}
	return linked, nil
}

func (s *Service) unlinkTransitIPsByIDLocked(ctx context.Context, t Tenant, gatewayID string, ids []string, now time.Time) error {
	for _, id := range ids {
		ti, err := s.transitIPs(t).Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if ti.GatewayID != gatewayID {
			continue
		}
		ti.GatewayID = ""
		ti.UpdatedAt = now
		if err := s.transitIPs(t).Put(ctx, ti.ID, ti); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) unlinkUnusedTransitIPsLocked(ctx context.Context, t Tenant, gatewayID string, candidateIDs []string, now time.Time) error {
	if len(candidateIDs) == 0 {
		return nil
	}
	snats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return err
	}
	dnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return err
	}

	used := make(map[string]bool)
	for _, sn := range snats {
		for _, id := range sn.TransitIPIDs {
			used[id] = true
		}
	}
	for _, dn := range dnats {
		if dn.TransitIPID != "" {
			used[dn.TransitIPID] = true
		}
	}

	seen := make(map[string]bool, len(candidateIDs))
	var toUnlink []string
	for _, id := range candidateIDs {
		if id == "" || seen[id] || used[id] {
			continue
		}
		seen[id] = true
		toUnlink = append(toUnlink, id)
	}
	return s.unlinkTransitIPsByIDLocked(ctx, t, gatewayID, toUnlink, now)
}

func toTransitIPAssociations(tips []transitIP) []transitIPAssociation {
	out := make([]transitIPAssociation, len(tips))
	for i, ti := range tips {
		out[i] = transitIPAssociation{
			TransitIPID:      ti.ID,
			TransitIPAddress: ti.Address,
		}
	}
	return out
}

func (s *Service) resolveTransitIPAddress(ctx context.Context, t Tenant, id string, cache map[string]string) (string, error) {
	if cache != nil {
		if addr, ok := cache[id]; ok {
			return addr, nil
		}
	}
	ti, err := s.transitIPs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if cache != nil {
		cache[id] = ti.Address
	}
	return ti.Address, nil
}

func (s *Service) resolveTransitIPAssociations(ctx context.Context, t Tenant, ids []string, cache map[string]string) ([]transitIPAssociation, error) {
	out := make([]transitIPAssociation, 0, len(ids))
	for _, id := range ids {
		addr, err := s.resolveTransitIPAddress(ctx, t, id, cache)
		if err != nil {
			return nil, err
		}
		out = append(out, transitIPAssociation{
			TransitIPID:      id,
			TransitIPAddress: addr,
		})
	}
	return out, nil
}

func (s *Service) resolvePrivateGatewayEP(ctx context.Context, t Tenant, gwID string, cache map[string]string) (string, error) {
	if cache != nil {
		if ep, ok := cache[gwID]; ok {
			return ep, nil
		}
	}
	gw, err := s.privateGateways(t).Get(ctx, gwID)
	if errors.Is(err, store.ErrNotFound) {
		return defaultEnterpriseProjectID, nil
	}
	if err != nil {
		return "", err
	}
	ep := gw.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	if cache != nil {
		cache[gwID] = ep
	}
	return ep, nil
}

func (s *Service) buildPrivateSnatView(ctx context.Context, t Tenant, r privateSnat) (privateSnatView, error) {
	ep, err := s.resolvePrivateGatewayEP(ctx, t, r.GatewayID, nil)
	if err != nil {
		return privateSnatView{}, err
	}
	assocs, err := s.resolveTransitIPAssociations(ctx, t, r.TransitIPIDs, nil)
	if err != nil {
		return privateSnatView{}, err
	}
	return privateSnatView{
		Rule:                r,
		Associations:        assocs,
		EnterpriseProjectID: ep,
	}, nil
}

func parsePrivateDnatPort(raw *string) (string, error) {
	if raw == nil || *raw == "" {
		return "0", nil
	}
	s := *raw
	v, ok := parsePortNumber(s)
	if !ok || v < 0 || v > 65535 || strconv.Itoa(v) != s {
		return "", errBadJSON("port %q is invalid", s)
	}
	return s, nil
}

func validatePrivateDnatFields(
	gatewayID, transitIPID, nicID, privIP, proto, intPort, transitPort, desc string,
) (privateDnat, error) {
	if !validDescription(desc) {
		return privateDnat{}, errBadJSON("description is invalid")
	}
	if (nicID == "") == (privIP == "") {
		return privateDnat{}, errPrivateDnatTargetInvalid()
	}

	typ := "COMPUTE"
	if privIP != "" {
		addr, err := netip.ParseAddr(privIP)
		if err != nil || !addr.Is4() {
			return privateDnat{}, errInvalidIP(privIP)
		}
		typ = "CUSTOMIZE"
	}

	if proto == "any" && (intPort != "0" || transitPort != "0") {
		return privateDnat{}, errPrivateDnatAnyPortMismatch()
	}
	if proto != "any" && (intPort == "0" || transitPort == "0") {
		return privateDnat{}, errPrivateDnatAnyPortMismatch()
	}

	return privateDnat{
		GatewayID:          gatewayID,
		TransitIPID:        transitIPID,
		NetworkInterfaceID: nicID,
		PrivateIP:          privIP,
		Type:               typ,
		Protocol:           proto,
		InternalPort:       intPort,
		TransitPort:        transitPort,
		Description:        desc,
	}, nil
}

func mergePrivateDnatUpdate(cur privateDnat, in updatePrivateDnatInput) (privateDnat, error) {
	desc := cur.Description
	if in.Description != nil {
		desc = *in.Description
	}

	transitIPID := cur.TransitIPID
	if in.TransitIPID != nil {
		if *in.TransitIPID == "" {
			return privateDnat{}, errBadJSON("transit_ip_id must not be empty")
		}
		if !isUUID(*in.TransitIPID) {
			return privateDnat{}, errPrivateSnatInvalidTransitIPID()
		}
		transitIPID = *in.TransitIPID
	}

	nicID := cur.NetworkInterfaceID
	privIP := cur.PrivateIP
	if cur.Type == "COMPUTE" {
		privIP = ""
	}
	switch {
	case in.NetworkInterfaceID != nil && in.PrivateIPAddress != nil:
		nicID = *in.NetworkInterfaceID
		privIP = *in.PrivateIPAddress
	case in.NetworkInterfaceID != nil:
		nicID = *in.NetworkInterfaceID
		if nicID != "" {
			privIP = ""
		}
	case in.PrivateIPAddress != nil:
		privIP = *in.PrivateIPAddress
		if privIP != "" {
			nicID = ""
		}
	}

	proto := cur.Protocol
	if in.Protocol != nil {
		norm, ok := normalizeDnatProtocol(*in.Protocol)
		if !ok {
			return privateDnat{}, errBadJSON("protocol %q is invalid", *in.Protocol)
		}
		proto = norm
	}

	intPort := cur.InternalPort
	if in.InternalServicePort != nil {
		p, err := parsePrivateDnatPort(in.InternalServicePort)
		if err != nil {
			return privateDnat{}, err
		}
		intPort = p
	}

	transitPort := cur.TransitPort
	if in.TransitServicePort != nil {
		p, err := parsePrivateDnatPort(in.TransitServicePort)
		if err != nil {
			return privateDnat{}, err
		}
		transitPort = p
	}

	validated, err := validatePrivateDnatFields(
		cur.GatewayID,
		transitIPID,
		nicID,
		privIP,
		proto,
		intPort,
		transitPort,
		desc,
	)
	if err != nil {
		return privateDnat{}, err
	}
	validated.ID = cur.ID
	validated.CreatedAt = cur.CreatedAt
	return validated, nil
}

func (s *Service) resolveAndValidatePrivateDnatBackendLocked(ctx context.Context, t Tenant, gw privateGateway, cand *privateDnat) error {
	if cand.NetworkInterfaceID == "" {
		return nil
	}
	port, ok, err := s.vpc.Port(ctx, t, cand.NetworkInterfaceID)
	if err != nil {
		return err
	}
	if !ok {
		return errPrivatePortNotFound(cand.NetworkInterfaceID)
	}
	sn, err := s.vpc.GetSubnet(ctx, t, port.SubnetID)
	if err != nil {
		if isAPIError(err) || errors.Is(err, vpc.ErrSubnetNotFound) || errors.Is(err, store.ErrNotFound) {
			return errPrivatePortNotInVPC(cand.NetworkInterfaceID)
		}
		return err
	}
	if sn.VPCID != gw.VPCID {
		return errPrivatePortNotInVPC(cand.NetworkInterfaceID)
	}
	cand.PrivateIP = port.IP
	cand.Type = "COMPUTE"
	return nil
}

// checkPrivateDnatConflicts enforces all four private DNAT conflict rules on one gateway (§3.9).
func checkPrivateDnatConflicts(cand privateDnat, existing []privateDnat) error {
	for _, other := range existing {
		if cand.TransitIPID == other.TransitIPID {
			switch {
			case cand.Protocol == "any" && other.Protocol == "any":
				return errPrivateDnatTransitConflict()
			case cand.Protocol == "any" || other.Protocol == "any":
				return errTransitIPDnatAllPortConflict(cand.TransitIPID)
			case cand.Protocol == other.Protocol && cand.TransitPort == other.TransitPort:
				return errPrivateDnatTransitConflict()
			}
		}

		sameNIC := cand.NetworkInterfaceID != "" && cand.NetworkInterfaceID == other.NetworkInterfaceID
		sameIP := cand.PrivateIP != "" && cand.PrivateIP == other.PrivateIP
		if sameNIC || sameIP {
			target := cand.NetworkInterfaceID
			if target == "" {
				target = other.NetworkInterfaceID
			}
			if target == "" {
				target = cand.PrivateIP
			}
			switch {
			case cand.Protocol == "any" && other.Protocol == "any":
				return errPrivateDnatInternalConflict()
			case cand.Protocol == "any" || other.Protocol == "any":
				return errPrivateDnatPortAllPortConflict(target)
			case cand.Protocol == other.Protocol && cand.InternalPort == other.InternalPort:
				return errPrivateDnatInternalConflict()
			}
		}
	}
	return nil
}
