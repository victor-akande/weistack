package nat

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type downlinkVPCInput struct {
	VirsubnetID     string
	NgportIPAddress string
}

type createPrivateGatewayInput struct {
	Name                string
	Description         string
	Spec                *string
	DownlinkVPCs        []downlinkVPCInput
	Tags                []tag
	EnterpriseProjectID string
}

type updatePrivateGatewayInput struct {
	Name        *string
	Description *string
	Spec        *string
}

type listPrivateGatewaysFilter struct {
	IDs                  []string
	ProjectIDs           []string
	Names                []string
	Descriptions         []string
	Specs                []string
	Statuses             []string
	VPCIDs               []string
	VirsubnetIDs         []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
}

type createTransitSubnetInput struct {
	Name               string
	Description        string
	VirsubnetID        string
	VirsubnetProjectID string
	Tags               []tag
}

type updateTransitSubnetInput struct {
	Name        *string
	Description *string
}

type listTransitSubnetsFilter struct {
	IDs                 []string
	Names               []string
	Descriptions        []string
	VirsubnetProjectIDs []string
	VPCIDs              []string
	VirsubnetIDs        []string
	Statuses            []string
	Page                pagination.Marker
}

func lookupPrivateSpec(name string) (privateSpec, bool) {
	for _, sp := range privateSpecs {
		if sp.Name == name {
			return sp, true
		}
	}
	return privateSpec{}, false
}

func parsePrivateResourceTags(raw []tag) ([]tag, error) {
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

func mapPrivateIPAllocError(subnetID, want string, err error) error {
	switch {
	case errors.Is(err, vpc.ErrSubnetNotFound):
		return errPrivateNotFound("Subnet", subnetID)
	case errors.Is(err, vpc.ErrIPNotUsable):
		return errInvalidIP(want)
	case errors.Is(err, vpc.ErrIPInUse):
		return errIPInUse(subnetID, want)
	case errors.Is(err, vpc.ErrSubnetFull):
		return errSubnetFull(subnetID)
	default:
		return err
	}
}

func privatePageInfo[T any](all, page []T, id func(T) string) pageInfo {
	info := pageInfo{CurrentCount: len(page)}
	if len(page) > 0 {
		info.PreviousMarker = id(page[0])
		if last := id(page[len(page)-1]); last != id(all[len(all)-1]) {
			info.NextMarker = last
		}
	}
	return info
}

func matchesPrivateFilter(want []string, got string) bool {
	return len(want) == 0 || slices.Contains(want, got)
}

func inPrivateEP(want []string, ep string) bool {
	if len(want) == 0 || slices.Contains(want, allGrantedEPs) {
		return true
	}
	return slices.Contains(want, ep)
}

func (s *Service) createPrivateGateway(ctx context.Context, t Tenant, in createPrivateGatewayInput) (privateGateway, error) {
	if !validName(in.Name) {
		return privateGateway{}, errBadJSON("invalid name")
	}
	if !validDescription(in.Description) {
		return privateGateway{}, errBadJSON("invalid description")
	}

	specName := "Small"
	if in.Spec != nil {
		if _, ok := lookupPrivateSpec(*in.Spec); !ok {
			return privateGateway{}, errBadJSON("invalid spec %q", *in.Spec)
		}
		specName = *in.Spec
	}

	ep := in.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	if !validEnterpriseProjectID(ep) {
		return privateGateway{}, errInvalidEnterpriseProjectID()
	}

	tags, err := parsePrivateResourceTags(in.Tags)
	if err != nil {
		return privateGateway{}, err
	}

	if len(in.DownlinkVPCs) == 0 {
		return privateGateway{}, errBadJSON("downlink_vpcs is required")
	}
	if len(in.DownlinkVPCs) > 1 {
		return privateGateway{}, errDownlinkVPCLimit(1)
	}
	dl := in.DownlinkVPCs[0]
	if dl.VirsubnetID == "" {
		return privateGateway{}, errBadJSON("virsubnet_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	subnet, err := s.vpc.GetSubnet(ctx, t, dl.VirsubnetID)
	if isAPIError(err) {
		return privateGateway{}, errPrivateNotFound("Subnet", dl.VirsubnetID)
	}
	if err != nil {
		return privateGateway{}, err
	}

	id := s.ids.UUID()
	ip, err := s.vpc.AllocateIP(ctx, t, dl.VirsubnetID, "nat:"+id, dl.NgportIPAddress)
	if err != nil {
		return privateGateway{}, mapPrivateIPAllocError(dl.VirsubnetID, dl.NgportIPAddress, err)
	}

	now := s.nowUTC()
	g := privateGateway{
		ID:                  id,
		Name:                in.Name,
		Description:         in.Description,
		Spec:                specName,
		VPCID:               subnet.VPCID,
		SubnetID:            dl.VirsubnetID,
		NgportIP:            ip,
		EnterpriseProjectID: ep,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.privateGateways(t).Create(ctx, g.ID, g); err != nil {
		_ = s.vpc.ReleaseIP(ctx, t, g.SubnetID, g.NgportIP)
		return privateGateway{}, err
	}
	return g, nil
}

func (s *Service) getPrivateGateway(ctx context.Context, t Tenant, id string) (privateGateway, error) {
	g, err := s.privateGateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateGateway{}, errPrivateNotFound("Gateway", id)
	}
	if err != nil {
		return privateGateway{}, err
	}
	return g, nil
}

func (s *Service) listPrivateGateways(ctx context.Context, t Tenant, f listPrivateGatewaysFilter) ([]privateGateway, pageInfo, error) {
	all, err := s.privateGateways(t).List(ctx, func(g privateGateway) bool {
		return matchesPrivateFilter(f.IDs, g.ID) &&
			matchesPrivateFilter(f.ProjectIDs, t.ProjectID) &&
			matchesPrivateFilter(f.Names, g.Name) &&
			matchesPrivateFilter(f.Descriptions, g.Description) &&
			matchesPrivateFilter(f.Specs, g.Spec) &&
			matchesPrivateFilter(f.Statuses, StatusActive) &&
			matchesPrivateFilter(f.VPCIDs, g.VPCID) &&
			matchesPrivateFilter(f.VirsubnetIDs, g.SubnetID) &&
			inPrivateEP(f.EnterpriseProjectIDs, g.EnterpriseProjectID)
	})
	if err != nil {
		return nil, pageInfo{}, err
	}
	slices.SortFunc(all, func(a, b privateGateway) int {
		return strings.Compare(a.ID, b.ID)
	})
	page, err := pagination.ByMarker(all, func(g privateGateway) string { return g.ID }, f.Page)
	if err != nil {
		return nil, pageInfo{}, errBadJSON("%s", err)
	}
	return page, privatePageInfo(all, page, func(g privateGateway) string { return g.ID }), nil
}

func (s *Service) countPrivateGatewayRulesLocked(ctx context.Context, t Tenant, gatewayID string) (int, error) {
	snats, err := s.privateSnats(t).List(ctx, func(r privateSnat) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return 0, err
	}
	dnats, err := s.privateDnats(t).List(ctx, func(r privateDnat) bool {
		return r.GatewayID == gatewayID
	})
	if err != nil {
		return 0, err
	}
	return len(snats) + len(dnats), nil
}

func (s *Service) updatePrivateGateway(ctx context.Context, t Tenant, id string, in updatePrivateGatewayInput) (privateGateway, error) {
	if in.Name != nil && !validName(*in.Name) {
		return privateGateway{}, errBadJSON("invalid name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return privateGateway{}, errBadJSON("invalid description")
	}
	var newSpec privateSpec
	if in.Spec != nil {
		var ok bool
		newSpec, ok = lookupPrivateSpec(*in.Spec)
		if !ok {
			return privateGateway{}, errBadJSON("invalid spec %q", *in.Spec)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.privateGateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return privateGateway{}, errPrivateNotFound("Gateway", id)
	}
	if err != nil {
		return privateGateway{}, err
	}

	if in.Spec != nil {
		if *in.Spec == existing.Spec {
			return privateGateway{}, errSamePrivateSpec(*in.Spec)
		}
		ruleCount, err := s.countPrivateGatewayRulesLocked(ctx, t, id)
		if err != nil {
			return privateGateway{}, err
		}
		if ruleCount > newSpec.RuleMax {
			return privateGateway{}, errPrivateRuleLimit(newSpec.RuleMax)
		}
	}

	updated, err := s.privateGateways(t).Update(ctx, id, func(g *privateGateway) error {
		if in.Name != nil {
			g.Name = *in.Name
		}
		if in.Description != nil {
			g.Description = *in.Description
		}
		if in.Spec != nil {
			g.Spec = *in.Spec
		}
		g.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return privateGateway{}, errPrivateNotFound("Gateway", id)
	}
	if err != nil {
		return privateGateway{}, err
	}
	return updated, nil
}

func (s *Service) deletePrivateGateway(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, err := s.privateGateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound("Gateway", id)
	}
	if err != nil {
		return err
	}

	ruleCount, err := s.countPrivateGatewayRulesLocked(ctx, t, id)
	if err != nil {
		return err
	}
	if ruleCount > 0 {
		return errPrivateHasDependencies(id)
	}

	if err := s.privateGateways(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.vpc.ReleaseIP(ctx, t, g.SubnetID, g.NgportIP)
}

func (s *Service) createTransitSubnet(ctx context.Context, t Tenant, in createTransitSubnetInput) (transitSubnet, int, error) {
	if !validName(in.Name) {
		return transitSubnet{}, 0, errBadJSON("invalid name")
	}
	if !validDescription(in.Description) {
		return transitSubnet{}, 0, errBadJSON("invalid description")
	}
	if in.VirsubnetID == "" {
		return transitSubnet{}, 0, errBadJSON("virsubnet_id is required")
	}
	if in.VirsubnetProjectID == "" || in.VirsubnetProjectID != t.ProjectID {
		return transitSubnet{}, 0, errBadJSON("virsubnet_project_id must match project_id")
	}
	tags, err := parsePrivateResourceTags(in.Tags)
	if err != nil {
		return transitSubnet{}, 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	subnet, err := s.vpc.GetSubnet(ctx, t, in.VirsubnetID)
	if isAPIError(err) {
		return transitSubnet{}, 0, errPrivateNotFound("Subnet", in.VirsubnetID)
	}
	if err != nil {
		return transitSubnet{}, 0, err
	}

	existingTS, err := s.transitSubnets(t).List(ctx, func(ts transitSubnet) bool {
		return ts.SubnetID == in.VirsubnetID
	})
	if err != nil {
		return transitSubnet{}, 0, err
	}
	if len(existingTS) > 0 {
		return transitSubnet{}, 0, errTransitSubnetUnavailable(in.VirsubnetID)
	}

	existingGW, err := s.privateGateways(t).List(ctx, func(g privateGateway) bool {
		return g.SubnetID == in.VirsubnetID
	})
	if err != nil {
		return transitSubnet{}, 0, err
	}
	if len(existingGW) > 0 {
		return transitSubnet{}, 0, errTransitSubnetUnavailable(in.VirsubnetID)
	}

	ipCount, err := s.countTransitIPsInSubnet(ctx, t, in.VirsubnetID)
	if err != nil {
		return transitSubnet{}, 0, err
	}

	now := s.nowUTC()
	ts := transitSubnet{
		ID:          s.ids.UUID(),
		Name:        in.Name,
		Description: in.Description,
		SubnetID:    in.VirsubnetID,
		VPCID:       subnet.VPCID,
		CIDR:        subnet.CIDR,
		Tags:        tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.transitSubnets(t).Create(ctx, ts.ID, ts); err != nil {
		return transitSubnet{}, 0, err
	}
	return ts, ipCount, nil
}

func (s *Service) countTransitIPsInSubnet(ctx context.Context, t Tenant, virsubnetID string) (int, error) {
	ips, err := s.transitIPs(t).List(ctx, func(ti transitIP) bool {
		return ti.SubnetID == virsubnetID
	})
	if err != nil {
		return 0, err
	}
	return len(ips), nil
}

func (s *Service) getTransitSubnet(ctx context.Context, t Tenant, id string) (transitSubnet, int, error) {
	ts, err := s.transitSubnets(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return transitSubnet{}, 0, errPrivateNotFound("TransitSubnet", id)
	}
	if err != nil {
		return transitSubnet{}, 0, err
	}
	ipCount, err := s.countTransitIPsInSubnet(ctx, t, ts.SubnetID)
	if err != nil {
		return transitSubnet{}, 0, err
	}
	return ts, ipCount, nil
}

func (s *Service) listTransitSubnets(ctx context.Context, t Tenant, f listTransitSubnetsFilter) ([]transitSubnet, map[string]int, pageInfo, error) {
	all, err := s.transitSubnets(t).List(ctx, func(ts transitSubnet) bool {
		return matchesPrivateFilter(f.IDs, ts.ID) &&
			matchesPrivateFilter(f.Names, ts.Name) &&
			matchesPrivateFilter(f.Descriptions, ts.Description) &&
			matchesPrivateFilter(f.VirsubnetProjectIDs, t.ProjectID) &&
			matchesPrivateFilter(f.VPCIDs, ts.VPCID) &&
			matchesPrivateFilter(f.VirsubnetIDs, ts.SubnetID) &&
			matchesPrivateFilter(f.Statuses, StatusActive)
	})
	if err != nil {
		return nil, nil, pageInfo{}, err
	}
	slices.SortFunc(all, func(a, b transitSubnet) int {
		return strings.Compare(a.ID, b.ID)
	})
	page, err := pagination.ByMarker(all, func(ts transitSubnet) string { return ts.ID }, f.Page)
	if err != nil {
		return nil, nil, pageInfo{}, errBadJSON("%s", err)
	}

	ips, err := s.transitIPs(t).List(ctx, nil)
	if err != nil {
		return nil, nil, pageInfo{}, err
	}
	counts := make(map[string]int, len(page))
	for _, ti := range ips {
		counts[ti.SubnetID]++
	}
	return page, counts, privatePageInfo(all, page, func(ts transitSubnet) string { return ts.ID }), nil
}

func (s *Service) updateTransitSubnet(ctx context.Context, t Tenant, id string, in updateTransitSubnetInput) (transitSubnet, int, error) {
	if in.Name != nil && !validName(*in.Name) {
		return transitSubnet{}, 0, errBadJSON("invalid name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return transitSubnet{}, 0, errBadJSON("invalid description")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	updated, err := s.transitSubnets(t).Update(ctx, id, func(ts *transitSubnet) error {
		if in.Name != nil {
			ts.Name = *in.Name
		}
		if in.Description != nil {
			ts.Description = *in.Description
		}
		ts.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return transitSubnet{}, 0, errPrivateNotFound("TransitSubnet", id)
	}
	if err != nil {
		return transitSubnet{}, 0, err
	}

	ipCount, err := s.countTransitIPsInSubnet(ctx, t, updated.SubnetID)
	if err != nil {
		return transitSubnet{}, 0, err
	}
	return updated, ipCount, nil
}

func (s *Service) deleteTransitSubnet(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.transitSubnets(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errPrivateNotFound("TransitSubnet", id)
	}
	if err != nil {
		return err
	}

	ipCount, err := s.countTransitIPsInSubnet(ctx, t, ts.SubnetID)
	if err != nil {
		return err
	}
	if ipCount > 0 {
		return errPrivateHasDependencies(id)
	}

	if err := s.transitSubnets(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
