package elb

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
)

const (
	memberTypeInstance = "instance"
	memberTypeIP       = "ip"
	memberIPVersionV4  = "v4"
)

var ipMemberAllowedProtocols = map[string]bool{
	"TCP":   true,
	"UDP":   true,
	"HTTP":  true,
	"HTTPS": true,
	"GRPC":  true,
	"QUIC":  true,
	"TLS":   true,
}

const ipMemberProtocolsList = "TCP, UDP, HTTP, HTTPS, GRPC, QUIC, TLS"

type createMemberInput struct {
	Address          string
	Name             string
	ProtocolPort     *int
	SubnetCIDRID     string
	Weight           *int
	AdminStateUp     *bool
	AvailabilityZone string
}

type updateMemberInput struct {
	Name             *string
	Weight           *int
	AdminStateUp     *bool
	ProtocolPort     *int
	AvailabilityZone *string
}

type listMembersFilter struct {
	IDs                  []string
	Names                []string
	Weights              []int
	AdminStateUp         *bool
	SubnetCIDRIDs        []string
	Addresses            []string
	ProtocolPorts        []int
	OperatingStatuses    []string
	EnterpriseProjectIDs []string
	IPVersions           []string
	MemberTypes          []string
	InstanceIDs          []string
	AvailabilityZones    []string
}

type listAllMembersFilter struct {
	IDs                  []string
	Names                []string
	Weights              []int
	AdminStateUp         *bool
	SubnetCIDRIDs        []string
	Addresses            []string
	ProtocolPorts        []int
	OperatingStatuses    []string
	EnterpriseProjectIDs []string
	IPVersions           []string
	PoolIDs              []string
	LoadBalancerIDs      []string
}

// memberView holds a member together with its dynamically computed health
// status and per-listener statuses.
type memberView struct {
	Member          member
	Pool            pool
	OperatingStatus string
	Statuses        []memberStatusWire
}

// memberOperatingStatus computes a member's operating_status on read (§3.5).
// It is never stored on the member record.
func (s *Service) memberOperatingStatus(ctx context.Context, t Tenant, m member, p pool, hm *healthMonitor, vpcID string) (string, error) {
	if !m.AdminStateUp || !p.AdminStateUp || (hm != nil && !hm.AdminStateUp) {
		return StatusOffline, nil
	}
	if hm == nil {
		return StatusNoMonitor, nil
	}
	subnetID := ""
	if m.MemberType == memberTypeInstance {
		subnetID = m.SubnetID
	}
	status, ok, err := s.servers.ServerAt(ctx, t, vpcID, subnetID, m.Address)
	if err != nil {
		return "", err
	}
	if ok && status == StatusActive {
		return StatusOnline, nil
	}
	return StatusOffline, nil
}

func (s *Service) poolVPCAndLB(ctx context.Context, t Tenant, p pool) (string, *loadBalancer, error) {
	if p.LoadBalancerID == "" {
		return p.VPCID, nil, nil
	}
	lb, err := s.loadBalancers(t).Get(ctx, p.LoadBalancerID)
	if errors.Is(err, store.ErrNotFound) {
		return p.VPCID, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	vpcID := lb.VPCID
	if vpcID == "" {
		vpcID = p.VPCID
	}
	return vpcID, &lb, nil
}

func (s *Service) poolHealthMonitor(ctx context.Context, t Tenant, p pool) (*healthMonitor, error) {
	if p.HealthMonitorID == "" {
		return nil, nil
	}
	hm, err := s.healthMonitors(t).Get(ctx, p.HealthMonitorID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &hm, nil
}

func (s *Service) poolListenerIDs(ctx context.Context, t Tenant, poolID string) ([]string, error) {
	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	policies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	return collectPoolListenerIDs(poolID, listeners, policies), nil
}

func collectPoolListenerIDs(poolID string, listeners []listener, policies []l7Policy) []string {
	seen := make(map[string]struct{})
	for _, l := range listeners {
		if l.DefaultPoolID == poolID {
			seen[l.ID] = struct{}{}
		}
	}
	for _, pol := range policies {
		if policyUsesPool(pol, poolID) && pol.ListenerID != "" {
			seen[pol.ListenerID] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func policyUsesPool(pol l7Policy, poolID string) bool {
	if pol.RedirectPoolID == poolID {
		return true
	}
	for _, cfg := range pol.RedirectPoolsConfig {
		if cfg.PoolID == poolID {
			return true
		}
	}
	return false
}

func buildMemberStatuses(listenerIDs []string, opStatus string) []memberStatusWire {
	if len(listenerIDs) == 0 {
		return []memberStatusWire{}
	}
	out := make([]memberStatusWire, len(listenerIDs))
	for i, id := range listenerIDs {
		out[i] = memberStatusWire{
			ListenerID:      id,
			OperatingStatus: opStatus,
		}
	}
	return out
}

func poolEnterpriseProjectID(p pool, lb *loadBalancer) string {
	if p.EnterpriseProjectID != "" {
		return p.EnterpriseProjectID
	}
	if lb != nil && lb.EnterpriseProjectID != "" {
		return lb.EnterpriseProjectID
	}
	return defaultEnterpriseProjectID
}

func (s *Service) buildMemberView(ctx context.Context, t Tenant, m member, p pool) (memberView, error) {
	vpcID, _, err := s.poolVPCAndLB(ctx, t, p)
	if err != nil {
		return memberView{}, err
	}
	hm, err := s.poolHealthMonitor(ctx, t, p)
	if err != nil {
		return memberView{}, err
	}
	opStatus, err := s.memberOperatingStatus(ctx, t, m, p, hm, vpcID)
	if err != nil {
		return memberView{}, err
	}
	listenerIDs, err := s.poolListenerIDs(ctx, t, p.ID)
	if err != nil {
		return memberView{}, err
	}
	return memberView{
		Member:          m,
		Pool:            p,
		OperatingStatus: opStatus,
		Statuses:        buildMemberStatuses(listenerIDs, opStatus),
	}, nil
}

// createMember adds a backend server member to poolID (§3.4).
func (s *Service) createMember(ctx context.Context, t Tenant, poolID string, in createMemberInput) (memberView, error) {
	if !validName(in.Name) {
		return memberView{}, errInvalidInput("name")
	}
	addr, err := netip.ParseAddr(in.Address)
	if err != nil || !addr.Is4() {
		return memberView{}, errInvalidInput("address")
	}
	weight := 1
	if in.Weight != nil {
		if *in.Weight < 0 || *in.Weight > 100 {
			return memberView{}, errInvalidInput("weight")
		}
		weight = *in.Weight
	}
	adminUp := true
	if in.AdminStateUp != nil {
		adminUp = *in.AdminStateUp
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return memberView{}, errNotFound("pool", poolID)
	}
	if err != nil {
		return memberView{}, err
	}

	port := 0
	if p.AnyPortEnable {
		if in.ProtocolPort != nil {
			if *in.ProtocolPort < 0 || *in.ProtocolPort > 65535 {
				return memberView{}, errInvalidInput("protocol_port")
			}
			port = *in.ProtocolPort
		}
	} else {
		if in.ProtocolPort == nil || *in.ProtocolPort < 1 || *in.ProtocolPort > 65535 {
			return memberView{}, errInvalidInput("protocol_port")
		}
		port = *in.ProtocolPort
	}

	vpcID, lb, err := s.poolVPCAndLB(ctx, t, p)
	if err != nil {
		return memberView{}, err
	}

	var (
		mType        string
		subnetCIDRID string
		subnetID     string
	)
	if in.SubnetCIDRID != "" {
		if in.AvailabilityZone != "" {
			return memberView{}, errInvalidInput("availability_zone")
		}
		sn, found, err := s.findSubnetByNeutronID(ctx, t, in.SubnetCIDRID)
		if err != nil {
			return memberView{}, err
		}
		if !found {
			return memberView{}, errNotFound("subnet", in.SubnetCIDRID)
		}
		if vpcID != "" && sn.VPCID != vpcID {
			return memberView{}, errInvalidInput("subnet_cidr_id")
		}
		prefix, err := netip.ParsePrefix(sn.CIDR)
		if err != nil || !prefix.Contains(addr) {
			return memberView{}, errInvalidInput("address")
		}
		mType = memberTypeInstance
		subnetCIDRID = sn.NeutronSubnetID
		subnetID = sn.ID
	} else {
		if !ipMemberAllowedProtocols[p.Protocol] {
			return memberView{}, errIPMemberProtocol(ipMemberProtocolsList)
		}
		if lb != nil && !lb.IPTargetEnable {
			return memberView{}, errIPTargetDisabled()
		}
		if in.AvailabilityZone != "" && !zones.Exists(t.Region, in.AvailabilityZone) {
			return memberView{}, errInvalidInput("availability_zone")
		}
		mType = memberTypeIP
	}

	canonicalAddr := addr.String()
	existing, err := s.members(t).List(ctx, func(m member) bool {
		return m.PoolID == poolID
	})
	if err != nil {
		return memberView{}, err
	}
	for _, m := range existing {
		if m.Address == canonicalAddr && m.ProtocolPort == port {
			return memberView{}, errConflict("A member with the same address and protocol_port already exists in the pool.")
		}
	}

	now := s.nowUTC()
	rec := member{
		ID:               s.ids.UUID(),
		PoolID:           poolID,
		Name:             in.Name,
		Address:          canonicalAddr,
		ProtocolPort:     port,
		SubnetCIDRID:     subnetCIDRID,
		SubnetID:         subnetID,
		MemberType:       mType,
		Weight:           weight,
		AdminStateUp:     adminUp,
		AvailabilityZone: in.AvailabilityZone,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.members(t).Create(ctx, rec.ID, rec); err != nil {
		return memberView{}, err
	}
	return s.buildMemberView(ctx, t, rec, p)
}

// showMember returns a single member in poolID with computed health (§3.4, §3.5).
func (s *Service) showMember(ctx context.Context, t Tenant, poolID, memberID string) (memberView, error) {
	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return memberView{}, errNotFound("pool", poolID)
	}
	if err != nil {
		return memberView{}, err
	}
	m, err := s.members(t).Get(ctx, memberID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.PoolID != poolID) {
		return memberView{}, errNotFound("member", memberID)
	}
	if err != nil {
		return memberView{}, err
	}
	return s.buildMemberView(ctx, t, m, p)
}

// updateMember modifies mutable fields of a member in poolID (§3.4).
func (s *Service) updateMember(ctx context.Context, t Tenant, poolID, memberID string, in updateMemberInput) (memberView, error) {
	if in.Name != nil && !validName(*in.Name) {
		return memberView{}, errInvalidInput("name")
	}
	if in.Weight != nil && (*in.Weight < 0 || *in.Weight > 100) {
		return memberView{}, errInvalidInput("weight")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return memberView{}, errNotFound("pool", poolID)
	}
	if err != nil {
		return memberView{}, err
	}
	m, err := s.members(t).Get(ctx, memberID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.PoolID != poolID) {
		return memberView{}, errNotFound("member", memberID)
	}
	if err != nil {
		return memberView{}, err
	}

	if in.AvailabilityZone != nil {
		if m.MemberType != memberTypeIP {
			return memberView{}, errInvalidInput("availability_zone")
		}
		if *in.AvailabilityZone != "" && !zones.Exists(t.Region, *in.AvailabilityZone) {
			return memberView{}, errInvalidInput("availability_zone")
		}
	}

	if in.ProtocolPort != nil {
		if p.AnyPortEnable {
			return memberView{}, errInvalidInput("protocol_port")
		}
		if *in.ProtocolPort < 1 || *in.ProtocolPort > 65535 {
			return memberView{}, errInvalidInput("protocol_port")
		}
		if *in.ProtocolPort != m.ProtocolPort {
			peers, err := s.members(t).List(ctx, func(other member) bool {
				return other.PoolID == poolID && other.ID != memberID
			})
			if err != nil {
				return memberView{}, err
			}
			for _, other := range peers {
				if other.Address == m.Address && other.ProtocolPort == *in.ProtocolPort {
					return memberView{}, errConflict("A member with the same address and protocol_port already exists in the pool.")
				}
			}
		}
	}

	now := s.nowUTC()
	updated, err := s.members(t).Update(ctx, memberID, func(rec *member) error {
		if in.Name != nil {
			rec.Name = *in.Name
		}
		if in.Weight != nil {
			rec.Weight = *in.Weight
		}
		if in.AdminStateUp != nil {
			rec.AdminStateUp = *in.AdminStateUp
		}
		if in.ProtocolPort != nil {
			rec.ProtocolPort = *in.ProtocolPort
		}
		if in.AvailabilityZone != nil {
			rec.AvailabilityZone = *in.AvailabilityZone
		}
		rec.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return memberView{}, errNotFound("member", memberID)
	}
	if err != nil {
		return memberView{}, err
	}
	return s.buildMemberView(ctx, t, updated, p)
}

// deleteMember removes a member from poolID (§3.4).
func (s *Service) deleteMember(ctx context.Context, t Tenant, poolID, memberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.pools(t).Get(ctx, poolID); errors.Is(err, store.ErrNotFound) {
		return errNotFound("pool", poolID)
	} else if err != nil {
		return err
	}
	m, err := s.members(t).Get(ctx, memberID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.PoolID != poolID) {
		return errNotFound("member", memberID)
	}
	if err != nil {
		return err
	}
	if err := s.members(t).Delete(ctx, memberID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// listMembers lists members of poolID with filtering and marker pagination (§3.4).
func (s *Service) listMembers(ctx context.Context, t Tenant, poolID string, f listMembersFilter, page pagination.Marker) ([]memberView, pageInfo, error) {
	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, pageInfo{}, errNotFound("pool", poolID)
	}
	if err != nil {
		return nil, pageInfo{}, err
	}

	vpcID, lb, err := s.poolVPCAndLB(ctx, t, p)
	if err != nil {
		return nil, pageInfo{}, err
	}
	hm, err := s.poolHealthMonitor(ctx, t, p)
	if err != nil {
		return nil, pageInfo{}, err
	}
	listenerIDs, err := s.poolListenerIDs(ctx, t, p.ID)
	if err != nil {
		return nil, pageInfo{}, err
	}
	epID := poolEnterpriseProjectID(p, lb)

	all, err := s.members(t).List(ctx, func(m member) bool {
		return m.PoolID == poolID
	})
	if err != nil {
		return nil, pageInfo{}, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	filtered := make([]memberView, 0, len(all))
	for _, m := range all {
		if !matchesListMembersStatic(m, epID, f) {
			continue
		}
		opStatus, err := s.memberOperatingStatus(ctx, t, m, p, hm, vpcID)
		if err != nil {
			return nil, pageInfo{}, err
		}
		if !matchesAny(f.OperatingStatuses, opStatus) {
			continue
		}
		filtered = append(filtered, memberView{
			Member:          m,
			Pool:            p,
			OperatingStatus: opStatus,
			Statuses:        buildMemberStatuses(listenerIDs, opStatus),
		})
	}
	return paginateSlice(filtered, func(v memberView) string { return v.Member.ID }, page)
}

func matchesListMembersStatic(m member, epID string, f listMembersFilter) bool {
	if !matchesAny(f.IDs, m.ID) ||
		!matchesAny(f.Names, m.Name) ||
		!matchesAny(f.SubnetCIDRIDs, m.SubnetCIDRID) ||
		!matchesAny(f.Addresses, m.Address) ||
		!matchesAny(f.IPVersions, memberIPVersionV4) ||
		!matchesAny(f.MemberTypes, m.MemberType) ||
		!matchesAny(f.InstanceIDs, "") ||
		!matchesAny(f.AvailabilityZones, m.AvailabilityZone) ||
		!inEPList(f.EnterpriseProjectIDs, epID) {
		return false
	}
	if len(f.Weights) > 0 && !slices.Contains(f.Weights, m.Weight) {
		return false
	}
	if len(f.ProtocolPorts) > 0 && !slices.Contains(f.ProtocolPorts, m.ProtocolPort) {
		return false
	}
	if f.AdminStateUp != nil && m.AdminStateUp != *f.AdminStateUp {
		return false
	}
	return true
}

// listAllMembers lists members across all pools of tenant t (§3.4).
func (s *Service) listAllMembers(ctx context.Context, t Tenant, f listAllMembersFilter, page pagination.Marker) ([]memberView, pageInfo, error) {
	allMembers, err := s.members(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allPools, err := s.pools(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allLBs, err := s.loadBalancers(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allHMs, err := s.healthMonitors(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allListeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allPolicies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}

	poolByID := make(map[string]pool, len(allPools))
	for _, p := range allPools {
		poolByID[p.ID] = p
	}
	lbByID := make(map[string]loadBalancer, len(allLBs))
	for _, lb := range allLBs {
		lbByID[lb.ID] = lb
	}
	hmByID := make(map[string]healthMonitor, len(allHMs))
	for _, hm := range allHMs {
		hmByID[hm.ID] = hm
	}
	listenersByPool := make(map[string][]string, len(allPools))
	for _, p := range allPools {
		listenersByPool[p.ID] = collectPoolListenerIDs(p.ID, allListeners, allPolicies)
	}

	sort.Slice(allMembers, func(i, j int) bool { return allMembers[i].ID < allMembers[j].ID })

	filtered := make([]memberView, 0, len(allMembers))
	for _, m := range allMembers {
		p := poolByID[m.PoolID]
		var lb *loadBalancer
		vpcID := p.VPCID
		if p.LoadBalancerID != "" {
			if foundLB, ok := lbByID[p.LoadBalancerID]; ok {
				lb = &foundLB
				if foundLB.VPCID != "" {
					vpcID = foundLB.VPCID
				}
			}
		}
		epID := poolEnterpriseProjectID(p, lb)
		if !matchesListAllMembersStatic(m, p, epID, f) {
			continue
		}
		var hm *healthMonitor
		if p.HealthMonitorID != "" {
			if foundHM, ok := hmByID[p.HealthMonitorID]; ok {
				hm = &foundHM
			}
		}
		opStatus, err := s.memberOperatingStatus(ctx, t, m, p, hm, vpcID)
		if err != nil {
			return nil, pageInfo{}, err
		}
		if !matchesAny(f.OperatingStatuses, opStatus) {
			continue
		}
		filtered = append(filtered, memberView{
			Member:          m,
			Pool:            p,
			OperatingStatus: opStatus,
			Statuses:        buildMemberStatuses(listenersByPool[m.PoolID], opStatus),
		})
	}
	return paginateSlice(filtered, func(v memberView) string { return v.Member.ID }, page)
}

func matchesListAllMembersStatic(m member, p pool, epID string, f listAllMembersFilter) bool {
	if !matchesAny(f.IDs, m.ID) ||
		!matchesAny(f.Names, m.Name) ||
		!matchesAny(f.SubnetCIDRIDs, m.SubnetCIDRID) ||
		!matchesAny(f.Addresses, m.Address) ||
		!matchesAny(f.IPVersions, memberIPVersionV4) ||
		!matchesAny(f.PoolIDs, m.PoolID) ||
		!matchesAny(f.LoadBalancerIDs, p.LoadBalancerID) ||
		!inEPList(f.EnterpriseProjectIDs, epID) {
		return false
	}
	if len(f.Weights) > 0 && !slices.Contains(f.Weights, m.Weight) {
		return false
	}
	if len(f.ProtocolPorts) > 0 && !slices.Contains(f.ProtocolPorts, m.ProtocolPort) {
		return false
	}
	if f.AdminStateUp != nil && m.AdminStateUp != *f.AdminStateUp {
		return false
	}
	return true
}
