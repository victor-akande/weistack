package elb

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

// poolOptional distinguishes absent, explicit null, and present values in JSON updates.
type poolOptional[T any] struct {
	Set   bool
	Value *T
}

func (o *poolOptional[T]) UnmarshalJSON(data []byte) error {
	o.Set = true
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		o.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}

type poolAzAffinityInput struct {
	Enable            *bool
	Percentage        *int
	Count             *int
	UnhealthyFallback *string
}

type createPoolInput struct {
	Name                           string
	Description                    string
	Protocol                       string
	LBAlgorithm                    string
	AdminStateUp                   *bool
	ListenerID                     string
	LoadBalancerID                 string
	VPCID                          string
	Type                           string
	IPVersion                      string
	SessionPersistence             *sessionPersistence
	SlowStart                      *slowStart
	ConnectionDrain                *connectionDrain
	PoolHealth                     *poolHealth
	AzAffinity                     *poolAzAffinityInput
	QuicCidHashStrategy            *quicCidHashStrategy
	MemberDeletionProtectionEnable *bool
	AnyPortEnable                  *bool
	ProtectionStatus               string
	ProtectionReason               string
	EnterpriseProjectID            *string
}

type updatePoolInput struct {
	Name                           *string
	Description                    *string
	LBAlgorithm                    *string
	AdminStateUp                   *bool
	VPCID                          *string
	Type                           *string
	SessionPersistence             poolOptional[sessionPersistence]
	SlowStart                      poolOptional[slowStart]
	ConnectionDrain                poolOptional[connectionDrain]
	PoolHealth                     poolOptional[poolHealth]
	AzAffinity                     poolOptional[poolAzAffinityInput]
	QuicCidHashStrategy            poolOptional[quicCidHashStrategy]
	MemberDeletionProtectionEnable *bool
	AnyPortEnable                  *bool
	ProtectionStatus               *string
	ProtectionReason               *string
}

type listPoolsFilter struct {
	IDs                            []string
	Names                          []string
	Descriptions                   []string
	AdminStateUp                   *bool
	HealthMonitorIDs               []string
	LoadBalancerIDs                []string
	ListenerIDs                    []string
	Protocols                      []string
	LBAlgorithms                   []string
	EnterpriseProjectIDs           []string
	IPVersions                     []string
	MemberAddresses                []string
	MemberDeviceIDs                []string
	MemberInstanceIDs              []string
	MemberDeletionProtectionEnable *bool
	VPCIDs                         []string
	Types                          []string
	ProtectionStatuses             []string
	ConnectionDrain                *bool
	PoolHealth                     []string
	AnyPortEnable                  *bool
	PublicBorderGroups             []string
	QuicCidLens                    []int
	QuicCidOffsets                 []int
	AzAffinities                   []string
	Page                           pagination.Marker
	PageReverse                    bool
}

type poolDetail struct {
	Pool        pool
	ListenerIDs []string
	MemberIDs   []string
}

func poolIsAPIError(err error) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr)
}

func poolValidProtocol(proto string) bool {
	switch proto {
	case "TCP", "UDP", "HTTP", "HTTPS", "QUIC", "GRPC", "TLS":
		return true
	default:
		return false
	}
}

func poolValidAlgorithm(proto, alg string) bool {
	switch alg {
	case "ROUND_ROBIN", "LEAST_CONNECTIONS", "SOURCE_IP":
		return true
	case "QUIC_CID":
		return proto == "QUIC"
	default:
		return false
	}
}

func poolValidType(typ string) bool {
	return typ == "" || typ == "instance" || typ == "ip"
}

func poolValidateIPVersion(v string) (string, error) {
	switch v {
	case "":
		return "v4", nil
	case "v4", "dualstack":
		return v, nil
	case "v6", "ipv6":
		return "", errNotImplemented("ipv6")
	default:
		return "", errInvalidInput("ip_version")
	}
}

func poolValidateSessionPersistence(proto string, sp *sessionPersistence) (*sessionPersistence, error) {
	if sp == nil {
		return nil, nil
	}
	switch sp.Type {
	case "SOURCE_IP", "HTTP_COOKIE", "APP_COOKIE":
	default:
		return nil, errInvalidInput("session_persistence.type")
	}

	out := &sessionPersistence{
		Type: sp.Type,
	}

	if sp.Type == "APP_COOKIE" {
		if sp.CookieName == nil || *sp.CookieName == "" || utf8.RuneCountInString(*sp.CookieName) > 1024 {
			return nil, errInvalidInput("session_persistence.cookie_name")
		}
		cn := *sp.CookieName
		out.CookieName = &cn
	} else if sp.CookieName != nil && *sp.CookieName != "" {
		return nil, errInvalidInput("session_persistence.cookie_name")
	}

	maxTimeout := 1440
	defaultTimeout := 1440
	if proto == "TCP" || proto == "UDP" {
		maxTimeout = 60
		defaultTimeout = 1
	}

	if sp.PersistenceTimeout != nil {
		t := *sp.PersistenceTimeout
		if t < 1 || t > maxTimeout {
			return nil, errInvalidInput("session_persistence.persistence_timeout")
		}
		out.PersistenceTimeout = &t
	} else if sp.Type != "APP_COOKIE" {
		t := defaultTimeout
		out.PersistenceTimeout = &t
	}

	return out, nil
}

func poolValidateSlowStart(proto string, ss *slowStart) error {
	if ss == nil {
		return nil
	}
	if ss.Enable && proto != "HTTP" && proto != "HTTPS" && proto != "GRPC" {
		return errInvalidInput("slow_start")
	}
	if ss.Duration < 30 || ss.Duration > 1200 {
		return errInvalidInput("slow_start.duration")
	}
	return nil
}

func poolValidateConnectionDrain(cd *connectionDrain) error {
	if cd == nil {
		return nil
	}
	if cd.Timeout != nil && (*cd.Timeout < 10 || *cd.Timeout > 4000) {
		return errInvalidInput("connection_drain.timeout")
	}
	return nil
}

func poolValidateHealth(ph *poolHealth) error {
	if ph == nil {
		return nil
	}
	if ph.MinimumHealthyMemberCount != nil {
		v := *ph.MinimumHealthyMemberCount
		if v != 0 && v != 1 {
			return errInvalidInput("pool_health.minimum_healthy_member_count")
		}
	}
	return nil
}

func poolValidateAzAffinity(in *poolAzAffinityInput) (*azAffinity, error) {
	if in == nil {
		return nil, nil
	}
	if in.Percentage != nil && (*in.Percentage < -1 || *in.Percentage > 100) {
		return nil, errInvalidInput("az_affinity.az_minimum_healthy_member_percentage")
	}
	if in.Count != nil && (*in.Count < -1 || *in.Count > 10000) {
		return nil, errInvalidInput("az_affinity.az_minimum_healthy_member_count")
	}
	fallback := ""
	if in.UnhealthyFallback != nil && *in.UnhealthyFallback != "" {
		switch *in.UnhealthyFallback {
		case "forward_to_all_member_of_local_az",
			"forward_to_healthy_member_of_remote_az",
			"forward_to_all_healthy_member",
			"forward_to_all_member":
			fallback = *in.UnhealthyFallback
		default:
			return nil, errInvalidInput("az_affinity.az_unhealthy_fallback_strategy")
		}
	}
	out := &azAffinity{
		Enable:            in.Enable != nil && *in.Enable,
		UnhealthyFallback: fallback,
	}
	if in.Percentage != nil {
		out.AzMinimumHealthy = *in.Percentage
	}
	return out, nil
}

func poolValidateQuicCidHashStrategy(q *quicCidHashStrategy) error {
	if q == nil {
		return nil
	}
	if q.Len < 1 || q.Len > 20 {
		return errInvalidInput("quic_cid_hash_strategy.len")
	}
	if q.Offset < 0 || q.Offset > 19 {
		return errInvalidInput("quic_cid_hash_strategy.offset")
	}
	return nil
}

func poolValidateProtection(status, reason string) error {
	switch status {
	case "", "nonProtection", "consoleProtection":
	default:
		return errInvalidInput("protection_status")
	}
	if utf8.RuneCountInString(reason) > 255 || strings.ContainsAny(reason, "<>") {
		return errInvalidInput("protection_reason")
	}
	return nil
}

func poolPolicyUsesPool(pol l7Policy, poolID string) bool {
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

// poolPaginate applies forward or reverse marker/limit pagination to a slice sorted by ascending ID.
func poolPaginate[T any](all []T, idOf func(T) string, page pagination.Marker, reverse bool) ([]T, pageInfo, error) {
	if !reverse {
		return paginateSlice(all, idOf, page)
	}
	end := len(all)
	if page.ID != "" {
		found := false
		for i, item := range all {
			if idOf(item) == page.ID {
				end = i
				found = true
				break
			}
		}
		if !found {
			return nil, pageInfo{}, errInvalidInput("marker")
		}
	}
	start := 0
	hasMore := false
	if page.Limit > 0 && end > page.Limit {
		start = end - page.Limit
		hasMore = true
	}
	out := make([]T, end-start)
	copy(out, all[start:end])
	return out, makePageInfo(out, idOf, hasMore), nil
}

func (s *Service) createPool(ctx context.Context, t Tenant, in createPoolInput) (poolDetail, error) {
	if !validName(in.Name) {
		return poolDetail{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return poolDetail{}, errInvalidInput("description")
	}
	if !poolValidProtocol(in.Protocol) {
		return poolDetail{}, errInvalidInput("protocol")
	}
	if !poolValidAlgorithm(in.Protocol, in.LBAlgorithm) {
		return poolDetail{}, errInvalidInput("lb_algorithm")
	}
	if !poolValidType(in.Type) {
		return poolDetail{}, errInvalidInput("type")
	}
	ipVersion, err := poolValidateIPVersion(in.IPVersion)
	if err != nil {
		return poolDetail{}, err
	}

	ep := defaultEnterpriseProjectID
	if in.EnterpriseProjectID != nil {
		if !validEnterpriseProjectID(*in.EnterpriseProjectID) {
			return poolDetail{}, errInvalidInput("enterprise_project_id")
		}
		ep = *in.EnterpriseProjectID
	}

	sp, err := poolValidateSessionPersistence(in.Protocol, in.SessionPersistence)
	if err != nil {
		return poolDetail{}, err
	}
	if err := poolValidateSlowStart(in.Protocol, in.SlowStart); err != nil {
		return poolDetail{}, err
	}
	if err := poolValidateConnectionDrain(in.ConnectionDrain); err != nil {
		return poolDetail{}, err
	}
	if err := poolValidateHealth(in.PoolHealth); err != nil {
		return poolDetail{}, err
	}
	azAff, err := poolValidateAzAffinity(in.AzAffinity)
	if err != nil {
		return poolDetail{}, err
	}
	if err := poolValidateQuicCidHashStrategy(in.QuicCidHashStrategy); err != nil {
		return poolDetail{}, err
	}
	if err := poolValidateProtection(in.ProtectionStatus, in.ProtectionReason); err != nil {
		return poolDetail{}, err
	}
	anyPort := in.AnyPortEnable != nil && *in.AnyPortEnable
	if anyPort && in.Protocol != "TCP" && in.Protocol != "UDP" && in.Protocol != "QUIC" {
		return poolDetail{}, errInvalidInput("any_port_enable")
	}

	// Placement requires at least one of listener_id, loadbalancer_id, or type.
	if in.ListenerID == "" && in.LoadBalancerID == "" {
		if in.Type == "" {
			return poolDetail{}, errInvalidInput("loadbalancer_id")
		}
		if in.Type == "instance" && in.VPCID == "" {
			return poolDetail{}, errInvalidInput("vpc_id")
		}
	}

	adminUp := true
	if in.AdminStateUp != nil {
		adminUp = *in.AdminStateUp
	}
	protStatus := in.ProtectionStatus
	if protStatus == "" {
		protStatus = "nonProtection"
	}
	ph := in.PoolHealth
	if ph == nil {
		ph = &poolHealth{MinimumHealthyMemberCount: intPtr(0)}
	}
	if ph.MinimumHealthyMemberCount == nil {
		ph = &poolHealth{MinimumHealthyMemberCount: intPtr(0)}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existingPools, err := s.pools(t).List(ctx, nil)
	if err != nil {
		return poolDetail{}, err
	}
	if !s.quotas.Allows(quota.ELBPool, len(existingPools), 1) {
		return poolDetail{}, errResourceQuotaExceeded("pool")
	}

	var (
		lbID         string
		lbVPCID      string
		boundLsn     *listener
		listenerRefs []string
	)

	if in.ListenerID != "" {
		lsn, err := s.listeners(t).Get(ctx, in.ListenerID)
		if errors.Is(err, store.ErrNotFound) {
			return poolDetail{}, errNotFound("listener", in.ListenerID)
		}
		if err != nil {
			return poolDetail{}, err
		}
		if lsn.DefaultPoolID != "" {
			return poolDetail{}, errConflict("The listener already has a default pool.")
		}
		if !listenerPoolProtocolAllowed(lsn.Protocol, in.Protocol) {
			return poolDetail{}, errInvalidInput("protocol")
		}
		if in.LoadBalancerID != "" && in.LoadBalancerID != lsn.LoadBalancerID {
			return poolDetail{}, errInvalidInput("loadbalancer_id")
		}
		lb, err := s.loadBalancers(t).Get(ctx, lsn.LoadBalancerID)
		if errors.Is(err, store.ErrNotFound) {
			return poolDetail{}, errNotFound("loadbalancer", lsn.LoadBalancerID)
		}
		if err != nil {
			return poolDetail{}, err
		}
		lbID = lb.ID
		lbVPCID = lb.VPCID
		boundLsn = &lsn
		listenerRefs = []string{lsn.ID}
	} else if in.LoadBalancerID != "" {
		lb, err := s.loadBalancers(t).Get(ctx, in.LoadBalancerID)
		if errors.Is(err, store.ErrNotFound) {
			return poolDetail{}, errNotFound("loadbalancer", in.LoadBalancerID)
		}
		if err != nil {
			return poolDetail{}, err
		}
		lbID = lb.ID
		lbVPCID = lb.VPCID
	}

	vpcID := in.VPCID
	if vpcID != "" {
		if _, err := s.vpc.GetVPC(ctx, t, vpcID); poolIsAPIError(err) {
			return poolDetail{}, errNotFound("vpc", vpcID)
		} else if err != nil {
			return poolDetail{}, err
		}
		if lbVPCID != "" && vpcID != lbVPCID {
			return poolDetail{}, errInvalidInput("vpc_id")
		}
	} else if lbVPCID != "" {
		vpcID = lbVPCID
	}

	now := s.nowUTC()
	p := pool{
		ID:                             s.ids.UUID(),
		Name:                           in.Name,
		Description:                    in.Description,
		Protocol:                       in.Protocol,
		LBAlgorithm:                    in.LBAlgorithm,
		AdminStateUp:                   adminUp,
		LoadBalancerID:                 lbID,
		VPCID:                          vpcID,
		Type:                           in.Type,
		IPVersion:                      ipVersion,
		SessionPersistence:             sp,
		SlowStart:                      in.SlowStart,
		ConnectionDrain:                in.ConnectionDrain,
		PoolHealth:                     ph,
		AzAffinity:                     azAff,
		QuicCidHashStrategy:            in.QuicCidHashStrategy,
		MemberDeletionProtectionEnable: in.MemberDeletionProtectionEnable != nil && *in.MemberDeletionProtectionEnable,
		AnyPortEnable:                  anyPort,
		ProtectionStatus:               protStatus,
		ProtectionReason:               in.ProtectionReason,
		EnterpriseProjectID:            ep,
		CreatedAt:                      now,
		UpdatedAt:                      now,
	}

	if err := s.pools(t).Create(ctx, p.ID, p); err != nil {
		return poolDetail{}, err
	}

	if boundLsn != nil {
		_, err := s.listeners(t).Update(ctx, boundLsn.ID, func(l *listener) error {
			l.DefaultPoolID = p.ID
			l.UpdatedAt = now
			return nil
		})
		if err != nil {
			_ = s.pools(t).Delete(ctx, p.ID)
			return poolDetail{}, err
		}
	}

	return poolDetail{
		Pool:        p,
		ListenerIDs: listenerRefs,
	}, nil
}

func (s *Service) buildPoolDetail(ctx context.Context, t Tenant, p pool) (poolDetail, error) {
	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return poolDetail{}, err
	}
	policies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return poolDetail{}, err
	}
	members, err := s.members(t).List(ctx, func(m member) bool { return m.PoolID == p.ID })
	if err != nil {
		return poolDetail{}, err
	}

	lsnIDs := collectPoolListenerIDs(p.ID, listeners, policies)

	memIDs := make([]string, 0, len(members))
	for _, m := range members {
		memIDs = append(memIDs, m.ID)
	}
	sort.Strings(memIDs)

	return poolDetail{
		Pool:        p,
		ListenerIDs: lsnIDs,
		MemberIDs:   memIDs,
	}, nil
}

func (s *Service) getPool(ctx context.Context, t Tenant, id string) (poolDetail, error) {
	p, err := s.pools(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return poolDetail{}, errNotFound("pool", id)
	}
	if err != nil {
		return poolDetail{}, err
	}
	return s.buildPoolDetail(ctx, t, p)
}

func (s *Service) listPools(ctx context.Context, t Tenant, f listPoolsFilter) ([]poolDetail, pageInfo, error) {
	allPools, err := s.pools(t).List(ctx, nil)
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
	allMembers, err := s.members(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}

	lsnByPool := make(map[string][]string)
	addLsn := func(poolID, lsnID string) {
		if poolID == "" || lsnID == "" {
			return
		}
		if !slices.Contains(lsnByPool[poolID], lsnID) {
			lsnByPool[poolID] = append(lsnByPool[poolID], lsnID)
		}
	}
	for _, l := range allListeners {
		addLsn(l.DefaultPoolID, l.ID)
	}
	for _, pol := range allPolicies {
		if pol.RedirectPoolID != "" {
			addLsn(pol.RedirectPoolID, pol.ListenerID)
		}
		for _, cfg := range pol.RedirectPoolsConfig {
			addLsn(cfg.PoolID, pol.ListenerID)
		}
	}

	memByPool := make(map[string][]member)
	for _, m := range allMembers {
		memByPool[m.PoolID] = append(memByPool[m.PoolID], m)
	}

	filtered := make([]poolDetail, 0, len(allPools))
	for _, p := range allPools {
		if !matchesAny(f.IDs, p.ID) {
			continue
		}
		if !matchesAny(f.Names, p.Name) {
			continue
		}
		if !matchesAny(f.Descriptions, p.Description) {
			continue
		}
		if f.AdminStateUp != nil && p.AdminStateUp != *f.AdminStateUp {
			continue
		}
		if !matchesAny(f.HealthMonitorIDs, p.HealthMonitorID) {
			continue
		}
		if !matchesAny(f.LoadBalancerIDs, p.LoadBalancerID) {
			continue
		}
		if !matchesAny(f.Protocols, p.Protocol) {
			continue
		}
		if !matchesAny(f.LBAlgorithms, p.LBAlgorithm) {
			continue
		}
		if !inEPList(f.EnterpriseProjectIDs, p.EnterpriseProjectID) {
			continue
		}
		if !matchesAny(f.IPVersions, p.IPVersion) {
			continue
		}
		if f.MemberDeletionProtectionEnable != nil && p.MemberDeletionProtectionEnable != *f.MemberDeletionProtectionEnable {
			continue
		}
		if !matchesAny(f.VPCIDs, p.VPCID) {
			continue
		}
		if !matchesAny(f.Types, p.Type) {
			continue
		}
		if !matchesAny(f.ProtectionStatuses, p.ProtectionStatus) {
			continue
		}
		if f.ConnectionDrain != nil {
			enabled := p.ConnectionDrain != nil && p.ConnectionDrain.Enable != nil && *p.ConnectionDrain.Enable
			if enabled != *f.ConnectionDrain {
				continue
			}
		}
		if len(f.PoolHealth) > 0 {
			cnt := 0
			if p.PoolHealth != nil && p.PoolHealth.MinimumHealthyMemberCount != nil {
				cnt = *p.PoolHealth.MinimumHealthyMemberCount
			}
			wantStr := "minimum_healthy_member_count=" + strconv.Itoa(cnt)
			if !slices.Contains(f.PoolHealth, wantStr) {
				continue
			}
		}
		if f.AnyPortEnable != nil && p.AnyPortEnable != *f.AnyPortEnable {
			continue
		}
		if !matchesAny(f.PublicBorderGroups, "center") {
			continue
		}
		if len(f.QuicCidLens) > 0 {
			if p.QuicCidHashStrategy == nil || !slices.Contains(f.QuicCidLens, p.QuicCidHashStrategy.Len) {
				continue
			}
		}
		if len(f.QuicCidOffsets) > 0 {
			if p.QuicCidHashStrategy == nil || !slices.Contains(f.QuicCidOffsets, p.QuicCidHashStrategy.Offset) {
				continue
			}
		}
		if len(f.AzAffinities) > 0 {
			azEnabled := p.AzAffinity != nil && p.AzAffinity.Enable
			wantStr := "enable=" + strconv.FormatBool(azEnabled)
			if !slices.Contains(f.AzAffinities, wantStr) {
				continue
			}
		}

		lsnIDs := lsnByPool[p.ID]
		if len(f.ListenerIDs) > 0 {
			matched := false
			for _, want := range f.ListenerIDs {
				if slices.Contains(lsnIDs, want) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		mems := memByPool[p.ID]
		if len(f.MemberAddresses) > 0 {
			matched := false
			for _, m := range mems {
				if slices.Contains(f.MemberAddresses, m.Address) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if len(f.MemberInstanceIDs) > 0 {
			matched := false
			for _, m := range mems {
				if slices.Contains(f.MemberInstanceIDs, m.ID) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if len(f.MemberDeviceIDs) > 0 {
			// Member records do not carry ECS device IDs in this emulator.
			continue
		}

		memIDs := make([]string, 0, len(mems))
		for _, m := range mems {
			memIDs = append(memIDs, m.ID)
		}
		sort.Strings(memIDs)

		filtered = append(filtered, poolDetail{
			Pool:        p,
			ListenerIDs: lsnIDs,
			MemberIDs:   memIDs,
		})
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Pool.ID < filtered[j].Pool.ID })
	return poolPaginate(filtered, func(d poolDetail) string { return d.Pool.ID }, f.Page, f.PageReverse)
}

func (s *Service) updatePool(ctx context.Context, t Tenant, id string, in updatePoolInput) (poolDetail, error) {
	if in.Name != nil && !validName(*in.Name) {
		return poolDetail{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return poolDetail{}, errInvalidInput("description")
	}
	if in.Type != nil && !poolValidType(*in.Type) {
		return poolDetail{}, errInvalidInput("type")
	}
	if in.ProtectionStatus != nil || in.ProtectionReason != nil {
		status := ""
		if in.ProtectionStatus != nil {
			status = *in.ProtectionStatus
		}
		reason := ""
		if in.ProtectionReason != nil {
			reason = *in.ProtectionReason
		}
		if err := poolValidateProtection(status, reason); err != nil {
			return poolDetail{}, err
		}
	}
	if in.ConnectionDrain.Set {
		if err := poolValidateConnectionDrain(in.ConnectionDrain.Value); err != nil {
			return poolDetail{}, err
		}
	}
	if in.PoolHealth.Set {
		if err := poolValidateHealth(in.PoolHealth.Value); err != nil {
			return poolDetail{}, err
		}
	}
	var nextAzAff *azAffinity
	if in.AzAffinity.Set {
		var err error
		nextAzAff, err = poolValidateAzAffinity(in.AzAffinity.Value)
		if err != nil {
			return poolDetail{}, err
		}
	}
	if in.QuicCidHashStrategy.Set {
		if err := poolValidateQuicCidHashStrategy(in.QuicCidHashStrategy.Value); err != nil {
			return poolDetail{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return poolDetail{}, errNotFound("pool", id)
	}
	if err != nil {
		return poolDetail{}, err
	}

	if in.LBAlgorithm != nil {
		if !poolValidAlgorithm(p.Protocol, *in.LBAlgorithm) {
			return poolDetail{}, errInvalidInput("lb_algorithm")
		}
		p.LBAlgorithm = *in.LBAlgorithm
	}

	if in.SessionPersistence.Set {
		if in.SessionPersistence.Value == nil {
			p.SessionPersistence = nil
		} else {
			cand := *in.SessionPersistence.Value
			if cand.Type == "" && p.SessionPersistence != nil {
				cand.Type = p.SessionPersistence.Type
			}
			validated, err := poolValidateSessionPersistence(p.Protocol, &cand)
			if err != nil {
				return poolDetail{}, err
			}
			p.SessionPersistence = validated
		}
	}

	if in.SlowStart.Set {
		if in.SlowStart.Value == nil {
			p.SlowStart = nil
		} else {
			cand := *in.SlowStart.Value
			if cand.Duration == 0 {
				if p.SlowStart != nil && p.SlowStart.Duration != 0 {
					cand.Duration = p.SlowStart.Duration
				} else {
					cand.Duration = 30
				}
			}
			if err := poolValidateSlowStart(p.Protocol, &cand); err != nil {
				return poolDetail{}, err
			}
			p.SlowStart = &cand
		}
	}

	if in.AnyPortEnable != nil {
		if *in.AnyPortEnable && p.Protocol != "TCP" && p.Protocol != "UDP" && p.Protocol != "QUIC" {
			return poolDetail{}, errInvalidInput("any_port_enable")
		}
		p.AnyPortEnable = *in.AnyPortEnable
	}

	if in.VPCID != nil && *in.VPCID != p.VPCID {
		if p.VPCID != "" {
			return poolDetail{}, errInvalidInput("vpc_id")
		}
		if *in.VPCID != "" {
			if _, err := s.vpc.GetVPC(ctx, t, *in.VPCID); poolIsAPIError(err) {
				return poolDetail{}, errNotFound("vpc", *in.VPCID)
			} else if err != nil {
				return poolDetail{}, err
			}
		}
		p.VPCID = *in.VPCID
	}

	if in.Type != nil && *in.Type != p.Type {
		if p.Type != "" {
			return poolDetail{}, errInvalidInput("type")
		}
		if *in.Type == "instance" && p.VPCID == "" {
			return poolDetail{}, errInvalidInput("vpc_id")
		}
		p.Type = *in.Type
	}

	if in.Name != nil {
		p.Name = *in.Name
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	if in.AdminStateUp != nil {
		p.AdminStateUp = *in.AdminStateUp
	}
	if in.MemberDeletionProtectionEnable != nil {
		p.MemberDeletionProtectionEnable = *in.MemberDeletionProtectionEnable
	}
	if in.ProtectionStatus != nil {
		p.ProtectionStatus = *in.ProtectionStatus
	}
	if in.ProtectionReason != nil {
		p.ProtectionReason = *in.ProtectionReason
	}
	if in.ConnectionDrain.Set {
		p.ConnectionDrain = in.ConnectionDrain.Value
	}
	if in.PoolHealth.Set {
		p.PoolHealth = in.PoolHealth.Value
	}
	if in.AzAffinity.Set {
		p.AzAffinity = nextAzAff
	}
	if in.QuicCidHashStrategy.Set {
		p.QuicCidHashStrategy = in.QuicCidHashStrategy.Value
	}

	p.UpdatedAt = s.nowUTC()
	if err := s.pools(t).Put(ctx, p.ID, p); err != nil {
		return poolDetail{}, err
	}
	return s.buildPoolDetail(ctx, t, p)
}

func (s *Service) deletePool(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("pool", id)
	}
	if err != nil {
		return err
	}

	if p.HealthMonitorID != "" {
		return errConflict("The pool has a health monitor.")
	}
	hms, err := s.healthMonitors(t).List(ctx, func(hm healthMonitor) bool { return hm.PoolID == id })
	if err != nil {
		return err
	}
	if len(hms) > 0 {
		return errConflict("The pool has a health monitor.")
	}

	mems, err := s.members(t).List(ctx, func(m member) bool { return m.PoolID == id })
	if err != nil {
		return err
	}
	if len(mems) > 0 {
		return errConflict("The pool has members.")
	}

	listeners, err := s.listeners(t).List(ctx, func(l listener) bool { return l.DefaultPoolID == id })
	if err != nil {
		return err
	}
	if len(listeners) > 0 {
		return errConflict("The pool is associated with a listener.")
	}

	policies, err := s.l7Policies(t).List(ctx, func(pol l7Policy) bool { return poolPolicyUsesPool(pol, id) })
	if err != nil {
		return err
	}
	if len(policies) > 0 {
		return errConflict("The pool is associated with an L7 policy.")
	}

	if err := s.pools(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (s *Service) deletePoolCascade(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.pools(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("pool", id)
	}
	if err != nil {
		return err
	}

	mems, err := s.members(t).List(ctx, func(m member) bool { return m.PoolID == id })
	if err != nil {
		return err
	}
	if p.MemberDeletionProtectionEnable && len(mems) > 0 {
		return errConflict("Member deletion protection is enabled on the pool.")
	}

	for _, m := range mems {
		if err := s.members(t).Delete(ctx, m.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	if p.HealthMonitorID != "" {
		if err := s.healthMonitors(t).Delete(ctx, p.HealthMonitorID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	hms, err := s.healthMonitors(t).List(ctx, func(hm healthMonitor) bool { return hm.PoolID == id })
	if err != nil {
		return err
	}
	for _, hm := range hms {
		if err := s.healthMonitors(t).Delete(ctx, hm.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	now := s.nowUTC()
	listeners, err := s.listeners(t).List(ctx, func(l listener) bool { return l.DefaultPoolID == id })
	if err != nil {
		return err
	}
	for _, l := range listeners {
		_, err := s.listeners(t).Update(ctx, l.ID, func(cur *listener) error {
			cur.DefaultPoolID = ""
			cur.UpdatedAt = now
			return nil
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	policies, err := s.l7Policies(t).List(ctx, func(pol l7Policy) bool { return poolPolicyUsesPool(pol, id) })
	if err != nil {
		return err
	}
	for _, pol := range policies {
		_, err := s.l7Policies(t).Update(ctx, pol.ID, func(cur *l7Policy) error {
			if cur.RedirectPoolID == id {
				cur.RedirectPoolID = ""
			}
			if len(cur.RedirectPoolsConfig) > 0 {
				kept := cur.RedirectPoolsConfig[:0]
				for _, cfg := range cur.RedirectPoolsConfig {
					if cfg.PoolID != id {
						kept = append(kept, cfg)
					}
				}
				cur.RedirectPoolsConfig = kept
			}
			cur.UpdatedAt = now
			return nil
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	if err := s.pools(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
