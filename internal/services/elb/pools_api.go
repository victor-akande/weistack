package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type createPoolSlowStartReq struct {
	Enable   *bool `json:"enable"`
	Duration *int  `json:"duration"`
}

func (r *createPoolSlowStartReq) toModel() *slowStart {
	if r == nil {
		return nil
	}
	dur := 30
	if r.Duration != nil {
		dur = *r.Duration
	}
	return &slowStart{
		Enable:   r.Enable != nil && *r.Enable,
		Duration: dur,
	}
}

type poolAzAffinityReq struct {
	Enable            *bool   `json:"enable"`
	Percentage        *int    `json:"az_minimum_healthy_member_percentage"`
	Count             *int    `json:"az_minimum_healthy_member_count"`
	UnhealthyFallback *string `json:"az_unhealthy_fallback_strategy"`
}

func (r *poolAzAffinityReq) toInput() *poolAzAffinityInput {
	if r == nil {
		return nil
	}
	return &poolAzAffinityInput{
		Enable:            r.Enable,
		Percentage:        r.Percentage,
		Count:             r.Count,
		UnhealthyFallback: r.UnhealthyFallback,
	}
}

type createPoolRequest struct {
	Pool *createPoolOptionReq `json:"pool"`
}

type createPoolOptionReq struct {
	AdminStateUp                   *bool                   `json:"admin_state_up"`
	AzAffinity                     *poolAzAffinityReq      `json:"az_affinity"`
	Description                    *string                 `json:"description"`
	LBAlgorithm                    string                  `json:"lb_algorithm"`
	ListenerID                     *string                 `json:"listener_id"`
	LoadBalancerID                 *string                 `json:"loadbalancer_id"`
	Name                           *string                 `json:"name"`
	ProjectID                      *string                 `json:"project_id"`
	Protocol                       string                  `json:"protocol"`
	SessionPersistence             *sessionPersistence     `json:"session_persistence"`
	SlowStart                      *createPoolSlowStartReq `json:"slow_start"`
	MemberDeletionProtectionEnable *bool                   `json:"member_deletion_protection_enable"`
	VPCID                          *string                 `json:"vpc_id"`
	Type                           *string                 `json:"type"`
	IPVersion                      *string                 `json:"ip_version"`
	ProtectionStatus               *string                 `json:"protection_status"`
	ProtectionReason               *string                 `json:"protection_reason"`
	AnyPortEnable                  *bool                   `json:"any_port_enable"`
	ConnectionDrain                *connectionDrain        `json:"connection_drain"`
	PoolHealth                     *poolHealth             `json:"pool_health"`
	PublicBorderGroup              *string                 `json:"public_border_group"`
	QuicCidHashStrategy            *quicCidHashStrategy    `json:"quic_cid_hash_strategy"`
	EnterpriseProjectID            *string                 `json:"enterprise_project_id"`
}

type updatePoolRequest struct {
	Pool *updatePoolOptionReq `json:"pool"`
}

type updatePoolOptionReq struct {
	AdminStateUp                   *bool                                `json:"admin_state_up"`
	Description                    *string                              `json:"description"`
	LBAlgorithm                    *string                              `json:"lb_algorithm"`
	Name                           *string                              `json:"name"`
	SessionPersistence             poolOptional[sessionPersistence]     `json:"session_persistence"`
	SlowStart                      poolOptional[createPoolSlowStartReq] `json:"slow_start"`
	MemberDeletionProtectionEnable *bool                                `json:"member_deletion_protection_enable"`
	VPCID                          *string                              `json:"vpc_id"`
	Type                           *string                              `json:"type"`
	ProtectionStatus               *string                              `json:"protection_status"`
	ProtectionReason               *string                              `json:"protection_reason"`
	AnyPortEnable                  *bool                                `json:"any_port_enable"`
	ConnectionDrain                poolOptional[connectionDrain]        `json:"connection_drain"`
	PoolHealth                     poolOptional[poolHealth]             `json:"pool_health"`
	QuicCidHashStrategy            poolOptional[quicCidHashStrategy]    `json:"quic_cid_hash_strategy"`
	AzAffinity                     poolOptional[poolAzAffinityReq]      `json:"az_affinity"`
}

type poolResponse struct {
	ID                             string               `json:"id"`
	Name                           string               `json:"name"`
	Description                    string               `json:"description"`
	Protocol                       string               `json:"protocol"`
	LBAlgorithm                    string               `json:"lb_algorithm"`
	AdminStateUp                   bool                 `json:"admin_state_up"`
	ProjectID                      string               `json:"project_id"`
	EnterpriseProjectID            string               `json:"enterprise_project_id"`
	HealthMonitorID                string               `json:"healthmonitor_id"`
	Listeners                      []idRef              `json:"listeners"`
	LoadBalancers                  []idRef              `json:"loadbalancers"`
	Members                        []idRef              `json:"members"`
	SessionPersistence             *sessionPersistence  `json:"session_persistence"`
	SlowStart                      *slowStart           `json:"slow_start"`
	IPVersion                      string               `json:"ip_version"`
	MemberDeletionProtectionEnable bool                 `json:"member_deletion_protection_enable"`
	VPCID                          string               `json:"vpc_id"`
	Type                           string               `json:"type"`
	ProtectionStatus               string               `json:"protection_status"`
	ProtectionReason               string               `json:"protection_reason"`
	AnyPortEnable                  bool                 `json:"any_port_enable"`
	ConnectionDrain                *connectionDrain     `json:"connection_drain"`
	PoolHealth                     *poolHealth          `json:"pool_health"`
	AzAffinity                     *azAffinity          `json:"az_affinity"`
	QuicCidHashStrategy            *quicCidHashStrategy `json:"quic_cid_hash_strategy"`
	PublicBorderGroup              string               `json:"public_border_group"`
	CreatedAt                      string               `json:"created_at"`
	UpdatedAt                      string               `json:"updated_at"`
}

type poolEnvelope struct {
	RequestID string       `json:"request_id"`
	Pool      poolResponse `json:"pool"`
}

type listPoolsResponse struct {
	RequestID string         `json:"request_id"`
	Pools     []poolResponse `json:"pools"`
	PageInfo  pageInfo       `json:"page_info"`
}

func poolDerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func poolNonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func toPoolResponse(t Tenant, d poolDetail) poolResponse {
	p := d.Pool
	listeners := make([]idRef, len(d.ListenerIDs))
	for i, id := range d.ListenerIDs {
		listeners[i] = idRef{ID: id}
	}
	lbs := make([]idRef, 0, 1)
	if p.LoadBalancerID != "" {
		lbs = append(lbs, idRef{ID: p.LoadBalancerID})
	}
	members := make([]idRef, len(d.MemberIDs))
	for i, id := range d.MemberIDs {
		members[i] = idRef{ID: id}
	}
	ipVer := p.IPVersion
	if ipVer == "" {
		ipVer = "v4"
	}
	protStatus := p.ProtectionStatus
	if protStatus == "" {
		protStatus = "nonProtection"
	}
	ep := p.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	return poolResponse{
		ID:                             p.ID,
		Name:                           p.Name,
		Description:                    p.Description,
		Protocol:                       p.Protocol,
		LBAlgorithm:                    p.LBAlgorithm,
		AdminStateUp:                   p.AdminStateUp,
		ProjectID:                      t.ProjectID,
		EnterpriseProjectID:            ep,
		HealthMonitorID:                p.HealthMonitorID,
		Listeners:                      listeners,
		LoadBalancers:                  lbs,
		Members:                        members,
		SessionPersistence:             p.SessionPersistence,
		SlowStart:                      p.SlowStart,
		IPVersion:                      ipVer,
		MemberDeletionProtectionEnable: p.MemberDeletionProtectionEnable,
		VPCID:                          p.VPCID,
		Type:                           p.Type,
		ProtectionStatus:               protStatus,
		ProtectionReason:               p.ProtectionReason,
		AnyPortEnable:                  p.AnyPortEnable,
		ConnectionDrain:                p.ConnectionDrain,
		PoolHealth:                     p.PoolHealth,
		AzAffinity:                     p.AzAffinity,
		QuicCidHashStrategy:            p.QuicCidHashStrategy,
		PublicBorderGroup:              "center",
		CreatedAt:                      formatTime(p.CreatedAt),
		UpdatedAt:                      formatTime(p.UpdatedAt),
	}
}

func (s *Service) handleCreatePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPoolRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Pool == nil {
		return errInvalidInput("pool")
	}
	opt := req.Pool
	detail, err := s.createPool(r.Context(), t, createPoolInput{
		Name:                           poolDerefString(opt.Name),
		Description:                    poolDerefString(opt.Description),
		Protocol:                       opt.Protocol,
		LBAlgorithm:                    opt.LBAlgorithm,
		AdminStateUp:                   opt.AdminStateUp,
		ListenerID:                     poolDerefString(opt.ListenerID),
		LoadBalancerID:                 poolDerefString(opt.LoadBalancerID),
		VPCID:                          poolDerefString(opt.VPCID),
		Type:                           poolDerefString(opt.Type),
		IPVersion:                      poolDerefString(opt.IPVersion),
		SessionPersistence:             opt.SessionPersistence,
		SlowStart:                      opt.SlowStart.toModel(),
		ConnectionDrain:                opt.ConnectionDrain,
		PoolHealth:                     opt.PoolHealth,
		AzAffinity:                     opt.AzAffinity.toInput(),
		QuicCidHashStrategy:            opt.QuicCidHashStrategy,
		MemberDeletionProtectionEnable: opt.MemberDeletionProtectionEnable,
		AnyPortEnable:                  opt.AnyPortEnable,
		ProtectionStatus:               poolDerefString(opt.ProtectionStatus),
		ProtectionReason:               poolDerefString(opt.ProtectionReason),
		EnterpriseProjectID:            opt.EnterpriseProjectID,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, poolEnvelope{
		RequestID: requestID(r),
		Pool:      toPoolResponse(t, detail),
	})
}

func (s *Service) handleListPools(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	pageReverse, err := parseBoolQuery(q, "page_reverse")
	if err != nil {
		return err
	}
	adminStateUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	memDelProt, err := parseBoolQuery(q, "member_deletion_protection_enable")
	if err != nil {
		return err
	}
	connDrain, err := parseBoolQuery(q, "connection_drain")
	if err != nil {
		return err
	}
	anyPort, err := parseBoolQuery(q, "any_port_enable")
	if err != nil {
		return err
	}
	quicLens, err := parseIntQueryValues(q, "quic_cid_len")
	if err != nil {
		return err
	}
	quicOffsets, err := parseIntQueryValues(q, "quic_cid_offset")
	if err != nil {
		return err
	}

	items, pi, err := s.listPools(r.Context(), t, listPoolsFilter{
		IDs:                            poolNonEmpty(q["id"]),
		Names:                          poolNonEmpty(q["name"]),
		Descriptions:                   poolNonEmpty(q["description"]),
		AdminStateUp:                   adminStateUp,
		HealthMonitorIDs:               poolNonEmpty(q["healthmonitor_id"]),
		LoadBalancerIDs:                poolNonEmpty(q["loadbalancer_id"]),
		ListenerIDs:                    poolNonEmpty(q["listener_id"]),
		Protocols:                      poolNonEmpty(q["protocol"]),
		LBAlgorithms:                   poolNonEmpty(q["lb_algorithm"]),
		EnterpriseProjectIDs:           poolNonEmpty(q["enterprise_project_id"]),
		IPVersions:                     poolNonEmpty(q["ip_version"]),
		MemberAddresses:                poolNonEmpty(q["member_address"]),
		MemberDeviceIDs:                poolNonEmpty(q["member_device_id"]),
		MemberInstanceIDs:              poolNonEmpty(q["member_instance_id"]),
		MemberDeletionProtectionEnable: memDelProt,
		VPCIDs:                         poolNonEmpty(q["vpc_id"]),
		Types:                          poolNonEmpty(q["type"]),
		ProtectionStatuses:             poolNonEmpty(q["protection_status"]),
		ConnectionDrain:                connDrain,
		PoolHealth:                     poolNonEmpty(q["pool_health"]),
		AnyPortEnable:                  anyPort,
		PublicBorderGroups:             poolNonEmpty(q["public_border_group"]),
		QuicCidLens:                    quicLens,
		QuicCidOffsets:                 quicOffsets,
		AzAffinities:                   poolNonEmpty(q["az_affinity"]),
		Page:                           page,
		PageReverse:                    pageReverse != nil && *pageReverse,
	})
	if err != nil {
		return err
	}

	out := make([]poolResponse, 0, len(items))
	for _, item := range items {
		out = append(out, toPoolResponse(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, listPoolsResponse{
		RequestID: requestID(r),
		Pools:     out,
		PageInfo:  pi,
	})
}

func (s *Service) handleShowPool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "pool_id")
	detail, err := s.getPool(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, poolEnvelope{
		RequestID: requestID(r),
		Pool:      toPoolResponse(t, detail),
	})
}

func (s *Service) handleUpdatePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePoolRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Pool == nil {
		return errInvalidInput("pool")
	}
	id := chi.URLParam(r, "pool_id")
	opt := req.Pool

	var ssOpt poolOptional[slowStart]
	if opt.SlowStart.Set {
		ssOpt.Set = true
		if opt.SlowStart.Value != nil {
			ss := &slowStart{
				Enable: opt.SlowStart.Value.Enable != nil && *opt.SlowStart.Value.Enable,
			}
			if opt.SlowStart.Value.Duration != nil {
				ss.Duration = *opt.SlowStart.Value.Duration
			}
			ssOpt.Value = ss
		}
	}

	var azOpt poolOptional[poolAzAffinityInput]
	if opt.AzAffinity.Set {
		azOpt.Set = true
		if opt.AzAffinity.Value != nil {
			azOpt.Value = opt.AzAffinity.Value.toInput()
		}
	}

	detail, err := s.updatePool(r.Context(), t, id, updatePoolInput{
		Name:                           opt.Name,
		Description:                    opt.Description,
		LBAlgorithm:                    opt.LBAlgorithm,
		AdminStateUp:                   opt.AdminStateUp,
		VPCID:                          opt.VPCID,
		Type:                           opt.Type,
		SessionPersistence:             opt.SessionPersistence,
		SlowStart:                      ssOpt,
		ConnectionDrain:                opt.ConnectionDrain,
		PoolHealth:                     opt.PoolHealth,
		AzAffinity:                     azOpt,
		QuicCidHashStrategy:            opt.QuicCidHashStrategy,
		MemberDeletionProtectionEnable: opt.MemberDeletionProtectionEnable,
		AnyPortEnable:                  opt.AnyPortEnable,
		ProtectionStatus:               opt.ProtectionStatus,
		ProtectionReason:               opt.ProtectionReason,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, poolEnvelope{
		RequestID: requestID(r),
		Pool:      toPoolResponse(t, detail),
	})
}

func (s *Service) handleDeletePool(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "pool_id")
	if err := s.deletePool(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeletePoolCascade(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "pool_id")
	if err := s.deletePoolCascade(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
