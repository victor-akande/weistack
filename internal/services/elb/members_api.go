package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type createMemberRequest struct {
	Member *createMemberOption `json:"member"`
}

// createMemberOption mirrors SDK model CreateMemberOption.
type createMemberOption struct {
	Address          string `json:"address"`
	AdminStateUp     *bool  `json:"admin_state_up"`
	Name             string `json:"name"`
	ProjectID        string `json:"project_id"`
	ProtocolPort     *int   `json:"protocol_port"`
	SubnetCIDRID     string `json:"subnet_cidr_id"`
	Weight           *int   `json:"weight"`
	AvailabilityZone string `json:"availability_zone"`
}

type updateMemberRequest struct {
	Member *updateMemberOption `json:"member"`
}

// updateMemberOption mirrors SDK model UpdateMemberOption.
type updateMemberOption struct {
	AdminStateUp     *bool   `json:"admin_state_up"`
	AvailabilityZone *string `json:"availability_zone"`
	Name             *string `json:"name"`
	Weight           *int    `json:"weight"`
	ProtocolPort     *int    `json:"protocol_port"`
}

// memberWire mirrors SDK model Member.
type memberWire struct {
	ID               string             `json:"id"`
	AvailabilityZone string             `json:"availability_zone"`
	Name             string             `json:"name"`
	ProjectID        string             `json:"project_id"`
	AdminStateUp     bool               `json:"admin_state_up"`
	SubnetCIDRID     *string            `json:"subnet_cidr_id,omitempty"`
	ProtocolPort     int                `json:"protocol_port"`
	Weight           int                `json:"weight"`
	Address          string             `json:"address"`
	IPVersion        string             `json:"ip_version"`
	OperatingStatus  string             `json:"operating_status"`
	Status           []memberStatusWire `json:"status"`
	CreatedAt        string             `json:"created_at"`
	UpdatedAt        string             `json:"updated_at"`
	MemberType       string             `json:"member_type"`
	InstanceID       string             `json:"instance_id"`
}

// memberInfoWire mirrors SDK model MemberInfo (used by ListAllMembers).
type memberInfoWire struct {
	ID               string             `json:"id"`
	AvailabilityZone string             `json:"availability_zone"`
	Name             string             `json:"name"`
	ProjectID        string             `json:"project_id"`
	PoolID           string             `json:"pool_id"`
	AdminStateUp     bool               `json:"admin_state_up"`
	SubnetCIDRID     *string            `json:"subnet_cidr_id,omitempty"`
	ProtocolPort     int                `json:"protocol_port"`
	Weight           int                `json:"weight"`
	Address          string             `json:"address"`
	IPVersion        string             `json:"ip_version"`
	OperatingStatus  string             `json:"operating_status"`
	Status           []memberStatusWire `json:"status"`
	LoadbalancerID   string             `json:"loadbalancer_id,omitempty"`
	Loadbalancers    []idRef            `json:"loadbalancers"`
	CreatedAt        string             `json:"created_at"`
	UpdatedAt        string             `json:"updated_at"`
	MemberType       string             `json:"member_type"`
	InstanceID       string             `json:"instance_id"`
}

type memberResponse struct {
	RequestID string     `json:"request_id"`
	Member    memberWire `json:"member"`
}

type listMembersResponse struct {
	RequestID string       `json:"request_id"`
	PageInfo  pageInfo     `json:"page_info"`
	Members   []memberWire `json:"members"`
}

type listAllMembersResponse struct {
	RequestID string           `json:"request_id"`
	PageInfo  pageInfo         `json:"page_info"`
	Members   []memberInfoWire `json:"members"`
}

func toMemberWire(t Tenant, v memberView) memberWire {
	m := v.Member
	var subnetCIDR *string
	if m.SubnetCIDRID != "" {
		s := m.SubnetCIDRID
		subnetCIDR = &s
	}
	statuses := v.Statuses
	if statuses == nil {
		statuses = []memberStatusWire{}
	}
	return memberWire{
		ID:               m.ID,
		AvailabilityZone: m.AvailabilityZone,
		Name:             m.Name,
		ProjectID:        t.ProjectID,
		AdminStateUp:     m.AdminStateUp,
		SubnetCIDRID:     subnetCIDR,
		ProtocolPort:     m.ProtocolPort,
		Weight:           m.Weight,
		Address:          m.Address,
		IPVersion:        memberIPVersionV4,
		OperatingStatus:  v.OperatingStatus,
		Status:           statuses,
		CreatedAt:        formatTime(m.CreatedAt),
		UpdatedAt:        formatTime(m.UpdatedAt),
		MemberType:       m.MemberType,
		InstanceID:       "",
	}
}

func toMemberInfoWire(t Tenant, v memberView) memberInfoWire {
	m := v.Member
	var subnetCIDR *string
	if m.SubnetCIDRID != "" {
		s := m.SubnetCIDRID
		subnetCIDR = &s
	}
	statuses := v.Statuses
	if statuses == nil {
		statuses = []memberStatusWire{}
	}
	lbs := []idRef{}
	if v.Pool.LoadBalancerID != "" {
		lbs = []idRef{{ID: v.Pool.LoadBalancerID}}
	}
	return memberInfoWire{
		ID:               m.ID,
		AvailabilityZone: m.AvailabilityZone,
		Name:             m.Name,
		ProjectID:        t.ProjectID,
		PoolID:           m.PoolID,
		AdminStateUp:     m.AdminStateUp,
		SubnetCIDRID:     subnetCIDR,
		ProtocolPort:     m.ProtocolPort,
		Weight:           m.Weight,
		Address:          m.Address,
		IPVersion:        memberIPVersionV4,
		OperatingStatus:  v.OperatingStatus,
		Status:           statuses,
		LoadbalancerID:   v.Pool.LoadBalancerID,
		Loadbalancers:    lbs,
		CreatedAt:        formatTime(m.CreatedAt),
		UpdatedAt:        formatTime(m.UpdatedAt),
		MemberType:       m.MemberType,
		InstanceID:       "",
	}
}

func (s *Service) handleCreateMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createMemberRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Member == nil {
		return errInvalidInput("member")
	}
	poolID := chi.URLParam(r, "pool_id")
	v, err := s.createMember(r.Context(), t, poolID, createMemberInput{
		Address:          req.Member.Address,
		Name:             req.Member.Name,
		ProtocolPort:     req.Member.ProtocolPort,
		SubnetCIDRID:     req.Member.SubnetCIDRID,
		Weight:           req.Member.Weight,
		AdminStateUp:     req.Member.AdminStateUp,
		AvailabilityZone: req.Member.AvailabilityZone,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, memberResponse{
		RequestID: requestID(r),
		Member:    toMemberWire(t, v),
	})
}

func (s *Service) handleListMembers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	adminUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	weights, err := parseIntQueryValues(q, "weight")
	if err != nil {
		return err
	}
	ports, err := parseIntQueryValues(q, "protocol_port")
	if err != nil {
		return err
	}
	poolID := chi.URLParam(r, "pool_id")
	views, pi, err := s.listMembers(r.Context(), t, poolID, listMembersFilter{
		IDs:                  q["id"],
		Names:                q["name"],
		Weights:              weights,
		AdminStateUp:         adminUp,
		SubnetCIDRIDs:        q["subnet_cidr_id"],
		Addresses:            q["address"],
		ProtocolPorts:        ports,
		OperatingStatuses:    q["operating_status"],
		EnterpriseProjectIDs: q["enterprise_project_id"],
		IPVersions:           q["ip_version"],
		MemberTypes:          q["member_type"],
		InstanceIDs:          q["instance_id"],
		AvailabilityZones:    q["availability_zone"],
	}, page)
	if err != nil {
		return err
	}
	members := make([]memberWire, len(views))
	for i, v := range views {
		members[i] = toMemberWire(t, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, listMembersResponse{
		RequestID: requestID(r),
		PageInfo:  pi,
		Members:   members,
	})
}

func (s *Service) handleShowMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	poolID := chi.URLParam(r, "pool_id")
	memberID := chi.URLParam(r, "member_id")
	v, err := s.showMember(r.Context(), t, poolID, memberID)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, memberResponse{
		RequestID: requestID(r),
		Member:    toMemberWire(t, v),
	})
}

func (s *Service) handleUpdateMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateMemberRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Member == nil {
		return errInvalidInput("member")
	}
	poolID := chi.URLParam(r, "pool_id")
	memberID := chi.URLParam(r, "member_id")
	v, err := s.updateMember(r.Context(), t, poolID, memberID, updateMemberInput{
		Name:             req.Member.Name,
		Weight:           req.Member.Weight,
		AdminStateUp:     req.Member.AdminStateUp,
		ProtocolPort:     req.Member.ProtocolPort,
		AvailabilityZone: req.Member.AvailabilityZone,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, memberResponse{
		RequestID: requestID(r),
		Member:    toMemberWire(t, v),
	})
}

func (s *Service) handleDeleteMember(w http.ResponseWriter, r *http.Request, t Tenant) error {
	poolID := chi.URLParam(r, "pool_id")
	memberID := chi.URLParam(r, "member_id")
	if err := s.deleteMember(r.Context(), t, poolID, memberID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListAllMembers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	adminUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	weights, err := parseIntQueryValues(q, "weight")
	if err != nil {
		return err
	}
	ports, err := parseIntQueryValues(q, "protocol_port")
	if err != nil {
		return err
	}
	views, pi, err := s.listAllMembers(r.Context(), t, listAllMembersFilter{
		IDs:                  q["id"],
		Names:                q["name"],
		Weights:              weights,
		AdminStateUp:         adminUp,
		SubnetCIDRIDs:        q["subnet_cidr_id"],
		Addresses:            q["address"],
		ProtocolPorts:        ports,
		OperatingStatuses:    q["operating_status"],
		EnterpriseProjectIDs: q["enterprise_project_id"],
		IPVersions:           q["ip_version"],
		PoolIDs:              q["pool_id"],
		LoadBalancerIDs:      q["loadbalancer_id"],
	}, page)
	if err != nil {
		return err
	}
	members := make([]memberInfoWire, len(views))
	for i, v := range views {
		members[i] = toMemberInfoWire(t, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, listAllMembersResponse{
		RequestID: requestID(r),
		PageInfo:  pi,
		Members:   members,
	})
}
