package vpc

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

// This file serves the older and newer API versions that real clients
// use alongside the ones the emulator is built around: the v3 VPC detail,
// and the v1 security group API. The Terraform provider, for example,
// creates security groups with v3 but reads and deletes them with v1.
// Everything is a view of the same stored records.

// v3VPC mirrors the SDK model vpc/v3 Vpc.
type v3VPC struct {
	ID                               string          `json:"id"`
	Name                             string          `json:"name"`
	Description                      string          `json:"description"`
	CIDR                             string          `json:"cidr"`
	ExtendCIDRs                      []string        `json:"extend_cidrs"`
	Status                           string          `json:"status"`
	ProjectID                        string          `json:"project_id"`
	EnterpriseProjectID              string          `json:"enterprise_project_id"`
	CreatedAt                        TimeZ           `json:"created_at"`
	UpdatedAt                        TimeZ           `json:"updated_at"`
	CloudResources                   []cloudResource `json:"cloud_resources"`
	Tags                             []Tag           `json:"tags"`
	BlockServiceEndpointStates       string          `json:"block_service_endpoint_states"`
	EnableNetworkAddressUsageMetrics bool            `json:"enable_network_address_usage_metrics"`
}

// cloudResource mirrors the SDK model vpc/v3 CloudResource.
type cloudResource struct {
	ResourceType  string `json:"resource_type"`
	ResourceCount int    `json:"resource_count"`
}

type v3VPCResponse struct {
	RequestID string `json:"request_id"`
	VPC       v3VPC  `json:"vpc"`
}

// v3Status maps a v1 VPC status to the v3 vocabulary.
func v3Status(v1 string) string {
	switch v1 {
	case VPCStatusOK:
		return "ACTIVE"
	case VPCStatusCreating:
		return "PENDING"
	}
	return v1
}

func (s *Service) handleShowVPCv3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "vpc_id")
	v, err := s.vpcs(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return apierr.New(http.StatusNotFound, "VPC.9904", "VPC %s does not exist.", id)
	}
	if err != nil {
		return err
	}
	subnets, err := s.subnetsOfVPC(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v3VPCResponse{
		RequestID: requestID(r),
		VPC: v3VPC{
			ID: v.ID, Name: v.Name, Description: v.Description, CIDR: v.CIDR, ExtendCIDRs: []string{},
			Status: v3Status(v.Status), ProjectID: v.TenantID, EnterpriseProjectID: v.EnterpriseProjectID,
			CreatedAt: TimeZ(time.Time(v.CreatedAt)), UpdatedAt: TimeZ(time.Time(v.UpdatedAt)),
			CloudResources: []cloudResource{
				{ResourceType: "virsubnet", ResourceCount: len(subnets)},
			},
			Tags:                             []Tag{},
			BlockServiceEndpointStates:       v.BlockServiceEndpointStates,
			EnableNetworkAddressUsageMetrics: v.EnableNetworkAddressUsageMetrics,
		},
	})
}

// v1SecurityGroup mirrors the SDK model vpc/v2 SecurityGroup (the v1 API).
type v1SecurityGroup struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	VPCID               string   `json:"vpc_id"`
	EnterpriseProjectID string   `json:"enterprise_project_id"`
	Rules               []v1Rule `json:"security_group_rules"`
}

// v1Rule mirrors the SDK model vpc/v2 SecurityGroupRule. The v1 API has
// a port range where v3 has a port list.
type v1Rule struct {
	ID                   string  `json:"id"`
	Description          string  `json:"description"`
	SecurityGroupID      string  `json:"security_group_id"`
	Direction            string  `json:"direction"`
	Ethertype            string  `json:"ethertype"`
	Protocol             *string `json:"protocol"`
	PortRangeMin         *int    `json:"port_range_min"`
	PortRangeMax         *int    `json:"port_range_max"`
	RemoteIPPrefix       *string `json:"remote_ip_prefix"`
	RemoteGroupID        *string `json:"remote_group_id"`
	RemoteAddressGroupID *string `json:"remote_address_group_id"`
	TenantID             string  `json:"tenant_id"`
}

// toV1 renders a stored rule in the v1 form. A port list that is not a
// single port or a single range has no v1 equivalent and is left open.
func (r SecurityGroupRule) toV1() v1Rule {
	out := v1Rule{
		ID: r.ID, Description: r.Description, SecurityGroupID: r.SecurityGroupID, Direction: r.Direction,
		Ethertype: r.Ethertype, Protocol: r.Protocol, RemoteIPPrefix: r.RemoteIPPrefix, RemoteGroupID: r.RemoteGroupID,
		RemoteAddressGroupID: r.RemoteAddressGroupID, TenantID: r.ProjectID,
	}
	if r.Multiport != nil && !strings.Contains(*r.Multiport, ",") {
		lo, hi, isRange := strings.Cut(*r.Multiport, "-")
		if !isRange {
			hi = lo
		}
		if a, err := strconv.Atoi(lo); err == nil {
			if b, err := strconv.Atoi(hi); err == nil {
				out.PortRangeMin, out.PortRangeMax = &a, &b
			}
		}
	}
	return out
}

// v1Error translates an error of the v3 security group code to the v1
// API's envelope codes.
func v1Error(err error) error {
	var e *apierr.Error
	if !errors.As(err, &e) {
		return err
	}
	switch {
	case e.Status == http.StatusNotFound:
		return apierr.New(http.StatusNotFound, "VPC.0603", "%s", e.Message)
	case e.Status == http.StatusConflict:
		return apierr.New(http.StatusConflict, "VPC.0602", "%s", e.Message)
	case e.Status == http.StatusBadRequest:
		return apierr.New(http.StatusBadRequest, "VPC.0601", "%s", e.Message)
	}
	return err
}

func (s *Service) v1Group(ctx context.Context, t Tenant, id string) (v1SecurityGroup, error) {
	g, err := s.GetSecurityGroup(ctx, t, id)
	if err != nil {
		return v1SecurityGroup{}, v1Error(err)
	}
	out := v1SecurityGroup{
		ID: g.ID, Name: g.Name, Description: g.Description, EnterpriseProjectID: g.EnterpriseProjectID,
		Rules: make([]v1Rule, 0, len(g.SecurityGroupRules)),
	}
	for _, r := range g.SecurityGroupRules {
		out.Rules = append(out.Rules, r.toV1())
	}
	return out, nil
}

type v1GroupResponse struct {
	SecurityGroup v1SecurityGroup `json:"security_group"`
}

type v1GroupsResponse struct {
	SecurityGroups []v1SecurityGroup `json:"security_groups"`
}

type v1RuleResponse struct {
	SecurityGroupRule v1Rule `json:"security_group_rule"`
}

type v1RulesResponse struct {
	SecurityGroupRules []v1Rule `json:"security_group_rules"`
}

type v1CreateGroupRequest struct {
	SecurityGroup *struct {
		Name                string  `json:"name"`
		VPCID               string  `json:"vpc_id"`
		EnterpriseProjectID *string `json:"enterprise_project_id"`
	} `json:"security_group"`
}

type v1CreateRuleRequest struct {
	SecurityGroupRule *struct {
		SecurityGroupID      string  `json:"security_group_id"`
		Description          *string `json:"description"`
		Direction            string  `json:"direction"`
		Ethertype            *string `json:"ethertype"`
		Protocol             *string `json:"protocol"`
		PortRangeMin         *int    `json:"port_range_min"`
		PortRangeMax         *int    `json:"port_range_max"`
		RemoteIPPrefix       *string `json:"remote_ip_prefix"`
		RemoteGroupID        *string `json:"remote_group_id"`
		RemoteAddressGroupID *string `json:"remote_address_group_id"`
	} `json:"security_group_rule"`
}

func errInvalidV1Group(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0601", format, args...)
}

func (s *Service) handleCreateGroupV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req v1CreateGroupRequest
	if err := decode(r, &req, errInvalidV1Group); err != nil {
		return err
	}
	if req.SecurityGroup == nil {
		return errInvalidV1Group("the request body must contain a security_group object")
	}
	if req.SecurityGroup.VPCID != "" {
		if _, err := s.GetVPC(r.Context(), t, req.SecurityGroup.VPCID); err != nil {
			return errInvalidV1Group("vpc_id %q does not exist", req.SecurityGroup.VPCID)
		}
	}
	g, err := s.CreateSecurityGroup(r.Context(), t, CreateSecurityGroupOption{
		Name: req.SecurityGroup.Name, EnterpriseProjectID: req.SecurityGroup.EnterpriseProjectID,
	}, false)
	if err != nil {
		return v1Error(err)
	}
	out, err := s.v1Group(r.Context(), t, g.ID)
	if err != nil {
		return err
	}
	out.VPCID = req.SecurityGroup.VPCID
	return httpx.WriteJSON(w, http.StatusOK, v1GroupResponse{SecurityGroup: out})
}

func (s *Service) handleShowGroupV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	out, err := s.v1Group(r.Context(), t, chi.URLParam(r, "security_group_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v1GroupResponse{SecurityGroup: out})
}

func (s *Service) handleListGroupsV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	page, err := pagination.ParseMarker(r.URL.Query(), v1ListLimits)
	if err != nil {
		return errInvalidV1Group("%s", err)
	}
	groups, err := s.ListSecurityGroups(r.Context(), t, ListSecurityGroupsFilter{EnterpriseProjectID: r.URL.Query().Get("enterprise_project_id")})
	if err != nil {
		return err
	}
	groups, err = pagination.ByMarker(groups, func(g SecurityGroup) string { return g.ID }, page)
	if err != nil {
		return errInvalidV1Group("%s", err)
	}
	res := v1GroupsResponse{SecurityGroups: make([]v1SecurityGroup, 0, len(groups))}
	for _, g := range groups {
		out, err := s.v1Group(r.Context(), t, g.ID)
		if err != nil {
			return err
		}
		res.SecurityGroups = append(res.SecurityGroups, out)
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleDeleteGroupV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSecurityGroup(r.Context(), t, chi.URLParam(r, "security_group_id")); err != nil {
		return v1Error(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// portsToMultiport converts a v1 port range to the v3 port list.
func portsToMultiport(lo, hi *int) (*string, error) {
	switch {
	case lo == nil && hi == nil:
		return nil, nil
	case lo == nil || hi == nil:
		return nil, errInvalidV1Group("port_range_min and port_range_max must be given together")
	case *lo == *hi:
		v := strconv.Itoa(*lo)
		return &v, nil
	}
	v := strconv.Itoa(*lo) + "-" + strconv.Itoa(*hi)
	return &v, nil
}

func (s *Service) handleCreateRuleV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req v1CreateRuleRequest
	if err := decode(r, &req, errInvalidV1Group); err != nil {
		return err
	}
	if req.SecurityGroupRule == nil {
		return errInvalidV1Group("the request body must contain a security_group_rule object")
	}
	in := req.SecurityGroupRule
	multiport, err := portsToMultiport(in.PortRangeMin, in.PortRangeMax)
	if err != nil {
		return err
	}
	rule, err := s.CreateSecurityGroupRule(r.Context(), t, CreateSecurityGroupRuleOption{
		SecurityGroupID: in.SecurityGroupID, Description: in.Description, Direction: in.Direction,
		Ethertype: in.Ethertype, Protocol: in.Protocol, Multiport: multiport, RemoteIPPrefix: in.RemoteIPPrefix,
		RemoteGroupID: in.RemoteGroupID, RemoteAddressGroupID: in.RemoteAddressGroupID,
	}, false)
	if err != nil {
		return v1Error(err)
	}
	return httpx.WriteJSON(w, http.StatusOK, v1RuleResponse{SecurityGroupRule: rule.toV1()})
}

func (s *Service) handleShowRuleV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	rule, err := s.GetSecurityGroupRule(r.Context(), t, chi.URLParam(r, "security_group_rule_id"))
	if err != nil {
		return v1Error(err)
	}
	return httpx.WriteJSON(w, http.StatusOK, v1RuleResponse{SecurityGroupRule: rule.toV1()})
}

func (s *Service) handleListRulesV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidV1Group("%s", err)
	}
	f := ListSecurityGroupRulesFilter{RemoteIPPrefix: q.Get("remote_ip_prefix")}
	if id := q.Get("security_group_id"); id != "" {
		f.SecurityGroupIDs = []string{id}
	}
	rules, err := s.ListSecurityGroupRules(r.Context(), t, f)
	if err != nil {
		return err
	}
	rules, err = pagination.ByMarker(rules, func(r SecurityGroupRule) string { return r.ID }, page)
	if err != nil {
		return errInvalidV1Group("%s", err)
	}
	res := v1RulesResponse{SecurityGroupRules: make([]v1Rule, 0, len(rules))}
	for _, rule := range rules {
		res.SecurityGroupRules = append(res.SecurityGroupRules, rule.toV1())
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleDeleteRuleV1(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSecurityGroupRule(r.Context(), t, chi.URLParam(r, "security_group_rule_id")); err != nil {
		return v1Error(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
