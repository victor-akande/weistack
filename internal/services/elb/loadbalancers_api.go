package elb

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// --- §3.1 Wire types ---

type createLoadBalancerBandwidthWire struct {
	Name        *string `json:"name,omitempty"`
	Size        *int    `json:"size,omitempty"`
	ChargeMode  *string `json:"charge_mode,omitempty"`
	ShareType   *string `json:"share_type,omitempty"`
	BillingInfo *string `json:"billing_info,omitempty"`
	ID          *string `json:"id,omitempty"`
}

type createLoadBalancerPublicIPWire struct {
	IPVersion   *int                             `json:"ip_version,omitempty"`
	NetworkType string                           `json:"network_type"`
	BillingInfo *string                          `json:"billing_info,omitempty"`
	Description *string                          `json:"description,omitempty"`
	Bandwidth   *createLoadBalancerBandwidthWire `json:"bandwidth"`
}

type createLoadBalancerOptionWire struct {
	ProjectID                *string                         `json:"project_id,omitempty"`
	Name                     string                          `json:"name,omitempty"`
	Description              string                          `json:"description,omitempty"`
	VIPAddress               string                          `json:"vip_address,omitempty"`
	VIPSubnetCIDRID          string                          `json:"vip_subnet_cidr_id,omitempty"`
	IPv6VIPVirsubnetID       *string                         `json:"ipv6_vip_virsubnet_id,omitempty"`
	IPv6VIPAddress           *string                         `json:"ipv6_vip_address,omitempty"`
	IPv6Bandwidth            json.RawMessage                 `json:"ipv6_bandwidth,omitempty"`
	Provider                 string                          `json:"provider,omitempty"`
	L4FlavorID               string                          `json:"l4_flavor_id,omitempty"`
	L7FlavorID               string                          `json:"l7_flavor_id,omitempty"`
	Guaranteed               *bool                           `json:"guaranteed,omitempty"`
	VPCID                    string                          `json:"vpc_id,omitempty"`
	AvailabilityZoneList     []string                        `json:"availability_zone_list"`
	EnterpriseProjectID      *string                         `json:"enterprise_project_id,omitempty"`
	Tags                     []tag                           `json:"tags,omitempty"`
	AdminStateUp             *bool                           `json:"admin_state_up,omitempty"`
	BillingInfo              *string                         `json:"billing_info,omitempty"`
	PublicIPIDs              []string                        `json:"publicip_ids,omitempty"`
	PublicIP                 *createLoadBalancerPublicIPWire `json:"publicip,omitempty"`
	ELBVirsubnetIDs          []string                        `json:"elb_virsubnet_ids,omitempty"`
	IPTargetEnable           *bool                           `json:"ip_target_enable,omitempty"`
	DeletionProtectionEnable *bool                           `json:"deletion_protection_enable,omitempty"`
	PrepaidOptions           json.RawMessage                 `json:"prepaid_options,omitempty"`
	Autoscaling              *autoscalingRef                 `json:"autoscaling,omitempty"`
	WafFailureAction         string                          `json:"waf_failure_action,omitempty"`
	ProtectionStatus         string                          `json:"protection_status,omitempty"`
	ProtectionReason         string                          `json:"protection_reason,omitempty"`
	ChargeMode               *string                         `json:"charge_mode,omitempty"`
	LogGroupID               *string                         `json:"log_group_id,omitempty"`
	LogTopicID               *string                         `json:"log_topic_id,omitempty"`
}

type createLoadBalancerRequest struct {
	Loadbalancer *createLoadBalancerOptionWire `json:"loadbalancer"`
}

type updateLoadBalancerOptionFields struct {
	Name                     *string         `json:"name,omitempty"`
	AdminStateUp             *bool           `json:"admin_state_up,omitempty"`
	Description              *string         `json:"description,omitempty"`
	IPv6VIPVirsubnetID       *string         `json:"ipv6_vip_virsubnet_id,omitempty"`
	VIPSubnetCIDRID          *string         `json:"vip_subnet_cidr_id,omitempty"`
	VIPAddress               *string         `json:"vip_address,omitempty"`
	L4FlavorID               *string         `json:"l4_flavor_id,omitempty"`
	L7FlavorID               *string         `json:"l7_flavor_id,omitempty"`
	IPv6Bandwidth            json.RawMessage `json:"ipv6_bandwidth,omitempty"`
	IPTargetEnable           *bool           `json:"ip_target_enable,omitempty"`
	ELBVirsubnetIDs          *[]string       `json:"elb_virsubnet_ids,omitempty"`
	DeletionProtectionEnable *bool           `json:"deletion_protection_enable,omitempty"`
	PrepaidOptions           json.RawMessage `json:"prepaid_options,omitempty"`
	Autoscaling              *autoscalingRef `json:"autoscaling,omitempty"`
	ChargeMode               *string         `json:"charge_mode,omitempty"`
	WafFailureAction         *string         `json:"waf_failure_action,omitempty"`
	ProtectionStatus         *string         `json:"protection_status,omitempty"`
	ProtectionReason         *string         `json:"protection_reason,omitempty"`
	IPv6VIPAddress           *string         `json:"ipv6_vip_address,omitempty"`
	LogGroupID               *string         `json:"log_group_id,omitempty"`
	LogTopicID               *string         `json:"log_topic_id,omitempty"`
}

type updateLoadBalancerOptionWire struct {
	updateLoadBalancerOptionFields
	vipSubnetCIDRIDPresent bool
}

func (u *updateLoadBalancerOptionWire) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, u.vipSubnetCIDRIDPresent = raw["vip_subnet_cidr_id"]
	return json.Unmarshal(data, &u.updateLoadBalancerOptionFields)
}

type updateLoadBalancerRequest struct {
	Loadbalancer *updateLoadBalancerOptionWire `json:"loadbalancer"`
}

type batchAvailableZonesRequest struct {
	AvailabilityZoneList []string `json:"availability_zone_list"`
}

// loadBalancerWire matches SDK model LoadBalancer (§3.1).
type loadBalancerWire struct {
	ID                       string             `json:"id"`
	Description              string             `json:"description"`
	ProvisioningStatus       string             `json:"provisioning_status"`
	AdminStateUp             bool               `json:"admin_state_up"`
	Provider                 string             `json:"provider"`
	Pools                    []idRef            `json:"pools"`
	Listeners                []idRef            `json:"listeners"`
	OperatingStatus          string             `json:"operating_status"`
	Name                     string             `json:"name"`
	ProjectID                string             `json:"project_id"`
	VIPSubnetCIDRID          string             `json:"vip_subnet_cidr_id"`
	VIPAddress               string             `json:"vip_address"`
	VIPPortID                string             `json:"vip_port_id"`
	Tags                     []tag              `json:"tags"`
	CreatedAt                string             `json:"created_at"`
	UpdatedAt                string             `json:"updated_at"`
	Guaranteed               bool               `json:"guaranteed"`
	VPCID                    string             `json:"vpc_id"`
	EIPs                     []eipInfoWire      `json:"eips"`
	IPv6VIPAddress           string             `json:"ipv6_vip_address"`
	IPv6VIPVirsubnetID       string             `json:"ipv6_vip_virsubnet_id"`
	IPv6VIPPortID            string             `json:"ipv6_vip_port_id"`
	AvailabilityZoneList     []string           `json:"availability_zone_list"`
	EnterpriseProjectID      string             `json:"enterprise_project_id"`
	BillingInfo              string             `json:"billing_info"`
	L4FlavorID               string             `json:"l4_flavor_id"`
	L4ScaleFlavorID          string             `json:"l4_scale_flavor_id"`
	L7FlavorID               string             `json:"l7_flavor_id"`
	L7ScaleFlavorID          string             `json:"l7_scale_flavor_id"`
	LoadbalancerType         string             `json:"loadbalancer_type"`
	PublicIPs                []publicIPInfoWire `json:"publicips"`
	GlobalEIPs               []any              `json:"global_eips"`
	ELBVirsubnetIDs          []string           `json:"elb_virsubnet_ids"`
	ELBVirsubnetType         string             `json:"elb_virsubnet_type"`
	IPTargetEnable           bool               `json:"ip_target_enable"`
	FrozenScene              string             `json:"frozen_scene"`
	DeletionProtectionEnable bool               `json:"deletion_protection_enable"`
	Autoscaling              *autoscalingRef    `json:"autoscaling,omitempty"`
	PublicBorderGroup        string             `json:"public_border_group"`
	WafFailureAction         string             `json:"waf_failure_action,omitempty"`
	ProtectionStatus         string             `json:"protection_status"`
	ProtectionReason         string             `json:"protection_reason"`
}

type loadBalancerResponse struct {
	Loadbalancer loadBalancerWire `json:"loadbalancer"`
	RequestID    string           `json:"request_id"`
}

type listLoadBalancersResponse struct {
	Loadbalancers []loadBalancerWire `json:"loadbalancers"`
	PageInfo      pageInfo           `json:"page_info"`
	RequestID     string             `json:"request_id"`
}

// --- Status tree wire types (SDK LoadBalancerStatusResult) ---

type loadBalancerStatusL7Rule struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	ProvisioningStatus string `json:"provisioning_status"`
}

type loadBalancerStatusPolicy struct {
	Action             string                     `json:"action"`
	ID                 string                     `json:"id"`
	ProvisioningStatus string                     `json:"provisioning_status"`
	Name               string                     `json:"name"`
	Rules              []loadBalancerStatusL7Rule `json:"rules"`
}

type loadBalancerStatusHealthMonitor struct {
	Type               string `json:"type"`
	ID                 string `json:"id"`
	Name               string `json:"name"`
	ProvisioningStatus string `json:"provisioning_status"`
}

type loadBalancerStatusMember struct {
	ProvisioningStatus string `json:"provisioning_status"`
	Address            string `json:"address"`
	ProtocolPort       int    `json:"protocol_port"`
	ID                 string `json:"id"`
	OperatingStatus    string `json:"operating_status"`
}

type loadBalancerStatusPool struct {
	ProvisioningStatus string                           `json:"provisioning_status"`
	Name               string                           `json:"name"`
	Healthmonitor      *loadBalancerStatusHealthMonitor `json:"healthmonitor,omitempty"`
	Members            []loadBalancerStatusMember       `json:"members"`
	ID                 string                           `json:"id"`
	OperatingStatus    string                           `json:"operating_status"`
}

type loadBalancerStatusListener struct {
	Name               string                     `json:"name"`
	ProvisioningStatus string                     `json:"provisioning_status"`
	Pools              []loadBalancerStatusPool   `json:"pools"`
	L7Policies         []loadBalancerStatusPolicy `json:"l7policies"`
	ID                 string                     `json:"id"`
	OperatingStatus    string                     `json:"operating_status"`
}

type loadBalancerStatusWire struct {
	Name               string                       `json:"name"`
	ProvisioningStatus string                       `json:"provisioning_status"`
	Listeners          []loadBalancerStatusListener `json:"listeners"`
	Pools              []loadBalancerStatusPool     `json:"pools"`
	ID                 string                       `json:"id"`
	OperatingStatus    string                       `json:"operating_status"`
}

type loadBalancerStatusResult struct {
	Loadbalancer loadBalancerStatusWire `json:"loadbalancer"`
}

type showLoadBalancerStatusResponse struct {
	Statuses  loadBalancerStatusResult `json:"statuses"`
	RequestID string                   `json:"request_id"`
}

func lbRawNonNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func checkCreateOutOfScope(opt *createLoadBalancerOptionWire) string {
	switch {
	case lbRawNonNull(opt.PrepaidOptions):
		return "prepaid_options"
	case opt.IPv6VIPVirsubnetID != nil && *opt.IPv6VIPVirsubnetID != "":
		return "ipv6_vip_virsubnet_id"
	case opt.IPv6VIPAddress != nil && *opt.IPv6VIPAddress != "":
		return "ipv6_vip_address"
	case lbRawNonNull(opt.IPv6Bandwidth):
		return "ipv6_bandwidth"
	case opt.ChargeMode != nil && *opt.ChargeMode != "":
		return "charge_mode"
	case opt.BillingInfo != nil && *opt.BillingInfo != "":
		return "billing_info"
	case opt.LogGroupID != nil && *opt.LogGroupID != "":
		return "log_group_id"
	case opt.LogTopicID != nil && *opt.LogTopicID != "":
		return "log_topic_id"
	default:
		return ""
	}
}

func checkUpdateOutOfScope(opt *updateLoadBalancerOptionWire) string {
	switch {
	case lbRawNonNull(opt.PrepaidOptions):
		return "prepaid_options"
	case opt.IPv6VIPVirsubnetID != nil && *opt.IPv6VIPVirsubnetID != "":
		return "ipv6_vip_virsubnet_id"
	case opt.IPv6VIPAddress != nil && *opt.IPv6VIPAddress != "":
		return "ipv6_vip_address"
	case lbRawNonNull(opt.IPv6Bandwidth):
		return "ipv6_bandwidth"
	case opt.ChargeMode != nil && *opt.ChargeMode != "":
		return "charge_mode"
	case opt.LogGroupID != nil && *opt.LogGroupID != "":
		return "log_group_id"
	case opt.LogTopicID != nil && *opt.LogTopicID != "":
		return "log_topic_id"
	default:
		return ""
	}
}

func (s *Service) toLoadBalancerWire(ctx context.Context, t Tenant, lb loadBalancer) (loadBalancerWire, error) {
	lsns, err := s.listeners(t).List(ctx, func(l listener) bool {
		return l.LoadBalancerID == lb.ID
	})
	if err != nil {
		return loadBalancerWire{}, err
	}
	slices.SortFunc(lsns, func(a, b listener) int { return strings.Compare(a.ID, b.ID) })
	lsnRefs := make([]idRef, len(lsns))
	for i, l := range lsns {
		lsnRefs[i] = idRef{ID: l.ID}
	}

	pls, err := s.pools(t).List(ctx, func(p pool) bool {
		return p.LoadBalancerID == lb.ID
	})
	if err != nil {
		return loadBalancerWire{}, err
	}
	slices.SortFunc(pls, func(a, b pool) int { return strings.Compare(a.ID, b.ID) })
	poolRefs := make([]idRef, len(pls))
	for i, p := range pls {
		poolRefs[i] = idRef{ID: p.ID}
	}

	eips, err := s.resolveEIPInfos(ctx, t, lb.EIPIDs)
	if err != nil {
		return loadBalancerWire{}, err
	}
	publicIPs := make([]publicIPInfoWire, len(eips))
	for i, e := range eips {
		publicIPs[i] = publicIPInfoWire{
			PublicIPID:      e.EIPID,
			PublicIPAddress: e.EIPAddress,
			IPVersion:       e.IPVersion,
		}
	}

	tags := make([]tag, len(lb.Tags))
	copy(tags, lb.Tags)
	azs := make([]string, len(lb.AvailabilityZoneList))
	copy(azs, lb.AvailabilityZoneList)
	virsubnets := make([]string, len(lb.ELBVirsubnetIDs))
	copy(virsubnets, lb.ELBVirsubnetIDs)

	provider := lb.Provider
	if provider == "" {
		provider = lbDefaultProvider
	}
	ps := lb.ProtectionStatus
	if ps == "" {
		ps = lbProtectionStatusNone
	}

	return loadBalancerWire{
		ID:                       lb.ID,
		Description:              lb.Description,
		ProvisioningStatus:       StatusActive,
		AdminStateUp:             lb.AdminStateUp,
		Provider:                 provider,
		Pools:                    poolRefs,
		Listeners:                lsnRefs,
		OperatingStatus:          StatusOnline,
		Name:                     lb.Name,
		ProjectID:                t.ProjectID,
		VIPSubnetCIDRID:          lb.VIPSubnetCIDRID,
		VIPAddress:               lb.VIPAddress,
		VIPPortID:                lb.VIPPortID,
		Tags:                     tags,
		CreatedAt:                formatTime(lb.CreatedAt),
		UpdatedAt:                formatTime(lb.UpdatedAt),
		Guaranteed:               lb.Guaranteed,
		VPCID:                    lb.VPCID,
		EIPs:                     eips,
		IPv6VIPAddress:           "",
		IPv6VIPVirsubnetID:       "",
		IPv6VIPPortID:            "",
		AvailabilityZoneList:     azs,
		EnterpriseProjectID:      lb.EnterpriseProjectID,
		BillingInfo:              "",
		L4FlavorID:               lb.L4FlavorID,
		L4ScaleFlavorID:          "",
		L7FlavorID:               lb.L7FlavorID,
		L7ScaleFlavorID:          "",
		LoadbalancerType:         lbTypeDedicated,
		PublicIPs:                publicIPs,
		GlobalEIPs:               []any{},
		ELBVirsubnetIDs:          virsubnets,
		ELBVirsubnetType:         lbVirsubnetTypeIPv4,
		IPTargetEnable:           lb.IPTargetEnable,
		FrozenScene:              "",
		DeletionProtectionEnable: lb.DeletionProtectionEnable,
		Autoscaling:              lb.Autoscaling,
		PublicBorderGroup:        lbPublicBorderGroupCenter,
		WafFailureAction:         lb.WafFailureAction,
		ProtectionStatus:         ps,
		ProtectionReason:         lb.ProtectionReason,
	}, nil
}

// --- §3.1 HTTP Handlers ---

func (s *Service) handleCreateLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createLoadBalancerRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Loadbalancer == nil {
		return errInvalidInput("loadbalancer")
	}
	opt := req.Loadbalancer

	in := createLoadBalancerInput{
		Name:                     opt.Name,
		Description:              opt.Description,
		VIPAddress:               opt.VIPAddress,
		VIPSubnetCIDRID:          opt.VIPSubnetCIDRID,
		VPCID:                    opt.VPCID,
		Provider:                 opt.Provider,
		L4FlavorID:               opt.L4FlavorID,
		L7FlavorID:               opt.L7FlavorID,
		Guaranteed:               opt.Guaranteed,
		AvailabilityZoneList:     opt.AvailabilityZoneList,
		Tags:                     opt.Tags,
		AdminStateUp:             opt.AdminStateUp,
		PublicIPIDs:              opt.PublicIPIDs,
		ELBVirsubnetIDs:          opt.ELBVirsubnetIDs,
		IPTargetEnable:           opt.IPTargetEnable,
		DeletionProtectionEnable: opt.DeletionProtectionEnable,
		Autoscaling:              opt.Autoscaling,
		WafFailureAction:         opt.WafFailureAction,
		ProtectionStatus:         opt.ProtectionStatus,
		ProtectionReason:         opt.ProtectionReason,
		OutOfScopeFeature:        checkCreateOutOfScope(opt),
	}
	if opt.EnterpriseProjectID != nil {
		in.EnterpriseProjectIDSet = true
		in.EnterpriseProjectID = *opt.EnterpriseProjectID
	}
	if opt.PublicIP != nil {
		pub := &createLoadBalancerPublicIPInput{
			IPVersion:   opt.PublicIP.IPVersion,
			NetworkType: opt.PublicIP.NetworkType,
			BillingInfo: opt.PublicIP.BillingInfo,
			Description: opt.PublicIP.Description,
		}
		if opt.PublicIP.Bandwidth != nil {
			pub.Bandwidth = &createLoadBalancerBandwidthInput{
				Name:        opt.PublicIP.Bandwidth.Name,
				Size:        opt.PublicIP.Bandwidth.Size,
				ChargeMode:  opt.PublicIP.Bandwidth.ChargeMode,
				ShareType:   opt.PublicIP.Bandwidth.ShareType,
				BillingInfo: opt.PublicIP.Bandwidth.BillingInfo,
				ID:          opt.PublicIP.Bandwidth.ID,
			}
		}
		in.PublicIP = pub
	}

	lb, err := s.createLoadBalancer(r.Context(), t, in)
	if err != nil {
		return err
	}
	wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, loadBalancerResponse{
		Loadbalancer: wire,
		RequestID:    requestID(r),
	})
}

func (s *Service) handleListLoadBalancers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	adminStateUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	if _, err := parseBoolQuery(q, "include_recycle_bin"); err != nil {
		return err
	}
	guaranteed, err := parseBoolQuery(q, "guaranteed")
	if err != nil {
		return err
	}
	delProt, err := parseBoolQuery(q, "deletion_protection_enable")
	if err != nil {
		return err
	}
	ipVersions, err := parseIntQueryValues(q, "ip_version")
	if err != nil {
		return err
	}

	items, pi, err := s.listLoadBalancers(r.Context(), t, listLoadBalancersFilter{
		IDs:                      q["id"],
		Names:                    q["name"],
		Descriptions:             q["description"],
		AdminStateUp:             adminStateUp,
		ProvisioningStatuses:     q["provisioning_status"],
		OperatingStatuses:        q["operating_status"],
		Guaranteed:               guaranteed,
		VPCIDs:                   q["vpc_id"],
		VIPPortIDs:               q["vip_port_id"],
		VIPAddresses:             q["vip_address"],
		VIPSubnetCIDRIDs:         q["vip_subnet_cidr_id"],
		IPv6VIPPortIDs:           q["ipv6_vip_port_id"],
		IPv6VIPAddresses:         q["ipv6_vip_address"],
		IPv6VIPVirsubnetIDs:      q["ipv6_vip_virsubnet_id"],
		EIPs:                     q["eips"],
		PublicIPs:                q["publicips"],
		AvailabilityZoneList:     q["availability_zone_list"],
		L4FlavorIDs:              q["l4_flavor_id"],
		L4ScaleFlavorIDs:         q["l4_scale_flavor_id"],
		L7FlavorIDs:              q["l7_flavor_id"],
		L7ScaleFlavorIDs:         q["l7_scale_flavor_id"],
		BillingInfos:             q["billing_info"],
		MemberDeviceIDs:          q["member_device_id"],
		MemberAddresses:          q["member_address"],
		EnterpriseProjectIDs:     q["enterprise_project_id"],
		IPVersions:               ipVersions,
		DeletionProtectionEnable: delProt,
		ELBVirsubnetTypes:        q["elb_virsubnet_type"],
		Autoscaling:              q["autoscaling"],
		ProtectionStatuses:       q["protection_status"],
		GlobalEIPs:               q["global_eips"],
		LogTopicIDs:              q["log_topic_id"],
		LogGroupIDs:              q["log_group_id"],
		Page:                     page,
	})
	if err != nil {
		return err
	}

	wires := make([]loadBalancerWire, 0, len(items))
	for _, lb := range items {
		wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
		if err != nil {
			return err
		}
		wires = append(wires, wire)
	}
	return httpx.WriteJSON(w, http.StatusOK, listLoadBalancersResponse{
		Loadbalancers: wires,
		PageInfo:      pi,
		RequestID:     requestID(r),
	})
}

func (s *Service) handleShowLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "loadbalancer_id")
	lb, err := s.getLoadBalancer(r.Context(), t, id)
	if err != nil {
		return err
	}
	wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, loadBalancerResponse{
		Loadbalancer: wire,
		RequestID:    requestID(r),
	})
}

func (s *Service) handleUpdateLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateLoadBalancerRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Loadbalancer == nil {
		return errInvalidInput("loadbalancer")
	}
	opt := req.Loadbalancer
	id := chi.URLParam(r, "loadbalancer_id")

	lb, err := s.updateLoadBalancer(r.Context(), t, id, updateLoadBalancerInput{
		Name:                     opt.Name,
		Description:              opt.Description,
		AdminStateUp:             opt.AdminStateUp,
		VIPSubnetCIDRIDPresent:   opt.vipSubnetCIDRIDPresent,
		VIPSubnetCIDRID:          opt.VIPSubnetCIDRID,
		VIPAddress:               opt.VIPAddress,
		L4FlavorID:               opt.L4FlavorID,
		L7FlavorID:               opt.L7FlavorID,
		IPTargetEnable:           opt.IPTargetEnable,
		ELBVirsubnetIDs:          opt.ELBVirsubnetIDs,
		DeletionProtectionEnable: opt.DeletionProtectionEnable,
		Autoscaling:              opt.Autoscaling,
		WafFailureAction:         opt.WafFailureAction,
		ProtectionStatus:         opt.ProtectionStatus,
		ProtectionReason:         opt.ProtectionReason,
		OutOfScopeFeature:        checkUpdateOutOfScope(opt),
	})
	if err != nil {
		return err
	}
	wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, loadBalancerResponse{
		Loadbalancer: wire,
		RequestID:    requestID(r),
	})
}

func (s *Service) handleDeleteLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "loadbalancer_id")
	if err := s.deleteLoadBalancer(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteLoadBalancerForce(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "loadbalancer_id")
	if err := s.deleteLoadBalancerForce(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleShowLoadBalancerStatus(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "loadbalancer_id")
	statuses, err := s.loadBalancerStatus(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showLoadBalancerStatusResponse{
		Statuses:  statuses,
		RequestID: requestID(r),
	})
}

func (s *Service) handleBatchAddAvailableZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchAvailableZonesRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	id := chi.URLParam(r, "loadbalancer_id")
	lb, err := s.batchAddAvailableZones(r.Context(), t, id, req.AvailabilityZoneList)
	if err != nil {
		return err
	}
	wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, loadBalancerResponse{
		Loadbalancer: wire,
		RequestID:    requestID(r),
	})
}

func (s *Service) handleBatchRemoveAvailableZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchAvailableZonesRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	id := chi.URLParam(r, "loadbalancer_id")
	lb, err := s.batchRemoveAvailableZones(r.Context(), t, id, req.AvailabilityZoneList)
	if err != nil {
		return err
	}
	wire, err := s.toLoadBalancerWire(r.Context(), t, lb)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, loadBalancerResponse{
		Loadbalancer: wire,
		RequestID:    requestID(r),
	})
}
