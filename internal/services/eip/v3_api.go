package eip

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

const (
	v3PublicIPTypeEIP          = "EIP"
	associateInstanceTypePort  = "PORT"
	associateInstanceTypeNATGW = "NATGW"
	associateInstanceTypeELB   = "ELB"
	billingModePayPerUse       = "PAY_PER_USE"
	maxDescriptionLen          = 255
	maxV3Offset                = 99999
)

// v3ListLimits bounds "limit" on v3 list operations: 0 to 2000, 2000 when omitted.
var v3ListLimits = pagination.Limits{Default: 2000, Min: 0, Max: 2000}

// subnetLookup is optionally implemented by Ports (vpc.Service) to resolve
// a port's VPC ID for vnic.vpc_id in v3 responses.
type subnetLookup interface {
	GetSubnet(ctx context.Context, t vpc.Tenant, id string) (vpc.Subnet, error)
}

func v3RequestID(r *http.Request) string {
	return reqctx.From(r.Context()).RequestID
}

type updatePublicIPV3Request struct {
	PublicIP *updatePublicIPOptionV3Wire `json:"publicip"`
}

type updatePublicIPOptionV3Wire struct {
	updatePublicIPOptionV3
	associateTypePresent bool
	associateIDPresent   bool
}

func (u *updatePublicIPOptionV3Wire) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, u.associateTypePresent = raw["associate_instance_type"]
	_, u.associateIDPresent = raw["associate_instance_id"]
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(&u.updatePublicIPOptionV3)
}

func (s *Service) handleListPublicIPsV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v3ListLimits)
	if err != nil {
		return errInvalidPublicIP("Invalid limit.")
	}
	offset := 0
	if raw := q.Get("offset"); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 0 || n > maxV3Offset {
			return errInvalidPublicIP("Invalid offset.")
		}
		offset = n
	}

	sortKey := q.Get("sort_key")
	if sortKey != "" && !validV3SortKey(sortKey) {
		return errInvalidPublicIP("Invalid sort_key.")
	}
	sortDir := q.Get("sort_dir")
	if sortDir != "" && sortDir != "asc" && sortDir != "desc" {
		return errInvalidPublicIP("Invalid sort_dir.")
	}

	items, err := s.publicips(t).List(r.Context(), nil)
	if err != nil {
		return err
	}

	matched := make([]publicIPSingleShowResp, 0, len(items))
	for _, p := range items {
		view, err := s.toPublicIPSingleShowResp(r.Context(), t, p)
		if err != nil {
			return err
		}
		if matchPublicIPV3Filter(q, view) {
			matched = append(matched, view)
		}
	}

	sortPublicIPsV3(matched, sortKey, sortDir)
	totalCount := len(matched)

	var window []publicIPSingleShowResp
	switch {
	case page.ID != "":
		window, err = pagination.ByMarker(matched, func(p publicIPSingleShowResp) string { return p.ID }, page)
		if err != nil {
			return errPublicIPNotFound()
		}
	case offset > 0:
		window = pagination.ByOffset(matched, pagination.Offset{Offset: offset, Limit: page.Limit})
	default:
		window, err = pagination.ByMarker(matched, func(p publicIPSingleShowResp) string { return p.ID }, page)
		if err != nil {
			return errPublicIPNotFound()
		}
	}
	if window == nil {
		window = []publicIPSingleShowResp{}
	}

	info := pageInfoOption{CurrentCount: len(window)}
	if len(window) > 0 {
		info.PreviousMarker = window[0].ID
		if last := window[len(window)-1].ID; last != matched[len(matched)-1].ID {
			info.NextMarker = &last
		}
	}

	return httpx.WriteJSON(w, http.StatusOK, listPublicIPsV3Response{
		RequestID:  v3RequestID(r),
		PublicIPs:  window,
		PageInfo:   info,
		TotalCount: totalCount,
	})
}

func (s *Service) handleShowPublicIPV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.getPublicIP(r.Context(), t, id)
	if err != nil {
		return err
	}
	out, err := s.toPublicIPSingleShowResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showPublicIPV3Response{
		RequestID: v3RequestID(r),
		PublicIP:  out,
	})
}

func (s *Service) handleUpdatePublicIPV3(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePublicIPV3Request
	if err := decode(r, &req, errInvalidV3Input); err != nil {
		return err
	}
	if req.PublicIP == nil {
		return errInvalidV3Input("")
	}
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.updatePublicIPV3(r.Context(), t, id, updatePublicIPV3Spec{
		Alias:                req.PublicIP.Alias,
		Description:          req.PublicIP.Description,
		AssociateTypePresent: req.PublicIP.associateTypePresent,
		AssociateType:        req.PublicIP.AssociateInstanceType,
		AssociateIDPresent:   req.PublicIP.associateIDPresent,
		AssociateID:          req.PublicIP.AssociateInstanceID,
	})
	if err != nil {
		return err
	}
	out, err := s.toPublicIPInstanceResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, publicIPInstanceV3Response{
		RequestID: v3RequestID(r),
		PublicIP:  out,
	})
}

func (s *Service) handleAssociatePublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req associatePublicIPsRequest
	if err := decode(r, &req, errInvalidV3Input); err != nil {
		return err
	}
	if req.PublicIP == nil {
		return errInvalidV3Input("")
	}
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.associatePublicIP(r.Context(), t, id, *req.PublicIP)
	if err != nil {
		return err
	}
	out, err := s.toPublicIPInstanceResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, publicIPInstanceV3Response{
		RequestID: v3RequestID(r),
		PublicIP:  out,
	})
}

func (s *Service) handleDisassociatePublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.disassociatePublicIP(r.Context(), t, id)
	if err != nil {
		return err
	}
	out, err := s.toPublicIPInstanceResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, publicIPInstanceV3Response{
		RequestID: v3RequestID(r),
		PublicIP:  out,
	})
}

func validateAssociateInstanceType(typ string) error {
	switch typ {
	case "":
		return errInvalidV3Input("")
	case associateInstanceTypePort:
		return nil
	case associateInstanceTypeNATGW, associateInstanceTypeELB, "ELBV1", "VPN":
		return apierr.NotImplemented("eip", "associating EIP with "+typ)
	default:
		return errInvalidV3Input("")
	}
}

func (s *Service) bindPublicIPLocked(ctx context.Context, t Tenant, pip *publicIP, portID string) error {
	port, ok, err := s.ports.Port(ctx, t, portID)
	if err != nil {
		return err
	}
	if !ok {
		return errInvalidPort()
	}
	if pip.Status == StatusPendingCreate {
		return errPublicIPBusy()
	}
	existing, err := s.publicips(t).List(ctx, nil)
	if err != nil {
		return err
	}
	for _, other := range existing {
		if other.ID != pip.ID && other.PortID == portID {
			return errPortAlreadyBound()
		}
	}
	if pip.NATGatewayID != "" || pip.ELBLoadBalancerID != "" || (pip.PortID != "" && pip.PortID != portID) {
		return errPublicIPAlreadyBound()
	}
	if pip.PortID == "" {
		pip.PortID = port.ID
		pip.PrivateIP = port.IP
		pip.Status = StatusActive
	}
	return nil
}

func unbindPublicIPLocked(pip *publicIP) error {
	if pip.Status == StatusPendingCreate {
		return errPublicIPBusy()
	}
	if pip.PortID != "" && pip.ELBLoadBalancerID == "" {
		pip.PortID = ""
		pip.PrivateIP = ""
		pip.Status = StatusDown
	}
	return nil
}

func (s *Service) associatePublicIP(ctx context.Context, t Tenant, id string, opt associatePublicIPsOption) (publicIP, error) {
	if err := validateAssociateInstanceType(opt.AssociateInstanceType); err != nil {
		return publicIP{}, err
	}
	if opt.AssociateInstanceID == "" {
		return publicIP{}, errInvalidV3Input("")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return publicIP{}, errPublicIPNotFound()
	}
	if err != nil {
		return publicIP{}, err
	}

	if err := s.bindPublicIPLocked(ctx, t, &pip, opt.AssociateInstanceID); err != nil {
		return publicIP{}, err
	}
	pip.UpdatedAt = s.nowUTC()
	if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
		return publicIP{}, err
	}
	return pip, nil
}

func (s *Service) disassociatePublicIP(ctx context.Context, t Tenant, id string) (publicIP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return publicIP{}, errPublicIPNotFound()
	}
	if err != nil {
		return publicIP{}, err
	}
	if pip.Status == StatusPendingCreate {
		return publicIP{}, errPublicIPBusy()
	}
	if pip.PortID != "" && pip.ELBLoadBalancerID == "" {
		pip.PortID = ""
		pip.PrivateIP = ""
		pip.Status = StatusDown
		pip.UpdatedAt = s.nowUTC()
		if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
			return publicIP{}, err
		}
	}
	return pip, nil
}

type updatePublicIPV3Spec struct {
	Alias                *string
	Description          *string
	AssociateTypePresent bool
	AssociateType        *string
	AssociateIDPresent   bool
	AssociateID          *string
}

func (s *Service) updatePublicIPV3(ctx context.Context, t Tenant, id string, spec updatePublicIPV3Spec) (publicIP, error) {
	if spec.Alias != nil && *spec.Alias != "" && !validName(*spec.Alias) {
		return publicIP{}, errInvalidV3Input("alias is invalid")
	}
	if spec.Description != nil {
		if utf8.RuneCountInString(*spec.Description) > maxDescriptionLen {
			return publicIP{}, errInvalidV3Input("description must not exceed %d characters", maxDescriptionLen)
		}
		if strings.ContainsAny(*spec.Description, "<>") {
			return publicIP{}, errInvalidV3Input("description cannot contain angle brackets (< or >)")
		}
	}

	var (
		bindPortID string
		doBind     bool
		doUnbind   bool
	)
	if spec.AssociateTypePresent || spec.AssociateIDPresent {
		typeVal := derefString(spec.AssociateType)
		idVal := derefString(spec.AssociateID)
		switch {
		case spec.AssociateTypePresent && spec.AssociateIDPresent && typeVal == "" && idVal == "":
			doUnbind = true
		case typeVal != "":
			if err := validateAssociateInstanceType(typeVal); err != nil {
				return publicIP{}, err
			}
			if idVal == "" {
				return publicIP{}, errInvalidV3Input("")
			}
			doBind = true
			bindPortID = idVal
		default:
			return publicIP{}, errInvalidV3Input("")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pip, err := s.publicips(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return publicIP{}, errPublicIPNotFound()
	}
	if err != nil {
		return publicIP{}, err
	}

	if doBind {
		if err := s.bindPublicIPLocked(ctx, t, &pip, bindPortID); err != nil {
			return publicIP{}, err
		}
	} else if doUnbind {
		if err := unbindPublicIPLocked(&pip); err != nil {
			return publicIP{}, err
		}
	}

	if spec.Alias != nil {
		pip.Alias = *spec.Alias
	}
	if spec.Description != nil {
		pip.Description = *spec.Description
	}
	pip.UpdatedAt = s.nowUTC()
	if err := s.publicips(t).Put(ctx, pip.ID, pip); err != nil {
		return publicIP{}, err
	}
	return pip, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Service) toPublicIPSingleShowResp(ctx context.Context, t Tenant, p publicIP) (publicIPSingleShowResp, error) {
	var bwInfo *publicIPBandwidthInfo
	if p.BandwidthID != "" {
		bw, err := s.bandwidths(t).Get(ctx, p.BandwidthID)
		if err == nil {
			bwInfo = &publicIPBandwidthInfo{
				ID:         bw.ID,
				Size:       bw.Size,
				ShareType:  bw.ShareType,
				ChargeMode: bw.ChargeMode,
				Name:       bw.Name,
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return publicIPSingleShowResp{}, err
		}
	}

	var (
		vnic      *vnicInfo
		assocType *string
		assocID   *string
	)
	switch {
	case p.ELBLoadBalancerID != "":
		if p.PortID != "" {
			vnic = &vnicInfo{
				PrivateIPAddress: p.PrivateIP,
				PortID:           p.PortID,
			}
		}
		typ := associateInstanceTypeELB
		lbID := p.ELBLoadBalancerID
		assocType = &typ
		assocID = &lbID
	case p.PortID != "":
		v := &vnicInfo{
			PrivateIPAddress: p.PrivateIP,
			PortID:           p.PortID,
		}
		port, ok, err := s.ports.Port(ctx, t, p.PortID)
		if err != nil {
			return publicIPSingleShowResp{}, err
		}
		if ok {
			if port.IP != "" {
				v.PrivateIPAddress = port.IP
			}
			v.DeviceID = port.DeviceID
			v.DeviceOwner = port.DeviceOwner
			v.MAC = port.MAC
			if port.SubnetID != "" {
				if sl, hasSubnet := s.ports.(subnetLookup); hasSubnet {
					sn, snErr := sl.GetSubnet(ctx, t, port.SubnetID)
					var apiErr *apierr.Error
					switch {
					case snErr == nil:
						v.VPCID = sn.VPCID
					case !errors.As(snErr, &apiErr):
						return publicIPSingleShowResp{}, snErr
					}
				}
			}
		}
		vnic = v
		typ := associateInstanceTypePort
		pid := p.PortID
		assocType = &typ
		assocID = &pid
	case p.NATGatewayID != "":
		typ := associateInstanceTypeNATGW
		gwID := p.NATGatewayID
		assocType = &typ
		assocID = &gwID
	}

	poolName := p.Type
	if poolName == "" {
		poolName = "5_bgp"
	}

	var tags []string
	if len(p.Tags) > 0 {
		tags = make([]string, 0, len(p.Tags))
		for _, tg := range p.Tags {
			tags = append(tags, tg.Key+"="+tg.Value)
		}
	}

	return publicIPSingleShowResp{
		ID:                    p.ID,
		ProjectID:             t.ProjectID,
		IPVersion:             4,
		PublicIPAddress:       p.Address,
		NetworkType:           poolName,
		Status:                p.Status,
		Description:           p.Description,
		PublicBorderGroup:     PublicBorderGroupCenter,
		CreatedAt:             p.CreatedAt.UTC().Format(v3TimeFormat),
		UpdatedAt:             p.UpdatedAt.UTC().Format(v3TimeFormat),
		Type:                  v3PublicIPTypeEIP,
		Vnic:                  vnic,
		Bandwidth:             bwInfo,
		EnterpriseProjectID:   p.EnterpriseProjectID,
		BillingInfo:           nil,
		LockStatus:            "",
		AssociateInstanceType: assocType,
		AssociateInstanceID:   assocID,
		PublicIPPoolID:        nil,
		PublicIPPoolName:      poolName,
		Alias:                 p.Alias,
		Tags:                  tags,
	}, nil
}

func (s *Service) toPublicIPInstanceResp(ctx context.Context, t Tenant, p publicIP) (publicIPInstanceResp, error) {
	show, err := s.toPublicIPSingleShowResp(ctx, t, p)
	if err != nil {
		return publicIPInstanceResp{}, err
	}
	return publicIPInstanceResp{
		ID:                    show.ID,
		ProjectID:             show.ProjectID,
		IPVersion:             show.IPVersion,
		PublicIPAddress:       show.PublicIPAddress,
		Status:                show.Status,
		Description:           show.Description,
		PublicBorderGroup:     show.PublicBorderGroup,
		CreatedAt:             show.CreatedAt,
		UpdatedAt:             show.UpdatedAt,
		Type:                  show.Type,
		Vnic:                  show.Vnic,
		Bandwidth:             show.Bandwidth,
		EnterpriseProjectID:   show.EnterpriseProjectID,
		BillingInfo:           show.BillingInfo,
		LockStatus:            show.LockStatus,
		AssociateInstanceType: show.AssociateInstanceType,
		AssociateInstanceID:   show.AssociateInstanceID,
		PublicIPPoolID:        show.PublicIPPoolID,
		PublicIPPoolName:      show.PublicIPPoolName,
		Alias:                 show.Alias,
	}, nil
}

func validV3SortKey(k string) bool {
	switch k {
	case "id", "public_ip_address", "public_ipv6_address", "ip_version",
		"created_at", "updated_at", "public_border_group":
		return true
	default:
		return false
	}
}

func sortPublicIPsV3(items []publicIPSingleShowResp, sortKey, sortDir string) {
	desc := sortDir == "desc"
	slices.SortFunc(items, func(a, b publicIPSingleShowResp) int {
		var d int
		switch sortKey {
		case "public_ip_address":
			d = strings.Compare(a.PublicIPAddress, b.PublicIPAddress)
		case "ip_version":
			d = cmp.Compare(a.IPVersion, b.IPVersion)
		case "created_at":
			d = strings.Compare(a.CreatedAt, b.CreatedAt)
		case "updated_at":
			d = strings.Compare(a.UpdatedAt, b.UpdatedAt)
		case "public_border_group":
			d = strings.Compare(a.PublicBorderGroup, b.PublicBorderGroup)
		default:
			d = strings.Compare(a.ID, b.ID)
		}
		if d == 0 {
			d = strings.Compare(a.ID, b.ID)
		}
		if desc {
			return -d
		}
		return d
	})
}

func matchPublicIPV3Filter(q url.Values, p publicIPSingleShowResp) bool {
	if !matchFilterSlice(q["id"], p.ID) {
		return false
	}
	if !matchFilterSlice(q["ip_version"], strconv.Itoa(p.IPVersion)) {
		return false
	}
	if !matchFilterSlice(q["public_ip_address"], p.PublicIPAddress) {
		return false
	}
	if like := q.Get("public_ip_address_like"); like != "" && !strings.Contains(p.PublicIPAddress, like) {
		return false
	}
	if len(q["public_ipv6_address"]) > 0 || q.Get("public_ipv6_address_like") != "" {
		return false
	}
	if !matchFilterSlice(q["type"], p.Type) {
		return false
	}
	if !matchFilterSlice(q["network_type"], p.NetworkType) {
		return false
	}
	if !matchFilterSlice(q["publicip_pool_name"], p.PublicIPPoolName) {
		return false
	}
	if !matchFilterSlice(q["status"], p.Status) {
		return false
	}
	if !matchFilterSlice(q["alias"], p.Alias) {
		return false
	}
	if like := q.Get("alias_like"); like != "" && !strings.Contains(p.Alias, like) {
		return false
	}
	if !matchFilterSlice(q["description"], p.Description) {
		return false
	}
	if !matchVnicFilter(q, p.Vnic) {
		return false
	}
	if !matchBandwidthFilter(q, p.Bandwidth) {
		return false
	}
	if len(q["billing_info"]) > 0 {
		return false
	}
	if mode := q.Get("billing_mode"); mode != "" && mode != billingModePayPerUse {
		return false
	}
	if !matchFilterSlice(q["associate_instance_type"], derefString(p.AssociateInstanceType)) {
		return false
	}
	if !matchFilterSlice(q["associate_instance_id"], derefString(p.AssociateInstanceID)) {
		return false
	}
	if eps := q["enterprise_project_id"]; len(eps) > 0 && !slices.Contains(eps, allGrantedEPs) && !slices.Contains(eps, p.EnterpriseProjectID) {
		return false
	}
	if !matchFilterSlice(q["public_border_group"], p.PublicBorderGroup) {
		return false
	}
	return true
}

func matchVnicFilter(q url.Values, v *vnicInfo) bool {
	hasVnicFilter := len(q["vnic.private_ip_address"]) > 0 ||
		q.Get("vnic.private_ip_address_like") != "" ||
		len(q["vnic.device_id"]) > 0 ||
		len(q["vnic.device_owner"]) > 0 ||
		q.Get("vnic.device_owner_prefixlike") != "" ||
		len(q["vnic.vpc_id"]) > 0 ||
		len(q["vnic.port_id"]) > 0 ||
		len(q["vnic.instance_type"]) > 0 ||
		len(q["vnic.instance_id"]) > 0
	if !hasVnicFilter {
		return true
	}
	if v == nil {
		return false
	}
	if len(q["vnic.instance_type"]) > 0 || len(q["vnic.instance_id"]) > 0 {
		return false
	}
	if !matchFilterSlice(q["vnic.private_ip_address"], v.PrivateIPAddress) {
		return false
	}
	if like := q.Get("vnic.private_ip_address_like"); like != "" && !strings.Contains(v.PrivateIPAddress, like) {
		return false
	}
	if !matchFilterSlice(q["vnic.device_id"], v.DeviceID) {
		return false
	}
	if !matchFilterSlice(q["vnic.device_owner"], v.DeviceOwner) {
		return false
	}
	if pref := q.Get("vnic.device_owner_prefixlike"); pref != "" && !strings.HasPrefix(v.DeviceOwner, pref) {
		return false
	}
	if !matchFilterSlice(q["vnic.vpc_id"], v.VPCID) {
		return false
	}
	if !matchFilterSlice(q["vnic.port_id"], v.PortID) {
		return false
	}
	return true
}

func matchBandwidthFilter(q url.Values, b *publicIPBandwidthInfo) bool {
	hasBWFilter := len(q["bandwidth.id"]) > 0 ||
		len(q["bandwidth.name"]) > 0 ||
		len(q["bandwidth.name_like"]) > 0 ||
		len(q["bandwidth.size"]) > 0 ||
		len(q["bandwidth.share_type"]) > 0 ||
		len(q["bandwidth.charge_mode"]) > 0
	if !hasBWFilter {
		return true
	}
	if b == nil {
		return false
	}
	if !matchFilterSlice(q["bandwidth.id"], b.ID) {
		return false
	}
	if !matchFilterSlice(q["bandwidth.name"], b.Name) {
		return false
	}
	if likes := q["bandwidth.name_like"]; len(likes) > 0 {
		matched := false
		for _, sub := range likes {
			if strings.Contains(b.Name, sub) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if !matchFilterSlice(q["bandwidth.size"], strconv.Itoa(b.Size)) {
		return false
	}
	if !matchFilterSlice(q["bandwidth.share_type"], b.ShareType) {
		return false
	}
	if !matchFilterSlice(q["bandwidth.charge_mode"], b.ChargeMode) {
		return false
	}
	return true
}
