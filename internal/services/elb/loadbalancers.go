package elb

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

const (
	lbDefaultProvider         = "vlb"
	lbTypeDedicated           = "dedicated"
	lbVirsubnetTypeIPv4       = "ipv4"
	lbPublicBorderGroupCenter = "center"
	lbProtectionStatusNone    = "nonProtection"
	lbProtectionStatusConsole = "consoleProtection"
	lbWafFailureForward       = "forward"
	lbWafFailureDiscard       = "discard"
)

type createLoadBalancerBandwidthInput struct {
	Name        *string
	Size        *int
	ChargeMode  *string
	ShareType   *string
	ID          *string
	BillingInfo *string
}

type createLoadBalancerPublicIPInput struct {
	IPVersion   *int
	NetworkType string
	BillingInfo *string
	Description *string
	Bandwidth   *createLoadBalancerBandwidthInput
}

type createLoadBalancerInput struct {
	Name                     string
	Description              string
	VIPAddress               string
	VIPSubnetCIDRID          string
	VPCID                    string
	Provider                 string
	L4FlavorID               string
	L7FlavorID               string
	Guaranteed               *bool
	AvailabilityZoneList     []string
	EnterpriseProjectID      string
	EnterpriseProjectIDSet   bool
	Tags                     []tag
	AdminStateUp             *bool
	PublicIPIDs              []string
	PublicIP                 *createLoadBalancerPublicIPInput
	ELBVirsubnetIDs          []string
	IPTargetEnable           *bool
	DeletionProtectionEnable *bool
	Autoscaling              *autoscalingRef
	WafFailureAction         string
	ProtectionStatus         string
	ProtectionReason         string
	// Out-of-scope fields that yield WeiStack.0501 when present.
	OutOfScopeFeature string
}

type updateLoadBalancerInput struct {
	Name                     *string
	Description              *string
	AdminStateUp             *bool
	VIPSubnetCIDRIDPresent   bool
	VIPSubnetCIDRID          *string
	VIPAddress               *string
	L4FlavorID               *string
	L7FlavorID               *string
	IPTargetEnable           *bool
	ELBVirsubnetIDs          *[]string
	DeletionProtectionEnable *bool
	Autoscaling              *autoscalingRef
	WafFailureAction         *string
	ProtectionStatus         *string
	ProtectionReason         *string
	// Out-of-scope fields that yield WeiStack.0501 when present.
	OutOfScopeFeature string
}

type listLoadBalancersFilter struct {
	IDs                      []string
	Names                    []string
	Descriptions             []string
	AdminStateUp             *bool
	ProvisioningStatuses     []string
	OperatingStatuses        []string
	Guaranteed               *bool
	VPCIDs                   []string
	VIPPortIDs               []string
	VIPAddresses             []string
	VIPSubnetCIDRIDs         []string
	IPv6VIPPortIDs           []string
	IPv6VIPAddresses         []string
	IPv6VIPVirsubnetIDs      []string
	EIPs                     []string
	PublicIPs                []string
	AvailabilityZoneList     []string
	L4FlavorIDs              []string
	L4ScaleFlavorIDs         []string
	L7FlavorIDs              []string
	L7ScaleFlavorIDs         []string
	BillingInfos             []string
	MemberDeviceIDs          []string
	MemberAddresses          []string
	EnterpriseProjectIDs     []string
	IPVersions               []int
	DeletionProtectionEnable *bool
	ELBVirsubnetTypes        []string
	Autoscaling              []string
	ProtectionStatuses       []string
	GlobalEIPs               []string
	LogTopicIDs              []string
	LogGroupIDs              []string
	Page                     pagination.Marker
}

func lbIsAPIError(err error) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr)
}

func lbValidProtectionStatus(s string) bool {
	return s == lbProtectionStatusNone || s == lbProtectionStatusConsole
}

func lbValidProtectionReason(s string) bool {
	return utf8.RuneCountInString(s) <= 255 && !strings.ContainsAny(s, "<>")
}

func lbValidWafFailureAction(s string) bool {
	return s == lbWafFailureForward || s == lbWafFailureDiscard
}

func lbValidBandwidthName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func mapAllocateIPError(err error, subnetCIDRID string) error {
	switch {
	case errors.Is(err, vpc.ErrSubnetNotFound):
		return errNotFound("subnet", subnetCIDRID)
	case errors.Is(err, vpc.ErrIPNotUsable):
		return errInvalidInput("vip_address")
	case errors.Is(err, vpc.ErrIPInUse):
		return errConflict("VIP address is already in use.")
	case errors.Is(err, vpc.ErrSubnetFull):
		return errSubnetFull()
	default:
		return err
	}
}

func mapEIPError(err error, eipID, bwID string) error {
	switch {
	case errors.Is(err, eip.ErrNATNotFound):
		return errNotFound("publicip", eipID)
	case errors.Is(err, eip.ErrNATBound):
		return errConflict("The EIP is already bound.")
	case errors.Is(err, eip.ErrNATHeld):
		return errConflict("The EIP is already in use by a NAT gateway.")
	case errors.Is(err, eip.ErrNATNotReady):
		return errConflict("The EIP is not ready.")
	}
	var apiErr *apierr.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "VPC.0306":
			return errNotFound("bandwidth", bwID)
		case "VPC.0504":
			return errNotFound("publicip", eipID)
		case "VPC.0510", "VPC.0511", "VPC.0512", "VPC.0517", "VPC.0521", "VPC.0522", "VPC.0532":
			return errConflict(apiErr.Message)
		default:
			return errInvalidInput("publicip")
		}
	}
	return err
}

func validateAZList(region string, azs []string) error {
	if len(azs) == 0 {
		return errInvalidInput("availability_zone_list")
	}
	seen := make(map[string]struct{}, len(azs))
	for _, az := range azs {
		if !zones.Exists(region, az) {
			return errInvalidInput("availability_zone_list")
		}
		if _, dup := seen[az]; dup {
			return errInvalidInput("availability_zone_list")
		}
		seen[az] = struct{}{}
	}
	return nil
}

func buildELBServerIP(pub *createLoadBalancerPublicIPInput, epID string) (eip.ServerIP, string, error) {
	if pub.BillingInfo != nil && *pub.BillingInfo != "" {
		return eip.ServerIP{}, "", errNotImplemented("publicip.billing_info")
	}
	if pub.IPVersion != nil {
		switch *pub.IPVersion {
		case 4:
		case 6:
			return eip.ServerIP{}, "", errNotImplemented("ipv6 publicip")
		default:
			return eip.ServerIP{}, "", errInvalidInput("publicip.ip_version")
		}
	}
	if pub.NetworkType == "" {
		return eip.ServerIP{}, "", errInvalidInput("publicip.network_type")
	}
	if pub.Bandwidth == nil {
		return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth")
	}
	bw := pub.Bandwidth
	if bw.BillingInfo != nil && *bw.BillingInfo != "" {
		return eip.ServerIP{}, "", errNotImplemented("publicip.bandwidth.billing_info")
	}
	desc := ""
	if pub.Description != nil {
		if !validDescription(*pub.Description) {
			return eip.ServerIP{}, "", errInvalidInput("publicip.description")
		}
		desc = *pub.Description
	}

	if bw.ID != nil && *bw.ID != "" {
		if bw.ShareType != nil && *bw.ShareType != "" && *bw.ShareType != eip.ShareTypeWhole {
			return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.share_type")
		}
		return eip.ServerIP{
			Type:                pub.NetworkType,
			ShareType:           eip.ShareTypeWhole,
			BandwidthID:         *bw.ID,
			Description:         desc,
			EnterpriseProjectID: epID,
		}, *bw.ID, nil
	}

	if bw.ShareType == nil || *bw.ShareType == "" {
		return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.share_type")
	}
	switch *bw.ShareType {
	case eip.ShareTypeWhole:
		return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.id")
	case eip.ShareTypePer:
		if bw.Name == nil || !lbValidBandwidthName(*bw.Name) {
			return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.name")
		}
		if bw.Size == nil || *bw.Size < 1 || *bw.Size > 2000 {
			return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.size")
		}
		if bw.ChargeMode == nil || (*bw.ChargeMode != eip.ChargeModeBandwidth && *bw.ChargeMode != eip.ChargeModeTraffic) {
			return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.charge_mode")
		}
		return eip.ServerIP{
			Type:                pub.NetworkType,
			ShareType:           eip.ShareTypePer,
			Size:                *bw.Size,
			ChargeMode:          *bw.ChargeMode,
			BandwidthName:       *bw.Name,
			Description:         desc,
			EnterpriseProjectID: epID,
		}, "", nil
	default:
		return eip.ServerIP{}, "", errInvalidInput("publicip.bandwidth.share_type")
	}
}

func (s *Service) createLoadBalancer(ctx context.Context, t Tenant, in createLoadBalancerInput) (loadBalancer, error) {
	if in.OutOfScopeFeature != "" {
		return loadBalancer{}, errNotImplemented(in.OutOfScopeFeature)
	}
	if !validName(in.Name) {
		return loadBalancer{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return loadBalancer{}, errInvalidInput("description")
	}
	provider := in.Provider
	if provider == "" {
		provider = lbDefaultProvider
	}
	if provider != lbDefaultProvider {
		return loadBalancer{}, errInvalidInput("provider")
	}
	guaranteed := true
	if in.Guaranteed != nil {
		if !*in.Guaranteed {
			return loadBalancer{}, errInvalidInput("guaranteed")
		}
		guaranteed = *in.Guaranteed
	}
	adminStateUp := true
	if in.AdminStateUp != nil {
		adminStateUp = *in.AdminStateUp
	}
	ipTargetEnable := false
	if in.IPTargetEnable != nil {
		ipTargetEnable = *in.IPTargetEnable
	}
	deletionProtection := false
	if in.DeletionProtectionEnable != nil {
		deletionProtection = *in.DeletionProtectionEnable
	}
	epID := defaultEnterpriseProjectID
	if in.EnterpriseProjectIDSet {
		if in.EnterpriseProjectID == "" || !validEnterpriseProjectID(in.EnterpriseProjectID) {
			return loadBalancer{}, errInvalidInput("enterprise_project_id")
		}
		epID = in.EnterpriseProjectID
	}
	if err := validTags(in.Tags); err != nil {
		return loadBalancer{}, err
	}
	if in.WafFailureAction != "" && !lbValidWafFailureAction(in.WafFailureAction) {
		return loadBalancer{}, errInvalidInput("waf_failure_action")
	}
	protectionStatus := in.ProtectionStatus
	if protectionStatus == "" {
		protectionStatus = lbProtectionStatusNone
	}
	if !lbValidProtectionStatus(protectionStatus) {
		return loadBalancer{}, errInvalidInput("protection_status")
	}
	if !lbValidProtectionReason(in.ProtectionReason) {
		return loadBalancer{}, errInvalidInput("protection_reason")
	}
	if err := validateAZList(t.Region, in.AvailabilityZoneList); err != nil {
		return loadBalancer{}, err
	}

	// Flavors: at least one required; L4 must be type L4, L7 must be type L7 (§3.1).
	if in.L4FlavorID == "" && in.L7FlavorID == "" {
		return loadBalancer{}, errInvalidInput("l4_flavor_id")
	}
	if in.L4FlavorID != "" {
		f, ok := findSeededFlavor(t.Region, t.ProjectID, in.L4FlavorID)
		if !ok {
			return loadBalancer{}, errNotFound("flavor", in.L4FlavorID)
		}
		if f.Type != "L4" {
			return loadBalancer{}, errInvalidInput("l4_flavor_id")
		}
	}
	if in.L7FlavorID != "" {
		f, ok := findSeededFlavor(t.Region, t.ProjectID, in.L7FlavorID)
		if !ok {
			return loadBalancer{}, errNotFound("flavor", in.L7FlavorID)
		}
		if f.Type != "L7" {
			return loadBalancer{}, errInvalidInput("l7_flavor_id")
		}
	}

	// Network preconditions (§3.1).
	if in.VIPAddress != "" && in.VIPSubnetCIDRID == "" {
		return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
	}
	if in.VIPSubnetCIDRID == "" && len(in.ELBVirsubnetIDs) == 0 {
		return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
	}

	// EIP preconditions (§3.1).
	hasPublicIP := in.PublicIP != nil
	hasPublicIPIDs := len(in.PublicIPIDs) > 0
	if hasPublicIP && hasPublicIPIDs {
		return loadBalancer{}, errInvalidInput("publicip")
	}
	if (hasPublicIP || hasPublicIPIDs) && in.VIPSubnetCIDRID == "" {
		return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
	}
	var (
		bindEIPID string
		serverIP  eip.ServerIP
		wholeBWID string
	)
	if hasPublicIPIDs {
		bindEIPID = in.PublicIPIDs[0]
		if bindEIPID == "" {
			return loadBalancer{}, errInvalidInput("publicip_ids")
		}
	}
	if hasPublicIP {
		var err error
		serverIP, wholeBWID, err = buildELBServerIP(in.PublicIP, epID)
		if err != nil {
			return loadBalancer{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	vpcID := in.VPCID
	if vpcID != "" {
		if _, err := s.vpc.GetVPC(ctx, t, vpcID); lbIsAPIError(err) {
			return loadBalancer{}, errNotFound("vpc", vpcID)
		} else if err != nil {
			return loadBalancer{}, err
		}
	}

	var vipSubnet vpc.Subnet
	if in.VIPSubnetCIDRID != "" {
		sn, ok, err := s.findSubnetByNeutronID(ctx, t, in.VIPSubnetCIDRID)
		if err != nil {
			return loadBalancer{}, err
		}
		if !ok {
			return loadBalancer{}, errNotFound("subnet", in.VIPSubnetCIDRID)
		}
		if vpcID != "" && sn.VPCID != vpcID {
			return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
		}
		if vpcID == "" {
			vpcID = sn.VPCID
		}
		vipSubnet = sn
	}

	virsubnets := make([]string, 0, len(in.ELBVirsubnetIDs))
	seenVir := make(map[string]struct{}, len(in.ELBVirsubnetIDs))
	for _, snID := range in.ELBVirsubnetIDs {
		if snID == "" {
			return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
		}
		if _, dup := seenVir[snID]; dup {
			return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
		}
		seenVir[snID] = struct{}{}
		sn, err := s.vpc.GetSubnet(ctx, t, snID)
		if lbIsAPIError(err) {
			return loadBalancer{}, errNotFound("subnet", snID)
		}
		if err != nil {
			return loadBalancer{}, err
		}
		if vpcID != "" && sn.VPCID != vpcID {
			return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
		}
		if vpcID == "" {
			vpcID = sn.VPCID
		}
		virsubnets = append(virsubnets, sn.ID)
	}
	if len(virsubnets) == 0 && vipSubnet.ID != "" {
		virsubnets = []string{vipSubnet.ID}
	}

	lbID := s.ids.UUID()
	var (
		vipAddress string
		vipPortID  string
	)
	if in.VIPSubnetCIDRID != "" {
		addr, err := s.vpc.AllocateIP(ctx, t, vipSubnet.ID, "elb:"+lbID, in.VIPAddress)
		if err != nil {
			return loadBalancer{}, mapAllocateIPError(err, in.VIPSubnetCIDRID)
		}
		vipAddress = addr
		vipPortID = s.ids.UUID()
	}

	eipIDs := []string{}
	if hasPublicIPIDs {
		if _, err := s.eips.BindToELB(ctx, t, bindEIPID, lbID, vipPortID, vipAddress); err != nil {
			if vipAddress != "" {
				_ = s.vpc.ReleaseIP(ctx, t, vipSubnet.ID, vipAddress)
			}
			return loadBalancer{}, mapEIPError(err, bindEIPID, "")
		}
		eipIDs = []string{bindEIPID}
	} else if hasPublicIP {
		newEIPID, _, err := s.eips.CreateForELB(ctx, t, lbID, vipPortID, vipAddress, serverIP)
		if err != nil {
			if vipAddress != "" {
				_ = s.vpc.ReleaseIP(ctx, t, vipSubnet.ID, vipAddress)
			}
			return loadBalancer{}, mapEIPError(err, "", wholeBWID)
		}
		eipIDs = []string{newEIPID}
	}

	now := s.nowUTC()
	azs := make([]string, len(in.AvailabilityZoneList))
	copy(azs, in.AvailabilityZoneList)
	tags := make([]tag, len(in.Tags))
	copy(tags, in.Tags)

	var autoscaling *autoscalingRef
	if in.Autoscaling != nil {
		cp := *in.Autoscaling
		if in.Autoscaling.MinL7FlavorID != nil {
			v := *in.Autoscaling.MinL7FlavorID
			cp.MinL7FlavorID = &v
		}
		autoscaling = &cp
	}

	lb := loadBalancer{
		ID:                       lbID,
		Name:                     in.Name,
		Description:              in.Description,
		AdminStateUp:             adminStateUp,
		Provider:                 provider,
		VPCID:                    vpcID,
		VIPSubnetCIDRID:          in.VIPSubnetCIDRID,
		VIPSubnetID:              vipSubnet.ID,
		VIPAddress:               vipAddress,
		VIPPortID:                vipPortID,
		ELBVirsubnetIDs:          virsubnets,
		AvailabilityZoneList:     azs,
		L4FlavorID:               in.L4FlavorID,
		L7FlavorID:               in.L7FlavorID,
		Guaranteed:               guaranteed,
		IPTargetEnable:           ipTargetEnable,
		DeletionProtectionEnable: deletionProtection,
		EnterpriseProjectID:      epID,
		EIPIDs:                   eipIDs,
		Autoscaling:              autoscaling,
		WafFailureAction:         in.WafFailureAction,
		ProtectionStatus:         protectionStatus,
		ProtectionReason:         in.ProtectionReason,
		Tags:                     tags,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	if err := s.loadBalancers(t).Create(ctx, lb.ID, lb); err != nil {
		for _, eid := range eipIDs {
			_ = s.eips.UnbindFromELB(ctx, t, eid, lbID)
		}
		if vipAddress != "" {
			_ = s.vpc.ReleaseIP(ctx, t, vipSubnet.ID, vipAddress)
		}
		return loadBalancer{}, err
	}
	return lb, nil
}

func (s *Service) getLoadBalancer(ctx context.Context, t Tenant, id string) (loadBalancer, error) {
	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return loadBalancer{}, errNotFound("loadbalancer", id)
	}
	return lb, err
}

func (s *Service) listLoadBalancers(ctx context.Context, t Tenant, f listLoadBalancersFilter) ([]loadBalancer, pageInfo, error) {
	all, err := s.loadBalancers(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}

	// Preload LB->member addresses only if member_address filter is specified.
	var lbMemberAddrs map[string]map[string]struct{}
	if len(f.MemberAddresses) > 0 {
		lbMemberAddrs, err = s.loadMemberAddressesByLB(ctx, t)
		if err != nil {
			return nil, pageInfo{}, err
		}
	}

	matched := make([]loadBalancer, 0, len(all))
	for _, lb := range all {
		ok, err := s.matchLoadBalancerFilter(ctx, t, lb, f, lbMemberAddrs)
		if err != nil {
			return nil, pageInfo{}, err
		}
		if ok {
			matched = append(matched, lb)
		}
	}

	slices.SortFunc(matched, func(a, b loadBalancer) int {
		return strings.Compare(a.ID, b.ID)
	})
	return paginateSlice(matched, func(lb loadBalancer) string { return lb.ID }, f.Page)
}

func (s *Service) loadMemberAddressesByLB(ctx context.Context, t Tenant) (map[string]map[string]struct{}, error) {
	pools, err := s.pools(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	poolToLB := make(map[string]string, len(pools))
	for _, p := range pools {
		if p.LoadBalancerID != "" {
			poolToLB[p.ID] = p.LoadBalancerID
		}
	}
	members, err := s.members(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]struct{})
	for _, m := range members {
		lbID := poolToLB[m.PoolID]
		if lbID == "" {
			continue
		}
		if out[lbID] == nil {
			out[lbID] = make(map[string]struct{})
		}
		out[lbID][m.Address] = struct{}{}
	}
	return out, nil
}

func (s *Service) matchLoadBalancerFilter(
	ctx context.Context,
	t Tenant,
	lb loadBalancer,
	f listLoadBalancersFilter,
	lbMemberAddrs map[string]map[string]struct{},
) (bool, error) {
	if !matchesAny(f.IDs, lb.ID) {
		return false, nil
	}
	if !matchesAny(f.Names, lb.Name) {
		return false, nil
	}
	if !matchesAny(f.Descriptions, lb.Description) {
		return false, nil
	}
	if f.AdminStateUp != nil && lb.AdminStateUp != *f.AdminStateUp {
		return false, nil
	}
	if !matchesAny(f.ProvisioningStatuses, StatusActive) {
		return false, nil
	}
	if !matchesAny(f.OperatingStatuses, StatusOnline) {
		return false, nil
	}
	if f.Guaranteed != nil && lb.Guaranteed != *f.Guaranteed {
		return false, nil
	}
	if !matchesAny(f.VPCIDs, lb.VPCID) {
		return false, nil
	}
	if !matchesAny(f.VIPPortIDs, lb.VIPPortID) {
		return false, nil
	}
	if !matchesAny(f.VIPAddresses, lb.VIPAddress) {
		return false, nil
	}
	if !matchesAny(f.VIPSubnetCIDRIDs, lb.VIPSubnetCIDRID) {
		return false, nil
	}
	if len(f.IPv6VIPPortIDs) > 0 || len(f.IPv6VIPAddresses) > 0 || len(f.IPv6VIPVirsubnetIDs) > 0 {
		return false, nil
	}
	if len(f.AvailabilityZoneList) > 0 {
		found := false
		for _, az := range lb.AvailabilityZoneList {
			if slices.Contains(f.AvailabilityZoneList, az) {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	if !matchesAny(f.L4FlavorIDs, lb.L4FlavorID) {
		return false, nil
	}
	if len(f.L4ScaleFlavorIDs) > 0 {
		return false, nil
	}
	if !matchesAny(f.L7FlavorIDs, lb.L7FlavorID) {
		return false, nil
	}
	if len(f.L7ScaleFlavorIDs) > 0 {
		return false, nil
	}
	if !matchesAny(f.BillingInfos, "") {
		return false, nil
	}
	if len(f.MemberDeviceIDs) > 0 {
		return false, nil
	}
	if len(f.MemberAddresses) > 0 {
		addrs := lbMemberAddrs[lb.ID]
		found := false
		for _, want := range f.MemberAddresses {
			if _, ok := addrs[want]; ok {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	if !inEPList(f.EnterpriseProjectIDs, lb.EnterpriseProjectID) {
		return false, nil
	}
	if len(f.IPVersions) > 0 {
		if !slices.Contains(f.IPVersions, 4) {
			return false, nil
		}
	}
	if f.DeletionProtectionEnable != nil && lb.DeletionProtectionEnable != *f.DeletionProtectionEnable {
		return false, nil
	}
	if !matchesAny(f.ELBVirsubnetTypes, lbVirsubnetTypeIPv4) {
		return false, nil
	}
	if len(f.Autoscaling) > 0 {
		enabled := lb.Autoscaling != nil && lb.Autoscaling.Enable
		wantStr := "enable=false"
		if enabled {
			wantStr = "enable=true"
		}
		if !slices.Contains(f.Autoscaling, wantStr) {
			return false, nil
		}
	}
	ps := lb.ProtectionStatus
	if ps == "" {
		ps = lbProtectionStatusNone
	}
	if !matchesAny(f.ProtectionStatuses, ps) {
		return false, nil
	}
	if len(f.GlobalEIPs) > 0 || len(f.LogTopicIDs) > 0 || len(f.LogGroupIDs) > 0 {
		return false, nil
	}
	if len(f.EIPs) > 0 || len(f.PublicIPs) > 0 {
		eips, err := s.resolveEIPInfos(ctx, t, lb.EIPIDs)
		if err != nil {
			return false, err
		}
		if len(f.EIPs) > 0 && !matchEIPQueryFilter(f.EIPs, eips) {
			return false, nil
		}
		if len(f.PublicIPs) > 0 && !matchEIPQueryFilter(f.PublicIPs, eips) {
			return false, nil
		}
	}
	return true, nil
}

// matchEIPQueryFilter evaluates ELB's "eips=eip_id=xxx&eips=eip_address=yyy"
// and "publicips=publicip_id=xxx" query filter expressions.
func matchEIPQueryFilter(exprs []string, eips []eipInfoWire) bool {
	if len(eips) == 0 {
		return false
	}
	byKey := make(map[string][]string)
	for _, raw := range exprs {
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			return false
		}
		switch k {
		case "eip_id", "publicip_id", "public_id":
			byKey["id"] = append(byKey["id"], v)
		case "eip_address", "publicip_address", "public_address":
			byKey["address"] = append(byKey["address"], v)
		case "ip_version":
			byKey["ip_version"] = append(byKey["ip_version"], v)
		default:
			return false
		}
	}
	for _, e := range eips {
		if wants := byKey["id"]; len(wants) > 0 && !slices.Contains(wants, e.EIPID) {
			continue
		}
		if wants := byKey["address"]; len(wants) > 0 && !slices.Contains(wants, e.EIPAddress) {
			continue
		}
		if wants := byKey["ip_version"]; len(wants) > 0 && !slices.Contains(wants, "4") {
			continue
		}
		return true
	}
	return false
}

func (s *Service) updateLoadBalancer(ctx context.Context, t Tenant, id string, in updateLoadBalancerInput) (loadBalancer, error) {
	if in.OutOfScopeFeature != "" {
		return loadBalancer{}, errNotImplemented(in.OutOfScopeFeature)
	}
	if in.Name != nil && !validName(*in.Name) {
		return loadBalancer{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return loadBalancer{}, errInvalidInput("description")
	}
	if in.WafFailureAction != nil && *in.WafFailureAction != "" && !lbValidWafFailureAction(*in.WafFailureAction) {
		return loadBalancer{}, errInvalidInput("waf_failure_action")
	}
	if in.ProtectionStatus != nil && !lbValidProtectionStatus(*in.ProtectionStatus) {
		return loadBalancer{}, errInvalidInput("protection_status")
	}
	if in.ProtectionReason != nil && !lbValidProtectionReason(*in.ProtectionReason) {
		return loadBalancer{}, errInvalidInput("protection_reason")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return loadBalancer{}, errNotFound("loadbalancer", id)
	}
	if err != nil {
		return loadBalancer{}, err
	}

	// Flavor updates: must stay the same type, else ELB.8959 (§3.1).
	newL4 := lb.L4FlavorID
	if in.L4FlavorID != nil && *in.L4FlavorID != "" {
		f, ok := findSeededFlavor(t.Region, t.ProjectID, *in.L4FlavorID)
		if !ok {
			return loadBalancer{}, errNotFound("flavor", *in.L4FlavorID)
		}
		if f.Type != "L4" {
			return loadBalancer{}, errFlavorTypeChange("l4_flavor_id", "L4", f.Type)
		}
		newL4 = *in.L4FlavorID
	}
	newL7 := lb.L7FlavorID
	if in.L7FlavorID != nil && *in.L7FlavorID != "" {
		f, ok := findSeededFlavor(t.Region, t.ProjectID, *in.L7FlavorID)
		if !ok {
			return loadBalancer{}, errNotFound("flavor", *in.L7FlavorID)
		}
		if f.Type != "L7" {
			return loadBalancer{}, errFlavorTypeChange("l7_flavor_id", "L7", f.Type)
		}
		newL7 = *in.L7FlavorID
	}

	// Turning ip_target_enable off with IP members in any pool: ELB.8907 (§3.1).
	if in.IPTargetEnable != nil && !*in.IPTargetEnable && lb.IPTargetEnable {
		hasIP, err := s.loadBalancerHasIPMembers(ctx, t, lb.ID)
		if err != nil {
			return loadBalancer{}, err
		}
		if hasIP {
			return loadBalancer{}, errConflict("The load balancer has IP members and cannot disable ip_target_enable.")
		}
	}

	// Validate updated elb_virsubnet_ids if provided.
	var newVirsubnets []string
	if in.ELBVirsubnetIDs != nil {
		if len(*in.ELBVirsubnetIDs) == 0 {
			return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
		}
		newVirsubnets = make([]string, 0, len(*in.ELBVirsubnetIDs))
		seen := make(map[string]struct{}, len(*in.ELBVirsubnetIDs))
		for _, snID := range *in.ELBVirsubnetIDs {
			if snID == "" {
				return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
			}
			if _, dup := seen[snID]; dup {
				return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
			}
			seen[snID] = struct{}{}
			sn, err := s.vpc.GetSubnet(ctx, t, snID)
			if lbIsAPIError(err) {
				return loadBalancer{}, errNotFound("subnet", snID)
			}
			if err != nil {
				return loadBalancer{}, err
			}
			if sn.VPCID != lb.VPCID {
				return loadBalancer{}, errInvalidInput("elb_virsubnet_ids")
			}
			newVirsubnets = append(newVirsubnets, sn.ID)
		}
	}

	// Handle VIP removal or move (§3.1).
	removingVIP := in.VIPSubnetCIDRIDPresent && (in.VIPSubnetCIDRID == nil || *in.VIPSubnetCIDRID == "")
	if removingVIP {
		if in.VIPAddress != nil && *in.VIPAddress != "" {
			return loadBalancer{}, errInvalidInput("vip_address")
		}
		if len(lb.EIPIDs) > 0 {
			return loadBalancer{}, errConflict("The load balancer has EIPs bound and cannot remove its VIP.")
		}
		if lb.VIPSubnetID != "" && lb.VIPAddress != "" {
			if err := s.vpc.ReleaseIP(ctx, t, lb.VIPSubnetID, lb.VIPAddress); err != nil {
				return loadBalancer{}, err
			}
		}
		lb.VIPSubnetCIDRID = ""
		lb.VIPSubnetID = ""
		lb.VIPAddress = ""
		lb.VIPPortID = ""
	} else if (in.VIPSubnetCIDRID != nil && *in.VIPSubnetCIDRID != "") || (in.VIPAddress != nil && *in.VIPAddress != "") {
		targetCIDRID := lb.VIPSubnetCIDRID
		if in.VIPSubnetCIDRID != nil && *in.VIPSubnetCIDRID != "" {
			targetCIDRID = *in.VIPSubnetCIDRID
		}
		if targetCIDRID == "" {
			return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
		}
		subnetChanged := targetCIDRID != lb.VIPSubnetCIDRID
		addrChanged := in.VIPAddress != nil && *in.VIPAddress != "" && *in.VIPAddress != lb.VIPAddress
		if subnetChanged || addrChanged {
			targetSub, ok, err := s.findSubnetByNeutronID(ctx, t, targetCIDRID)
			if err != nil {
				return loadBalancer{}, err
			}
			if !ok {
				return loadBalancer{}, errNotFound("subnet", targetCIDRID)
			}
			if targetSub.VPCID != lb.VPCID {
				return loadBalancer{}, errInvalidInput("vip_subnet_cidr_id")
			}
			wantAddr := ""
			if in.VIPAddress != nil && *in.VIPAddress != "" {
				wantAddr = *in.VIPAddress
			}
			newAddr, err := s.vpc.AllocateIP(ctx, t, targetSub.ID, "elb:"+lb.ID, wantAddr)
			if err != nil {
				return loadBalancer{}, mapAllocateIPError(err, targetCIDRID)
			}
			if lb.VIPSubnetID != "" && lb.VIPAddress != "" {
				_ = s.vpc.ReleaseIP(ctx, t, lb.VIPSubnetID, lb.VIPAddress)
			}
			lb.VIPSubnetCIDRID = targetCIDRID
			lb.VIPSubnetID = targetSub.ID
			lb.VIPAddress = newAddr
			if lb.VIPPortID == "" {
				lb.VIPPortID = s.ids.UUID()
			}
		}
	}

	if in.Name != nil {
		lb.Name = *in.Name
	}
	if in.Description != nil {
		lb.Description = *in.Description
	}
	if in.AdminStateUp != nil {
		lb.AdminStateUp = *in.AdminStateUp
	}
	lb.L4FlavorID = newL4
	lb.L7FlavorID = newL7
	if in.IPTargetEnable != nil {
		lb.IPTargetEnable = *in.IPTargetEnable
	}
	if newVirsubnets != nil {
		lb.ELBVirsubnetIDs = newVirsubnets
	}
	if in.DeletionProtectionEnable != nil {
		lb.DeletionProtectionEnable = *in.DeletionProtectionEnable
	}
	if in.Autoscaling != nil {
		cp := *in.Autoscaling
		if in.Autoscaling.MinL7FlavorID != nil {
			v := *in.Autoscaling.MinL7FlavorID
			cp.MinL7FlavorID = &v
		}
		lb.Autoscaling = &cp
	}
	if in.WafFailureAction != nil {
		lb.WafFailureAction = *in.WafFailureAction
	}
	if in.ProtectionStatus != nil {
		lb.ProtectionStatus = *in.ProtectionStatus
	}
	if in.ProtectionReason != nil {
		lb.ProtectionReason = *in.ProtectionReason
	}
	lb.UpdatedAt = s.nowUTC()

	if err := s.loadBalancers(t).Put(ctx, lb.ID, lb); err != nil {
		return loadBalancer{}, err
	}
	return lb, nil
}

func (s *Service) loadBalancerHasIPMembers(ctx context.Context, t Tenant, lbID string) (bool, error) {
	pools, err := s.pools(t).List(ctx, func(p pool) bool {
		return p.LoadBalancerID == lbID
	})
	if err != nil {
		return false, err
	}
	if len(pools) == 0 {
		return false, nil
	}
	poolSet := make(map[string]struct{}, len(pools))
	for _, p := range pools {
		poolSet[p.ID] = struct{}{}
	}
	members, err := s.members(t).List(ctx, func(m member) bool {
		if _, ok := poolSet[m.PoolID]; !ok {
			return false
		}
		return m.MemberType == "ip" || m.SubnetCIDRID == ""
	})
	if err != nil {
		return false, err
	}
	return len(members) > 0, nil
}

func (s *Service) deleteLoadBalancer(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("loadbalancer", id)
	}
	if err != nil {
		return err
	}
	if lb.DeletionProtectionEnable {
		return errConflict("The load balancer has deletion protection enabled.")
	}

	lsns, err := s.listeners(t).List(ctx, func(l listener) bool {
		return l.LoadBalancerID == lb.ID
	})
	if err != nil {
		return err
	}
	pls, err := s.pools(t).List(ctx, func(p pool) bool {
		return p.LoadBalancerID == lb.ID
	})
	if err != nil {
		return err
	}
	if len(lsns) > 0 || len(pls) > 0 {
		return errConflict("The load balancer has listeners or pools.")
	}

	return s.cleanupAndDeleteLoadBalancerLocked(ctx, t, lb)
}

func (s *Service) deleteLoadBalancerForce(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("loadbalancer", id)
	}
	if err != nil {
		return err
	}
	if lb.DeletionProtectionEnable {
		return errConflict("The load balancer has deletion protection enabled.")
	}

	// 1. Delete L7 rules and L7 policies belonging to this load balancer's listeners.
	lsns, err := s.listeners(t).List(ctx, func(l listener) bool {
		return l.LoadBalancerID == lb.ID
	})
	if err != nil {
		return err
	}
	if len(lsns) > 0 {
		lsnSet := make(map[string]struct{}, len(lsns))
		for _, l := range lsns {
			lsnSet[l.ID] = struct{}{}
		}
		policies, err := s.l7Policies(t).List(ctx, func(p l7Policy) bool {
			_, ok := lsnSet[p.ListenerID]
			return ok
		})
		if err != nil {
			return err
		}
		if len(policies) > 0 {
			polSet := make(map[string]struct{}, len(policies))
			for _, pol := range policies {
				polSet[pol.ID] = struct{}{}
			}
			rules, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool {
				_, ok := polSet[r.PolicyID]
				return ok
			})
			if err != nil {
				return err
			}
			for _, r := range rules {
				if err := s.l7Rules(t).Delete(ctx, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
			for _, pol := range policies {
				if err := s.l7Policies(t).Delete(ctx, pol.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
		}
	}

	// 2. Delete members, health monitors, and pools belonging to this load balancer.
	pls, err := s.pools(t).List(ctx, func(p pool) bool {
		return p.LoadBalancerID == lb.ID
	})
	if err != nil {
		return err
	}
	if len(pls) > 0 {
		poolSet := make(map[string]struct{}, len(pls))
		for _, p := range pls {
			poolSet[p.ID] = struct{}{}
		}
		mems, err := s.members(t).List(ctx, func(m member) bool {
			_, ok := poolSet[m.PoolID]
			return ok
		})
		if err != nil {
			return err
		}
		for _, m := range mems {
			if err := s.members(t).Delete(ctx, m.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		hms, err := s.healthMonitors(t).List(ctx, func(hm healthMonitor) bool {
			_, ok := poolSet[hm.PoolID]
			return ok
		})
		if err != nil {
			return err
		}
		for _, hm := range hms {
			if err := s.healthMonitors(t).Delete(ctx, hm.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		for _, p := range pls {
			if err := s.pools(t).Delete(ctx, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}

	// 3. Delete listeners belonging to this load balancer.
	for _, l := range lsns {
		if err := s.listeners(t).Delete(ctx, l.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}

	// 4. Unbind EIPs, release VIP, delete load balancer.
	return s.cleanupAndDeleteLoadBalancerLocked(ctx, t, lb)
}

func (s *Service) cleanupAndDeleteLoadBalancerLocked(ctx context.Context, t Tenant, lb loadBalancer) error {
	for _, eipID := range lb.EIPIDs {
		if err := s.eips.UnbindFromELB(ctx, t, eipID, lb.ID); err != nil {
			return err
		}
	}
	if lb.VIPSubnetID != "" && lb.VIPAddress != "" {
		if err := s.vpc.ReleaseIP(ctx, t, lb.VIPSubnetID, lb.VIPAddress); err != nil {
			return err
		}
	}
	if err := s.loadBalancers(t).Delete(ctx, lb.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (s *Service) batchAddAvailableZones(ctx context.Context, t Tenant, id string, addAZs []string) (loadBalancer, error) {
	if err := validateAZList(t.Region, addAZs); err != nil {
		return loadBalancer{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return loadBalancer{}, errNotFound("loadbalancer", id)
	}
	if err != nil {
		return loadBalancer{}, err
	}

	for _, az := range addAZs {
		if slices.Contains(lb.AvailabilityZoneList, az) {
			return loadBalancer{}, errInvalidInput("availability_zone_list")
		}
	}
	lb.AvailabilityZoneList = append(lb.AvailabilityZoneList, addAZs...)
	lb.UpdatedAt = s.nowUTC()
	if err := s.loadBalancers(t).Put(ctx, lb.ID, lb); err != nil {
		return loadBalancer{}, err
	}
	return lb, nil
}

func (s *Service) batchRemoveAvailableZones(ctx context.Context, t Tenant, id string, removeAZs []string) (loadBalancer, error) {
	if len(removeAZs) == 0 {
		return loadBalancer{}, errInvalidInput("availability_zone_list")
	}
	removeSet := make(map[string]struct{}, len(removeAZs))
	for _, az := range removeAZs {
		if az == "" {
			return loadBalancer{}, errInvalidInput("availability_zone_list")
		}
		if _, dup := removeSet[az]; dup {
			return loadBalancer{}, errInvalidInput("availability_zone_list")
		}
		removeSet[az] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return loadBalancer{}, errNotFound("loadbalancer", id)
	}
	if err != nil {
		return loadBalancer{}, err
	}

	for _, az := range removeAZs {
		if !slices.Contains(lb.AvailabilityZoneList, az) {
			return loadBalancer{}, errInvalidInput("availability_zone_list")
		}
	}
	remaining := make([]string, 0, len(lb.AvailabilityZoneList))
	for _, az := range lb.AvailabilityZoneList {
		if _, drop := removeSet[az]; !drop {
			remaining = append(remaining, az)
		}
	}
	if len(remaining) == 0 {
		return loadBalancer{}, errInvalidInput("availability_zone_list")
	}
	lb.AvailabilityZoneList = remaining
	lb.UpdatedAt = s.nowUTC()
	if err := s.loadBalancers(t).Put(ctx, lb.ID, lb); err != nil {
		return loadBalancer{}, err
	}
	return lb, nil
}

func (s *Service) resolveEIPInfos(ctx context.Context, t Tenant, eipIDs []string) ([]eipInfoWire, error) {
	out := make([]eipInfoWire, 0, len(eipIDs))
	for _, id := range eipIDs {
		addr, ok, err := s.eips.PublicIPAddress(ctx, t, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, eipInfoWire{
			EIPID:      id,
			EIPAddress: addr,
			IPVersion:  4,
		})
	}
	return out, nil
}

func (s *Service) loadBalancerStatus(ctx context.Context, t Tenant, id string) (loadBalancerStatusResult, error) {
	lb, err := s.getLoadBalancer(ctx, t, id)
	if err != nil {
		return loadBalancerStatusResult{}, err
	}

	lsns, err := s.listeners(t).List(ctx, func(l listener) bool {
		return l.LoadBalancerID == lb.ID
	})
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	slices.SortFunc(lsns, func(a, b listener) int { return strings.Compare(a.ID, b.ID) })

	pls, err := s.pools(t).List(ctx, func(p pool) bool {
		return p.LoadBalancerID == lb.ID
	})
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	slices.SortFunc(pls, func(a, b pool) int { return strings.Compare(a.ID, b.ID) })

	// Index health monitors and members for the load balancer's pools.
	allHMs, err := s.healthMonitors(t).List(ctx, nil)
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	hmByPool := make(map[string]*healthMonitor, len(allHMs))
	for i := range allHMs {
		hm := allHMs[i]
		if hm.PoolID != "" {
			hmByPool[hm.PoolID] = &hm
		}
	}

	allMembers, err := s.members(t).List(ctx, nil)
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	membersByPool := make(map[string][]member)
	for _, m := range allMembers {
		membersByPool[m.PoolID] = append(membersByPool[m.PoolID], m)
	}

	poolViews := make(map[string]loadBalancerStatusPool, len(pls))
	topPools := make([]loadBalancerStatusPool, 0, len(pls))
	for _, p := range pls {
		hm := hmByPool[p.ID]
		mems := membersByPool[p.ID]
		slices.SortFunc(mems, func(a, b member) int { return strings.Compare(a.ID, b.ID) })

		memViews := make([]loadBalancerStatusMember, 0, len(mems))
		for _, m := range mems {
			opStatus, err := s.memberOperatingStatus(ctx, t, m, p, hm, lb.VPCID)
			if err != nil {
				return loadBalancerStatusResult{}, err
			}
			memViews = append(memViews, loadBalancerStatusMember{
				ID:                 m.ID,
				Address:            m.Address,
				ProtocolPort:       m.ProtocolPort,
				ProvisioningStatus: StatusActive,
				OperatingStatus:    opStatus,
			})
		}
		var hmView *loadBalancerStatusHealthMonitor
		if hm != nil {
			hmView = &loadBalancerStatusHealthMonitor{
				ID:                 hm.ID,
				Name:               hm.Name,
				Type:               hm.Type,
				ProvisioningStatus: StatusActive,
			}
		}
		pv := loadBalancerStatusPool{
			ID:                 p.ID,
			Name:               p.Name,
			ProvisioningStatus: StatusActive,
			OperatingStatus:    StatusOnline,
			Healthmonitor:      hmView,
			Members:            memViews,
		}
		poolViews[p.ID] = pv
		topPools = append(topPools, pv)
	}

	// Index L7 policies and rules for this load balancer's listeners.
	allPolicies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	policiesByListener := make(map[string][]l7Policy)
	for _, pol := range allPolicies {
		policiesByListener[pol.ListenerID] = append(policiesByListener[pol.ListenerID], pol)
	}

	allRules, err := s.l7Rules(t).List(ctx, nil)
	if err != nil {
		return loadBalancerStatusResult{}, err
	}
	rulesByPolicy := make(map[string][]l7Rule)
	for _, r := range allRules {
		rulesByPolicy[r.PolicyID] = append(rulesByPolicy[r.PolicyID], r)
	}

	lsnViews := make([]loadBalancerStatusListener, 0, len(lsns))
	for _, l := range lsns {
		pols := policiesByListener[l.ID]
		slices.SortFunc(pols, func(a, b l7Policy) int { return strings.Compare(a.ID, b.ID) })

		polViews := make([]loadBalancerStatusPolicy, 0, len(pols))
		poolIDSet := make(map[string]struct{})
		if l.DefaultPoolID != "" {
			poolIDSet[l.DefaultPoolID] = struct{}{}
		}
		for _, pol := range pols {
			if pol.RedirectPoolID != "" {
				poolIDSet[pol.RedirectPoolID] = struct{}{}
			}
			for _, rpc := range pol.RedirectPoolsConfig {
				if rpc.PoolID != "" {
					poolIDSet[rpc.PoolID] = struct{}{}
				}
			}
			rs := rulesByPolicy[pol.ID]
			slices.SortFunc(rs, func(a, b l7Rule) int { return strings.Compare(a.ID, b.ID) })
			rViews := make([]loadBalancerStatusL7Rule, 0, len(rs))
			for _, r := range rs {
				rViews = append(rViews, loadBalancerStatusL7Rule{
					ID:                 r.ID,
					Type:               r.Type,
					ProvisioningStatus: StatusActive,
				})
			}
			polViews = append(polViews, loadBalancerStatusPolicy{
				ID:                 pol.ID,
				Name:               pol.Name,
				Action:             pol.Action,
				ProvisioningStatus: StatusActive,
				Rules:              rViews,
			})
		}

		lsnPools := make([]loadBalancerStatusPool, 0, len(poolIDSet))
		for pid := range poolIDSet {
			if pv, ok := poolViews[pid]; ok {
				lsnPools = append(lsnPools, pv)
			}
		}
		slices.SortFunc(lsnPools, func(a, b loadBalancerStatusPool) int { return strings.Compare(a.ID, b.ID) })

		lsnViews = append(lsnViews, loadBalancerStatusListener{
			ID:                 l.ID,
			Name:               l.Name,
			ProvisioningStatus: StatusActive,
			OperatingStatus:    StatusOnline,
			Pools:              lsnPools,
			L7Policies:         polViews,
		})
	}

	return loadBalancerStatusResult{
		Loadbalancer: loadBalancerStatusWire{
			ID:                 lb.ID,
			Name:               lb.Name,
			ProvisioningStatus: StatusActive,
			OperatingStatus:    StatusOnline,
			Listeners:          lsnViews,
			Pools:              topPools,
		},
	}, nil
}
