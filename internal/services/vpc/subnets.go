package vpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

// maxSubnetPrefix is the longest subnet mask the API accepts.
const maxSubnetPrefix = 29

// extraDHCPOptNames are the opt_name values the API accepts.
var extraDHCPOptNames = map[string]bool{
	"ntp": true, "domainname": true, "addresstime": true, "ipv6_addresstime": true,
}

// view converts a stored record to the API model, filling the computed
// available_ip_address_count.
func (rec subnetRecord) view() Subnet {
	sn := rec.Subnet
	if plan, err := newAddressPlan(sn.CIDR, sn.GatewayIP); err == nil {
		sn.AvailableIPAddressCount = max(plan.capacity()-len(rec.Allocations), 0)
	}
	return sn
}

// CreateSubnet creates a subnet in status UNKNOWN; it becomes ACTIVE
// after the lifecycle delay.
func (s *Service) CreateSubnet(ctx context.Context, t Tenant, opt CreateSubnetOption) (Subnet, error) {
	if err := checkName(opt.Name, false); err != nil {
		return Subnet{}, errInvalidSubnet("%s", err)
	}
	sn := Subnet{
		Name:             opt.Name,
		CIDR:             opt.CIDR,
		GatewayIP:        opt.GatewayIP,
		VPCID:            opt.VPCID,
		DHCPEnable:       true,
		Status:           SubnetStatusUnknown,
		DNSList:          []string{},
		ExtraDHCPOpts:    []ExtraDHCPOption{},
		TenantID:         t.ProjectID,
		NeutronSubnetID:  s.ids.UUID(),
		AvailabilityZone: deref(opt.AvailabilityZone),
		Description:      deref(opt.Description),
	}
	if err := checkDescription(sn.Description); err != nil {
		return Subnet{}, errInvalidSubnet("%s", err)
	}
	if opt.DHCPEnable != nil {
		sn.DHCPEnable = *opt.DHCPEnable
	}
	if opt.EnableNetworkAddressUsageMetrics != nil {
		sn.EnableNetworkAddressUsageMetrics = *opt.EnableNetworkAddressUsageMetrics
	}

	if opt.CIDR == "" {
		return Subnet{}, errInvalidSubnet("cidr is required")
	}
	block, err := parseIPv4CIDR(opt.CIDR)
	if err != nil {
		return Subnet{}, errInvalidSubnetCIDR("cidr %s", err)
	}
	if block.Bits() > maxSubnetPrefix {
		return Subnet{}, errInvalidSubnetCIDR("the subnet mask of %q cannot be greater than %d", opt.CIDR, maxSubnetPrefix)
	}
	if err := checkGateway(block, opt.GatewayIP); err != nil {
		return Subnet{}, errInvalidSubnet("%s", err)
	}
	if err := applyDNS(&sn, opt.PrimaryDNS, opt.SecondaryDNS, opt.DNSList); err != nil {
		return Subnet{}, errInvalidSubnet("%s", err)
	}
	if opt.ExtraDHCPOpts != nil {
		if err := checkExtraDHCPOpts(*opt.ExtraDHCPOpts); err != nil {
			return Subnet{}, errInvalidSubnet("%s", err)
		}
		sn.ExtraDHCPOpts = append([]ExtraDHCPOption{}, *opt.ExtraDHCPOpts...)
	}
	if !isUUID(opt.VPCID) {
		return Subnet{}, errInvalidSubnet("vpc_id %q is invalid", opt.VPCID)
	}

	// In the v1 API a subnet's ID is the ID of its Neutron network.
	sn.ID = s.ids.UUID()
	sn.NeutronNetworkID = sn.ID
	if opt.IPv6Enable != nil && *opt.IPv6Enable {
		s.enableIPv6(&sn)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	parent, err := s.vpcs(t).Get(ctx, opt.VPCID)
	if errors.Is(err, store.ErrNotFound) {
		return Subnet{}, errSubnetVPCNotFound(opt.VPCID)
	}
	if err != nil {
		return Subnet{}, err
	}
	if parent.CIDR != "" {
		if outer, err := parseIPv4CIDR(parent.CIDR); err == nil && !contains(outer, block) {
			return Subnet{}, errSubnetOutsideVPC(opt.CIDR, parent.CIDR)
		}
	}
	siblings, err := s.subnetsOfVPC(ctx, t, opt.VPCID)
	if err != nil {
		return Subnet{}, err
	}
	for _, sib := range siblings {
		if other, err := parseIPv4CIDR(sib.CIDR); err == nil && other.Overlaps(block) {
			return Subnet{}, errSubnetCIDRConflict(opt.CIDR, sib.CIDR)
		}
	}

	sn.CreatedAt = s.timestamp()
	sn.UpdatedAt = sn.CreatedAt
	rec := subnetRecord{Subnet: sn}
	if err := s.subnets(t).Create(ctx, sn.ID, rec); err != nil {
		return Subnet{}, err
	}
	s.scheduleSubnetActivation(t, sn.ID)
	return rec.view(), nil
}

// enableIPv6 gives the subnet a /64 from the documentation prefix. The
// emulator does not route IPv6; the values exist so clients see the
// fields real IPv6-enabled subnets carry.
func (s *Service) enableIPv6(sn *Subnet) {
	id := s.ids.Hex32()
	sn.IPv6Enable = true
	sn.CIDRv6 = fmt.Sprintf("2001:db8:%s:%s::/64", id[0:4], id[4:8])
	sn.GatewayIPv6 = fmt.Sprintf("2001:db8:%s:%s::1", id[0:4], id[4:8])
	sn.NeutronSubnetIDv6 = s.ids.UUID()
}

// checkGateway enforces that the gateway is an address inside the
// subnet other than its network and broadcast addresses.
func checkGateway(block netip.Prefix, gateway string) error {
	if gateway == "" {
		return errors.New("gateway_ip is required")
	}
	gw, err := netip.ParseAddr(gateway)
	if err != nil || !gw.Is4() {
		return fmt.Errorf("gateway_ip %q is not an IPv4 address", gateway)
	}
	if !block.Contains(gw) {
		return fmt.Errorf("gateway_ip %s is not in the subnet %s", gateway, block)
	}
	if gw == block.Addr() || gw == lastAddr(block) {
		return fmt.Errorf("gateway_ip %s is the network or broadcast address of %s", gateway, block)
	}
	return nil
}

// applyDNS validates and sets the DNS fields. Non-nil arguments replace
// the current values. Per the API reference: with only secondary_dns
// given, primary_dns takes its value; dnsList, when given, wins.
func applyDNS(sn *Subnet, primary, secondary *string, list *[]string) error {
	if primary != nil {
		sn.PrimaryDNS = *primary
	}
	if secondary != nil {
		sn.SecondaryDNS = *secondary
	}
	if sn.PrimaryDNS == "" && sn.SecondaryDNS != "" {
		sn.PrimaryDNS, sn.SecondaryDNS = sn.SecondaryDNS, ""
	}
	for field, v := range map[string]string{"primary_dns": sn.PrimaryDNS, "secondary_dns": sn.SecondaryDNS} {
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err != nil {
			return fmt.Errorf("%s %q is not an IP address", field, v)
		}
	}

	switch {
	case list != nil:
		for _, v := range *list {
			if _, err := netip.ParseAddr(v); err != nil {
				return fmt.Errorf("dnsList entry %q is not an IP address", v)
			}
		}
		sn.DNSList = append([]string{}, *list...)
	case primary != nil || secondary != nil:
		sn.DNSList = []string{}
		for _, v := range []string{sn.PrimaryDNS, sn.SecondaryDNS} {
			if v != "" {
				sn.DNSList = append(sn.DNSList, v)
			}
		}
	}
	return nil
}

func checkExtraDHCPOpts(opts []ExtraDHCPOption) error {
	seen := map[string]bool{}
	for _, o := range opts {
		if !extraDHCPOptNames[o.OptName] {
			return fmt.Errorf("extra_dhcp_opts opt_name %q is not supported", o.OptName)
		}
		if seen[o.OptName] {
			return fmt.Errorf("extra_dhcp_opts opt_name %q is repeated", o.OptName)
		}
		seen[o.OptName] = true
	}
	return nil
}

func (s *Service) scheduleSubnetActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskSubnetCreate,
		Run: func(ctx context.Context, fault error) {
			status := SubnetStatusActive
			if fault != nil {
				status = SubnetStatusError
			}
			_, err := s.subnets(t).Update(ctx, id, func(rec *subnetRecord) error {
				rec.Status = status
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "subnet activation failed", "subnet_id", id, "error", err)
			}
		},
	})
}

// subnetsOfVPC returns the stored subnets of one VPC.
func (s *Service) subnetsOfVPC(ctx context.Context, t Tenant, vpcID string) ([]subnetRecord, error) {
	return s.subnets(t).List(ctx, func(rec subnetRecord) bool { return rec.VPCID == vpcID })
}

// GetSubnet returns one subnet.
func (s *Service) GetSubnet(ctx context.Context, t Tenant, id string) (Subnet, error) {
	if !isUUID(id) {
		return Subnet{}, errInvalidSubnet("subnetId %q is invalid", id)
	}
	rec, err := s.subnets(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Subnet{}, errSubnetNotFound(id)
	}
	if err != nil {
		return Subnet{}, err
	}
	return rec.view(), nil
}

// ListSubnets returns the project's subnets in creation order.
func (s *Service) ListSubnets(ctx context.Context, t Tenant, f ListSubnetsFilter) ([]Subnet, error) {
	recs, err := s.subnets(t).List(ctx, func(rec subnetRecord) bool {
		return f.VPCID == "" || rec.VPCID == f.VPCID
	})
	if err != nil {
		return nil, err
	}
	out := make([]Subnet, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.view())
	}
	return out, nil
}

// subnetInVPC loads a subnet addressed through its VPC, as the update
// and delete paths are.
func (s *Service) subnetInVPC(ctx context.Context, t Tenant, vpcID, id string) (subnetRecord, error) {
	if !isUUID(vpcID) {
		return subnetRecord{}, errInvalidSubnet("vpcId %q is invalid", vpcID)
	}
	if !isUUID(id) {
		return subnetRecord{}, errInvalidSubnet("subnetId %q is invalid", id)
	}
	rec, err := s.subnets(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return subnetRecord{}, errSubnetNotFound(id)
	}
	if err != nil {
		return subnetRecord{}, err
	}
	if rec.VPCID != vpcID {
		return subnetRecord{}, errSubnetNotInVPC(id, vpcID)
	}
	return rec, nil
}

// UpdateSubnet changes the fields set in opt.
func (s *Service) UpdateSubnet(ctx context.Context, t Tenant, vpcID, id string, opt UpdateSubnetOption) (Subnet, error) {
	if err := checkName(opt.Name, false); err != nil {
		return Subnet{}, errInvalidSubnet("%s", err)
	}
	if opt.Description != nil {
		if err := checkDescription(*opt.Description); err != nil {
			return Subnet{}, errInvalidSubnet("%s", err)
		}
	}
	if opt.ExtraDHCPOpts != nil {
		if err := checkExtraDHCPOpts(*opt.ExtraDHCPOpts); err != nil {
			return Subnet{}, errInvalidSubnet("%s", err)
		}
	}
	if _, err := s.subnetInVPC(ctx, t, vpcID, id); err != nil {
		return Subnet{}, err
	}

	// IPv6 identifiers are generated outside the update callback, which
	// may run more than once.
	var v6 Subnet
	if opt.IPv6Enable != nil && *opt.IPv6Enable {
		s.enableIPv6(&v6)
	}
	now := s.timestamp()

	rec, err := s.subnets(t).Update(ctx, id, func(rec *subnetRecord) error {
		if err := applyDNS(&rec.Subnet, opt.PrimaryDNS, opt.SecondaryDNS, opt.DNSList); err != nil {
			return errInvalidSubnet("%s", err)
		}
		rec.Name = opt.Name
		if opt.Description != nil {
			rec.Description = *opt.Description
		}
		if opt.DHCPEnable != nil {
			rec.DHCPEnable = *opt.DHCPEnable
		}
		if opt.ExtraDHCPOpts != nil {
			rec.ExtraDHCPOpts = append([]ExtraDHCPOption{}, *opt.ExtraDHCPOpts...)
		}
		if opt.EnableNetworkAddressUsageMetrics != nil {
			rec.EnableNetworkAddressUsageMetrics = *opt.EnableNetworkAddressUsageMetrics
		}
		if opt.IPv6Enable != nil {
			switch {
			case *opt.IPv6Enable && !rec.IPv6Enable:
				rec.IPv6Enable = true
				rec.CIDRv6, rec.GatewayIPv6, rec.NeutronSubnetIDv6 = v6.CIDRv6, v6.GatewayIPv6, v6.NeutronSubnetIDv6
			case !*opt.IPv6Enable:
				rec.IPv6Enable = false
				rec.CIDRv6, rec.GatewayIPv6, rec.NeutronSubnetIDv6 = "", "", ""
			}
		}
		rec.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return Subnet{}, errSubnetNotFound(id)
	}
	if err != nil {
		return Subnet{}, err
	}
	return rec.view(), nil
}

// DeleteSubnet removes a subnet that has no private IP addresses in use.
func (s *Service) DeleteSubnet(ctx context.Context, t Tenant, vpcID, id string) error {
	// Both locks: no allocation may slip in between the in-use check and
	// the delete.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipamMu.Lock()
	defer s.ipamMu.Unlock()

	rec, err := s.subnetInVPC(ctx, t, vpcID, id)
	if err != nil {
		return err
	}
	if rec.Status == SubnetStatusUnknown {
		return errSubnetBusy(id)
	}
	if n := len(rec.Allocations); n > 0 {
		return errSubnetInUse(id, n)
	}
	if err := s.subnets(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.engine.Cancel(id)
	return nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
