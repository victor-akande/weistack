package vpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	// defaultSecGroupName is the group every project owns from the start.
	defaultSecGroupName = "default"
	// defaultRulePriority is the priority of the rules a new group is
	// created with; rules added later default to userRulePriority.
	defaultRulePriority = 100
	userRulePriority    = 1
	minRulePriority     = 1
	maxRulePriority     = 100
	maxTags             = 20
)

// ensureDefaultSecGroup creates the project's "default" security group
// the first time security groups are used in it, as every real project
// has one. The caller must hold s.mu.
func (s *Service) ensureDefaultSecGroup(ctx context.Context, t Tenant) error {
	existing, err := s.secGroups(t).List(ctx, func(g SecurityGroup) bool { return g.Name == defaultSecGroupName })
	if err != nil || len(existing) > 0 {
		return err
	}
	_, err = s.insertSecGroup(ctx, t, SecurityGroup{
		Name:                defaultSecGroupName,
		Description:         "Default security group",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                []Tag{},
	})
	return err
}

// insertSecGroup stores a group with the four rules every new group
// gets: all egress allowed, and ingress allowed from members of the
// group itself, for IPv4 and IPv6. The caller must hold s.mu.
func (s *Service) insertSecGroup(ctx context.Context, t Tenant, g SecurityGroup) (SecurityGroupInfo, error) {
	now := TimeZ(s.timestamp())
	g.ID = s.ids.UUID()
	g.ProjectID = t.ProjectID
	g.CreatedAt, g.UpdatedAt = now, now
	if err := s.secGroups(t).Create(ctx, g.ID, g); err != nil {
		return SecurityGroupInfo{}, err
	}

	info := SecurityGroupInfo{SecurityGroup: g}
	for _, d := range []struct {
		direction, ethertype string
		self                 bool
	}{
		{"ingress", "IPv6", true},
		{"egress", "IPv6", false},
		{"egress", "IPv4", false},
		{"ingress", "IPv4", true},
	} {
		rule := SecurityGroupRule{
			ID:              s.ids.UUID(),
			SecurityGroupID: g.ID,
			Direction:       d.direction,
			Ethertype:       d.ethertype,
			Action:          "allow",
			Priority:        defaultRulePriority,
			ProjectID:       t.ProjectID,
			Enabled:         true,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if d.self {
			rule.RemoteGroupID = &g.ID
		}
		if err := s.secGroupRules(t).Create(ctx, rule.ID, rule); err != nil {
			return SecurityGroupInfo{}, err
		}
		info.SecurityGroupRules = append(info.SecurityGroupRules, rule)
	}
	return info, nil
}

// buildSecGroup validates a create request and returns the group to store.
func buildSecGroup(opt CreateSecurityGroupOption) (SecurityGroup, error) {
	g := SecurityGroup{
		Name:                opt.Name,
		Description:         deref(opt.Description),
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                []Tag{},
	}
	if err := checkName(g.Name, false); err != nil {
		return SecurityGroup{}, errInvalidSecGroup("%s", err)
	}
	if err := checkDescription(g.Description); err != nil {
		return SecurityGroup{}, errInvalidSecGroup("%s", err)
	}
	if opt.EnterpriseProjectID != nil && *opt.EnterpriseProjectID != "" {
		g.EnterpriseProjectID = *opt.EnterpriseProjectID
	}
	if g.EnterpriseProjectID != defaultEnterpriseProjectID && !isUUID(g.EnterpriseProjectID) {
		return SecurityGroup{}, errInvalidSecGroup("enterprise_project_id %q is invalid", g.EnterpriseProjectID)
	}
	if opt.Tags != nil {
		if len(*opt.Tags) > maxTags {
			return SecurityGroup{}, errInvalidSecGroup("a security group can have at most %d tags", maxTags)
		}
		seen := map[string]bool{}
		for _, tag := range *opt.Tags {
			if tag.Key == "" || seen[tag.Key] {
				return SecurityGroup{}, errInvalidSecGroup("tag keys must be non-empty and unique")
			}
			seen[tag.Key] = true
		}
		g.Tags = append([]Tag{}, *opt.Tags...)
	}
	return g, nil
}

// CreateSecurityGroup creates a security group with its default rules.
// With dryRun the request is only validated and the zero value returned.
func (s *Service) CreateSecurityGroup(ctx context.Context, t Tenant, opt CreateSecurityGroupOption, dryRun bool) (SecurityGroupInfo, error) {
	g, err := buildSecGroup(opt)
	if err != nil || dryRun {
		return SecurityGroupInfo{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureDefaultSecGroup(ctx, t); err != nil {
		return SecurityGroupInfo{}, err
	}
	return s.insertSecGroup(ctx, t, g)
}

// GetSecurityGroup returns a group with its rules.
func (s *Service) GetSecurityGroup(ctx context.Context, t Tenant, id string) (SecurityGroupInfo, error) {
	g, err := s.secGroups(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return SecurityGroupInfo{}, errSecGroupNotFound(id)
	}
	if err != nil {
		return SecurityGroupInfo{}, err
	}
	rules, err := s.secGroupRules(t).List(ctx, func(r SecurityGroupRule) bool { return r.SecurityGroupID == id })
	if err != nil {
		return SecurityGroupInfo{}, err
	}
	return SecurityGroupInfo{SecurityGroup: g, SecurityGroupRules: rules}, nil
}

func matchAny(allowed []string, v string) bool {
	return len(allowed) == 0 || slices.Contains(allowed, v)
}

// ListSecurityGroups returns the project's groups, without rules, in
// creation order. The first call in a project creates its default group.
func (s *Service) ListSecurityGroups(ctx context.Context, t Tenant, f ListSecurityGroupsFilter) ([]SecurityGroup, error) {
	s.mu.Lock()
	err := s.ensureDefaultSecGroup(ctx, t)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.secGroups(t).List(ctx, func(g SecurityGroup) bool {
		return matchAny(f.IDs, g.ID) && matchAny(f.Names, g.Name) && matchAny(f.Descriptions, g.Description) &&
			(f.EnterpriseProjectID == "" || g.EnterpriseProjectID == f.EnterpriseProjectID)
	})
}

// UpdateSecurityGroup changes the name and description set in opt.
func (s *Service) UpdateSecurityGroup(ctx context.Context, t Tenant, id string, opt UpdateSecurityGroupOption, dryRun bool) (SecurityGroupInfo, error) {
	if opt.Name != nil {
		if err := checkName(*opt.Name, false); err != nil {
			return SecurityGroupInfo{}, errInvalidSecGroup("%s", err)
		}
	}
	if opt.Description != nil {
		if err := checkDescription(*opt.Description); err != nil {
			return SecurityGroupInfo{}, errInvalidSecGroup("%s", err)
		}
	}
	if dryRun {
		_, err := s.GetSecurityGroup(ctx, t, id)
		return SecurityGroupInfo{}, err
	}
	now := TimeZ(s.timestamp())
	_, err := s.secGroups(t).Update(ctx, id, func(g *SecurityGroup) error {
		if opt.Name != nil {
			g.Name = *opt.Name
		}
		if opt.Description != nil {
			g.Description = *opt.Description
		}
		g.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return SecurityGroupInfo{}, errSecGroupNotFound(id)
	}
	if err != nil {
		return SecurityGroupInfo{}, err
	}
	return s.GetSecurityGroup(ctx, t, id)
}

// DeleteSecurityGroup removes a group, its rules, and the rules of other
// groups that name it as their remote group. The default group cannot be
// deleted.
func (s *Service) DeleteSecurityGroup(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, err := s.secGroups(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errSecGroupNotFound(id)
	}
	if err != nil {
		return err
	}
	if g.Name == defaultSecGroupName {
		return errSecGroupConflict("The default security group cannot be deleted.")
	}
	rules, err := s.secGroupRules(t).List(ctx, func(r SecurityGroupRule) bool {
		return r.SecurityGroupID == id || (r.RemoteGroupID != nil && *r.RemoteGroupID == id)
	})
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := s.secGroupRules(t).Delete(ctx, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return s.secGroups(t).Delete(ctx, id)
}

// protocolNames maps the protocol names the API accepts to the ethertype
// each requires ("" for either).
var protocolNames = map[string]string{"tcp": "", "udp": "", "icmp": "IPv4", "icmpv6": "IPv6"}

// buildRule validates a create request and returns the rule to store,
// without its ID, project and timestamps. Existence of the groups it
// references is checked by the caller.
func buildRule(opt CreateSecurityGroupRuleOption) (SecurityGroupRule, error) {
	r := SecurityGroupRule{
		SecurityGroupID: opt.SecurityGroupID,
		Description:     deref(opt.Description),
		Ethertype:       "IPv4",
		Action:          "allow",
		Priority:        userRulePriority,
		Enabled:         true,
	}
	if r.SecurityGroupID == "" {
		return r, errInvalidSecGroup("security_group_id is required")
	}
	if err := checkDescription(r.Description); err != nil {
		return r, errInvalidSecGroup("%s", err)
	}

	r.Direction = strings.ToLower(opt.Direction)
	if r.Direction != "ingress" && r.Direction != "egress" {
		return r, errInvalidSecGroup("direction must be ingress or egress")
	}

	if opt.Ethertype != nil && *opt.Ethertype != "" {
		switch strings.ToLower(*opt.Ethertype) {
		case "ipv4":
			r.Ethertype = "IPv4"
		case "ipv6":
			r.Ethertype = "IPv6"
		default:
			return r, errInvalidSecGroup("ethertype %q is not supported; use IPv4 or IPv6", *opt.Ethertype)
		}
	}

	if opt.Protocol != nil && *opt.Protocol != "" {
		proto := strings.ToLower(*opt.Protocol)
		if family, named := protocolNames[proto]; named {
			if family != "" && family != r.Ethertype {
				return r, errInvalidSecGroup("protocol %s requires ethertype %s", proto, family)
			}
		} else if n, err := strconv.Atoi(proto); err != nil || n < 0 || n > 255 {
			return r, errInvalidSecGroup("protocol %q must be icmp, tcp, udp, icmpv6 or an IP protocol number from 0 to 255", *opt.Protocol)
		}
		r.Protocol = &proto
	}

	if opt.Multiport != nil && *opt.Multiport != "" {
		if r.Protocol == nil || (*r.Protocol != "tcp" && *r.Protocol != "udp") {
			return r, errInvalidSecGroup("multiport can only be set when protocol is tcp or udp")
		}
		if err := checkMultiport(*opt.Multiport); err != nil {
			return r, errInvalidSecGroup("%s", err)
		}
		r.Multiport = opt.Multiport
	}

	remotes := 0
	for _, p := range []*string{opt.RemoteIPPrefix, opt.RemoteGroupID, opt.RemoteAddressGroupID} {
		if p != nil && *p != "" {
			remotes++
		}
	}
	if remotes > 1 {
		return r, errInvalidSecGroup("remote_ip_prefix, remote_group_id and remote_address_group_id are mutually exclusive")
	}
	if opt.RemoteIPPrefix != nil && *opt.RemoteIPPrefix != "" {
		prefix, err := parseRemotePrefix(*opt.RemoteIPPrefix, r.Ethertype)
		if err != nil {
			return r, errInvalidSecGroup("%s", err)
		}
		r.RemoteIPPrefix = &prefix
	}
	if opt.RemoteGroupID != nil && *opt.RemoteGroupID != "" {
		r.RemoteGroupID = opt.RemoteGroupID
	}
	if opt.RemoteAddressGroupID != nil && *opt.RemoteAddressGroupID != "" {
		r.RemoteAddressGroupID = opt.RemoteAddressGroupID
	}

	if opt.Action != nil && *opt.Action != "" {
		r.Action = strings.ToLower(*opt.Action)
		if r.Action != "allow" && r.Action != "deny" {
			return r, errInvalidSecGroup("action must be allow or deny")
		}
	}
	if opt.Priority != nil {
		r.Priority = *opt.Priority
		if r.Priority < minRulePriority || r.Priority > maxRulePriority {
			return r, errInvalidSecGroup("priority must be between %d and %d", minRulePriority, maxRulePriority)
		}
	}
	if opt.Enabled != nil {
		r.Enabled = *opt.Enabled
	}
	return r, nil
}

// checkMultiport validates a port list: single ports and ranges from 1
// to 65535 separated by commas, such as "22,80,8000-8100".
func checkMultiport(s string) error {
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			hi = lo
		}
		a, errA := strconv.Atoi(lo)
		b, errB := strconv.Atoi(hi)
		if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
			return fmt.Errorf("multiport %q is invalid: use ports from 1 to 65535 as a single port (80), a range (1-30) or a comma-separated list (22,3389,80)", s)
		}
	}
	return nil
}

// parseRemotePrefix normalises a remote_ip_prefix: a bare address gains
// a full-length mask and host bits are cleared. The address family must
// match the rule's ethertype.
func parseRemotePrefix(s, ethertype string) (string, error) {
	var prefix netip.Prefix
	if addr, err := netip.ParseAddr(s); err == nil {
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	} else if prefix, err = netip.ParsePrefix(s); err != nil {
		return "", fmt.Errorf("remote_ip_prefix %q is not an IP address or CIDR block", s)
	}
	if prefix.Addr().Is4() != (ethertype == "IPv4") {
		return "", fmt.Errorf("remote_ip_prefix %s does not match ethertype %s", s, ethertype)
	}
	return prefix.Masked().String(), nil
}

func eqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// sameRule reports whether two rules of one group match the same traffic
// with the same outcome, which the API rejects as a duplicate.
func sameRule(a, b SecurityGroupRule) bool {
	return a.SecurityGroupID == b.SecurityGroupID && a.Direction == b.Direction &&
		a.Ethertype == b.Ethertype && eqPtr(a.Protocol, b.Protocol) && eqPtr(a.Multiport, b.Multiport) &&
		eqPtr(a.RemoteIPPrefix, b.RemoteIPPrefix) && eqPtr(a.RemoteGroupID, b.RemoteGroupID) &&
		eqPtr(a.RemoteAddressGroupID, b.RemoteAddressGroupID) &&
		a.Action == b.Action && a.Priority == b.Priority
}

// CreateSecurityGroupRule adds a rule to a group. With dryRun the
// request is only validated and the zero value returned.
func (s *Service) CreateSecurityGroupRule(ctx context.Context, t Tenant, opt CreateSecurityGroupRuleOption, dryRun bool) (SecurityGroupRule, error) {
	rule, err := buildRule(opt)
	if err != nil {
		return SecurityGroupRule{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.secGroups(t).Get(ctx, rule.SecurityGroupID); errors.Is(err, store.ErrNotFound) {
		return SecurityGroupRule{}, errSecGroupNotFound(rule.SecurityGroupID)
	} else if err != nil {
		return SecurityGroupRule{}, err
	}
	if rule.RemoteGroupID != nil {
		if _, err := s.secGroups(t).Get(ctx, *rule.RemoteGroupID); errors.Is(err, store.ErrNotFound) {
			return SecurityGroupRule{}, errSecGroupNotFound(*rule.RemoteGroupID)
		} else if err != nil {
			return SecurityGroupRule{}, err
		}
	}
	if rule.RemoteAddressGroupID != nil {
		return SecurityGroupRule{}, errAddressGroupNotFound(*rule.RemoteAddressGroupID)
	}
	dups, err := s.secGroupRules(t).List(ctx, func(r SecurityGroupRule) bool { return sameRule(r, rule) })
	if err != nil {
		return SecurityGroupRule{}, err
	}
	if len(dups) > 0 {
		return SecurityGroupRule{}, errSecGroupConflict("The security group rule already exists (rule %s).", dups[0].ID)
	}
	if dryRun {
		return SecurityGroupRule{}, nil
	}

	now := TimeZ(s.timestamp())
	rule.ID = s.ids.UUID()
	rule.ProjectID = t.ProjectID
	rule.CreatedAt, rule.UpdatedAt = now, now
	if err := s.secGroupRules(t).Create(ctx, rule.ID, rule); err != nil {
		return SecurityGroupRule{}, err
	}
	return rule, nil
}

// GetSecurityGroupRule returns one rule.
func (s *Service) GetSecurityGroupRule(ctx context.Context, t Tenant, id string) (SecurityGroupRule, error) {
	r, err := s.secGroupRules(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return SecurityGroupRule{}, errSecGroupRuleNotFound(id)
	}
	return r, err
}

func matchAnyPtr(allowed []string, v *string) bool {
	return len(allowed) == 0 || (v != nil && slices.Contains(allowed, *v))
}

// ListSecurityGroupRules returns the project's rules in creation order.
func (s *Service) ListSecurityGroupRules(ctx context.Context, t Tenant, f ListSecurityGroupRulesFilter) ([]SecurityGroupRule, error) {
	return s.secGroupRules(t).List(ctx, func(r SecurityGroupRule) bool {
		return matchAny(f.IDs, r.ID) &&
			matchAny(f.SecurityGroupIDs, r.SecurityGroupID) &&
			matchAnyPtr(f.Protocols, r.Protocol) &&
			matchAny(f.Descriptions, r.Description) &&
			matchAnyPtr(f.RemoteGroupIDs, r.RemoteGroupID) &&
			matchAny(f.Ethertypes, r.Ethertype) &&
			matchAnyPtr(f.RemoteAddressGroupIDs, r.RemoteAddressGroupID) &&
			(len(f.Priorities) == 0 || slices.Contains(f.Priorities, r.Priority)) &&
			(f.Direction == "" || r.Direction == f.Direction) &&
			(f.Action == "" || r.Action == f.Action) &&
			(f.RemoteIPPrefix == "" || (r.RemoteIPPrefix != nil && *r.RemoteIPPrefix == f.RemoteIPPrefix)) &&
			(f.Enabled == nil || r.Enabled == *f.Enabled)
	})
}

// DeleteSecurityGroupRule removes one rule.
func (s *Service) DeleteSecurityGroupRule(ctx context.Context, t Tenant, id string) error {
	err := s.secGroupRules(t).Delete(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errSecGroupRuleNotFound(id)
	}
	return err
}
