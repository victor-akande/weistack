package elb

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

type ipgCreateInput struct {
	Name                string
	Description         string
	IPList              []ipInfo
	IPListSet           bool
	EnterpriseProjectID *string
}

type ipgUpdateInput struct {
	Name        *string
	Description *string
	IPList      *[]ipInfo
}

type ipgListFilter struct {
	IDs                  []string
	Names                []string
	Descriptions         []string
	IPs                  []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
}

type ipgDetail struct {
	Group       ipGroup
	ListenerIDs []string
}

// ipgNormalizeIP validates an IP group entry as an IPv4 address or a canonical
// IPv4 CIDR block (§3.9), returning its normalized wire representation and a
// canonical prefix key used to reject duplicates (including x.x.x.x vs x.x.x.x/32).
func ipgNormalizeIP(raw string) (string, netip.Prefix, bool) {
	if raw == "" {
		return "", netip.Prefix{}, false
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() || p.Masked() != p {
			return "", netip.Prefix{}, false
		}
		return p.String(), p, true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return "", netip.Prefix{}, false
	}
	return addr.String(), netip.PrefixFrom(addr, 32), true
}

func ipgValidateIPList(entries []ipInfo) ([]ipInfo, error) {
	out := make([]ipInfo, 0, len(entries))
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for _, entry := range entries {
		norm, key, ok := ipgNormalizeIP(entry.IP)
		if !ok {
			return nil, errInvalidInput("ip_list")
		}
		if !validDescription(entry.Description) {
			return nil, errInvalidInput("ip_list")
		}
		if _, dup := seen[key]; dup {
			return nil, errInvalidInput("ip_list")
		}
		seen[key] = struct{}{}
		out = append(out, ipInfo{
			IP:          norm,
			Description: entry.Description,
		})
	}
	return out, nil
}

func ipgListenerContains(l listener, ipgID string) bool {
	if l.IPGroup == nil || l.IPGroup.IPGroupID == "" {
		return false
	}
	for id := range strings.SplitSeq(l.IPGroup.IPGroupID, ",") {
		if id == ipgID {
			return true
		}
	}
	return false
}

func ipgListenersForGroup(listeners []listener, ipgID string) []string {
	var out []string
	for _, l := range listeners {
		if ipgListenerContains(l, ipgID) {
			out = append(out, l.ID)
		}
	}
	slices.Sort(out)
	return out
}

func ipgListenersByGroup(listeners []listener) map[string][]string {
	byGroup := make(map[string][]string)
	for _, l := range listeners {
		if l.IPGroup == nil || l.IPGroup.IPGroupID == "" {
			continue
		}
		seenForListener := make(map[string]struct{})
		for id := range strings.SplitSeq(l.IPGroup.IPGroupID, ",") {
			if id == "" {
				continue
			}
			if _, dup := seenForListener[id]; dup {
				continue
			}
			seenForListener[id] = struct{}{}
			byGroup[id] = append(byGroup[id], l.ID)
		}
	}
	for id := range byGroup {
		slices.Sort(byGroup[id])
	}
	return byGroup
}

func ipgMatchesIPs(wants []string, list []ipInfo) bool {
	if len(wants) == 0 {
		return true
	}
	for _, entry := range list {
		if slices.Contains(wants, entry.IP) {
			return true
		}
	}
	return false
}

func (s *Service) createIPGroup(ctx context.Context, t Tenant, in ipgCreateInput) (ipgDetail, error) {
	if !validName(in.Name) {
		return ipgDetail{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return ipgDetail{}, errInvalidInput("description")
	}
	if !in.IPListSet {
		return ipgDetail{}, errInvalidInput("ip_list")
	}
	ipList, err := ipgValidateIPList(in.IPList)
	if err != nil {
		return ipgDetail{}, err
	}
	ep := defaultEnterpriseProjectID
	if in.EnterpriseProjectID != nil {
		if !validEnterpriseProjectID(*in.EnterpriseProjectID) {
			return ipgDetail{}, errInvalidInput("enterprise_project_id")
		}
		ep = *in.EnterpriseProjectID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowUTC()
	rec := ipGroup{
		ID:                  s.ids.UUID(),
		Name:                in.Name,
		Description:         in.Description,
		IPList:              ipList,
		EnterpriseProjectID: ep,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.ipGroups(t).Create(ctx, rec.ID, rec); err != nil {
		return ipgDetail{}, err
	}
	return ipgDetail{Group: rec}, nil
}

func (s *Service) getIPGroup(ctx context.Context, t Tenant, id string) (ipgDetail, error) {
	rec, err := s.ipGroups(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ipgDetail{}, errNotFound("ipgroup", id)
	}
	if err != nil {
		return ipgDetail{}, err
	}
	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return ipgDetail{}, err
	}
	return ipgDetail{
		Group:       rec,
		ListenerIDs: ipgListenersForGroup(listeners, rec.ID),
	}, nil
}

func (s *Service) listIPGroups(ctx context.Context, t Tenant, f ipgListFilter) ([]ipgDetail, pageInfo, error) {
	items, err := s.ipGroups(t).List(ctx, func(g ipGroup) bool {
		if !matchesAny(f.IDs, g.ID) {
			return false
		}
		if !matchesAny(f.Names, g.Name) {
			return false
		}
		if !matchesAny(f.Descriptions, g.Description) {
			return false
		}
		if !ipgMatchesIPs(f.IPs, g.IPList) {
			return false
		}
		ep := g.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		if !inEPList(f.EnterpriseProjectIDs, ep) {
			return false
		}
		return true
	})
	if err != nil {
		return nil, pageInfo{}, err
	}

	slices.SortFunc(items, func(a, b ipGroup) int {
		return strings.Compare(a.ID, b.ID)
	})
	paged, pi, err := paginateSlice(items, func(g ipGroup) string { return g.ID }, f.Page)
	if err != nil {
		return nil, pageInfo{}, err
	}

	var byGroup map[string][]string
	if len(paged) > 0 {
		listeners, err := s.listeners(t).List(ctx, nil)
		if err != nil {
			return nil, pageInfo{}, err
		}
		byGroup = ipgListenersByGroup(listeners)
	}

	out := make([]ipgDetail, len(paged))
	for i, g := range paged {
		out[i] = ipgDetail{
			Group:       g,
			ListenerIDs: byGroup[g.ID],
		}
	}
	return out, pi, nil
}

func (s *Service) updateIPGroup(ctx context.Context, t Tenant, id string, in ipgUpdateInput) (ipgDetail, error) {
	if in.Name != nil && !validName(*in.Name) {
		return ipgDetail{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return ipgDetail{}, errInvalidInput("description")
	}
	var validatedIPList []ipInfo
	if in.IPList != nil {
		var err error
		validatedIPList, err = ipgValidateIPList(*in.IPList)
		if err != nil {
			return ipgDetail{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	updated, err := s.ipGroups(t).Update(ctx, id, func(g *ipGroup) error {
		if in.Name != nil {
			g.Name = *in.Name
		}
		if in.Description != nil {
			g.Description = *in.Description
		}
		if in.IPList != nil {
			g.IPList = validatedIPList
		}
		g.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return ipgDetail{}, errNotFound("ipgroup", id)
	}
	if err != nil {
		return ipgDetail{}, err
	}

	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return ipgDetail{}, err
	}
	return ipgDetail{
		Group:       updated,
		ListenerIDs: ipgListenersForGroup(listeners, updated.ID),
	}, nil
}

func (s *Service) deleteIPGroup(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.ipGroups(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		return errNotFound("ipgroup", id)
	} else if err != nil {
		return err
	}

	listeners, err := s.listeners(t).List(ctx, func(l listener) bool {
		return ipgListenerContains(l, id)
	})
	if err != nil {
		return err
	}
	if len(listeners) > 0 {
		return errConflict("The IP group is associated with one or more listeners.")
	}

	if err := s.ipGroups(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
