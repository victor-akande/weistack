package nat

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type sessionConfInput struct {
	TCPSessionExpireTime  *int
	UDPSessionExpireTime  *int
	ICMPSessionExpireTime *int
	TCPTimeWaitTime       *int
}

type createGatewayInput struct {
	Name                string
	RouterID            string
	InternalNetworkID   string
	NgportIPAddress     string
	Description         string
	Spec                string
	EnterpriseProjectID string
	SessionConf         *sessionConfInput
	Tags                []string
	PrepaidOptions      bool
}

type updateGatewayInput struct {
	Name           *string
	Description    *string
	Spec           *string
	SessionConf    *sessionConfInput
	PrepaidOptions bool
}

type listGatewaysFilter struct {
	TenantID            string
	ID                  string
	EnterpriseProjectID string
	Description         string
	CreatedAt           string
	Name                string
	Statuses            []string
	Specs               []string
	AdminStateUp        *bool
	InternalNetworkID   string
	RouterID            string
	Page                pagination.Marker
}

func validPublicSpec(spec string) bool {
	switch spec {
	case "1", "2", "3", "4", "5":
		return true
	default:
		return false
	}
}

func dnatRulesLimitForSpec(_ string) int {
	return publicDnatRulesLimit
}

func isAPIError(err error) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr)
}

func validateSessionConf(in *sessionConfInput) error {
	if in == nil {
		return nil
	}
	for _, v := range []*int{
		in.TCPSessionExpireTime,
		in.UDPSessionExpireTime,
		in.ICMPSessionExpireTime,
		in.TCPTimeWaitTime,
	} {
		if v != nil && *v < 0 {
			return errInvalidParams("")
		}
	}
	return nil
}

func applySessionConf(dst *sessionConf, in *sessionConfInput) {
	if in == nil {
		return
	}
	if in.TCPSessionExpireTime != nil {
		dst.TCPSessionExpireTime = *in.TCPSessionExpireTime
	}
	if in.UDPSessionExpireTime != nil {
		dst.UDPSessionExpireTime = *in.UDPSessionExpireTime
	}
	if in.ICMPSessionExpireTime != nil {
		dst.ICMPSessionExpireTime = *in.ICMPSessionExpireTime
	}
	if in.TCPTimeWaitTime != nil {
		dst.TCPTimeWaitTime = *in.TCPTimeWaitTime
	}
}

func parseCreateGatewayTags(raw []string) ([]tag, error) {
	if len(raw) > maxTags {
		return nil, errTooManyTags()
	}
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]tag, 0, len(raw))
	for _, s := range raw {
		k, v, _ := strings.Cut(s, "*")
		if !validTag(k, v) {
			return nil, errInvalidTag()
		}
		if i := slices.IndexFunc(out, func(existing tag) bool { return existing.Key == k }); i >= 0 {
			out[i].Value = v
			continue
		}
		out = append(out, tag{Key: k, Value: v})
	}
	return out, nil
}

func (s *Service) createGateway(ctx context.Context, t Tenant, in createGatewayInput) (gateway, error) {
	if in.PrepaidOptions {
		return gateway{}, apierr.NotImplemented("nat", "yearly/monthly NAT gateways")
	}
	if !validName(in.Name) || in.RouterID == "" || in.InternalNetworkID == "" || in.Spec == "" {
		return gateway{}, errInvalidParams("")
	}
	if !validPublicSpec(in.Spec) {
		return gateway{}, errInvalidSpec(in.Spec)
	}
	if !validDescription(in.Description) {
		return gateway{}, errInvalidDescription()
	}
	ep := in.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	if !validEnterpriseProjectID(ep) {
		return gateway{}, errInvalidEnterpriseProjectID()
	}
	if err := validateSessionConf(in.SessionConf); err != nil {
		return gateway{}, err
	}
	sess := defaultSessionConf
	applySessionConf(&sess, in.SessionConf)

	tags, err := parseCreateGatewayTags(in.Tags)
	if err != nil {
		return gateway{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.vpc.GetVPC(ctx, t, in.RouterID); isAPIError(err) {
		return gateway{}, errRouterNotFound(in.RouterID)
	} else if err != nil {
		return gateway{}, err
	}

	subnet, err := s.vpc.GetSubnet(ctx, t, in.InternalNetworkID)
	if isAPIError(err) {
		return gateway{}, errNetworkNotFound(in.InternalNetworkID)
	}
	if err != nil {
		return gateway{}, err
	}
	if subnet.VPCID != in.RouterID {
		return gateway{}, errSubnetNotInRouter(in.RouterID, in.InternalNetworkID)
	}

	id := s.ids.UUID()
	ip, err := s.vpc.AllocateIP(ctx, t, in.InternalNetworkID, "nat:"+id, in.NgportIPAddress)
	if err != nil {
		switch {
		case errors.Is(err, vpc.ErrSubnetNotFound):
			return gateway{}, errNetworkNotFound(in.InternalNetworkID)
		case errors.Is(err, vpc.ErrIPNotUsable), errors.Is(err, vpc.ErrIPInUse):
			return gateway{}, errInvalidParams("")
		case errors.Is(err, vpc.ErrSubnetFull):
			return gateway{}, errSubnetFull(in.InternalNetworkID)
		default:
			return gateway{}, err
		}
	}

	g := gateway{
		ID:                  id,
		Name:                in.Name,
		Description:         in.Description,
		Spec:                in.Spec,
		Status:              StatusPendingCreate,
		RouterID:            in.RouterID,
		InternalNetworkID:   in.InternalNetworkID,
		NgportIP:            ip,
		EnterpriseProjectID: ep,
		Session:             sess,
		Tags:                tags,
		CreatedAt:           s.nowUTC(),
	}
	if err := s.gateways(t).Create(ctx, g.ID, g); err != nil {
		_ = s.vpc.ReleaseIP(ctx, t, g.InternalNetworkID, g.NgportIP)
		return gateway{}, err
	}
	s.scheduleGatewayActivation(t, g.ID)
	return g, nil
}

func (s *Service) getGateway(ctx context.Context, t Tenant, id string) (gateway, error) {
	g, err := s.gateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return gateway{}, errGatewayNotFound(id)
	}
	if err != nil {
		return gateway{}, err
	}
	return g, nil
}

func matchesPublicCreatedAt(created time.Time, want string) bool {
	u := created.UTC()
	if u.Format(publicTimeFormat) == want {
		return true
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	} {
		if parsed, err := time.ParseInLocation(layout, want, time.UTC); err == nil {
			if strings.Contains(want, ".") {
				return u.Equal(parsed.UTC())
			}
			return u.Truncate(time.Second).Equal(parsed.UTC().Truncate(time.Second))
		}
	}
	return false
}

func (s *Service) listGateways(ctx context.Context, t Tenant, f listGatewaysFilter) ([]gateway, error) {
	items, err := s.gateways(t).List(ctx, func(g gateway) bool {
		if f.TenantID != "" && f.TenantID != t.ProjectID {
			return false
		}
		if f.ID != "" && g.ID != f.ID {
			return false
		}
		if !inEP(f.EnterpriseProjectID, g.EnterpriseProjectID) {
			return false
		}
		if f.Description != "" && g.Description != f.Description {
			return false
		}
		if f.CreatedAt != "" && !matchesPublicCreatedAt(g.CreatedAt, f.CreatedAt) {
			return false
		}
		if f.Name != "" && g.Name != f.Name {
			return false
		}
		if len(f.Statuses) > 0 && !slices.Contains(f.Statuses, g.Status) {
			return false
		}
		if len(f.Specs) > 0 && !slices.Contains(f.Specs, g.Spec) {
			return false
		}
		if f.AdminStateUp != nil && !*f.AdminStateUp {
			return false
		}
		if f.InternalNetworkID != "" && g.InternalNetworkID != f.InternalNetworkID {
			return false
		}
		if f.RouterID != "" && g.RouterID != f.RouterID {
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(items, func(a, b gateway) int {
		return strings.Compare(a.ID, b.ID)
	})
	page, err := pagination.ByMarker(items, func(g gateway) string { return g.ID }, f.Page)
	if err != nil {
		return nil, errInvalidParams("")
	}
	return page, nil
}

func (s *Service) updateGateway(ctx context.Context, t Tenant, id string, in updateGatewayInput) (gateway, error) {
	if in.PrepaidOptions {
		return gateway{}, apierr.NotImplemented("nat", "yearly/monthly NAT gateways")
	}
	if in.Name != nil && !validName(*in.Name) {
		return gateway{}, errInvalidParams("")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return gateway{}, errInvalidDescription()
	}
	if in.Spec != nil && !validPublicSpec(*in.Spec) {
		return gateway{}, errInvalidSpec(*in.Spec)
	}
	if err := validateSessionConf(in.SessionConf); err != nil {
		return gateway{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.gateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return gateway{}, errGatewayNotFound(id)
	}
	if err != nil {
		return gateway{}, err
	}
	if existing.Status != StatusActive {
		return gateway{}, errGatewayNotActive(id)
	}
	if in.Spec != nil {
		limit := dnatRulesLimitForSpec(*in.Spec)
		dnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
			return r.GatewayID == id
		})
		if err != nil {
			return gateway{}, err
		}
		if len(dnats) > limit {
			return gateway{}, errDnatLimitExceeded(limit)
		}
	}

	updated, err := s.gateways(t).Update(ctx, id, func(g *gateway) error {
		if in.Name != nil {
			g.Name = *in.Name
		}
		if in.Description != nil {
			g.Description = *in.Description
		}
		if in.Spec != nil {
			g.Spec = *in.Spec
		}
		if in.SessionConf != nil {
			applySessionConf(&g.Session, in.SessionConf)
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return gateway{}, errGatewayNotFound(id)
	}
	if err != nil {
		return gateway{}, err
	}
	return updated, nil
}

func (s *Service) deleteGateway(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, err := s.gateways(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errGatewayNotFound(id)
	}
	if err != nil {
		return err
	}
	if g.Status == StatusPendingCreate {
		return errGatewayNotActive(id)
	}

	snats, err := s.snatRules(t).List(ctx, func(r snatRule) bool {
		return r.GatewayID == id
	})
	if err != nil {
		return err
	}
	if len(snats) > 0 {
		return errRulesExist()
	}

	dnats, err := s.dnatRules(t).List(ctx, func(r dnatRule) bool {
		return r.GatewayID == id
	})
	if err != nil {
		return err
	}
	if len(dnats) > 0 {
		return errRulesExist()
	}

	if err := s.gateways(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.engine.Cancel(id)
	return s.vpc.ReleaseIP(ctx, t, g.InternalNetworkID, g.NgportIP)
}
