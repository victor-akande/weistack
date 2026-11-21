// Package elb emulates Huawei Cloud dedicated Elastic Load Balance (v3):
// load balancers, listeners, pools, members, health monitors, certificates,
// L7 policies and rules, IP groups, security policies, flavors, availability
// zones, and resource tags.
package elb

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Store kinds owned by this service (§2).
const (
	kindLoadBalancer   = "elb.loadbalancer"
	kindListener       = "elb.listener"
	kindPool           = "elb.pool"
	kindMember         = "elb.member"
	kindHealthMonitor  = "elb.healthmonitor"
	kindCertificate    = "elb.certificate"
	kindL7Policy       = "elb.l7policy"
	kindL7Rule         = "elb.l7rule"
	kindIPGroup        = "elb.ipgroup"
	kindSecurityPolicy = "elb.securitypolicy"
)

// Resource statuses (§1, §3).
const (
	StatusActive    = "ACTIVE"
	StatusOnline    = "ONLINE"
	StatusOffline   = "OFFLINE"
	StatusNoMonitor = "NO_MONITOR"
)

// Limits, defaults, and wire time format (§2, §3).
const (
	timeFormat                 = "2006-01-02T15:04:05Z"
	defaultEnterpriseProjectID = "0"
	allGrantedEPs              = "all_granted_eps"
	maxTags                    = 20
)

// Tenant identifies whose resources a call operates on.
type Tenant = vpc.Tenant

// Network is what ELB needs of the VPC service; *vpc.Service has all of it.
type Network interface {
	GetVPC(ctx context.Context, t vpc.Tenant, id string) (vpc.VPC, error)
	GetSubnet(ctx context.Context, t vpc.Tenant, id string) (vpc.Subnet, error)
	ListSubnets(ctx context.Context, t vpc.Tenant, f vpc.ListSubnetsFilter) ([]vpc.Subnet, error)
	AllocateIP(ctx context.Context, t vpc.Tenant, subnetID, owner, want string) (string, error)
	ReleaseIP(ctx context.Context, t vpc.Tenant, subnetID, ip string) error
}

// PublicIPs is what ELB needs of the EIP service; *eip.Service implements it (§4.2).
type PublicIPs interface {
	BindToELB(ctx context.Context, t vpc.Tenant, eipID, lbID, vipPortID, vipAddress string) (address string, err error)
	CreateForELB(ctx context.Context, t vpc.Tenant, lbID, vipPortID, vipAddress string, ip eip.ServerIP) (id, address string, err error)
	UnbindFromELB(ctx context.Context, t vpc.Tenant, eipID, lbID string) error
	PublicIPAddress(ctx context.Context, t vpc.Tenant, eipID string) (string, bool, error)
}

// Servers finds the state of the server with a NIC at an address (§4.1).
type Servers interface {
	// ServerAt returns the status of the project's server with a NIC in
	// subnetID (the subnet's ID; "" means any subnet of vpcID) at ip.
	ServerAt(ctx context.Context, t vpc.Tenant, vpcID, subnetID, ip string) (status string, ok bool, err error)
}

// Deps are the dependencies of the ELB service (§4.1).
type Deps struct {
	Store   store.Store
	IDs     *ids.Generator
	Logger  *slog.Logger
	Vault   *vault.Vault // certificate private keys
	VPC     Network      // *vpc.Service
	EIPs    PublicIPs    // *eip.Service (§4.2)
	Servers Servers      // *ecs.Service (§4.1)
	Now     func() time.Time
}

// Service is the dedicated ELB v3 emulator.
type Service struct {
	store   store.Store
	ids     *ids.Generator
	log     *slog.Logger
	vault   *vault.Vault
	vpc     Network
	eips    PublicIPs
	servers Servers
	now     func() time.Time

	// mu serialises writes that check conflicts across records.
	mu sync.Mutex
}

// New returns the ELB service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.IDs == nil || d.Logger == nil || d.Vault == nil || d.VPC == nil || d.EIPs == nil || d.Servers == nil {
		return nil, errors.New("elb: Store, IDs, Logger, Vault, VPC, EIPs and Servers are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		store:   d.Store,
		ids:     d.IDs,
		log:     d.Logger,
		vault:   d.Vault,
		vpc:     d.VPC,
		eips:    d.EIPs,
		servers: d.Servers,
		now:     d.Now,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "elb" }

// Version implements server.Service.
func (s *Service) Version() string { return "v3 (dedicated)" }

func (s *Service) loadBalancers(t Tenant) store.Collection[loadBalancer] {
	return store.Of[loadBalancer](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindLoadBalancer})
}

func (s *Service) listeners(t Tenant) store.Collection[listener] {
	return store.Of[listener](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindListener})
}

func (s *Service) pools(t Tenant) store.Collection[pool] {
	return store.Of[pool](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindPool})
}

func (s *Service) members(t Tenant) store.Collection[member] {
	return store.Of[member](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindMember})
}

func (s *Service) healthMonitors(t Tenant) store.Collection[healthMonitor] {
	return store.Of[healthMonitor](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindHealthMonitor})
}

func (s *Service) certificates(t Tenant) store.Collection[certificate] {
	return store.Of[certificate](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindCertificate})
}

func (s *Service) l7Policies(t Tenant) store.Collection[l7Policy] {
	return store.Of[l7Policy](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindL7Policy})
}

func (s *Service) l7Rules(t Tenant) store.Collection[l7Rule] {
	return store.Of[l7Rule](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindL7Rule})
}

func (s *Service) ipGroups(t Tenant) store.Collection[ipGroup] {
	return store.Of[ipGroup](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindIPGroup})
}

func (s *Service) securityPolicies(t Tenant) store.Collection[securityPolicy] {
	return store.Of[securityPolicy](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSecurityPolicy})
}

func (s *Service) nowUTC() time.Time {
	return s.now().UTC().Truncate(time.Second)
}

func formatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// listLimits bounds "limit" on list operations: 1-2000, default 2000 (§3).
var listLimits = pagination.Limits{Default: 2000, Min: 1, Max: 2000}

var (
	uuidRE     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tagKeyRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	tagValueRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,255}$`)
)

func validName(s string) bool {
	return utf8.RuneCountInString(s) <= 255
}

func validDescription(s string) bool {
	return utf8.RuneCountInString(s) <= 255
}

func isUUID(s string) bool {
	return uuidRE.MatchString(s)
}

func validEnterpriseProjectID(s string) bool {
	return s == defaultEnterpriseProjectID || isUUID(s)
}

func inEPList(wants []string, ep string) bool {
	if len(wants) == 0 {
		return true
	}
	for _, w := range wants {
		if w == "" || w == allGrantedEPs || w == ep {
			return true
		}
	}
	return false
}

func validTag(k, v string) bool {
	return tagKeyRE.MatchString(k) && tagValueRE.MatchString(v)
}

func validTags(tags []tag) error {
	if len(tags) > maxTags {
		return errInvalidInput("tags")
	}
	seen := make(map[string]struct{}, len(tags))
	for _, tg := range tags {
		if !validTag(tg.Key, tg.Value) {
			return errInvalidInput("tags")
		}
		if _, dup := seen[tg.Key]; dup {
			return errInvalidInput("tags")
		}
		seen[tg.Key] = struct{}{}
	}
	return nil
}

func matchesAny(wants []string, v string) bool {
	if len(wants) == 0 {
		return true
	}
	return slices.Contains(wants, v)
}

func parseBoolQuery(q url.Values, key string) (*bool, error) {
	raw := q.Get(key)
	if raw == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(strings.ToLower(raw))
	if err != nil {
		return nil, errInvalidInput(key)
	}
	return &b, nil
}

func parseIntQueryValues(q url.Values, key string) ([]int, error) {
	vals := q[key]
	if len(vals) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(vals))
	for _, raw := range vals {
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, errInvalidInput(key)
		}
		out = append(out, n)
	}
	return out, nil
}

func makePageInfo[T any](items []T, idOf func(T) string, hasMore bool) pageInfo {
	pi := pageInfo{CurrentCount: len(items)}
	if len(items) > 0 {
		pi.PreviousMarker = idOf(items[0])
		if hasMore {
			last := idOf(items[len(items)-1])
			pi.NextMarker = &last
		}
	}
	return pi
}

// paginateSlice applies ELB v3 marker/limit pagination to a slice sorted by ascending ID.
func paginateSlice[T any](all []T, idOf func(T) string, page pagination.Marker) ([]T, pageInfo, error) {
	start := 0
	if page.ID != "" {
		found := false
		for i, item := range all {
			if idOf(item) == page.ID {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, pageInfo{}, errInvalidInput("marker")
		}
	}
	rem := all[start:]
	hasMore := false
	if page.Limit > 0 && len(rem) > page.Limit {
		rem = rem[:page.Limit]
		hasMore = true
	}
	out := make([]T, len(rem))
	copy(out, rem)
	return out, makePageInfo(out, idOf, hasMore), nil
}

// findSubnetByNeutronID finds a VPC subnet in t whose neutron_subnet_id matches id (§3.1, §3.4).
func (s *Service) findSubnetByNeutronID(ctx context.Context, t Tenant, neutronSubnetID string) (vpc.Subnet, bool, error) {
	subnets, err := s.vpc.ListSubnets(ctx, t, vpc.ListSubnetsFilter{})
	if err != nil {
		return vpc.Subnet{}, false, err
	}
	for _, sn := range subnets {
		if sn.NeutronSubnetID == neutronSubnetID {
			return sn, true, nil
		}
	}
	return vpc.Subnet{}, false, nil
}

// listenerPoolProtocolAllowed reports whether a listener with listenerProto
// may forward to a pool with poolProto (§3.3).
func listenerPoolProtocolAllowed(listenerProto, poolProto string) bool {
	switch listenerProto {
	case "UDP":
		return poolProto == "UDP" || poolProto == "QUIC"
	case "TCP":
		return poolProto == "TCP"
	case "HTTP":
		return poolProto == "HTTP"
	case "HTTPS":
		return poolProto == "HTTP" || poolProto == "HTTPS" || poolProto == "GRPC"
	case "TLS":
		return poolProto == "TCP" || poolProto == "TLS"
	case "QUIC":
		return poolProto == "UDP" || poolProto == "QUIC"
	default:
		return false
	}
}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		t := Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")}

		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "elb operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleFlatRequestID, err)
	}
}

func requestID(r *http.Request) string {
	return reqctx.From(r.Context()).RequestID
}

func decode(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errInvalidInput("body")
	}
	return nil
}

func (s *Service) notImplemented(op string) handler {
	return func(http.ResponseWriter, *http.Request, Tenant) error {
		return errNotImplemented(op)
	}
}
