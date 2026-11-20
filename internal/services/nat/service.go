// Package nat emulates Huawei Cloud NAT Gateway: public NAT gateways,
// SNAT and DNAT rules, private NAT gateways, transit subnets, transit IPs,
// and resource tags.
package nat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Store kinds owned by this service (§2).
const (
	kindGateway        = "nat.gateway"
	kindSnat           = "nat.snat"
	kindDnat           = "nat.dnat"
	kindPrivateGateway = "nat.private-gateway"
	kindTransitSubnet  = "nat.transit-subnet"
	kindTransitIP      = "nat.transit-ip"
	kindPrivateSnat    = "nat.private-snat"
	kindPrivateDnat    = "nat.private-dnat"
)

// Lifecycle task kinds, matched by fault injection (§4.5).
const (
	taskGatewayCreate = "nat.gateway.create"
	taskSnatCreate    = "nat.snat.create"
	taskDnatCreate    = "nat.dnat.create"
)

// Resource statuses (§1, §3).
const (
	StatusPendingCreate = "PENDING_CREATE"
	StatusActive        = "ACTIVE"
	StatusInactive      = "INACTIVE"
)

// Limits, defaults and wire time formats (§2, §3).
const (
	publicTimeFormat            = "2006-01-02 15:04:05.000000"
	privateTimeFormat           = "2006-01-02T15:04:05Z"
	defaultEnterpriseProjectID  = "0"
	allGrantedEPs               = "all_granted_eps"
	maxTags                     = 20
	maxSnatEIPs                 = 20
	publicDnatRulesLimit        = 200
	publicSnatPublicIPLimit     = 20
	privateTransitIPPoolSizeMax = 1
)

// Tenant identifies whose resources a call operates on.
type Tenant = vpc.Tenant

// Network is what NAT needs of the VPC service; *vpc.Service has all of it.
type Network interface {
	GetVPC(ctx context.Context, t vpc.Tenant, id string) (vpc.VPC, error)
	GetSubnet(ctx context.Context, t vpc.Tenant, id string) (vpc.Subnet, error)
	ListSubnets(ctx context.Context, t vpc.Tenant, f vpc.ListSubnetsFilter) ([]vpc.Subnet, error)
	Port(ctx context.Context, t vpc.Tenant, id string) (vpc.Port, bool, error)
	AllocateIP(ctx context.Context, t vpc.Tenant, subnetID, owner, want string) (string, error)
	ReleaseIP(ctx context.Context, t vpc.Tenant, subnetID, ip string) error
}

// PublicIPs is what NAT needs of the EIP service; *eip.Service implements it.
type PublicIPs interface {
	HoldForNAT(ctx context.Context, t vpc.Tenant, eipID, gatewayID string) (string, error)
	ReleaseFromNAT(ctx context.Context, t vpc.Tenant, eipID, gatewayID string) error
	PublicIPByAddress(ctx context.Context, t vpc.Tenant, address string) (id string, ok bool, err error)
	PublicIPAddress(ctx context.Context, t vpc.Tenant, eipID string) (string, bool, error)
}

// Deps are the dependencies of the service.
type Deps struct {
	Store  store.Store
	Engine *lifecycle.Engine
	IDs    *ids.Generator
	Logger *slog.Logger
	VPC    Network   // the VPC service
	EIPs   PublicIPs // the EIP service (§4.2)
	Now    func() time.Time
}

// Service is the NAT Gateway emulator.
type Service struct {
	store  store.Store
	engine *lifecycle.Engine
	ids    *ids.Generator
	log    *slog.Logger
	vpc    Network
	eips   PublicIPs
	now    func() time.Time

	// mu serialises every write that checks conflicts or holds EIPs and
	// transit IPs across records.
	mu sync.Mutex
}

// New returns the NAT Gateway service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil || d.VPC == nil || d.EIPs == nil {
		return nil, errors.New("nat: Store, Engine, IDs, Logger, VPC and EIPs are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		store:  d.Store,
		engine: d.Engine,
		ids:    d.IDs,
		log:    d.Logger,
		vpc:    d.VPC,
		eips:   d.EIPs,
		now:    d.Now,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "nat" }

// Version implements server.Service.
func (s *Service) Version() string { return "v2 (public), v3 (private, tags)" }

func (s *Service) gateways(t Tenant) store.Collection[gateway] {
	return store.Of[gateway](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindGateway})
}

func (s *Service) snatRules(t Tenant) store.Collection[snatRule] {
	return store.Of[snatRule](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSnat})
}

func (s *Service) dnatRules(t Tenant) store.Collection[dnatRule] {
	return store.Of[dnatRule](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindDnat})
}

func (s *Service) privateGateways(t Tenant) store.Collection[privateGateway] {
	return store.Of[privateGateway](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindPrivateGateway})
}

func (s *Service) transitSubnets(t Tenant) store.Collection[transitSubnet] {
	return store.Of[transitSubnet](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindTransitSubnet})
}

func (s *Service) transitIPs(t Tenant) store.Collection[transitIP] {
	return store.Of[transitIP](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindTransitIP})
}

func (s *Service) privateSnats(t Tenant) store.Collection[privateSnat] {
	return store.Of[privateSnat](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindPrivateSnat})
}

func (s *Service) privateDnats(t Tenant) store.Collection[privateDnat] {
	return store.Of[privateDnat](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindPrivateDnat})
}

func (s *Service) nowUTC() time.Time {
	return s.now().UTC().Truncate(time.Microsecond)
}

// Resume reschedules PENDING_CREATE public gateways and rules found at startup.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("nat: resuming transitions: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil {
			continue
		}
		if scope.Kind != kindGateway && scope.Kind != kindSnat && scope.Kind != kindDnat {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var r struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			if err := json.Unmarshal(rec.Data, &r); err != nil {
				return fmt.Errorf("nat: decoding %s/%s: %w", key, rec.ID, err)
			}
			if r.Status != StatusPendingCreate {
				continue
			}
			switch scope.Kind {
			case kindGateway:
				s.scheduleGatewayActivation(t, r.ID)
			case kindSnat:
				s.scheduleSnatActivation(t, r.ID)
			case kindDnat:
				s.scheduleDnatActivation(t, r.ID)
			}
		}
	}
	return nil
}

func (s *Service) scheduleGatewayActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskGatewayCreate,
		Run: func(ctx context.Context, fault error) {
			next := StatusActive
			if fault != nil {
				next = StatusInactive
			}
			_, err := s.gateways(t).Update(ctx, id, func(g *gateway) error {
				if g.Status == StatusPendingCreate {
					g.Status = next
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "nat gateway activation failed", "nat_gateway_id", id, "error", err)
			}
		},
	})
}

func (s *Service) scheduleSnatActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskSnatCreate,
		Run: func(ctx context.Context, fault error) {
			next := StatusActive
			if fault != nil {
				next = StatusInactive
			}
			_, err := s.snatRules(t).Update(ctx, id, func(r *snatRule) error {
				if r.Status == StatusPendingCreate {
					r.Status = next
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "nat snat rule activation failed", "snat_rule_id", id, "error", err)
			}
		},
	})
}

func (s *Service) scheduleDnatActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskDnatCreate,
		Run: func(ctx context.Context, fault error) {
			next := StatusActive
			if fault != nil {
				next = StatusInactive
			}
			_, err := s.dnatRules(t).Update(ctx, id, func(r *dnatRule) error {
				if r.Status == StatusPendingCreate {
					r.Status = next
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "nat dnat rule activation failed", "dnat_rule_id", id, "error", err)
			}
		},
	})
}

// listLimits bounds "limit" on list operations: 1–2000, default 2000 (§3).
var listLimits = pagination.Limits{Default: 2000, Min: 1, Max: 2000}

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func validName(s string) bool {
	return nameRE.MatchString(s)
}

func validDescription(s string) bool {
	return utf8.RuneCountInString(s) <= 255 && !strings.ContainsAny(s, "<>")
}

func isUUID(s string) bool {
	return uuidRE.MatchString(s)
}

func validEnterpriseProjectID(s string) bool {
	return s == defaultEnterpriseProjectID || isUUID(s)
}

func inEP(want, ep string) bool {
	return want == "" || want == allGrantedEPs || want == ep
}

func validTag(k, v string) bool {
	kl := utf8.RuneCountInString(k)
	vl := utf8.RuneCountInString(v)
	return kl >= 1 && kl <= 128 && vl <= 255
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
			s.log.ErrorContext(r.Context(), "nat operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleFlatRequestID, err)
	}
}

func decode(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errBadJSON("%s", err)
	}
	return nil
}
