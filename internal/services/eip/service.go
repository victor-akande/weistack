// Package eip emulates Huawei Cloud Elastic IP: public IPv4 addresses,
// dedicated and shared bandwidths, and EIP resource tags.
//
// EIP shares the VPC endpoint (vpc.{region}.myhuaweicloud.com), so it is
// mounted on the VPC router through vpc.Extension rather than registered
// as a standalone server.Service.
package eip

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sync"
	"time"

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

// Store kinds owned by this service.
const (
	kindPublicIP  = "eip.publicip"
	kindBandwidth = "eip.bandwidth"
	kindAddress   = "eip.address"
)

// Lifecycle task kind, matched by fault injection.
const taskPublicIPCreate = "eip.publicip.create"

// Quotas and defaults.
const (
	DefaultMaxPerProject       = 50
	maxSharedBandwidths        = 5
	maxEIPsPerSharedBandwidth  = 20
	defaultEnterpriseProjectID = "0"
	allGrantedEPs              = "all_granted_eps"
)

// Tenant identifies whose resources a call operates on.
type Tenant = vpc.Tenant

// PortLookup finds a port of a project; vpc.Service implements it.
type PortLookup interface {
	Port(ctx context.Context, t vpc.Tenant, id string) (vpc.Port, bool, error)
}

// Deps are the dependencies of the service.
type Deps struct {
	Store         store.Store
	Engine        *lifecycle.Engine
	IDs           *ids.Generator
	Logger        *slog.Logger
	Ports         PortLookup // the VPC service
	MaxPerProject int        // -eip-max-per-project
	Now           func() time.Time
}

// Service is the EIP emulator.
type Service struct {
	store         store.Store
	engine        *lifecycle.Engine
	ids           *ids.Generator
	log           *slog.Logger
	ports         PortLookup
	maxPerProject int
	now           func() time.Time

	// mu serialises check-then-write sequences across publicips and
	// bandwidths (quota, port binding uniqueness, shared bandwidth updates).
	mu sync.Mutex

	// pool overrides the default candidate IPv4 address pool in tests.
	pool []string
}

// New returns the EIP service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil || d.Ports == nil {
		return nil, errors.New("eip: Store, Engine, IDs, Logger and Ports are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxPerProject <= 0 {
		d.MaxPerProject = DefaultMaxPerProject
	}
	return &Service{
		store:         d.Store,
		engine:        d.Engine,
		ids:           d.IDs,
		log:           d.Logger,
		ports:         d.Ports,
		maxPerProject: d.MaxPerProject,
		now:           d.Now,
	}, nil
}

func (s *Service) publicips(t Tenant) store.Collection[publicIP] {
	return store.Of[publicIP](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindPublicIP})
}

func (s *Service) bandwidths(t Tenant) store.Collection[bandwidth] {
	return store.Of[bandwidth](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindBandwidth})
}

func (s *Service) addresses(region string) store.Collection[addressClaim] {
	return store.Of[addressClaim](s.store, store.Scope{Region: region, ProjectID: store.Global, Kind: kindAddress})
}

func (s *Service) nowUTC() time.Time {
	return s.now().UTC().Truncate(time.Second)
}

// v1ListLimits bounds "limit" on v1 list operations: 0 to the maximum
// 32-bit integer, 2000 when omitted.
var v1ListLimits = pagination.Limits{Default: 2000, Min: 0, Max: math.MaxInt32}

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func validName(s string) bool {
	return nameRE.MatchString(s)
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

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

func (s *Service) v1(op string, fn handler) http.HandlerFunc {
	return s.adapt(op, apierr.StyleCodeMessage, fn)
}

func (s *Service) v3(op string, fn handler) http.HandlerFunc {
	return s.adapt(op, apierr.StyleFlatRequestID, fn)
}

func (s *Service) adapt(op string, style apierr.Style, fn handler) http.HandlerFunc {
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
			s.log.ErrorContext(r.Context(), "eip operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, style, err)
	}
}

func decode(r *http.Request, dst any, invalid func(string, ...any) *apierr.Error) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return invalid("%s", err)
	}
	return nil
}
