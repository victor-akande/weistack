// Package vpc emulates Huawei Cloud Virtual Private Cloud: VPCs, subnets,
// security groups and security group rules.
//
// Request and response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/vpc/v2 and v3). The Go methods on
// Service (CreateVPC, GetVPC, ...) are the service layer; other emulated
// services call them directly to resolve network dependencies.
package vpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Store kinds owned by this service.
const (
	kindVPC          = "vpc.vpc"
	kindSubnet       = "vpc.subnet"
	kindSecGroup     = "vpc.secgroup"
	kindSecGroupRule = "vpc.secgroup-rule"
)

// Lifecycle task kinds, matched by fault injection.
const (
	taskVPCCreate    = "vpc.vpc.create"
	taskSubnetCreate = "vpc.subnet.create"
)

// Tenant identifies whose resources a call operates on.
type Tenant struct {
	Region    string
	ProjectID string
}

// Deps are the dependencies of the service.
type Deps struct {
	Store  store.Store
	Engine *lifecycle.Engine
	IDs    *ids.Generator
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the VPC emulator.
type Service struct {
	store  store.Store
	engine *lifecycle.Engine
	ids    *ids.Generator
	log    *slog.Logger
	now    func() time.Time

	// mu serialises check-then-write sequences that span several
	// records (name uniqueness, CIDR overlap), which a single-record
	// compare-and-swap cannot protect.
	mu sync.Mutex
	// ipamMu serialises private IP allocation. Correctness comes from
	// the store's compare-and-swap; the mutex only spares a burst of
	// concurrent allocations from retrying against each other.
	ipamMu sync.Mutex
}

// New returns the VPC service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil {
		return nil, errors.New("vpc: Store, Engine, IDs and Logger are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{store: d.Store, engine: d.Engine, ids: d.IDs, log: d.Logger, now: d.Now}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "vpc" }

// Version implements server.Service.
func (s *Service) Version() string { return "v1, v3" }

func (s *Service) vpcs(t Tenant) store.Collection[VPC] {
	return store.Of[VPC](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVPC})
}

func (s *Service) subnets(t Tenant) store.Collection[subnetRecord] {
	return store.Of[subnetRecord](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSubnet})
}

func (s *Service) secGroups(t Tenant) store.Collection[SecurityGroup] {
	return store.Of[SecurityGroup](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSecGroup})
}

func (s *Service) secGroupRules(t Tenant) store.Collection[SecurityGroupRule] {
	return store.Of[SecurityGroupRule](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSecGroupRule})
}

// timestamp returns the current time truncated to the second, the
// resolution of the API's timestamps.
func (s *Service) timestamp() Time {
	return Time(s.now().UTC().Truncate(time.Second))
}

// Resume reschedules transitions that were pending when a persistent
// emulator last stopped, so no resource is stranded in a transient
// state. Call it once at startup.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("vpc: resuming transitions: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			// Both kinds carry "id" and "status"; that is all resuming needs.
			var r struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			if scope.Kind != kindVPC && scope.Kind != kindSubnet {
				break
			}
			if err := json.Unmarshal(rec.Data, &r); err != nil {
				return fmt.Errorf("vpc: decoding %s/%s: %w", key, rec.ID, err)
			}
			switch {
			case scope.Kind == kindVPC && r.Status == VPCStatusCreating:
				s.scheduleVPCActivation(t, r.ID)
			case scope.Kind == kindSubnet && r.Status == SubnetStatusUnknown:
				s.scheduleSubnetActivation(t, r.ID)
			}
		}
	}
	return nil
}
