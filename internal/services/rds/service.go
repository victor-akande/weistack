// Package rds emulates Huawei Cloud Relational Database Service: MySQL
// and PostgreSQL instances as metadata. Nothing listens on an
// instance's address; no SQL is accepted.
//
// Request and response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/rds/v3).
package rds

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Store kinds owned by this service.
const (
	kindInstance = "rds.instance"
	kindJob      = "rds.job"
)

// DefaultMaxInstances is the per-project instance quota.
const DefaultMaxInstances = 20

// Tenant identifies whose resources a call operates on.
type Tenant struct {
	Region    string
	ProjectID string
}

func (t Tenant) vpc() vpc.Tenant { return vpc.Tenant{Region: t.Region, ProjectID: t.ProjectID} }

// Deps are the dependencies of the service.
type Deps struct {
	Store   store.Store
	Engine  *lifecycle.Engine
	IDs     *ids.Generator
	Logger  *slog.Logger
	Network *vpc.Service
	// MaxInstances is the per-project quota; zero means the default.
	MaxInstances int
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the RDS emulator.
type Service struct {
	store        store.Store
	engine       *lifecycle.Engine
	ids          *ids.Generator
	log          *slog.Logger
	network      *vpc.Service
	maxInstances int
	now          func() time.Time

	// mu serialises operations that check then write across records:
	// quota and name uniqueness on create, and status checks.
	mu sync.Mutex
}

// New returns the RDS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil || d.Network == nil {
		return nil, errors.New("rds: Store, Engine, IDs, Logger and Network are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxInstances == 0 {
		d.MaxInstances = DefaultMaxInstances
	}
	return &Service{
		store: d.Store, engine: d.Engine, ids: d.IDs, log: d.Logger, network: d.Network,
		maxInstances: d.MaxInstances, now: d.Now,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "rds" }

// Version implements server.Service.
func (s *Service) Version() string { return "v3" }

func (s *Service) instances(t Tenant) store.Collection[Instance] {
	return store.Of[Instance](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindInstance})
}

func (s *Service) jobs(t Tenant) store.Collection[Job] {
	return store.Of[Job](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindJob})
}
