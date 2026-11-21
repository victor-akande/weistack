// Package evs emulates Huawei Cloud Elastic Volume Service: volumes,
// snapshots, tags, volume types, availability zones, and jobs.
//
// Response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/evs/v2).
package evs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/ims"
)

// Sentinel errors returned to ECS and mapped to ECS error codes.
var (
	ErrVolumeNotFound  = errors.New("evs: volume not found")
	ErrNotAvailable    = errors.New("evs: volume is not available")
	ErrAlreadyAttached = errors.New("evs: volume is already attached to this server")
	ErrOtherAZ         = errors.New("evs: volume and server are in different availability zones")
	ErrTooManyDisks    = errors.New("evs: server has reached the maximum number of data disks")
	ErrBadDevice       = errors.New("evs: invalid or occupied device name")
	ErrNotAttached     = errors.New("evs: volume is not attached to this server")
	ErrSystemDisk      = errors.New("evs: cannot perform operation on system disk")
	ErrShared          = errors.New("evs: cannot update delete_on_termination on multiattach volume")
	ErrServerNotFound  = errors.New("evs: server not found")
)

// Tenant identifies whose volumes a call is about.
type Tenant struct {
	Region    string
	ProjectID string
}

// ServerInfo describes an ECS server's AZ and status for EVS checks.
type ServerInfo struct {
	AvailabilityZone string
	Status           string
}

// Servers is what EVS needs from ECS; *ecs.Service implements it.
type Servers interface {
	// ServerForVolume returns a server's AZ and status, or ErrServerNotFound.
	ServerForVolume(ctx context.Context, t Tenant, id string) (ServerInfo, error)
	// AttachVolume attaches an available volume as attachvolume does.
	AttachVolume(ctx context.Context, t Tenant, serverID, volumeID string) error
}

// Deps are the dependencies of the service.
type Deps struct {
	Store  store.Store
	Engine *lifecycle.Engine
	IDs    *ids.Generator
	Logger *slog.Logger
	Images *ims.Service // imageRef
	Keys   cmk.Keys     // encryption; nil refuses encrypted volumes with EVS.2040
	Now    func() time.Time
}

// Service is the EVS emulator.
type Service struct {
	store  store.Store
	engine *lifecycle.Engine
	ids    *ids.Generator
	log    *slog.Logger
	images *ims.Service
	keys   cmk.Keys
	now    func() time.Time

	mu      sync.Mutex
	servers Servers
}

// New returns the EVS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil {
		return nil, errors.New("evs: Store is required")
	}
	if d.Engine == nil {
		return nil, errors.New("evs: Engine is required")
	}
	if d.IDs == nil {
		return nil, errors.New("evs: IDs is required")
	}
	if d.Logger == nil {
		return nil, errors.New("evs: Logger is required")
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		store:  d.Store,
		engine: d.Engine,
		ids:    d.IDs,
		log:    d.Logger,
		images: d.Images,
		keys:   d.Keys,
		now:    now,
	}, nil
}

// SetServers installs the ECS callback after both services exist.
func (s *Service) SetServers(srv Servers) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers = srv
}

// Name implements server.Service.
func (s *Service) Name() string { return "evs" }

// Version implements server.Service.
func (s *Service) Version() string { return "v2, v2.1" }

const (
	kindVolume   = "evs.volume"
	kindSnapshot = "evs.snapshot"
	kindJob      = "evs.job"
)

func (s *Service) volumes(t Tenant) store.Collection[volume] {
	return store.Of[volume](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVolume})
}

func (s *Service) snapshots(t Tenant) store.Collection[snapshot] {
	return store.Of[snapshot](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSnapshot})
}

func (s *Service) jobs(t Tenant) store.Collection[job] {
	return store.Of[job](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindJob})
}

// Resume continues any asynchronous volume or snapshot operations that
// were in flight when a persistent emulator last stopped.
func (s *Service) Resume(_ context.Context) error {
	return nil
}
