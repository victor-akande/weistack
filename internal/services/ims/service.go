// Package ims emulates Huawei Cloud Image Management Service: the
// public images every region offers and, per project, private images.
//
// Request and response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/ims/v2).
package ims

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

// kindImage is the store kind of images. Public images live in the
// store.Global project of each region; private images in their owner's.
const kindImage = "ims.image"

// kindJob is the store kind of asynchronous jobs, kept per project.
const kindJob = "ims.job"

// Lifecycle task kinds, matched by fault injection.
const (
	taskImageSave     = "ims.image.save"
	taskImageActivate = "ims.image.activate"
)

// ErrServerNotFound is returned by a ServerLookup for an unknown server.
var ErrServerNotFound = errors.New("ims: server not found")

// Server is what IMS needs to know about an ECS server to make an image
// of it.
type Server struct {
	ID string
	// ImageID is the image the server was created from; the new image
	// inherits its operating system attributes. May be empty.
	ImageID string
	// SystemDiskGB is the size of the system disk, which becomes the
	// image's min_disk. Zero means unknown.
	SystemDiskGB int
}

// ServerLookup resolves ECS servers. The ECS service implements it.
type ServerLookup interface {
	// LookupServer returns the server or ErrServerNotFound.
	LookupServer(ctx context.Context, region, projectID, id string) (Server, error)
}

var projectIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	// DefaultProjectID is used for requests that carry no X-Project-Id
	// header: unlike most services, IMS paths do not name the project.
	DefaultProjectID string
	// SeedDir optionally holds images.yaml, extending the built-in
	// public images.
	SeedDir string
	// Servers resolves instance_id when an image is created from a
	// server. It may be nil, and may be set later with SetServers, since
	// ECS in turn depends on IMS.
	Servers ServerLookup
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the IMS emulator.
type Service struct {
	store          store.Store
	engine         *lifecycle.Engine
	ids            *ids.Generator
	log            *slog.Logger
	now            func() time.Time
	defaultProject string
	seeds          []Image

	// mu serialises check-then-write sequences on private images (name
	// uniqueness) and guards servers.
	mu      sync.Mutex
	servers ServerLookup

	// seedMu guards seeded, the regions whose public images are known
	// to be in the store.
	seedMu sync.Mutex
	seeded map[string]bool
}

// New returns the IMS service. It fails if the seed data is invalid.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil || d.DefaultProjectID == "" {
		return nil, errors.New("ims: Store, Engine, IDs, Logger and DefaultProjectID are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	seeds, err := loadSeedImages(d.SeedDir)
	if err != nil {
		return nil, err
	}
	return &Service{
		store: d.Store, engine: d.Engine, ids: d.IDs, log: d.Logger, now: d.Now,
		defaultProject: d.DefaultProjectID,
		seeds:          seeds,
		servers:        d.Servers,
		seeded:         make(map[string]bool),
	}, nil
}

// SetServers installs the ECS lookup used to create images from servers.
func (s *Service) SetServers(l ServerLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers = l
}

// Name implements server.Service.
func (s *Service) Name() string { return "ims" }

// Version implements server.Service.
func (s *Service) Version() string { return "v1, v2" }

// Reset implements server.Resetter: after the store is wiped, public
// images are seeded again on next use.
func (s *Service) Reset(context.Context) error {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	s.seeded = make(map[string]bool)
	return nil
}

func (s *Service) publicImages(region string) store.Collection[Image] {
	return store.Of[Image](s.store, store.Scope{Region: region, ProjectID: store.Global, Kind: kindImage})
}

func (s *Service) privateImages(t Tenant) store.Collection[Image] {
	return store.Of[Image](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindImage})
}

func (s *Service) jobs(t Tenant) store.Collection[Job] {
	return store.Of[Job](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindJob})
}

// ensureSeeded puts the public images into a region the first time the
// region is used. Seeding per region on demand means any region name a
// client uses has images, without configuring a region list.
func (s *Service) ensureSeeded(ctx context.Context, region string) error {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	if s.seeded[region] {
		return nil
	}
	public := s.publicImages(region)
	for _, img := range s.seeds {
		// Create, not Put: with persistence the images are already there.
		if err := public.Create(ctx, img.ID, img); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	s.seeded[region] = true
	return nil
}
