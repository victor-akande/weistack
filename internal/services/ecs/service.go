// Package ecs emulates Huawei Cloud Elastic Cloud Server: flavors,
// availability zones, servers and the asynchronous jobs that manage
// them. Servers are state only; nothing boots.
//
// Request and response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/ecs/v2).
package ecs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/evs"
	"github.com/victor-akande/weistack/internal/services/ims"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// EIPs attaches, releases and looks up elastic IPs for server NICs.
// eip.Service implements it.
type EIPs interface {
	AttachToServer(ctx context.Context, t vpc.Tenant, portID, serverName string, ip eip.ServerIP) (string, error)
	PortsRemoved(ctx context.Context, t vpc.Tenant, portIDs []string, release bool)
	AddressesByPort(ctx context.Context, t vpc.Tenant) (map[string]string, error)
}

// Tenant identifies whose resources a call operates on.
type Tenant struct {
	Region    string
	ProjectID string
}

// Deps are the dependencies of the service.
type Deps struct {
	// Quotas are the per-project limits (internal/core/quota).
	Quotas quota.Limits
	Store  store.Store
	Engine *lifecycle.Engine
	IDs    *ids.Generator
	Logger *slog.Logger
	// Network resolves VPCs, subnets and security groups and hands out
	// private IP addresses.
	Network *vpc.Service
	// EIPs attaches and releases elastic IPs for servers. Nil ignores
	// publicip requests.
	EIPs EIPs
	// Images resolves imageRef.
	Images *ims.Service
	// Volumes manages the disks of servers.
	Volumes *evs.Service
	// Keys checks the KMS keys of encrypted disks. Nil refuses them.
	Keys cmk.Keys
	// Quota bounds what one project may hold. Zero fields get defaults.
	Quota Quota
	// SeedDir optionally holds flavors.yaml, extending the built-in
	// flavors.
	SeedDir string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Quota is the per-project ECS quota.
type Quota struct {
	Servers int
	VCPUs   int
}

// Service is the ECS emulator.
type Service struct {
	store  store.Store
	engine *lifecycle.Engine
	ids    *ids.Generator
	log    *slog.Logger
	now    func() time.Time

	network *vpc.Service
	eips    EIPs
	images  *ims.Service
	volumes *evs.Service
	keys    cmk.Keys
	quotas  quota.Limits

	// mu serialises operations that check then write across records:
	// quota accounting on create, and delete.
	mu sync.Mutex

	flavors      []FlavorSpec
	flavorByName map[string]FlavorSpec
}

// New returns the ECS service. It fails if the seed data is invalid.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Engine == nil || d.IDs == nil || d.Logger == nil || d.Network == nil || d.Images == nil || d.Volumes == nil {
		return nil, errors.New("ecs: Store, Engine, IDs, Logger, Network, Images and Volumes are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	flavors, err := loadFlavors(d.SeedDir)
	if err != nil {
		return nil, err
	}
	s := &Service{
		store: d.Store, engine: d.Engine, ids: d.IDs, log: d.Logger, now: d.Now,
		network: d.Network, eips: d.EIPs, images: d.Images, volumes: d.Volumes, keys: d.Keys, quotas: d.Quotas,
		flavors:      flavors,
		flavorByName: make(map[string]FlavorSpec, len(flavors)),
	}
	for _, f := range flavors {
		s.flavorByName[f.Name] = f
	}
	return s, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "ecs" }

// Version implements server.Service.
func (s *Service) Version() string { return "v1, v2.1" }

// FlavorByName returns a flavor, or false if no such flavor exists.
func (s *Service) FlavorByName(name string) (FlavorSpec, bool) {
	f, ok := s.flavorByName[name]
	return f, ok
}

// ListFlavors returns the flavors sold in an availability zone, or
// every flavor when az is empty. An unknown zone sells nothing.
func (s *Service) ListFlavors(t Tenant, az string) []Flavor {
	out := []Flavor{}
	if az != "" && !zones.Exists(t.Region, az) {
		return out
	}
	for _, f := range s.flavors {
		out = append(out, f.view(t))
	}
	return out
}
