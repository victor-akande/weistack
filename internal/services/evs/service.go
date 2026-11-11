// Package evs emulates the read side of Huawei Cloud Elastic Volume
// Service for the disks of ECS servers.
//
// WeiStack has no standalone volumes: every disk belongs to the server
// it was created with and lives exactly as long as that server. EVS
// shows those disks, so that clients which read a server's disks
// through EVS (Terraform's huaweicloud_compute_instance does) work.
// Creating, attaching, resizing and deleting volumes is not emulated.
//
// Response types mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/evs/v2).
package evs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// Volume is one disk of a server, as its owner describes it.
type Volume struct {
	ID       string
	Name     string
	Type     string
	SizeGB   int
	Device   string
	Bootable bool
	// ServerID is the server the disk is attached to.
	ServerID         string
	AvailabilityZone string
	// ImageID and ImageName are set on a disk created from an image.
	ImageID   string
	ImageName string
	// Created and Updated are RFC 3339 timestamps.
	Created             string
	Updated             string
	EnterpriseProjectID string
}

// VolumeSource lists the disks of a project. The ECS service implements
// it.
type VolumeSource interface {
	Volumes(ctx context.Context, region, projectID string) ([]Volume, error)
}

// Deps are the dependencies of the service.
type Deps struct {
	Logger *slog.Logger
	// Volumes may be nil, and may be set later with SetVolumes.
	Volumes VolumeSource
}

// Service is the EVS emulator.
type Service struct {
	log *slog.Logger

	mu      sync.Mutex
	volumes VolumeSource
}

// New returns the EVS service.
func New(d Deps) (*Service, error) {
	if d.Logger == nil {
		return nil, errors.New("evs: Logger is required")
	}
	return &Service{log: d.Logger, volumes: d.Volumes}, nil
}

// SetVolumes installs the source of disks.
func (s *Service) SetVolumes(v VolumeSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.volumes = v
}

// Name implements server.Service.
func (s *Service) Name() string { return "evs" }

// Version implements server.Service.
func (s *Service) Version() string { return "v2 (read only)" }

// list returns the project's disks; none without a source.
func (s *Service) list(ctx context.Context, region, projectID string) ([]Volume, error) {
	s.mu.Lock()
	src := s.volumes
	s.mu.Unlock()
	if src == nil {
		return nil, nil
	}
	return src.Volumes(ctx, region, projectID)
}
