package ecs

import (
	"context"
	"errors"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/evs"
)

// ServerForVolume implements evs.Servers.
func (s *Service) ServerForVolume(ctx context.Context, t evs.Tenant, id string) (evs.ServerInfo, error) {
	srv, err := s.servers(Tenant{Region: t.Region, ProjectID: t.ProjectID}).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return evs.ServerInfo{}, evs.ErrServerNotFound
	}
	if err != nil {
		return evs.ServerInfo{}, err
	}
	return evs.ServerInfo{AvailabilityZone: srv.AvailabilityZone, Status: srv.Status}, nil
}

// AttachVolume implements evs.Servers. It is implemented in Wave 1 (W2).
func (s *Service) AttachVolume(_ context.Context, _ evs.Tenant, _, _ string) error {
	return apierr.NotImplemented("ecs", "AttachServerVolume")
}

func (s *Service) handleAttachVolume(_ http.ResponseWriter, r *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", r.Method+" "+r.URL.Path)
}

func (s *Service) handleDetachVolume(_ http.ResponseWriter, r *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", r.Method+" "+r.URL.Path)
}

func (s *Service) handleUpdateBlockDevice(_ http.ResponseWriter, r *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", r.Method+" "+r.URL.Path)
}
