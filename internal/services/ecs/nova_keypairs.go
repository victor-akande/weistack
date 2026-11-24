package ecs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

func (s *Service) handleNovaCreateKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", "NovaCreateKeypair")
}

func (s *Service) handleNovaListKeypairs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", "NovaListKeypairs")
}

func (s *Service) handleNovaShowKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", "NovaShowKeypair")
}

func (s *Service) handleNovaDeleteKeypair(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("ecs", "NovaDeleteKeypair")
}
