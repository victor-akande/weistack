package kps

import (
	"context"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/services/ecs"
)

// NovaCreate implements ecs.Keypairs.
func (s *Service) NovaCreate(_ context.Context, _, _ string, _ ecs.NovaCreateKeypairInput) (ecs.NovaKeypairOutput, error) {
	return ecs.NovaKeypairOutput{}, apierr.NotImplemented("ecs", "NovaCreateKeypair")
}

// NovaList implements ecs.Keypairs.
func (s *Service) NovaList(_ context.Context, _, _, _ string, _ int) ([]ecs.NovaKeypairOutput, error) {
	return nil, apierr.NotImplemented("ecs", "NovaListKeypairs")
}

// NovaGet implements ecs.Keypairs.
func (s *Service) NovaGet(_ context.Context, _, _, _ string) (ecs.NovaKeypairDetailOutput, error) {
	return ecs.NovaKeypairDetailOutput{}, apierr.NotImplemented("ecs", "NovaShowKeypair")
}

// NovaDelete implements ecs.Keypairs.
func (s *Service) NovaDelete(_ context.Context, _, _, _ string) error {
	return apierr.NotImplemented("ecs", "NovaDeleteKeypair")
}
