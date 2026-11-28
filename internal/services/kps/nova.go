package kps

import (
	"context"

	"github.com/victor-akande/weistack/internal/services/ecs"
)

// NovaCreate implements ecs.Keypairs. A Nova create always makes a user-scope
// key pair in KPS's shared store.
func (s *Service) NovaCreate(ctx context.Context, region, projectID string, req ecs.NovaCreateKeypairInput) (ecs.NovaKeypairOutput, error) {
	act := createKeypairAction{
		Name:      req.Name,
		Type:      req.Type,
		PublicKey: req.PublicKey,
		Scope:     "user",
		UserID:    req.UserID,
	}
	if req.KeyProtection != nil {
		prot := &keyProtectionWire{
			PrivateKey: req.KeyProtection.PrivateKey,
		}
		if req.KeyProtection.Encryption != nil {
			prot.Encryption = &encryptionWire{
				Type:       req.KeyProtection.Encryption.Type,
				KMSKeyName: req.KeyProtection.Encryption.KMSKeyName,
				KMSKeyID:   req.KeyProtection.Encryption.KMSKeyID,
			}
		}
		act.KeyProtection = prot
	}

	kp, privPEM, err := s.createKeypair(ctx, nil, Tenant{Region: region, ProjectID: projectID}, act)
	if err != nil {
		return ecs.NovaKeypairOutput{}, err
	}
	return ecs.NovaKeypairOutput{
		Name:        kp.Name,
		Type:        kp.Type,
		PublicKey:   kp.PublicKey,
		PrivateKey:  privPEM,
		Fingerprint: kp.Fingerprint,
		UserID:      kp.UserID,
	}, nil
}

// NovaList implements ecs.Keypairs. Private keys are never returned.
func (s *Service) NovaList(ctx context.Context, region, projectID, marker string, limit int) ([]ecs.NovaKeypairOutput, error) {
	kps, _, _, err := s.listKeypairs(ctx, Tenant{Region: region, ProjectID: projectID}, marker, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ecs.NovaKeypairOutput, 0, len(kps))
	for _, kp := range kps {
		out = append(out, ecs.NovaKeypairOutput{
			Name:        kp.Name,
			Type:        kp.Type,
			PublicKey:   kp.PublicKey,
			Fingerprint: kp.Fingerprint,
			UserID:      kp.UserID,
		})
	}
	return out, nil
}

// NovaGet implements ecs.Keypairs.
func (s *Service) NovaGet(ctx context.Context, region, projectID, name string) (ecs.NovaKeypairDetailOutput, error) {
	kp, err := s.getKeypair(ctx, Tenant{Region: region, ProjectID: projectID}, name)
	if err != nil {
		return ecs.NovaKeypairDetailOutput{}, err
	}
	return ecs.NovaKeypairDetailOutput{
		ID:          kp.ID,
		Name:        kp.Name,
		Type:        kp.Type,
		PublicKey:   kp.PublicKey,
		Fingerprint: kp.Fingerprint,
		UserID:      kp.UserID,
		Deleted:     false,
		CreatedAt:   kp.CreatedAt,
		UpdatedAt:   kp.UpdatedAt,
	}, nil
}

// NovaDelete implements ecs.Keypairs.
func (s *Service) NovaDelete(ctx context.Context, region, projectID, name string) error {
	return s.deleteKeypair(ctx, Tenant{Region: region, ProjectID: projectID}, name)
}
