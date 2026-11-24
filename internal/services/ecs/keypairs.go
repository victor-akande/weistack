package ecs

import (
	"context"
	"errors"

	"github.com/victor-akande/weistack/internal/core/store"
)

// NovaEncryptionInput is the encryption configuration in a Nova v2.1 keypair
// create request.
type NovaEncryptionInput struct {
	Type       string
	KMSKeyName string
	KMSKeyID   string
}

// NovaKeyProtectionInput is the private-key protection block in a Nova v2.1
// keypair create request.
type NovaKeyProtectionInput struct {
	PrivateKey string
	Encryption *NovaEncryptionInput
}

// NovaCreateKeypairInput is the input to creating or importing a key pair
// through the Nova /v2.1/{project_id}/os-keypairs API.
type NovaCreateKeypairInput struct {
	Name          string
	Type          string
	PublicKey     string
	UserID        string
	KeyProtection *NovaKeyProtectionInput
}

// NovaKeypairOutput is a key pair returned by Nova create or list.
type NovaKeypairOutput struct {
	Name        string
	Type        string
	PublicKey   string
	PrivateKey  string
	Fingerprint string
	UserID      string
}

// NovaKeypairDetailOutput is a key pair returned by Nova show.
type NovaKeypairDetailOutput struct {
	ID          int64
	Name        string
	Type        string
	PublicKey   string
	Fingerprint string
	UserID      string
	Deleted     bool
	CreatedAt   int64
	UpdatedAt   int64
}

// Keypairs is the key pair service used by ECS for server key_name checks and
// the Nova /v2.1/{project_id}/os-keypairs routes. kps.Service implements it.
type Keypairs interface {
	Exists(ctx context.Context, region, projectID, name string) (bool, error)
	NovaCreate(ctx context.Context, region, projectID string, req NovaCreateKeypairInput) (NovaKeypairOutput, error)
	NovaList(ctx context.Context, region, projectID, marker string, limit int) ([]NovaKeypairOutput, error)
	NovaGet(ctx context.Context, region, projectID, name string) (NovaKeypairDetailOutput, error)
	NovaDelete(ctx context.Context, region, projectID, name string) error
}

// SetKeypairs wires the key pair service into ECS after both are constructed.
func (s *Service) SetKeypairs(kp Keypairs) {
	s.keypairs = kp
}

// ServerExists reports whether a server with serverID exists in the given
// region and project, returning its name if found.
func (s *Service) ServerExists(ctx context.Context, region, projectID, serverID string) (string, bool, error) {
	srv, err := s.servers(Tenant{Region: region, ProjectID: projectID}).Get(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return srv.Name, true, nil
}

// SetKeyName sets or clears (when keyName == "") the key_name of a server.
func (s *Service) SetKeyName(ctx context.Context, region, projectID, serverID, keyName string) error {
	now := s.now().UTC().Format(timeLayout)
	_, err := s.servers(Tenant{Region: region, ProjectID: projectID}).Update(ctx, serverID, func(srv *Server) error {
		srv.KeyName = keyName
		srv.Updated = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errServerNotFound(serverID)
	}
	return err
}
