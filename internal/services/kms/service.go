// Package kms emulates Huawei Cloud Key Management Service (part of Data
// Encryption Workshop) at kms.{region}.myhuaweicloud.com: customer master
// keys with real local cryptography, their states and scheduled
// deletion, data keys, rotation and tags.
//
// Key material never leaves the emulator in clear: it is sealed by the
// vault in the store, and ciphertexts are envelopes WeiStack alone can
// open.
//
// Response shapes mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/kms/v2). Error codes are only those in
// Huawei's published DEW error table.
package kms

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
)

// Deps are the dependencies of the service.
type Deps struct {
	// Quotas are the per-project limits (internal/core/quota).
	Quotas    quota.Limits
	Store     store.Store
	Logger    *slog.Logger
	IDs       *ids.Generator
	Vault     *vault.Vault
	Directory *identity.Directory
	// DefaultRegion and DefaultProjectID are the emulator's, for the
	// projects of services that name none (OBS).
	DefaultRegion, DefaultProjectID string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the KMS emulator.
type Service struct {
	store store.Store
	log   *slog.Logger
	ids   *ids.Generator
	vault *vault.Vault
	dir   *identity.Directory
	now   func() time.Time

	defaultRegion, defaultProject string

	// mu serialises changes that need unique aliases.
	mu sync.Mutex
}

// New returns the KMS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Logger == nil || d.IDs == nil || d.Vault == nil || d.Directory == nil {
		return nil, errors.New("kms: Store, Logger, IDs, Vault and Directory are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		store: d.Store, log: d.Logger, ids: d.IDs, vault: d.Vault, dir: d.Directory, now: d.Now,
		defaultRegion: d.DefaultRegion, defaultProject: d.DefaultProjectID,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "kms" }

// Version implements server.Service.
func (s *Service) Version() string {
	return "v1.0 (keys, encryption, data keys, rotation, tags)"
}

// tenant is where a request acts: a region and a project of an account.
type tenant struct {
	Region, ProjectID string
	Account           identity.Account
}

// account returns the account a request acts for: its known caller's,
// or the primary account for callers WeiStack does not know.
func (s *Service) account(ctx context.Context) identity.Account {
	if id := auth.FromContext(ctx); id.Known && id.Principal.AccountID != "" {
		if a, ok := s.dir.AccountByID(id.Principal.AccountID); ok {
			return a
		}
	}
	return s.dir.Account()
}

// kindKey is where keys are kept: by region, for every account and
// project, so that a key can be found by its ID alone (ciphertexts name
// only the key) and then checked against the caller.
const kindKey = "kms.key"

func (s *Service) keys(region string) store.Collection[key] {
	return store.Of[key](s.store, store.Scope{Region: region, ProjectID: store.Global, Kind: kindKey})
}
