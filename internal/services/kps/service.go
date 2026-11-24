// Package kps emulates Huawei Cloud Key Pair Service (part of Data Encryption
// Workshop) mounted on kms.{region}.myhuaweicloud.com under /v3/{project_id},
// and backs the Nova /v2.1/{project_id}/os-keypairs API on ECS.
//
// Request and response shapes mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/kps/v3). Private keys are stored only when
// key protection is enabled (sealed by the emulator vault or a KMS data key),
// and are never logged.
package kps

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/services/ecs"
	"github.com/victor-akande/weistack/internal/services/kms"
)

var _ ecs.Keypairs = (*Service)(nil)

// Tenant identifies the region and project a request acts on.
type Tenant struct {
	Region    string
	ProjectID string
}

// Servers is the subset of ECS that KPS uses for associate and disassociate
// tasks. ecs.Service implements it.
type Servers interface {
	ServerExists(ctx context.Context, region, projectID, serverID string) (name string, ok bool, err error)
	SetKeyName(ctx context.Context, region, projectID, serverID, keyName string) error
}

// Deps are the dependencies of the KPS service.
type Deps struct {
	Store     store.Store
	IDs       *ids.Generator
	Engine    *lifecycle.Engine
	Logger    *slog.Logger
	Vault     *vault.Vault
	Keys      cmk.Keys
	Servers   Servers
	Directory *identity.Directory
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// Service is the KPS emulator.
type Service struct {
	store   store.Store
	ids     *ids.Generator
	engine  *lifecycle.Engine
	log     *slog.Logger
	vault   *vault.Vault
	keys    cmk.Keys
	servers Servers
	dir     *identity.Directory
	clock   func() time.Time

	// mu serialises creation checks (unique keypair names and per-project IDs).
	mu sync.Mutex
}

// New returns a new KPS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.IDs == nil || d.Engine == nil || d.Logger == nil || d.Vault == nil {
		return nil, errors.New("kps: Store, IDs, Engine, Logger and Vault are required")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Service{
		store:   d.Store,
		ids:     d.IDs,
		engine:  d.Engine,
		log:     d.Logger,
		vault:   d.Vault,
		keys:    d.Keys,
		servers: d.Servers,
		dir:     d.Directory,
		clock:   d.Clock,
	}, nil
}

// KMSExtension returns a kms.Extension that mounts KPS's /v3/{project_id}
// routes on the KMS host.
func (s *Service) KMSExtension() kms.Extension {
	return kmsExtension{s: s}
}

type kmsExtension struct {
	s *Service
}

func (e kmsExtension) Routes(r chi.Router) {
	e.s.routes(r)
}

func (s *Service) routes(r chi.Router) {
	act := authz.Action
	kp := authz.Param("SSHKeyPair", "keypair_name")

	r.Route("/v3/{project_id}", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "kps", Style: apierr.StyleFlat, Deny: denied}))

		r.With(act("kps:SSHKeyPair:create")).Post("/keypairs", s.handle("CreateKeypair", s.handleCreateKeypair))
		r.With(act("kps:SSHKeyPair:list")).Get("/keypairs", s.handle("ListKeypairs", s.handleListKeypairs))
		r.With(act("kps:SSHKeyPair:importPrivateKey")).Post("/keypairs/private-key/import", s.handle("ImportPrivateKey", s.handleImportPrivateKey))
		r.With(act("kps:SSHKeyPair:exportPrivateKey")).Post("/keypairs/private-key/export", s.handle("ExportPrivateKey", s.handleExportPrivateKey))
		r.With(act("kps:SSHKeyPair:exportPrivateKey")).Post("/keypairs/private-key/batch-export", s.handle("BatchExportPrivateKey", s.handleBatchExportPrivateKey))
		r.With(act("kps:SSHKeyPair:bind")).Post("/keypairs/associate", s.handle("AssociateKeypair", s.handleAssociateKeypair))
		r.With(act("kps:SSHKeyPair:unbind")).Post("/keypairs/disassociate", s.handle("DisassociateKeypair", s.handleDisassociateKeypair))
		r.With(act("kps:SSHKeyPair:bind")).Post("/keypairs/batch-associate", s.handle("BatchAssociateKeypair", s.handleBatchAssociateKeypair))
		r.With(act("kps:SSHKeyPair:create")).Post("/keypairs/batch-import", s.handle("BatchImportKeypair", s.handleBatchImportKeypair))

		r.With(act("kps:SSHKeyPair:get", kp)).Get("/keypairs/{keypair_name}", s.handle("ListKeypairDetail", s.handleListKeypairDetail))
		r.With(act("kps:SSHKeyPair:update", kp)).Put("/keypairs/{keypair_name}", s.handle("UpdateKeypairDescription", s.handleUpdateKeypairDescription))
		r.With(act("kps:SSHKeyPair:delete", kp)).Delete("/keypairs/{keypair_name}", s.handle("DeleteKeypair", s.handleDeleteKeypair))
		r.With(act("kps:SSHKeyPair:clearPrivateKey", kp)).Delete("/keypairs/{keypair_name}/private-key", s.handle("ClearPrivateKey", s.handleClearPrivateKey))

		r.With(act("kps::getTask")).Get("/tasks/{task_id}", s.handle("ListKeypairTask", s.handleListKeypairTask))
		r.With(act("kps::getRunningTask")).Get("/running-tasks", s.handle("ListRunningTask", s.handleListRunningTask))
		r.With(act("kps::getFailedTask")).Get("/failed-tasks", s.handle("ListFailedTask", s.handleListFailedTask))
		r.With(act("kps::deleteFailedTask")).Delete("/failed-tasks", s.handle("DeleteAllFailedTask", s.handleDeleteAllFailedTask))
		r.With(act("kps::deleteFailedTask")).Delete("/failed-tasks/{task_id}", s.handle("DeleteFailedTask", s.handleDeleteFailedTask))
	})
}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := reqctx.From(ctx)
		info.SetOperation(op)
		t := Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")}

		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(ctx, "kps operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}

func (s *Service) keypairs(t Tenant) store.Collection[Keypair] {
	return store.Of[Keypair](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindKeypair})
}

func (s *Service) tasks(t Tenant) store.Collection[Task] {
	return store.Of[Task](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindTask})
}

func (s *Service) failedTasks(t Tenant) store.Collection[Task] {
	return store.Of[Task](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindFailedTask})
}

// callerUserID returns the IAM user ID of the request's caller. Under
// -iam=accept (unknown credentials), every caller acts as the account's root.
func (s *Service) callerUserID(ctx context.Context) string {
	if id := auth.FromContext(ctx); id.Known && id.Principal.UserID != "" {
		return id.Principal.UserID
	}
	if s.dir != nil {
		return s.dir.Account().RootUserID()
	}
	return "00000000000000000000000000000000"
}

// isVisible reports whether the caller may see kp: domain-scoped key pairs are
// visible to everyone in the project; user-scoped key pairs belong to their
// owner.
func (s *Service) isVisible(ctx context.Context, kp Keypair) bool {
	if kp.Scope == "domain" {
		return true
	}
	return kp.UserID == s.callerUserID(ctx)
}

// Exists implements ecs.Keypairs.
func (s *Service) Exists(ctx context.Context, region, projectID, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	kp, err := s.keypairs(Tenant{Region: region, ProjectID: projectID}).Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.isVisible(ctx, kp), nil
}
