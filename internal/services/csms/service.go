// Package csms emulates Huawei Cloud Secret Management Service (part of Data
// Encryption Workshop) mounted on kms.{region}.myhuaweicloud.com under
// /v1/{project_id}.
//
// Secret values are encrypted at rest with per-version KMS data keys and
// AES-256-GCM, and are never logged or stored in plaintext. Request and
// response shapes mirror huaweicloud-sdk-go-v3 services/csms/v1.
package csms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/services/kms"
)

// Tenant identifies the region and project a request acts on.
type Tenant struct {
	Region    string
	ProjectID string
}

// Deps are the dependencies of the CSMS service.
type Deps struct {
	Store     store.Store
	IDs       *ids.Generator
	Engine    *lifecycle.Engine
	Logger    *slog.Logger
	Vault     *vault.Vault
	Keys      cmk.Keys
	Quotas    quota.Limits
	Directory *identity.Directory
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// Service is the CSMS emulator.
type Service struct {
	store  store.Store
	ids    *ids.Generator
	engine *lifecycle.Engine
	log    *slog.Logger
	vault  *vault.Vault
	keys   cmk.Keys
	quotas quota.Limits
	dir    *identity.Directory
	clock  func() time.Time

	// mu serialises secret creation, restore, version pruning, and stage updates.
	mu sync.Mutex
}

// New returns a new CSMS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.IDs == nil || d.Engine == nil || d.Logger == nil || d.Vault == nil {
		return nil, errors.New("csms: Store, IDs, Engine, Logger and Vault are required")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Service{
		store:  d.Store,
		ids:    d.IDs,
		engine: d.Engine,
		log:    d.Logger,
		vault:  d.Vault,
		keys:   d.Keys,
		quotas: d.Quotas,
		dir:    d.Directory,
		clock:  d.Clock,
	}, nil
}

// KMSExtension returns a kms.Extension that mounts CSMS's /v1/{project_id}
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
	secName := authz.Param("secretName", "secret_name")
	anySecret := authz.Fixed("secretName", "*")
	secByID := s.secretByIDResource

	r.Route("/v1/{project_id}", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "csms", Style: apierr.StyleFlat, Deny: denied}))

		// Secrets
		r.With(act("csms:secret:create", s.createSecretResource)).Post("/secrets", s.handle("CreateSecret", s.handleCreateSecret))
		r.With(act("csms:secret:list", anySecret)).Get("/secrets", s.handle("ListSecrets", s.handleListSecrets))
		r.With(act("csms:secret:create", s.restoreSecretResource)).Post("/secrets/restore", s.handle("UploadSecretBlob", s.handleUploadSecretBlob))
		r.With(act("csms:secret:get", secName)).Get("/secrets/{secret_name}", s.handle("ShowSecret", s.handleShowSecret))
		r.With(act("csms:secret:update", secName)).Put("/secrets/{secret_name}", s.handle("UpdateSecret", s.handleUpdateSecret))
		r.With(act("csms:secret:delete", secName)).Delete("/secrets/{secret_name}", s.handle("DeleteSecret", s.handleDeleteSecret))
		r.With(act("csms:secret:get", secName)).Post("/secrets/{secret_name}/backup", s.handle("DownloadSecretBlob", s.handleDownloadSecretBlob))

		// Versions
		r.With(act("csms:secret:createVersion", secName)).Post("/secrets/{secret_name}/versions", s.handle("CreateSecretVersion", s.handleCreateSecretVersion))
		r.With(act("csms:secret:listVersion", secName)).Get("/secrets/{secret_name}/versions", s.handle("ListSecretVersions", s.handleListSecretVersions))
		r.With(act("csms:secret:getVersion", secName)).Get("/secrets/{secret_name}/versions/{version_id}", s.handle("ShowSecretVersion", s.handleShowSecretVersion))
		r.With(act("csms:secret:updateVersion", secName)).Put("/secrets/{secret_name}/versions/{version_id}", s.handle("UpdateVersion", s.handleUpdateVersion))

		// Stages
		r.With(act("csms:secret:getStage", secName)).Get("/secrets/{secret_name}/stages/{stage_name}", s.handle("ShowSecretStage", s.handleShowSecretStage))
		r.With(act("csms:secret:updateStage", secName)).Put("/secrets/{secret_name}/stages/{stage_name}", s.handle("UpdateSecretStage", s.handleUpdateSecretStage))
		r.With(act("csms:secret:deleteStage", secName)).Delete("/secrets/{secret_name}/stages/{stage_name}", s.handle("DeleteSecretStage", s.handleDeleteSecretStage))

		// Scheduled deletion & restore
		r.With(act("csms:secret:scheduleDeletion", secName)).Post("/secrets/{secret_name}/scheduled-deleted-tasks/create", s.handle("DeleteSecretForSchedule", s.handleDeleteSecretForSchedule))
		r.With(act("csms:secret:restoreSecret", secName)).Post("/secrets/{secret_name}/scheduled-deleted-tasks/cancel", s.handle("RestoreSecret", s.handleRestoreSecret))

		// Tags & password generation
		r.With(authz.Public()).Post("/csms/generate-password", s.handle("GenerateRandomPassword", s.handleGenerateRandomPassword))
		r.With(act("csms::listProjectTags")).Get("/csms/tags", s.handle("ListProjectSecretsTags", s.handleListProjectSecretsTags))
		r.With(act("csms:secret:getSecretsByTag", anySecret)).Post("/csms/resource_instances/action", s.handle("ListResourceInstances", s.handleListResourceInstances))
		r.With(act("csms:secret:createTag", secByID)).Post("/csms/{secret_id}/tags", s.handle("CreateSecretTag", s.handleCreateSecretTag))
		r.With(act("csms:secret:listTags", secByID)).Get("/csms/{secret_id}/tags", s.handle("ListSecretTags", s.handleListSecretTags))
		r.With(act("csms:secret:batchCreateOrDeleteTags", secByID)).Post("/csms/{secret_id}/tags/action", s.handle("BatchCreateOrDeleteTags", s.handleBatchCreateOrDeleteTags))
		r.With(act("csms:secret:deleteTag", secByID)).Delete("/csms/{secret_id}/tags/{key}", s.handle("DeleteSecretTag", s.handleDeleteSecretTag))
	})
}

// secretByIDResource looks up a secret by its ID path parameter and builds
// its secretName URN from the secret's Name, matching IAM 5.0's resource type.
func (s *Service) secretByIDResource(r *http.Request) (authz.Resource, bool) {
	t := Tenant{Region: reqctx.From(r.Context()).Region, ProjectID: chi.URLParam(r, "project_id")}
	sec, ok, err := s.findSecretByID(r.Context(), t, chi.URLParam(r, "secret_id"))
	if err != nil || !ok {
		return authz.Resource{}, false
	}
	return authz.Resource{Type: "secretName", Path: sec.Name}, true
}

// createSecretResource extracts the target secret name from a CreateSecret body
// without consuming r.Body, falling back to "*" when absent or malformed.
func (s *Service) createSecretResource(r *http.Request) (authz.Resource, bool) {
	if r.Body == nil {
		return authz.Resource{Type: "secretName", Path: "*"}, true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err == nil {
		var b struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &b) == nil && b.Name != "" {
			return authz.Resource{Type: "secretName", Path: b.Name}, true
		}
	}
	return authz.Resource{Type: "secretName", Path: "*"}, true
}

// restoreSecretResource extracts the secret name from an UploadSecretBlob body
// if the backup envelope can be opened, falling back to "*".
func (s *Service) restoreSecretResource(r *http.Request) (authz.Resource, bool) {
	if r.Body == nil {
		return authz.Resource{Type: "secretName", Path: "*"}, true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 6<<20))
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err == nil {
		var b struct {
			SecretBlob string `json:"secret_blob"`
		}
		if json.Unmarshal(raw, &b) == nil && b.SecretBlob != "" {
			if name := s.peekBackupSecretName(b.SecretBlob); name != "" {
				return authz.Resource{Type: "secretName", Path: name}, true
			}
		}
	}
	return authz.Resource{Type: "secretName", Path: "*"}, true
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
			s.log.ErrorContext(ctx, "csms operation failed", "operation", op)
		}
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}

func decodeJSON(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errBodyFormat
	}
	return nil
}

func (s *Service) secrets(t Tenant) store.Collection[Secret] {
	return store.Of[Secret](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindSecret})
}

func (s *Service) versions(t Tenant) store.Collection[Version] {
	return store.Of[Version](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVersion})
}

func (s *Service) findSecretByID(ctx context.Context, t Tenant, id string) (Secret, bool, error) {
	if id == "" {
		return Secret{}, false, nil
	}
	all, err := s.secrets(t).List(ctx, func(sec Secret) bool { return sec.ID == id })
	if err != nil || len(all) == 0 {
		return Secret{}, false, err
	}
	return all[0], true, nil
}

// accountID returns the caller's account ID, or the primary account's ID under
// -iam=accept.
func (s *Service) accountID(ctx context.Context) string {
	if id := auth.FromContext(ctx); id.Known && id.Principal.AccountID != "" {
		return id.Principal.AccountID
	}
	if s.dir != nil {
		return s.dir.Account().ID
	}
	return "00000000000000000000000000000000"
}

func (s *Service) nowMillis() int64 {
	return s.clock().UTC().UnixMilli()
}
