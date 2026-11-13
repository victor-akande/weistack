// Package iam emulates Huawei Cloud Identity and Access Management, in
// both its generations: classic IAM (the Keystone v3 API and Huawei's
// v3.0 extensions) and IAM 5.0 (/v5). Both work over one store, so a
// user created through either is visible through both.
//
// IAM is global: it is served at the region-less iam.myhuaweicloud.com as
// well as iam.{region}.myhuaweicloud.com, and its records belong to the
// emulator's account, not to a project.
//
// Response shapes mirror the models of the official Go SDK
// (huaweicloud-sdk-go-v3, services/iam/v3 and v5). Error codes are only
// those in Huawei's published IAM error code tables.
package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Store kinds. IAM records belong to the account, so they live in the
// store's global scope.
const kindProject = "iam.project"

// Deps are the dependencies of the service.
type Deps struct {
	Store     store.Store
	Logger    *slog.Logger
	Directory *identity.Directory
	// DefaultRegion and DefaultProjectID are the emulator's; that
	// region's project keeps the configured ID.
	DefaultRegion    string
	DefaultProjectID string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the IAM emulator.
type Service struct {
	store         store.Store
	log           *slog.Logger
	dir           *identity.Directory
	defaultRegion string
	defaultProj   string
	now           func() time.Time
}

// New returns the IAM service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Logger == nil || d.Directory == nil || d.DefaultRegion == "" || d.DefaultProjectID == "" {
		return nil, errors.New("iam: Store, Logger, Directory, DefaultRegion and DefaultProjectID are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		store: d.Store, log: d.Logger, dir: d.Directory,
		defaultRegion: d.DefaultRegion, defaultProj: d.DefaultProjectID, now: d.Now,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "iam" }

// Version implements server.Service.
func (s *Service) Version() string { return "v3, v3.0 (discovery)" }

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v3/auth/domains", s.handle("KeystoneListAuthDomains", s.handleListAuthDomains))
	r.Get("/v3/auth/projects", s.handle("KeystoneListAuthProjects", s.handleListAuthProjects))
	r.Get("/v3/projects", s.handle("KeystoneListProjects", s.handleListProjects))
	r.Get("/v3/projects/{project_id}", s.handle("KeystoneShowProject", s.handleShowProject))
}

func (s *Service) account() identity.Account { return s.dir.Account() }

func (s *Service) projects() store.Collection[project] {
	return store.Of[project](s.store, store.Scope{Region: store.Global, ProjectID: store.Global, Kind: kindProject})
}

type handler func(w http.ResponseWriter, r *http.Request) error

// handle names the operation for logs, sets IAM's trace header and renders
// errors. Classic IAM's error envelope is not documented; this uses the
// flat {"error_code", "error_msg"} form IAM 5.0 documents, which the SDK
// also reads for classic operations.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		// The SDK quotes this header in its error messages.
		w.Header().Set("X-IAM-Trace-Id", info.RequestID)
		err := fn(w, r)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "iam operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}

// regionRE is the shape of a region name, as in a host's region label.
var regionRE = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// Resume records the default region's project, so that it is listed
// from the first request.
func (s *Service) Resume(ctx context.Context) error {
	return s.ensureProject(ctx, s.defaultRegion)
}
