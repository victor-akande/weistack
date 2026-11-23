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
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
)

// Store kinds. IAM records belong to the account, so they live in the
// store's global scope.
const kindProject = "iam.project"

// Deps are the dependencies of the service.
type Deps struct {
	// Quotas are the per-project limits (internal/core/quota).
	Quotas    quota.Limits
	Store     store.Store
	Logger    *slog.Logger
	Directory *identity.Directory
	IDs       *ids.Generator
	// Vault seals the secret keys of access keys in the store.
	Vault *vault.Vault
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
	ids           *ids.Generator
	vault         *vault.Vault
	now           func() time.Time
	// mu serialises changes that span records or need unique names.
	mu     sync.Mutex
	tokens tokens
	// perms caches what principals may do (grants.go).
	perms permissions
}

// New returns the IAM service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Logger == nil || d.Directory == nil || d.IDs == nil || d.Vault == nil || d.DefaultRegion == "" || d.DefaultProjectID == "" {
		return nil, errors.New("iam: Store, Logger, Directory, IDs, Vault, DefaultRegion and DefaultProjectID are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{
		store: d.Store, log: d.Logger, dir: d.Directory, ids: d.IDs, vault: d.Vault,
		defaultRegion: d.DefaultRegion, defaultProj: d.DefaultProjectID, now: d.Now,
	}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "iam" }

// Version implements server.Service.
func (s *Service) Version() string {
	return "v3, v3.0, v5 (users, groups, tokens, access keys, roles, custom policies, role assignments, identity policies)"
}

// accountKey carries the account a background operation acts in.
type accountKey struct{}

// withAccount returns ctx acting in a, for work not done for a request.
func withAccount(ctx context.Context, a identity.Account) context.Context {
	return context.WithValue(ctx, accountKey{}, a)
}

// account returns the account ctx acts in: the one withAccount set, or
// that of the request's known caller, or the primary account (for
// callers WeiStack does not know, as in v0.1).
func (s *Service) account(ctx context.Context) identity.Account {
	if a, ok := ctx.Value(accountKey{}).(identity.Account); ok {
		return a
	}
	if id := auth.FromContext(ctx); id.Known && id.Principal.AccountID != "" {
		if a, ok := s.dir.AccountByID(id.Principal.AccountID); ok {
			return a
		}
	}
	return s.dir.Account()
}

// scope returns where ctx's account keeps records of kind. The primary
// account's are in the store's global scope, as before there were other
// accounts; another account's are under its ID.
func (s *Service) scope(ctx context.Context, kind string) store.Scope {
	a := s.account(ctx)
	if s.dir.Primary(a) {
		return global(kind)
	}
	return store.Scope{Region: store.Global, ProjectID: a.ID, Kind: kind}
}

func (s *Service) projects(ctx context.Context) store.Collection[project] {
	return store.Of[project](s.store, s.scope(ctx, kindProject))
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
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Any change may change what someone may do. The cache is
			// invalidated before the change and again before the response
			// leaves, so no grants computed from the data mid-change
			// survive to answer the client's next request.
			s.perms.changed()
			w = &changeWriter{ResponseWriter: w, changed: s.perms.changed}
		}
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

// changeWriter calls changed once, before the first byte of the response.
type changeWriter struct {
	http.ResponseWriter
	changed func()
	done    bool
}

func (c *changeWriter) mark() {
	if !c.done {
		c.done = true
		c.changed()
	}
}

func (c *changeWriter) WriteHeader(code int) {
	c.mark()
	c.ResponseWriter.WriteHeader(code)
}

func (c *changeWriter) Write(b []byte) (int, error) {
	c.mark()
	return c.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *changeWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// regionRE is the shape of a region name, as in a host's region label.
var regionRE = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// Resume records the default region's project, so that it is listed
// from the first request, the root user and the admin group, and
// registers the stored access keys with the directory, for the primary
// account and every added one.
func (s *Service) Resume(ctx context.Context) error {
	if err := s.prepare(withAccount(ctx, s.dir.Account())); err != nil {
		return err
	}
	return s.resumeAccounts(ctx)
}

// Reset implements server.Resetter: after the store is wiped, tokens end,
// added accounts and users' access keys are forgotten, and the primary
// account's project, root user and admin group are recorded again.
func (s *Service) Reset(ctx context.Context) error {
	defer s.perms.changed()
	s.tokens.clear()
	s.dir.Clear()
	return s.Resume(ctx)
}
