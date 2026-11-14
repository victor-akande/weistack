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

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
)

// Store kinds. IAM records belong to the account, so they live in the
// store's global scope.
const kindProject = "iam.project"

// Deps are the dependencies of the service.
type Deps struct {
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

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v3/auth/domains", s.handle("KeystoneListAuthDomains", s.handleListAuthDomains))
	r.Get("/v3/auth/projects", s.handle("KeystoneListAuthProjects", s.handleListAuthProjects))
	r.Get("/v3/projects", s.handle("KeystoneListProjects", s.handleListProjects))
	r.Get("/v3/projects/{project_id}", s.handle("KeystoneShowProject", s.handleShowProject))

	r.Post("/v3/auth/tokens", s.handle("KeystoneCreateUserToken", s.handleCreateToken))
	r.Get("/v3/auth/tokens", s.handle("KeystoneValidateToken", s.handleValidateToken))

	r.Post("/v3.0/OS-USER/users", s.handle("CreateUser", s.handleCreateUser))
	r.Get("/v3.0/OS-USER/users/{user_id}", s.handle("ShowUser", s.handleShowUser))
	r.Put("/v3.0/OS-USER/users/{user_id}", s.handle("UpdateUser", s.handleUpdateUser))
	r.Put("/v3.0/OS-USER/users/{user_id}/info", s.handle("UpdateUserInformation", s.handleUpdateUserInformation))
	r.Get("/v3.0/OS-USER/users/{user_id}/login-protect", s.handle("ShowUserLoginProtect", s.handleShowLoginProtect))
	r.Put("/v3.0/OS-USER/users/{user_id}/login-protect", s.handle("UpdateLoginProtect", s.handleUpdateLoginProtect))
	r.Post("/v3/users", s.handle("KeystoneCreateUser", s.handleKeystoneCreateUser))
	r.Get("/v3/users", s.handle("KeystoneListUsers", s.handleKeystoneListUsers))
	r.Get("/v3/users/{user_id}", s.handle("KeystoneShowUser", s.handleKeystoneShowUser))
	r.Patch("/v3/users/{user_id}", s.handle("KeystoneUpdateUserByAdmin", s.handleKeystoneUpdateUser))
	r.Delete("/v3/users/{user_id}", s.handle("KeystoneDeleteUser", s.handleKeystoneDeleteUser))
	r.Post("/v3/users/{user_id}/password", s.handle("KeystoneUpdateUserPassword", s.handleChangePassword))
	r.Get("/v3/users/{user_id}/groups", s.handle("KeystoneListGroupsForUser", s.handleListGroupsForUser))
	r.Get("/v3/users/{user_id}/projects", s.handle("KeystoneListProjectsForUser", s.handleListProjectsForUser))

	r.Post("/v3/groups", s.handle("KeystoneCreateGroup", s.handleCreateGroup))
	r.Get("/v3/groups", s.handle("KeystoneListGroups", s.handleListGroups))
	r.Get("/v3/groups/{group_id}", s.handle("KeystoneShowGroup", s.handleShowGroup))
	r.Patch("/v3/groups/{group_id}", s.handle("KeystoneUpdateGroup", s.handleUpdateGroup))
	r.Delete("/v3/groups/{group_id}", s.handle("KeystoneDeleteGroup", s.handleDeleteGroup))
	r.Get("/v3/groups/{group_id}/users", s.handle("KeystoneListUsersForGroupByAdmin", s.handleListUsersInGroup))
	r.Put("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneAddUserToGroup", s.handleAddUserToGroup))
	r.Head("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneCheckUserInGroup", s.handleCheckUserInGroup))
	r.Delete("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneRemoveUserFromGroup", s.handleRemoveUserFromGroup))

	r.Post("/v3.0/OS-CREDENTIAL/credentials", s.handle("CreatePermanentAccessKey", s.handleCreateCredential))
	r.Get("/v3.0/OS-CREDENTIAL/credentials", s.handle("ListPermanentAccessKeys", s.handleListCredentials))
	r.Get("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("ShowPermanentAccessKey", s.handleShowCredential))
	r.Put("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("UpdatePermanentAccessKey", s.handleUpdateCredential))
	r.Delete("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("DeletePermanentAccessKey", s.handleDeleteCredential))

	s.roleRoutes(r)
	s.policyRoutes(r)

	r.Post("/v5/users", s.handle("CreateUserV5", s.handleCreateUserV5))
	r.Get("/v5/users", s.handle("ListUsersV5", s.handleListUsersV5))
	r.Get("/v5/users/{user_id}", s.handle("ShowUserV5", s.handleShowUserV5))
	r.Put("/v5/users/{user_id}", s.handle("UpdateUserV5", s.handleUpdateUserV5))
	r.Delete("/v5/users/{user_id}", s.handle("DeleteUserV5", s.handleDeleteUserV5))
	r.Get("/v5/users/{user_id}/last-login", s.handle("ShowUserLastLoginV5", s.handleShowUserLastLoginV5))
	r.Post("/v5/users/{user_id}/access-keys", s.handle("CreateAccessKeyV5", s.handleCreateAccessKeyV5))
	r.Get("/v5/users/{user_id}/access-keys", s.handle("ListAccessKeysV5", s.handleListAccessKeysV5))
	r.Put("/v5/users/{user_id}/access-keys/{access_key_id}", s.handle("UpdateAccessKeyV5", s.handleUpdateAccessKeyV5))
	r.Delete("/v5/users/{user_id}/access-keys/{access_key_id}", s.handle("DeleteAccessKeyV5", s.handleDeleteAccessKeyV5))
	r.Get("/v5/users/{user_id}/access-keys/{access_key_id}/last-used", s.handle("ShowAccessKeyLastUsedV5", s.handleShowAccessKeyLastUsedV5))
	r.Post("/v5/groups", s.handle("CreateGroupV5", s.handleCreateGroupV5))
	r.Get("/v5/groups", s.handle("ListGroupsV5", s.handleListGroupsV5))
	r.Get("/v5/groups/{group_id}", s.handle("ShowGroupV5", s.handleShowGroupV5))
	r.Put("/v5/groups/{group_id}", s.handle("UpdateGroupV5", s.handleUpdateGroupV5))
	r.Delete("/v5/groups/{group_id}", s.handle("DeleteGroupV5", s.handleDeleteGroupV5))
	r.Post("/v5/groups/{group_id}/add-user", s.handle("AddUserToGroupV5", s.v5Membership(true)))
	r.Post("/v5/groups/{group_id}/remove-user", s.handle("RemoveUserFromGroupV5", s.v5Membership(false)))
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
// from the first request, and the root user, and registers the stored
// access keys with the directory.
func (s *Service) Resume(ctx context.Context) error {
	if err := s.ensureProject(ctx, s.defaultRegion); err != nil {
		return err
	}
	if err := s.ensureRoot(ctx); err != nil {
		return err
	}
	return s.registerAllKeys(ctx)
}

// Reset implements server.Resetter: after the store is wiped, tokens end,
// users' access keys are forgotten, and the account's project and root
// user are recorded again.
func (s *Service) Reset(ctx context.Context) error {
	s.tokens.clear()
	s.dir.Clear()
	return s.Resume(ctx)
}
