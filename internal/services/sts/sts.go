// Package sts emulates Huawei Cloud's Security Token Service at
// sts.{region}.myhuaweicloud.com. For now it answers who the caller is,
// which the SDKs fall back to when IAM lists no domain.
package sts

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Service is the STS emulator.
type Service struct {
	log *slog.Logger
	dir *identity.Directory
}

// New returns the STS service.
func New(log *slog.Logger, dir *identity.Directory) (*Service, error) {
	if log == nil || dir == nil {
		return nil, errors.New("sts: a logger and a directory are required")
	}
	return &Service{log: log, dir: dir}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "sts" }

// Version implements server.Service.
func (s *Service) Version() string { return "v5 (caller identity)" }

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v5/caller-identity", s.handleCallerIdentity)
}

// callerIdentity mirrors the SDK model sts/v1 GetCallerIdentityResponse.
type callerIdentity struct {
	AccountID    string `json:"account_id"`
	PrincipalURN string `json:"principal_urn"`
	PrincipalID  string `json:"principal_id"`
}

// handleCallerIdentity reports who signed the request. A user's key names
// that user. Credentials are not checked, so any other key, the
// administrator's included, stands for the account's root user.
func (s *Service) handleCallerIdentity(w http.ResponseWriter, r *http.Request) {
	reqctx.From(r.Context()).SetOperation("GetCallerIdentity")
	acct := s.dir.Account()
	out := callerIdentity{AccountID: acct.ID, PrincipalURN: acct.UserURN(acct.Name), PrincipalID: acct.RootUserID()}
	if id := auth.FromContext(r.Context()); id.Known && id.Principal.UserID != "" {
		out.PrincipalURN, out.PrincipalID = acct.UserURN(id.Principal.UserName), id.Principal.UserID
	}
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}
