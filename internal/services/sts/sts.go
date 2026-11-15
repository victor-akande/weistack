// Package sts emulates Huawei Cloud's Security Token Service at
// sts.{region}.myhuaweicloud.com. It answers who the caller is, which
// the SDKs fall back to when IAM lists no domain, and decodes the
// explanations of permission denials.
package sts

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Service is the STS emulator.
type Service struct {
	log    *slog.Logger
	dir    *identity.Directory
	sealer authz.Sealer
}

// New returns the STS service. sealer opens the explanations of
// permission denials; it is the one the server seals them with.
func New(log *slog.Logger, dir *identity.Directory, sealer authz.Sealer) (*Service, error) {
	if log == nil || dir == nil || sealer == nil {
		return nil, errors.New("sts: a logger, a directory and a sealer are required")
	}
	return &Service{log: log, dir: dir, sealer: sealer}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "sts" }

// Version implements server.Service.
func (s *Service) Version() string { return "v5 (caller identity, authorization messages)" }

// Routes implements server.Service. Asking who one is needs no
// permission (its API page has no authorization section); decoding a
// denial needs sts::decodeAuthorizationMessage.
func (s *Service) Routes(r chi.Router) {
	r.Use(authz.Service(authz.ServiceOptions{Name: "sts", Global: true, Style: apierr.StyleFlat, Deny: denied}))
	r.With(authz.Public()).Get("/v5/caller-identity", s.handleCallerIdentity)
	r.With(authz.Action("sts::decodeAuthorizationMessage")).Post("/v5/decode-authorization-message", s.handleDecode)
}

// STS's documented errors (api-iam5 ErrorCode).
var errMalformedMessage = apierr.New(http.StatusBadRequest, "STS5.1301", "the encoded message is malformed or invalid")

// denied is STS's documented permission error.
func denied(d *authz.Denial) *apierr.Error {
	return apierr.New(http.StatusForbidden, "STS5.1001", "you are not authorized to perform this operation").
		WithAuthorizationMessage(d.Encoded)
}

// maxEncodedMessage is the documented limit of encoded_message.
const maxEncodedMessage = 10240

// handleDecode serves POST /v5/decode-authorization-message: the plain
// explanation of a denial this emulator encoded.
func (s *Service) handleDecode(w http.ResponseWriter, r *http.Request) {
	reqctx.From(r.Context()).SetOperation("DecodeAuthorizationMessage")
	var b struct {
		EncodedMessage string `json:"encoded_message"`
	}
	if err := httpx.DecodeJSON(r, &b); err != nil || b.EncodedMessage == "" || len(b.EncodedMessage) > maxEncodedMessage {
		apierr.Write(w, r, apierr.StyleFlat, errMalformedMessage)
		return
	}
	plain, ok := authz.Decode(s.sealer, b.EncodedMessage)
	if !ok {
		apierr.Write(w, r, apierr.StyleFlat, errMalformedMessage)
		return
	}
	out := struct {
		DecodedMessage string `json:"decoded_message"`
	}{plain}
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
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
