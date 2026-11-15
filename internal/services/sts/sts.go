// Package sts emulates Huawei Cloud's Security Token Service at
// sts.{region}.myhuaweicloud.com. It answers who the caller is, which
// the SDKs fall back to when IAM lists no domain, decodes the
// explanations of permission denials, and issues temporary credentials
// for assuming an agency.
package sts

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Agencies finds the agencies STS assumes and issues their credentials.
// IAM implements it.
type Agencies interface {
	// FindAgency returns an agency of an account that can be assumed, by
	// its path and name, with its longest session.
	FindAgency(ctx context.Context, accountID, pathName string) (id string, maxSession time.Duration, ok bool)
	// Trusts reports whether the agency's trust lets caller assume it.
	Trusts(ctx context.Context, accountID, agencyID string, caller identity.Principal) bool
	// AgencyPrincipal is who a session of the agency acts as.
	AgencyPrincipal(ctx context.Context, accountID, agencyID, session string) (identity.Principal, bool)
	// SessionPolicies reports whether every ID names an identity policy
	// of the account.
	SessionPolicies(ctx context.Context, accountID string, ids []string) bool
	// IssueTemporary returns credentials that act as p for d.
	IssueTemporary(ctx context.Context, p identity.Principal, d time.Duration) (identity.TemporaryCredentials, error)
}

// Service is the STS emulator.
type Service struct {
	log      *slog.Logger
	dir      *identity.Directory
	sealer   authz.Sealer
	agencies Agencies
}

// New returns the STS service. sealer opens the explanations of
// permission denials; it is the one the server seals them with.
// agencies may be nil, leaving agencies unassumable.
func New(log *slog.Logger, dir *identity.Directory, sealer authz.Sealer, agencies Agencies) (*Service, error) {
	if log == nil || dir == nil || sealer == nil {
		return nil, errors.New("sts: a logger, a directory and a sealer are required")
	}
	return &Service{log: log, dir: dir, sealer: sealer, agencies: agencies}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "sts" }

// Version implements server.Service.
func (s *Service) Version() string {
	return "v5 (caller identity, authorization messages, assuming agencies)"
}

// Routes implements server.Service. Asking who one is needs no
// permission (its API page has no authorization section); decoding a
// denial needs sts::decodeAuthorizationMessage.
func (s *Service) Routes(r chi.Router) {
	r.Use(authz.Service(authz.ServiceOptions{Name: "sts", Global: true, Style: apierr.StyleFlat, Deny: denied}))
	r.With(authz.Public()).Get("/v5/caller-identity", s.handleCallerIdentity)
	r.With(authz.Action("sts::decodeAuthorizationMessage")).Post("/v5/decode-authorization-message", s.handleDecode)
	// The agency comes from the body: the handler checks
	// sts:agencies:assume on it.
	r.With(authz.Defer()).Post("/v5/agencies/assume", s.handleAssumeAgency)
}

// STS's documented errors (api-iam5 ErrorCode).
var (
	errMalformedMessage = apierr.New(http.StatusBadRequest, "STS5.1301", "the encoded message is malformed or invalid")
	errDuration         = apierr.New(http.StatusBadRequest, "STS5.1102", "the duration seconds exceed the max session duration")
	errPolicyIDs        = apierr.New(http.StatusBadRequest, "STS5.1905", "the number of session managed policy ids exceeds the limit")
)

// errInput is WeiStack's own code for invalid input, which STS's error
// table has none for.
func errInput(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "WeiStack.0400", format, args...)
}

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

// handleCallerIdentity reports who signed the request, in its account. A
// user's key names that user. Credentials are not checked, so any other
// key, the administrator's included, stands for the primary account's
// root user.
func (s *Service) handleCallerIdentity(w http.ResponseWriter, r *http.Request) {
	reqctx.From(r.Context()).SetOperation("GetCallerIdentity")
	acct := s.dir.Account()
	id := auth.FromContext(r.Context())
	if a, ok := s.dir.AccountByID(id.Principal.AccountID); id.Known && ok {
		acct = a
	}
	out := callerIdentity{AccountID: acct.ID, PrincipalURN: acct.UserURN(acct.Name), PrincipalID: acct.RootUserID()}
	switch p := id.Principal; {
	case id.Known && p.Agency():
		out.PrincipalURN, out.PrincipalID = p.URN(acct), p.AgencyID+":"+p.SessionName
	case id.Known && p.UserID != "":
		out.PrincipalURN, out.PrincipalID = acct.UserURN(p.UserName), p.UserID
	}
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}
