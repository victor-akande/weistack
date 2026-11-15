package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
)

// Accounts manages the accounts besides the primary one (IAM implements
// it), which the admin API adds and lists.
type Accounts interface {
	// NewAccount adds an account whose root user holds root's keys, or
	// generated ones if root is nil, and returns them.
	NewAccount(ctx context.Context, name string, root *identity.Credentials) (identity.Account, identity.Credentials, error)
	// Accounts returns every account, the primary one first.
	Accounts() []identity.Account
	// ProjectIDOf returns an account's project in a region.
	ProjectIDOf(a identity.Account, region string) string
	// ProjectOwner returns the ID of the account whose project in region
	// projectID is, if it is any account's.
	ProjectOwner(projectID, region string) (string, bool)
}

// accountView is an account in the admin API. Its project is the one in
// the emulator's region.
type accountView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Primary   bool   `json:"primary"`
	ProjectID string `json:"project_id"`
}

func (s *Server) accountView(a identity.Account) accountView {
	return accountView{
		ID: a.ID, Name: a.Name, Primary: s.dir != nil && s.dir.Primary(a),
		ProjectID: s.accounts.ProjectIDOf(a, s.cfg.Region),
	}
}

// handleListAccounts is GET /_weistack/accounts: every account, without
// keys.
func (s *Server) handleListAccounts(w http.ResponseWriter, _ *http.Request) error {
	all := s.accounts.Accounts()
	out := struct {
		Accounts []accountView `json:"accounts"`
	}{Accounts: make([]accountView, 0, len(all))}
	for _, a := range all {
		out.Accounts = append(out.Accounts, s.accountView(a))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// newAccountRequest is the body of POST /_weistack/accounts. The keys
// are optional, given together, for clients configured in advance.
type newAccountRequest struct {
	Name      string `json:"name"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// newAccountResponse returns the root user's keys: the only time the
// emulator shows an added account's secret key.
type newAccountResponse struct {
	Account     accountView          `json:"account"`
	Credentials identity.Credentials `json:"credentials"`
}

var errAccountBody = apierr.New(http.StatusBadRequest, "WeiStack.0400", "the body must be a JSON object with a name, and optionally access_key and secret_key")

// maxAccountBody bounds the request body of POST /_weistack/accounts.
const maxAccountBody = 4 << 10

// handleNewAccount is POST /_weistack/accounts.
func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) error {
	var req newAccountRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAccountBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return errAccountBody
	}
	if dec.More() {
		return errAccountBody
	}
	var root *identity.Credentials
	if req.AccessKey != "" || req.SecretKey != "" {
		root = &identity.Credentials{AccessKey: req.AccessKey, SecretKey: req.SecretKey}
	}
	acct, creds, err := s.accounts.NewAccount(r.Context(), req.Name, root)
	if err != nil {
		var apiErr *apierr.Error
		if errors.As(err, &apiErr) {
			return apiErr
		}
		return apierr.Internal(err)
	}
	s.log.InfoContext(r.Context(), "account added", "account_id", acct.ID, "name", acct.Name, "access_key", creds.AccessKey)
	return httpx.WriteJSON(w, http.StatusCreated, newAccountResponse{Account: s.accountView(acct), Credentials: creds})
}
