package iam

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
)

// Classic temporary credentials: POST /v3.0/OS-CREDENTIAL/securitytokens
// (api-iam iam_04_0002, iam_04_0101). With the "token" method they act
// as the caller and need no permission; with "assume_role" they act as
// an agency of another account, and the caller needs iam:tokens:assume
// on it. Either may carry a classic policy, which Huawei documents as
// limiting the credentials on OBS only.

// The documented limits of duration_seconds: 15 minutes to 24 hours,
// 15 minutes by default.
const (
	minClassicDuration     = 900
	maxClassicDuration     = 86400
	defaultClassicDuration = 900
)

// sessionUserRE is the documented form of session_user.name.
var sessionUserRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{4,63}$`)

type securityTokenRequest struct {
	Auth *struct {
		Identity *struct {
			Methods []string `json:"methods"`
			Token   *struct {
				ID              string `json:"id"`
				DurationSeconds *int   `json:"duration_seconds"`
			} `json:"token"`
			AssumeRole *struct {
				AgencyName      string `json:"agency_name"`
				DomainID        string `json:"domain_id"`
				DomainName      string `json:"domain_name"`
				DurationSeconds *int   `json:"duration_seconds"`
				SessionUser     *struct {
					Name string `json:"name"`
				} `json:"session_user"`
			} `json:"assume_role"`
			Policy json.RawMessage `json:"policy"`
		} `json:"identity"`
	} `json:"auth"`
}

type temporaryView struct {
	Access        string `json:"access"`
	Secret        string `json:"secret"`
	SecurityToken string `json:"securitytoken"`
	ExpiresAt     string `json:"expires_at"`
}

// handleCreateSecurityToken is POST /v3.0/OS-CREDENTIAL/securitytokens.
func (s *Service) handleCreateSecurityToken(w http.ResponseWriter, r *http.Request) error {
	var req securityTokenRequest
	if err := decodeClassic(r, &req); err != nil {
		return err
	}
	switch {
	case req.Auth == nil:
		return errRequired("auth")
	case req.Auth.Identity == nil:
		return errRequired("identity")
	}
	id := req.Auth.Identity
	obsPolicy, err := classicSessionPolicy(id.Policy)
	if err != nil {
		return err
	}
	var (
		p identity.Principal
		d *int
	)
	switch {
	case slices.Equal(id.Methods, []string{"token"}):
		var tokenID string
		if id.Token != nil {
			tokenID, d = id.Token.ID, id.Token.DurationSeconds
		}
		p, err = s.tokenCaller(r, tokenID)
	case slices.Equal(id.Methods, []string{"assume_role"}):
		if id.AssumeRole == nil {
			return errRequired("assume_role")
		}
		d = id.AssumeRole.DurationSeconds
		p, err = s.assumeClassic(r, id.AssumeRole.AgencyName, nameID{ID: id.AssumeRole.DomainID, Name: id.AssumeRole.DomainName}, id.AssumeRole.SessionUser)
	default:
		return errInvalidField("methods", "")
	}
	if err != nil {
		return err
	}
	seconds := defaultClassicDuration
	if d != nil {
		if *d < minClassicDuration || *d > maxClassicDuration {
			return errInvalidField("duration_seconds", strconv.Itoa(*d))
		}
		seconds = *d
	}
	if obsPolicy != "" {
		ses := identity.Session{OBSPolicy: obsPolicy}
		if p.Session != nil {
			ses.Policy, ses.PolicyIDs = p.Session.Policy, p.Session.PolicyIDs
		}
		p.Session = &ses
	}
	creds, err := s.IssueTemporary(r.Context(), p, time.Duration(seconds)*time.Second)
	if err != nil {
		return err
	}
	s.log.InfoContext(r.Context(), "temporary credentials issued", "access_key", creds.AccessKey,
		"user", p.UserName, "agency", p.AgencyName, "expires_at", creds.ExpiresAt)
	return httpx.WriteJSON(w, http.StatusCreated, struct {
		Credential temporaryView `json:"credential"`
	}{temporaryView{
		Access: creds.AccessKey, Secret: creds.SecretKey, SecurityToken: creds.SecurityToken,
		ExpiresAt: creds.ExpiresAt.Format(keystoneTime),
	}})
}

// classicSessionPolicy checks the policy of a securitytokens request: a
// classic custom policy (Version 1.1). It returns it compacted.
func classicSessionPolicy(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	pol, err := policydoc.Parse(raw)
	if err != nil || pol.Version() != policydoc.VersionFine {
		return "", errInvalidField("policy", "")
	}
	var compact map[string]any
	if err := json.Unmarshal(raw, &compact); err != nil {
		return "", errInvalidField("policy", "")
	}
	b, err := json.Marshal(compact)
	return string(b), err
}

// tokenCaller is who the "token" method acts as: the user of the token
// in the X-Auth-Token header or the body, or else the request's signer.
// A caller WeiStack does not know (accept mode) is the primary
// account's root user.
func (s *Service) tokenCaller(r *http.Request, bodyToken string) (identity.Principal, error) {
	tokenID := r.Header.Get("X-Auth-Token")
	if tokenID == "" {
		tokenID = bodyToken
	}
	if tokenID != "" {
		p, err := s.CheckToken(r.Context(), tokenID)
		switch {
		case errors.Is(err, auth.ErrTokenExpired):
			return identity.Principal{}, errTokenExpired
		case errors.Is(err, auth.ErrTokenUnknown):
			return identity.Principal{}, errTokenInvalid
		}
		return p, err
	}
	return s.principalOf(r), nil
}

// principalOf is who signed r: its known principal, or the primary account's
// root user for a caller WeiStack does not know.
func (s *Service) principalOf(r *http.Request) identity.Principal {
	if id := auth.FromContext(r.Context()); id.Known {
		return id.Principal
	}
	acct := s.dir.Account()
	return identity.Principal{AccountID: acct.ID, UserID: acct.RootUserID(), UserName: acct.Name}
}

// assumeClassic is the "assume_role" method: the caller acts as an agency
// of the account domain names. Under -iam=enforce the caller needs
// iam:tokens:assume on the agency (/iam/agencies/<id> in a classic
// policy) and the agency must trust the caller's account.
func (s *Service) assumeClassic(r *http.Request, name string, domain nameID, su *struct {
	Name string `json:"name"`
}) (identity.Principal, error) {
	ctx := r.Context()
	switch {
	case name == "":
		return identity.Principal{}, errRequired("agency_name")
	case domain.ID == "" && domain.Name == "":
		return identity.Principal{}, errRequired("domain_id")
	case su != nil && !sessionUserRE.MatchString(su.Name):
		return identity.Principal{}, errInvalidField("session_user.name", su.Name)
	}
	caller := s.principalOf(r)
	acct, found := s.accountNamed(domain)
	var a agency
	if found {
		a, found = s.agencyAt(withAccount(ctx, acct), name)
	}
	uris := []string{"/iam/agencies/" + name}
	if found {
		uris = append(uris, "/iam/agencies/"+a.ID)
	}
	res := authz.Resource{URIs: uris}
	if err := authz.Check(r, "iam:tokens:assume", res); err != nil {
		return identity.Principal{}, err
	}
	if !found {
		if err := authz.Refuse(r, "iam:tokens:assume", "the agency does not exist", res); err != nil {
			return identity.Principal{}, err
		}
		return identity.Principal{}, errForbidden()
	}
	if authz.Enforced(r) && !s.Trusts(ctx, acct.ID, a.ID, caller) {
		return identity.Principal{}, authz.Refuse(r, "iam:tokens:assume", "the agency does not trust the caller's account", res)
	}
	session := caller.UserName
	switch {
	case su != nil:
		session = su.Name
	case caller.Agency():
		session = caller.SessionName
	}
	return identity.Principal{AccountID: acct.ID, AgencyID: a.ID, AgencyName: a.Name, SessionName: session}, nil
}
