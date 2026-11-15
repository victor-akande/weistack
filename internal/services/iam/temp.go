package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Temporary credentials: an access key, its secret key and a security
// token, which IAM's securitytokens and STS's AssumeAgency issue and
// clients send with every request (X-Security-Token; OBS clients
// x-obs-security-token or x-amz-security-token).
//
// Nothing is stored. The security token is the credentials' claims,
// sealed by the vault: who they act as, until when, with which session
// policies, and the secret key, which signature checks need back. A
// token that does not open, names another access key or has expired
// makes the access key unknown, as Huawei answers for it. Its user or
// agency is looked up on every request, so deleting or disabling it ends
// the credentials early.

// securityTokenLabel binds sealed security tokens to their purpose.
const securityTokenLabel = "weistack:security-token" //nolint:gosec // a label, not a credential

// claims are what a security token holds.
type claims struct {
	AccessKey  string    `json:"ak"`
	SecretKey  string    `json:"sk"`
	AccountID  string    `json:"account"`
	UserID     string    `json:"user_id,omitempty"`
	UserName   string    `json:"user_name,omitempty"`
	Admin      bool      `json:"admin,omitempty"`
	AgencyID   string    `json:"agency_id,omitempty"`
	AgencyName string    `json:"agency_name,omitempty"`
	Session    string    `json:"session,omitempty"`
	Policy     string    `json:"policy,omitempty"`
	PolicyIDs  []string  `json:"policy_ids,omitempty"`
	OBSPolicy  string    `json:"obs_policy,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// IssueTemporary returns temporary credentials that act as p for d.
func (s *Service) IssueTemporary(_ context.Context, p identity.Principal, d time.Duration) (identity.TemporaryCredentials, error) {
	creds, err := identity.NewCredentials()
	if err != nil {
		return identity.TemporaryCredentials{}, err
	}
	c := claims{
		AccessKey: creds.AccessKey, SecretKey: creds.SecretKey, AccountID: p.AccountID,
		UserID: p.UserID, UserName: p.UserName, Admin: p.Admin,
		AgencyID: p.AgencyID, AgencyName: p.AgencyName, Session: p.SessionName,
		ExpiresAt: s.now().UTC().Add(d).Truncate(time.Millisecond),
	}
	if p.Session != nil {
		c.Policy, c.PolicyIDs, c.OBSPolicy = p.Session.Policy, p.Session.PolicyIDs, p.Session.OBSPolicy
	}
	plain, err := json.Marshal(c) //nolint:gosec // sealed by the vault before it leaves
	if err != nil {
		return identity.TemporaryCredentials{}, err
	}
	sealed, err := s.vault.Seal(string(plain), securityTokenLabel)
	if err != nil {
		return identity.TemporaryCredentials{}, err
	}
	return identity.TemporaryCredentials{
		AccessKey: creds.AccessKey, SecretKey: creds.SecretKey,
		SecurityToken: base64.RawURLEncoding.EncodeToString(sealed), ExpiresAt: c.ExpiresAt,
	}, nil
}

// Temporary implements auth.TemporaryResolver: who temporary
// credentials act as, and their secret key, if securityToken is one IAM
// issued for accessKey, it has not expired, and its user or agency still
// exists (and the user is enabled).
func (s *Service) Temporary(ctx context.Context, accessKey, securityToken string) (identity.Principal, string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(securityToken, "="))
	if err != nil {
		return identity.Principal{}, "", false
	}
	plain, err := s.vault.Open(raw, securityTokenLabel)
	if err != nil {
		return identity.Principal{}, "", false
	}
	var c claims
	if err := json.Unmarshal([]byte(plain), &c); err != nil || c.AccessKey != accessKey || !s.now().Before(c.ExpiresAt) {
		return identity.Principal{}, "", false
	}
	acct, ok := s.dir.AccountByID(c.AccountID)
	if !ok {
		return identity.Principal{}, "", false
	}
	ctx = withAccount(ctx, acct)
	switch {
	case c.AgencyID != "":
		if _, ok := s.liveAgency(ctx, c.AgencyID); !ok {
			return identity.Principal{}, "", false
		}
	case c.Admin:
	default:
		u, err := s.users(ctx).Get(ctx, c.UserID)
		if err != nil || !u.Enabled {
			return identity.Principal{}, "", false
		}
	}
	p := identity.Principal{
		AccountID: c.AccountID, UserID: c.UserID, UserName: c.UserName, Admin: c.Admin,
		Temporary: true, AgencyID: c.AgencyID, AgencyName: c.AgencyName, SessionName: c.Session,
	}
	if c.Policy != "" || len(c.PolicyIDs) > 0 || c.OBSPolicy != "" {
		p.Session = &identity.Session{Policy: c.Policy, PolicyIDs: c.PolicyIDs, OBSPolicy: c.OBSPolicy}
	}
	return p, c.SecretKey, true
}

// liveAgency returns an agency of ctx's account that can be assumed: it
// exists and, if classic, has not expired.
func (s *Service) liveAgency(ctx context.Context, id string) (agency, bool) {
	a, err := s.agencies(ctx).Get(ctx, id)
	if err != nil {
		return agency{}, false
	}
	if a.ExpiresAt != nil && !s.now().Before(*a.ExpiresAt) {
		return agency{}, false
	}
	return a, true
}

// FindAgency returns the agency an STS request names in an account, by
// its name with its path (path/name, or just the name), if it can be
// assumed, with its longest session.
func (s *Service) FindAgency(ctx context.Context, accountID, pathName string) (id string, maxSession time.Duration, ok bool) {
	acct, ok := s.dir.AccountByID(accountID)
	if !ok {
		return "", 0, false
	}
	a, ok := s.agencyAt(withAccount(ctx, acct), pathName)
	if !ok {
		return "", 0, false
	}
	return a.ID, time.Duration(a.MaxSession) * time.Second, true
}

// agencyAt finds an assumable agency of ctx's account by path and name,
// or by ID.
func (s *Service) agencyAt(ctx context.Context, pathName string) (agency, bool) {
	found, err := s.agencies(ctx).List(ctx, func(a agency) bool {
		return strings.EqualFold(a.Path+a.Name, pathName) || a.ID == pathName
	})
	if err != nil || len(found) == 0 {
		return agency{}, false
	}
	return s.liveAgency(ctx, found[0].ID)
}

// Trusts reports whether an agency of an account lets caller assume it:
// a classic agency trusts the account it names; a trust agency's policy
// must allow sts:agencies:assume to the caller. Nothing assumes a
// service-linked agency, or one delegated to a cloud service, here.
func (s *Service) Trusts(ctx context.Context, accountID, agencyID string, caller identity.Principal) bool {
	acct, ok := s.dir.AccountByID(accountID)
	if !ok {
		return false
	}
	a, ok := s.liveAgency(withAccount(ctx, acct), agencyID)
	if !ok || a.ServicePrincipal != "" {
		return false
	}
	if a.Classic {
		return a.TrustDomainID != "" && a.TrustDomainID == caller.AccountID
	}
	callerAcct, ok := s.dir.AccountByID(caller.AccountID)
	if !ok {
		return false
	}
	pol, err := policydoc.ParseTrust([]byte(a.TrustPolicy))
	if err != nil {
		return false
	}
	req := policydoc.Request{
		Action: "sts:agencies:assume",
		Caller: &policydoc.Caller{AccountID: callerAcct.ID, URN: caller.URN(callerAcct)},
	}
	return policydoc.Evaluate(req, []policydoc.Source{{Name: a.Name, Policy: pol}}).Allowed
}

// AgencyPrincipal is who a session of an assumed agency acts as.
func (s *Service) AgencyPrincipal(ctx context.Context, accountID, agencyID, session string) (identity.Principal, bool) {
	acct, ok := s.dir.AccountByID(accountID)
	if !ok {
		return identity.Principal{}, false
	}
	a, ok := s.liveAgency(withAccount(ctx, acct), agencyID)
	if !ok {
		return identity.Principal{}, false
	}
	return identity.Principal{AccountID: acct.ID, AgencyID: a.ID, AgencyName: a.Name, SessionName: session}, true
}

// SessionPolicies checks the IDs of identity policies a session is
// limited to: each must be a policy of the account (or a system one).
func (s *Service) SessionPolicies(ctx context.Context, accountID string, ids []string) bool {
	acct, ok := s.dir.AccountByID(accountID)
	if !ok {
		return false
	}
	ctx = withAccount(ctx, acct)
	for _, id := range ids {
		if _, err := s.policies(ctx).Get(ctx, id); err != nil {
			return false
		}
	}
	return true
}

// sessionSources are the policies temporary credentials were issued
// with, as they apply in scope: an IAM 5.0 document and policy IDs
// everywhere, a classic document on OBS only.
func (s *Service) sessionSources(ctx context.Context, ses *identity.Session, service string) ([]policydoc.Source, error) {
	if ses == nil {
		return nil, nil
	}
	var out []policydoc.Source
	add := func(name, key, doc string) error {
		pol, err := s.perms.parse(key, []byte(doc))
		if err != nil {
			return err
		}
		out = append(out, policydoc.Source{Name: name, Policy: pol})
		return nil
	}
	if ses.Policy != "" {
		if err := add("session policy", "session:"+ses.Policy, ses.Policy); err != nil {
			return nil, err
		}
	}
	if ses.OBSPolicy != "" && service == "obs" {
		if err := add("session policy", "session:"+ses.OBSPolicy, ses.OBSPolicy); err != nil {
			return nil, err
		}
	}
	for _, id := range ses.PolicyIDs {
		p, err := s.policies(ctx).Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			// A policy deleted since allows nothing, but the session is
			// still limited.
			out = append(out, policydoc.Source{Name: id})
			continue
		}
		if err != nil {
			return nil, err
		}
		v := p.defaultVersion()
		if err := add(p.Name, "v5:"+p.ID+":"+v.ID, v.Document); err != nil {
			return nil, err
		}
	}
	return out, nil
}
