package sts

import (
	"net/http"
	"regexp"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Assuming an agency: POST /v5/agencies/assume (api-iam5 AssumeAgency).
// The caller needs sts:agencies:assume on the agency, and under
// -iam=enforce the agency must trust the caller: a trust agency's policy
// must allow it, a classic agency must name the caller's account. The
// credentials act as the agency, limited by the session policies given.

// The documented limits.
const (
	minDuration     = 900
	maxDuration     = 43200
	defaultDuration = 3600
	// chainedMax bounds a session assumed with temporary credentials
	// (role chaining).
	chainedMax       = 3600
	maxPolicyIDs     = 20
	maxSessionPolicy = 4096
	maxSourceID      = 64
	maxTags          = 50
)

var (
	agencyURNRE   = regexp.MustCompile(`^iam::([0-9a-f]{32}):agency:(.+)$`)
	sessionNameRE = regexp.MustCompile(`^[\w+=,.@-]{2,128}$`)
)

// v5Time is IAM 5.0's time format.
const v5Time = "2006-01-02T15:04:05.000Z"

type assumeRequest struct {
	AgencyURN         string   `json:"agency_urn"`
	SessionName       string   `json:"agency_session_name"`
	DurationSeconds   *int     `json:"duration_seconds"`
	Policy            *string  `json:"policy"`
	PolicyIDs         []string `json:"policy_ids"`
	ExternalID        *string  `json:"external_id"`
	SourceIdentity    *string  `json:"source_identity"`
	Tags              []tag    `json:"tags"`
	TransitiveTagKeys []string `json:"transitive_tag_keys"`
	SerialNumber      *string  `json:"serial_number"`
	TokenCode         *string  `json:"token_code"`
	ProvidedContexts  []any    `json:"provided_contexts"`
}

type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type assumeResponse struct {
	SourceIdentity *string `json:"source_identity,omitempty"`
	AssumedAgency  struct {
		URN string `json:"urn"`
		ID  string `json:"id"`
	} `json:"assumed_agency"`
	Credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		Expiration      string `json:"expiration"`
		SecretAccessKey string `json:"secret_access_key"`
		SecurityToken   string `json:"security_token"`
	} `json:"credentials"`
}

// handleAssumeAgency serves POST /v5/agencies/assume.
func (s *Service) handleAssumeAgency(w http.ResponseWriter, r *http.Request) {
	reqctx.From(r.Context()).SetOperation("AssumeAgency")
	if err := s.assumeAgency(w, r); err != nil {
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}

func (s *Service) assumeAgency(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b assumeRequest
	if err := httpx.DecodeJSON(r, &b); err != nil {
		return errInput("the request body is not valid JSON")
	}
	m := agencyURNRE.FindStringSubmatch(b.AgencyURN)
	switch {
	case m == nil:
		return errInput("agency_urn must be iam::<account-id>:agency:<name>")
	case !sessionNameRE.MatchString(b.SessionName):
		return errInput("agency_session_name must be 2 to 128 letters, digits or +=,.@-_")
	case len(b.PolicyIDs) > maxPolicyIDs:
		return errPolicyIDs
	case b.Policy != nil && (len(*b.Policy) < 1 || len(*b.Policy) > maxSessionPolicy):
		return errInput("policy must be 1 to %d characters", maxSessionPolicy)
	case b.SourceIdentity != nil && (len(*b.SourceIdentity) < 2 || len(*b.SourceIdentity) > maxSourceID):
		return errInput("source_identity must be 2 to %d characters", maxSourceID)
	case len(b.Tags) > maxTags:
		return errInput("at most %d tags", maxTags)
	}
	if b.Policy != nil {
		pol, err := policy.Parse([]byte(*b.Policy))
		if err != nil || pol.Version() != policy.Version5 {
			return errInput("policy must be an IAM 5.0 identity policy")
		}
	}
	accountID, pathName := m[1], m[2]

	res := authz.Resource{URN: b.AgencyURN}
	if err := authz.Check(r, "sts:agencies:assume", res); err != nil {
		return err
	}
	if len(b.Tags) > 0 {
		if err := authz.Check(r, "sts::tagSession", res); err != nil {
			return err
		}
	}
	if b.SourceIdentity != nil {
		if err := authz.Check(r, "sts::setSourceIdentity", res); err != nil {
			return err
		}
	}

	caller := s.caller(r)
	if s.agencies == nil {
		return s.refuse(r, "agencies are not emulated", res)
	}
	agencyID, maxSession, ok := s.agencies.FindAgency(ctx, accountID, pathName)
	if !ok {
		return s.refuse(r, "the agency does not exist", res)
	}
	if authz.Enforced(r) && !s.agencies.Trusts(ctx, accountID, agencyID, caller) {
		return s.refuse(r, "the agency's trust policy does not allow the caller", res)
	}
	if len(b.PolicyIDs) > 0 && !s.agencies.SessionPolicies(ctx, accountID, b.PolicyIDs) {
		return errInput("policy_ids must name identity policies of the agency's account")
	}

	seconds := defaultDuration
	if b.DurationSeconds != nil {
		seconds = *b.DurationSeconds
	}
	limit := min(int(maxSession/time.Second), maxDuration)
	if caller.Temporary {
		limit = min(limit, chainedMax)
	}
	switch {
	case seconds < minDuration:
		return errInput("duration_seconds must be at least %d", minDuration)
	case seconds > limit:
		return errDuration
	}

	p, ok := s.agencies.AgencyPrincipal(ctx, accountID, agencyID, b.SessionName)
	if !ok {
		return s.refuse(r, "the agency does not exist", res)
	}
	if b.Policy != nil || len(b.PolicyIDs) > 0 {
		p.Session = &identity.Session{PolicyIDs: b.PolicyIDs}
		if b.Policy != nil {
			p.Session.Policy = *b.Policy
		}
	}
	creds, err := s.agencies.IssueTemporary(ctx, p, time.Duration(seconds)*time.Second)
	if err != nil {
		return err
	}
	acct, _ := s.dir.AccountByID(accountID)
	s.log.InfoContext(ctx, "agency assumed", "agency", p.URN(acct), "access_key", creds.AccessKey, "expires_at", creds.ExpiresAt)

	var out assumeResponse
	out.SourceIdentity = b.SourceIdentity
	out.AssumedAgency.URN, out.AssumedAgency.ID = p.URN(acct), agencyID+":"+b.SessionName
	out.Credentials.AccessKeyID, out.Credentials.SecretAccessKey = creds.AccessKey, creds.SecretKey
	out.Credentials.SecurityToken, out.Credentials.Expiration = creds.SecurityToken, creds.ExpiresAt.UTC().Format(v5Time)
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// caller is who signed r: its known principal, or the primary account's
// root user for a caller WeiStack does not know.
func (s *Service) caller(r *http.Request) identity.Principal {
	if id := auth.FromContext(r.Context()); id.Known {
		return id.Principal
	}
	acct := s.dir.Account()
	return identity.Principal{AccountID: acct.ID, UserID: acct.RootUserID(), UserName: acct.Name}
}

// refuse denies assuming an agency, with an encoded explanation under
// -iam=enforce.
func (s *Service) refuse(r *http.Request, reason string, res authz.Resource) error {
	if err := authz.Refuse(r, "sts:agencies:assume", reason, res); err != nil {
		return err
	}
	return denied(&authz.Denial{Action: "sts:agencies:assume"})
}
