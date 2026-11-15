package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Agencies: identities an account creates for another account or a cloud
// service to act in it with the permissions granted to the agency.
//
// Classic IAM (/v3.0/OS-AGENCY) creates an agency for a delegated
// account (trust_domain_id or trust_domain_name) or a cloud service
// (trust_domain_name op_svc_<service>), with a validity period, and
// grants it classic roles like a user group. IAM 5.0 (/v5/agencies)
// creates a "trust agency" whose trust policy says who may assume it,
// and attaches identity policies to it; a service-linked agency is one a
// cloud service creates for itself. Both APIs share one store: IAM 5.0
// lists every agency, classic IAM its own.

const (
	kindAgency       = "iam.agency"
	kindDeletionTask = "iam.deletion-task"
	subjectAgency    = "agency"
)

// agency is an agency of either generation.
type agency struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description,omitempty"`

	// Classic agencies name their delegated party and expire.
	Classic         bool   `json:"classic,omitempty"`
	TrustDomainID   string `json:"trust_domain_id,omitempty"`
	TrustDomainName string `json:"trust_domain_name,omitempty"`
	// DurationHours is a classic agency's validity; 0 is FOREVER.
	DurationHours int        `json:"duration_hours,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`

	// Trust agencies hold a trust policy, as given.
	TrustPolicy string `json:"trust_policy,omitempty"`
	// MaxSession is the longest session, in seconds, assuming it gives.
	MaxSession int `json:"max_session_duration"`
	// ServicePrincipal marks a service-linked agency.
	ServicePrincipal string `json:"service_principal,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) agencies(ctx context.Context) store.Collection[agency] {
	return store.Of[agency](s.store, s.scope(ctx, kindAgency))
}

// Limits, from the API references (api-iam iam_12_0003, api-iam5
// CreateAgencyV5).
const (
	maxClassicAgencyDesc = 255
	maxAgencyDesc        = 1000
	minSessionDuration   = 3600
	maxSessionDuration   = 43200
)

var (
	agencyNameRE    = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
	serviceDomainRE = regexp.MustCompile(`^op_svc_[A-Za-z]+$`)
	servicePrinRE   = regexp.MustCompile(`^service\.[A-Za-z][A-Za-z0-9]*$`)
)

// IAM 5.0's agency codes.
var (
	errV5AgencyName      = apierr.New(http.StatusBadRequest, "PAP5.0029", "invalid agency name")
	errV5V5Only          = apierr.New(http.StatusBadRequest, "PAP5.0038", "This operation is only supported by v5 agencies")
	errV5NoAgency        = apierr.New(http.StatusNotFound, "PAP5.0012", "no such agency")
	errV5NoTask          = apierr.New(http.StatusNotFound, "PAP5.0015", "no such deletion task")
	errV5NoLinked        = apierr.New(http.StatusNotFound, "PAP5.0022", "no such service linked agency")
	errV5NoPrincipal     = apierr.New(http.StatusNotFound, "PAP5.0023", "no such service principal")
	errV5AgencyPolicies  = apierr.New(http.StatusConflict, "PAP5.0003", "attached policies per agency limit exceeded")
	errV5AgencyExists    = apierr.New(http.StatusConflict, "PAP5.0031", "agency already exists")
	errClassicAgencyName = errConflict("agency", "the name is in use")
)

// agencyNamed reports whether an agency has that name, ignoring case.
// The caller holds s.mu when the answer must stay true.
func (s *Service) agencyNamed(ctx context.Context, name string) (bool, error) {
	found, err := s.agencies(ctx).List(ctx, func(a agency) bool { return strings.EqualFold(a.Name, name) })
	return len(found) > 0, err
}

// deleteAgency removes an agency, its classic grants and its attached
// policies.
func (s *Service) deleteAgency(ctx context.Context, id string) error {
	if err := s.deleteAssignments(ctx, func(a assignment) bool { return a.Subject == subjectAgency && a.SubjectID == id }); err != nil {
		return err
	}
	held, err := s.attachmentsWhere(ctx, func(a policyAttachment) bool { return a.Subject == subjectAgency && a.SubjectID == id })
	if err != nil {
		return err
	}
	for _, a := range held {
		if err := s.policyAttachments(ctx).Delete(ctx, a.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return s.agencies(ctx).Delete(ctx, id)
}

// agencyURN is an agency's IAM 5.0 URN: iam::<account-id>:agency:<path><name>.
func (s *Service) agencyURN(ctx context.Context, a agency) string {
	return s.urn(ctx, "agency", a.Path+a.Name)
}

// ---- Classic: /v3.0/OS-AGENCY ----

// classicAgencyTime is the format of create_time and expire_time.
const classicAgencyTime = "2006-01-02T15:04:05.000000"

// classicAgencyView mirrors the SDK models iam/v3 AgencyCreateResult,
// AgencyShowResult and AgencyListResult.
type classicAgencyView struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Description     string  `json:"description"`
	DomainID        string  `json:"domain_id"`
	TrustDomainID   *string `json:"trust_domain_id"`
	TrustDomainName *string `json:"trust_domain_name,omitempty"`
	Duration        string  `json:"duration"`
	CreateTime      string  `json:"create_time"`
	ExpireTime      *string `json:"expire_time"`
	AgencyURN       string  `json:"agency_urn,omitempty"`
}

// classicView renders a classic agency; full adds what show and list
// return beyond create and update.
func (s *Service) classicView(ctx context.Context, a agency, full bool) classicAgencyView {
	v := classicAgencyView{
		ID: a.ID, Name: a.Name, Description: a.Description, DomainID: s.account(ctx).ID,
		Duration: "FOREVER", CreateTime: a.CreatedAt.UTC().Format(classicAgencyTime),
	}
	if a.TrustDomainID != "" {
		v.TrustDomainID = &a.TrustDomainID
	}
	if a.DurationHours > 0 {
		v.Duration = strconv.Itoa(a.DurationHours)
	}
	if a.ExpiresAt != nil {
		t := a.ExpiresAt.UTC().Format(classicAgencyTime)
		v.ExpireTime = &t
	}
	if full {
		if a.TrustDomainName != "" {
			v.TrustDomainName = &a.TrustDomainName
		}
		v.AgencyURN = s.agencyURN(ctx, a)
	}
	return v
}

type classicAgencyChange struct {
	Name            *string         `json:"name"`
	DomainID        *string         `json:"domain_id"`
	TrustDomainID   *string         `json:"trust_domain_id"`
	TrustDomainName *string         `json:"trust_domain_name"`
	Description     *string         `json:"description"`
	Duration        json.RawMessage `json:"duration"`
}

func readClassicAgency(r *http.Request) (classicAgencyChange, error) {
	var b struct {
		Agency *classicAgencyChange `json:"agency"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return classicAgencyChange{}, err
	}
	if b.Agency == nil {
		return classicAgencyChange{}, errRequired("agency")
	}
	return *b.Agency, nil
}

// agencyDuration reads a classic agency's validity: "FOREVER", "ONEDAY",
// or a number of days, as a number or a string. It returns hours, 0 for
// FOREVER.
func agencyDuration(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, true
	}
	var days int
	if err := json.Unmarshal(raw, &days); err == nil {
		return days * 24, days > 0
	}
	var str string
	if err := json.Unmarshal(raw, &str); err != nil {
		return 0, false
	}
	switch str {
	case "FOREVER":
		return 0, true
	case "ONEDAY":
		return 24, true
	}
	days, err := strconv.Atoi(str)
	return days * 24, err == nil && days > 0
}

// applyClassic applies a create or update to a. The caller holds s.mu.
func (s *Service) applyClassic(c classicAgencyChange, a *agency, now time.Time) error {
	if c.Description != nil {
		if utf8.RuneCountInString(*c.Description) > maxClassicAgencyDesc {
			return errInvalidField("description", *c.Description)
		}
		a.Description = *c.Description
	}
	switch {
	case c.TrustDomainName != nil && *c.TrustDomainName != "":
		name := *c.TrustDomainName
		if serviceDomainRE.MatchString(name) {
			a.TrustDomainID, a.TrustDomainName = "", name
			break
		}
		acct, ok := s.dir.AccountByName(name)
		if !ok {
			return errNotFound("domain", name)
		}
		a.TrustDomainID, a.TrustDomainName = acct.ID, acct.Name
	case c.TrustDomainID != nil && *c.TrustDomainID != "":
		acct, ok := s.dir.AccountByID(*c.TrustDomainID)
		if !ok {
			return errNotFound("domain", *c.TrustDomainID)
		}
		a.TrustDomainID, a.TrustDomainName = acct.ID, acct.Name
	}
	if c.Duration != nil {
		hours, ok := agencyDuration(c.Duration)
		if !ok {
			return errInvalidField("duration", string(c.Duration))
		}
		a.DurationHours, a.ExpiresAt = hours, nil
		if hours > 0 {
			t := now.Add(time.Duration(hours) * time.Hour)
			a.ExpiresAt = &t
		}
	}
	return nil
}

// POST /v3.0/OS-AGENCY/agencies
func (s *Service) handleCreateAgency(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, err := readClassicAgency(r)
	if err != nil {
		return err
	}
	switch {
	case c.Name == nil || *c.Name == "":
		return errRequired("name")
	case !agencyNameRE.MatchString(*c.Name):
		return errInvalidField("name", *c.Name)
	case c.DomainID == nil || *c.DomainID == "":
		return errRequired("domain_id")
	case *c.DomainID != s.account(ctx).ID:
		return errInvalidField("domain_id", *c.DomainID)
	case (c.TrustDomainID == nil || *c.TrustDomainID == "") && (c.TrustDomainName == nil || *c.TrustDomainName == ""):
		return errRequired("trust_domain_id")
	}
	now := s.now().UTC()
	a := agency{ID: s.ids.Hex32(), Name: *c.Name, Classic: true, MaxSession: minSessionDuration, CreatedAt: now}
	if c.Duration == nil {
		c.Duration = json.RawMessage(`"FOREVER"`)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.applyClassic(c, &a, now); err != nil {
		return err
	}
	if taken, err := s.agencyNamed(ctx, a.Name); err != nil || taken {
		if err == nil {
			err = errClassicAgencyName
		}
		return err
	}
	if err := s.agencies(ctx).Create(ctx, a.ID, a); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, map[string]classicAgencyView{"agency": s.classicView(ctx, a, false)})
}

// GET /v3.0/OS-AGENCY/agencies?domain_id=…[&trust_domain_id=…][&name=…]
func (s *Service) handleListAgencies(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	q := r.URL.Query()
	if q.Get("domain_id") == "" {
		return errInvalidParam("domain_id")
	}
	all, err := s.agencies(ctx).List(ctx, func(a agency) bool {
		return a.Classic && q.Get("domain_id") == s.account(ctx).ID &&
			(q.Get("name") == "" || q.Get("name") == a.Name) &&
			(q.Get("trust_domain_id") == "" || q.Get("trust_domain_id") == a.TrustDomainID)
	})
	if err != nil {
		return err
	}
	page, perPage, err := paging(q.Get("page"), q.Get("per_page"))
	if err != nil {
		return err
	}
	if perPage > 0 {
		all = pageOf(all, page, perPage)
	}
	out := struct {
		Agencies []classicAgencyView `json:"agencies"`
	}{make([]classicAgencyView, 0, len(all))}
	for _, a := range all {
		out.Agencies = append(out.Agencies, s.classicView(ctx, a, true))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// classicAgency returns the classic agency the path names.
func (s *Service) classicAgency(r *http.Request) (agency, error) {
	ctx := r.Context()
	id := chi.URLParam(r, "agency_id")
	a, err := s.agencies(ctx).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !a.Classic {
		return agency{}, errNotFound("agency", id)
	}
	return a, err
}

// GET /v3.0/OS-AGENCY/agencies/{agency_id}
func (s *Service) handleShowAgency(w http.ResponseWriter, r *http.Request) error {
	a, err := s.classicAgency(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, map[string]classicAgencyView{"agency": s.classicView(r.Context(), a, true)})
}

// PUT /v3.0/OS-AGENCY/agencies/{agency_id}
func (s *Service) handleUpdateAgency(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, err := readClassicAgency(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.classicAgency(r)
	if err != nil {
		return err
	}
	if err := s.applyClassic(c, &a, s.now().UTC()); err != nil {
		return err
	}
	if err := s.agencies(ctx).Put(ctx, a.ID, a); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, map[string]classicAgencyView{"agency": s.classicView(ctx, a, false)})
}

// DELETE /v3.0/OS-AGENCY/agencies/{agency_id}
func (s *Service) handleDeleteAgency(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.classicAgency(r)
	if err != nil {
		return err
	}
	if err := s.deleteAgency(r.Context(), a.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// roleAssignmentsBody is the body of the agency enterprise-project
// grants, which name their assignments in the body.
type roleAssignmentsBody struct {
	RoleAssignments []struct {
		AgencyID            string `json:"agency_id"`
		EnterpriseProjectID string `json:"enterprise_project_id"`
		RoleID              string `json:"role_id"`
	} `json:"role_assignments"`
}

// PUT and DELETE /v3.0/OS-PERMISSION/subjects/agency/scopes/enterprise-project/role-assignments
func (s *Service) agencyEPGrants(grant bool) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx := r.Context()
		var b roleAssignmentsBody
		if err := decodeClassic(r, &b); err != nil {
			return err
		}
		if len(b.RoleAssignments) == 0 {
			return errRequired("role_assignments")
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var todo []assignment
		for _, ra := range b.RoleAssignments {
			a, err := s.agencies(ctx).Get(ctx, ra.AgencyID)
			switch {
			case errors.Is(err, store.ErrNotFound) || err == nil && !a.Classic:
				return errNotFound("agency", ra.AgencyID)
			case err != nil:
				return err
			case ra.EnterpriseProjectID != defaultEP:
				return errNotFound("enterprise project", ra.EnterpriseProjectID)
			}
			ro, ok, err := s.findRole(ctx, ra.RoleID)
			if err != nil {
				return err
			}
			if !ok {
				return errNotFound("role", ra.RoleID)
			}
			todo = append(todo, assignment{
				ID:      assignmentID(subjectAgency, a.ID, ro.ID, scopeEP, defaultEP),
				Subject: subjectAgency, SubjectID: a.ID, RoleID: ro.ID, Scope: scopeEP, ScopeID: defaultEP,
				CreatedAt: s.now().UTC(),
			})
		}
		for _, a := range todo {
			var err error
			if grant {
				err = s.assignments(ctx).Create(ctx, a.ID, a)
				if errors.Is(err, store.ErrExists) {
					err = nil
				}
			} else {
				err = s.assignments(ctx).Delete(ctx, a.ID)
				if errors.Is(err, store.ErrNotFound) {
					err = nil
				}
			}
			if err != nil {
				return err
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// ---- IAM 5.0: /v5/agencies ----

// v5AgencyView mirrors the SDK models iam/v5 TrustAgency, Agency and
// AgencyEx.
type v5AgencyView struct {
	URN                string    `json:"urn"`
	TrustPolicy        *string   `json:"trust_policy"`
	CreatedAt          string    `json:"created_at"`
	Description        string    `json:"description"`
	MaxSessionDuration int       `json:"max_session_duration"`
	Path               string    `json:"path"`
	AgencyID           string    `json:"agency_id"`
	AgencyName         string    `json:"agency_name"`
	TrustDomainID      *string   `json:"trust_domain_id"`
	TrustDomainName    *string   `json:"trust_domain_name"`
	Tags               *[]v5Tags `json:"tags,omitempty"`
}

// v5Tags is a resource tag; agencies have none in WeiStack.
type v5Tags struct {
	Key   string `json:"tag_key"`
	Value string `json:"tag_value"`
}

func (s *Service) v5AgencyView(ctx context.Context, a agency) v5AgencyView {
	v := v5AgencyView{
		URN: s.agencyURN(ctx, a), CreatedAt: v5At(a.CreatedAt), Description: a.Description,
		MaxSessionDuration: a.MaxSession, Path: a.Path, AgencyID: a.ID, AgencyName: a.Name,
	}
	if a.TrustPolicy != "" {
		v.TrustPolicy = &a.TrustPolicy
	}
	if a.TrustDomainID != "" {
		v.TrustDomainID = &a.TrustDomainID
	}
	if a.TrustDomainName != "" {
		v.TrustDomainName = &a.TrustDomainName
	}
	return v
}

// v5Agency returns the agency the path names.
func (s *Service) v5Agency(r *http.Request) (agency, error) {
	ctx := r.Context()
	a, err := s.agencies(ctx).Get(ctx, chi.URLParam(r, "agency_id"))
	if errors.Is(err, store.ErrNotFound) {
		return agency{}, errV5NoAgency
	}
	return a, err
}

// checkTrustPolicy validates a trust policy as IAM 5.0 does.
func checkTrustPolicy(doc string) error {
	if len(doc) > maxPolicyBytes {
		return errV5PolicySize
	}
	if _, err := policydoc.ParseTrust([]byte(doc)); err != nil {
		return errV5Malformed.WithCause(err)
	}
	return nil
}

func validSession(n int) bool { return n >= minSessionDuration && n <= maxSessionDuration }

// POST /v5/agencies
func (s *Service) handleCreateAgencyV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b struct {
		Name        string  `json:"agency_name"`
		Path        string  `json:"path"`
		TrustPolicy string  `json:"trust_policy"`
		MaxSession  *int    `json:"max_session_duration"`
		Description *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	switch {
	case !agencyNameRE.MatchString(b.Name):
		return errV5AgencyName
	case !validPolicyPath(b.Path):
		return errV5Path
	case b.TrustPolicy == "":
		return errV5Input
	case b.MaxSession != nil && !validSession(*b.MaxSession):
		return errV5Input
	case b.Description != nil && utf8.RuneCountInString(*b.Description) > maxAgencyDesc:
		return errV5Input
	}
	if err := checkTrustPolicy(b.TrustPolicy); err != nil {
		return err
	}
	a := agency{
		ID: s.ids.Hex32(), Name: b.Name, Path: b.Path, TrustPolicy: b.TrustPolicy,
		MaxSession: minSessionDuration, CreatedAt: s.now().UTC(),
	}
	if b.MaxSession != nil {
		a.MaxSession = *b.MaxSession
	}
	if b.Description != nil {
		a.Description = *b.Description
	}
	if err := s.createV5Agency(ctx, a); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, map[string]v5AgencyView{"agency": s.v5AgencyView(ctx, a)})
}

func (s *Service) createV5Agency(ctx context.Context, a agency) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if taken, err := s.agencyNamed(ctx, a.Name); err != nil || taken {
		if err == nil {
			err = errV5AgencyExists
		}
		return err
	}
	return s.agencies(ctx).Create(ctx, a.ID, a)
}

// GET /v5/agencies[?path_prefix=…]
func (s *Service) handleListAgenciesV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	prefix := r.URL.Query().Get("path_prefix")
	all, err := s.agencies(ctx).List(ctx, func(a agency) bool { return strings.HasPrefix(a.Path, prefix) })
	if err != nil {
		return err
	}
	got, info, err := page(r, all, func(a agency) string { return a.ID })
	if err != nil {
		return err
	}
	views := make([]v5AgencyView, 0, len(got))
	for _, a := range got {
		views = append(views, s.v5AgencyView(ctx, a))
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Agencies []v5AgencyView `json:"agencies"`
		PageInfo pageInfo       `json:"page_info"`
	}{views, info})
}

// GET /v5/agencies/{agency_id}
func (s *Service) handleGetAgencyV5(w http.ResponseWriter, r *http.Request) error {
	a, err := s.v5Agency(r)
	if err != nil {
		return err
	}
	v := s.v5AgencyView(r.Context(), a)
	v.Tags = &[]v5Tags{}
	return httpx.WriteJSON(w, http.StatusOK, map[string]v5AgencyView{"agency": v})
}

// PUT /v5/agencies/{agency_id}
func (s *Service) handleUpdateAgencyV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b struct {
		MaxSession  *int    `json:"max_session_duration"`
		Description *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.MaxSession != nil && !validSession(*b.MaxSession) ||
		b.Description != nil && utf8.RuneCountInString(*b.Description) > maxAgencyDesc {
		return errV5Input
	}
	a, err := s.updateAgency(r, func(a *agency) error {
		if b.MaxSession != nil {
			a.MaxSession = *b.MaxSession
		}
		if b.Description != nil {
			a.Description = *b.Description
		}
		return nil
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, map[string]v5AgencyView{"agency": s.v5AgencyView(ctx, a)})
}

// PUT /v5/agencies/{agency_id}/trust-policy
func (s *Service) handleUpdateTrustPolicyV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		TrustPolicy string `json:"trust_policy"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.TrustPolicy == "" {
		return errV5Input
	}
	if err := checkTrustPolicy(b.TrustPolicy); err != nil {
		return err
	}
	if _, err := s.updateAgency(r, func(a *agency) error {
		if a.Classic {
			return errV5V5Only
		}
		a.TrustPolicy = b.TrustPolicy
		return nil
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) updateAgency(r *http.Request, fn func(*agency) error) (agency, error) {
	ctx := r.Context()
	a, err := s.agencies(ctx).Update(ctx, chi.URLParam(r, "agency_id"), fn)
	if errors.Is(err, store.ErrNotFound) {
		return agency{}, errV5NoAgency
	}
	return a, err
}

// DELETE /v5/agencies/{agency_id}
func (s *Service) handleDeleteAgencyV5(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.v5Agency(r)
	if err != nil {
		return err
	}
	if err := s.deleteAgency(r.Context(), a.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- Service-linked agencies ----

// deletionTask is the record of a service-linked agency's deletion, which
// WeiStack completes at once.
type deletionTask struct {
	ID        string    `json:"id"`
	AgencyID  string    `json:"agency_id"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) deletionTasks(ctx context.Context) store.Collection[deletionTask] {
	return store.Of[deletionTask](s.store, s.scope(ctx, kindDeletionTask))
}

// linkedAgencyName is the name of a service's service-linked agency:
// ServiceLinkedAgencyFor<Service>, under the path
// service-linked-agency/<service principal>/.
func linkedAgencyName(principal string) (name, path string) {
	return "ServiceLinkedAgencyFor" + strings.TrimPrefix(principal, "service."), "service-linked-agency/" + principal + "/"
}

// PUT /v5/service-linked-agencies
func (s *Service) handleCreateServiceLinkedAgencyV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b struct {
		ServicePrincipal string  `json:"service_principal"`
		Description      *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.ServicePrincipal == "" {
		return errV5Input
	}
	if !servicePrinRE.MatchString(b.ServicePrincipal) {
		return errV5NoPrincipal
	}
	if b.Description != nil && utf8.RuneCountInString(*b.Description) > maxAgencyDesc {
		return errV5Input
	}
	name, path := linkedAgencyName(b.ServicePrincipal)
	trust, _ := json.Marshal(map[string]any{
		"Version": policydoc.Version5,
		"Statement": []map[string]any{{
			"Effect": "Allow", "Action": []string{"sts:agencies:assume"},
			"Principal": map[string][]string{policydoc.PrincipalService: {b.ServicePrincipal}},
		}},
	})
	a := agency{
		ID: s.ids.Hex32(), Name: name, Path: path, TrustPolicy: string(trust), MaxSession: minSessionDuration,
		ServicePrincipal: b.ServicePrincipal, CreatedAt: s.now().UTC(),
	}
	if b.Description != nil {
		a.Description = *b.Description
	}
	if err := s.createV5Agency(ctx, a); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, map[string]v5AgencyView{"agency": s.v5AgencyView(ctx, a)})
}

// DELETE /v5/service-linked-agencies/{agency_id}: WeiStack deletes at
// once, and the task it answers with has succeeded.
func (s *Service) handleDeleteServiceLinkedAgencyV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.agencies(ctx).Get(ctx, chi.URLParam(r, "agency_id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && a.ServicePrincipal == "" {
		return errV5NoLinked
	}
	if err != nil {
		return err
	}
	if err := s.deleteAgency(ctx, a.ID); err != nil {
		return err
	}
	task := deletionTask{ID: s.ids.Hex32(), AgencyID: a.ID, CreatedAt: s.now().UTC()}
	if err := s.deletionTasks(ctx).Create(ctx, task.ID, task); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, map[string]string{"deletion_task_id": task.ID})
}

// GET /v5/service-linked-agencies/deletion-task/{deletion_task_id}
func (s *Service) handleGetDeletionTaskV5(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if _, err := s.deletionTasks(ctx).Get(ctx, chi.URLParam(r, "deletion_task_id")); errors.Is(err, store.ErrNotFound) {
		return errV5NoTask
	} else if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "succeeded"})
}
