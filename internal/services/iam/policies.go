package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// IAM 5.0 identity policies (/v5/policies): custom policies with up to
// five versions, attached to users and groups.

const (
	kindPolicy       = "iam.policy"
	kindPolicyAttach = "iam.policy-attachment"
)

// IAM 5.0's quotas (productdesc-iam5/iam_01_1135).
const (
	maxPolicies           = 1500
	maxPolicyVersions     = 5
	maxPolicyBytes        = 6144
	maxPoliciesPerSubject = 10
)

// policy is a custom identity policy. Versions are newest first, as
// ListPolicyVersionsV5 returns them.
type policy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	Description string          `json:"description,omitempty"`
	Versions    []policyVersion `json:"versions"`
	// LastVersion numbers versions: v1, v2 and so on, never reused.
	LastVersion int       `json:"last_version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type policyVersion struct {
	ID        string    `json:"id"`
	Document  string    `json:"document"`
	Default   bool      `json:"default"`
	CreatedAt time.Time `json:"created_at"`
}

func (p policy) defaultVersion() policyVersion {
	for _, v := range p.Versions {
		if v.Default {
			return v
		}
	}
	return policyVersion{}
}

// addVersion adds a version as the newest, the default if def.
func (p *policy) addVersion(doc string, def bool, now time.Time) policyVersion {
	p.LastVersion++
	v := policyVersion{ID: "v" + strconv.Itoa(p.LastVersion), Document: doc, Default: def, CreatedAt: now}
	if def {
		for i := range p.Versions {
			p.Versions[i].Default = false
		}
	}
	p.Versions = append([]policyVersion{v}, p.Versions...)
	p.UpdatedAt = now
	return v
}

// policyAttachment attaches a policy to a user or a group. Its ID is
// derived from the three, so attaching twice finds the first.
type policyAttachment struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	Subject    string    `json:"subject"`
	SubjectID  string    `json:"subject_id"`
	AttachedAt time.Time `json:"attached_at"`
}

func attachmentID(policyID, subject, subjectID string) string {
	sum := sha256.Sum256([]byte(policyID + "\x00" + subject + "\x00" + subjectID))
	return hex.EncodeToString(sum[:16])
}

func (s *Service) policies() store.Collection[policy] {
	return store.Of[policy](s.store, global(kindPolicy))
}

func (s *Service) policyAttachments() store.Collection[policyAttachment] {
	return store.Of[policyAttachment](s.store, global(kindPolicyAttach))
}

func (s *Service) attachmentsWhere(ctx context.Context, keep func(policyAttachment) bool) ([]policyAttachment, error) {
	all, err := s.policyAttachments().List(ctx, keep)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(all, func(a, b policyAttachment) int { return a.AttachedAt.Compare(b.AttachedAt) })
	return all, nil
}

// detachAll removes the attachments keep selects. The caller holds s.mu.
func (s *Service) detachAll(ctx context.Context, keep func(policyAttachment) bool) error {
	all, err := s.attachmentsWhere(ctx, keep)
	if err != nil {
		return err
	}
	for _, a := range all {
		if err := s.policyAttachments().Delete(ctx, a.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// Validation, from the IAM 5.0 API reference.
var (
	policyNameRE = regexp.MustCompile(`^[A-Za-z0-9_+=.@-]+$`)
	policyPathRE = regexp.MustCompile(`^([A-Za-z0-9.,+@=_-]+/)*$`)
)

const (
	maxPolicyName = 128
	maxPolicyPath = 512
	maxPolicyDesc = 1000
)

func validPolicyName(n string) bool { return len(n) <= maxPolicyName && policyNameRE.MatchString(n) }

func validPolicyPath(p string) bool { return len(p) <= maxPolicyPath && policyPathRE.MatchString(p) }

func validPolicyDescription(d string) bool { return utf8.RuneCountInString(d) <= maxPolicyDesc }

// checkDocument validates a policy document against IAM 5.0's grammar:
// Version "5.0" and a Statement list, each statement with an optional
// Sid, an Effect of Allow or Deny, an Action or NotAction list, an
// optional Resource or NotResource list and an optional Condition map.
// It returns PAP5.0011 for a malformed document and PAP5.0027 for one
// over 6,144 bytes.
func checkDocument(doc string) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(doc)); err != nil {
		return errV5Malformed
	}
	if compact.Len() > maxPolicyBytes {
		return errV5PolicySize
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &top); err != nil || len(top) != 2 {
		return errV5Malformed
	}
	var version string
	if json.Unmarshal(top["Version"], &version) != nil || version != "5.0" {
		return errV5Malformed
	}
	var statements []map[string]json.RawMessage
	if json.Unmarshal(top["Statement"], &statements) != nil || len(statements) == 0 {
		return errV5Malformed
	}
	for _, st := range statements {
		if !validStatement(st) {
			return errV5Malformed
		}
	}
	return nil
}

func validStatement(st map[string]json.RawMessage) bool {
	allowed := map[string]bool{
		"Sid": true, "Effect": true, "Action": true, "NotAction": true,
		"Resource": true, "NotResource": true, "Condition": true,
	}
	for k := range st {
		if !allowed[k] {
			return false
		}
	}
	var str string
	if raw, ok := st["Sid"]; ok && json.Unmarshal(raw, &str) != nil {
		return false
	}
	if json.Unmarshal(st["Effect"], &str) != nil || str != "Allow" && str != "Deny" {
		return false
	}
	// Exactly one of Action and NotAction; at most one of Resource and
	// NotResource.
	if !oneStringList(st, "Action", "NotAction", true) || !oneStringList(st, "Resource", "NotResource", false) {
		return false
	}
	if raw, ok := st["Condition"]; ok {
		var cond map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &cond) != nil {
			return false
		}
		for _, keys := range cond {
			for _, v := range keys {
				var one string
				var many []string
				if json.Unmarshal(v, &one) != nil && json.Unmarshal(v, &many) != nil {
					return false
				}
			}
		}
	}
	return true
}

// oneStringList checks that at most one of a and b is present (exactly
// one if required) and that it is a non-empty list of non-empty strings.
func oneStringList(st map[string]json.RawMessage, a, b string, required bool) bool {
	rawA, okA := st[a]
	rawB, okB := st[b]
	switch {
	case okA && okB:
		return false
	case !okA && !okB:
		return !required
	}
	raw := rawA
	if okB {
		raw = rawB
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return false
	}
	return !slices.Contains(list, "")
}

// Views.

// v5PolicyView mirrors the SDK model iam/v5 Policy.
type v5PolicyView struct {
	PolicyType       string `json:"policy_type"`
	PolicyName       string `json:"policy_name"`
	PolicyID         string `json:"policy_id"`
	URN              string `json:"urn"`
	Path             string `json:"path"`
	DefaultVersionID string `json:"default_version_id"`
	AttachmentCount  int    `json:"attachment_count"`
	Description      string `json:"description"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// policyURN is iam::<account>:policy:<path><name>, as Huawei documents.
func (s *Service) policyURN(p policy) string { return s.urn("policy", p.Path+p.Name) }

func (s *Service) v5Policy(ctx context.Context, p policy) (v5PolicyView, error) {
	attached, err := s.attachmentsWhere(ctx, func(a policyAttachment) bool { return a.PolicyID == p.ID })
	if err != nil {
		return v5PolicyView{}, err
	}
	return v5PolicyView{
		PolicyType: "custom", PolicyName: p.Name, PolicyID: p.ID, URN: s.policyURN(p), Path: p.Path,
		DefaultVersionID: p.defaultVersion().ID, AttachmentCount: len(attached), Description: p.Description,
		CreatedAt: v5At(p.CreatedAt), UpdatedAt: v5At(p.UpdatedAt),
	}, nil
}

// v5VersionView mirrors the SDK model iam/v5 PolicyVersion.
type v5VersionView struct {
	Document  string `json:"document"`
	VersionID string `json:"version_id"`
	IsDefault bool   `json:"is_default"`
	CreatedAt string `json:"created_at"`
}

func v5Version(v policyVersion) v5VersionView {
	return v5VersionView{Document: v.Document, VersionID: v.ID, IsDefault: v.Default, CreatedAt: v5At(v.CreatedAt)}
}

type v5PolicyResponse struct {
	Policy v5PolicyView `json:"policy"`
}

type v5VersionResponse struct {
	PolicyVersion v5VersionView `json:"policy_version"`
}

func (s *Service) getPolicy(r *http.Request) (policy, error) {
	p, err := s.policies().Get(r.Context(), chi.URLParam(r, "policy_id"))
	if errors.Is(err, store.ErrNotFound) {
		return policy{}, errV5NoPolicy
	}
	return p, err
}

// Policies.

// POST /v5/policies.
func (s *Service) handleCreatePolicyV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		PolicyName     *string `json:"policy_name"`
		Path           *string `json:"path"`
		PolicyDocument *string `json:"policy_document"`
		Description    *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	switch {
	case b.PolicyName == nil || !validPolicyName(*b.PolicyName), b.PolicyDocument == nil,
		b.Description != nil && !validPolicyDescription(*b.Description):
		return errV5Input
	case b.Path != nil && !validPolicyPath(*b.Path):
		return errV5Path
	}
	if err := checkDocument(*b.PolicyDocument); err != nil {
		return err
	}
	now := s.now().UTC()
	p := policy{ID: s.ids.UUID(), Name: *b.PolicyName, Path: deref(b.Path), Description: deref(b.Description), CreatedAt: now}
	p.addVersion(*b.PolicyDocument, true, now)

	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.policies().List(r.Context(), nil)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(all, func(o policy) bool { return o.Name == p.Name }) {
		return errV5PolicyExists
	}
	if len(all) >= maxPolicies {
		return errV5TooManyPolicies
	}
	if err := s.policies().Create(r.Context(), p.ID, p); err != nil {
		return err
	}
	v, err := s.v5Policy(r.Context(), p)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, v5PolicyResponse{v})
}

// GET /v5/policies. Only custom policies are emulated, so policy_type
// system lists none.
func (s *Service) handleListPoliciesV5(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	typ := q.Get("policy_type")
	if typ != "" && typ != "custom" && typ != "system" {
		return errV5Input
	}
	only := q.Get("only_attached")
	if only != "" && only != "true" && only != "false" {
		return errV5Input
	}
	prefix := q.Get("path_prefix")
	if !validPolicyPath(prefix) {
		return errV5Path
	}
	all, err := s.policies().List(r.Context(), func(p policy) bool {
		return typ != "system" && strings.HasPrefix(p.Path, prefix)
	})
	if err != nil {
		return err
	}
	views := make([]v5PolicyView, 0, len(all))
	for _, p := range all {
		v, err := s.v5Policy(r.Context(), p)
		if err != nil {
			return err
		}
		if only != "true" || v.AttachmentCount > 0 {
			views = append(views, v)
		}
	}
	got, info, err := page(r, views, func(v v5PolicyView) string { return v.PolicyID })
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Policies []v5PolicyView `json:"policies"`
		PageInfo pageInfo       `json:"page_info"`
	}{got, info})
}

// GET /v5/policies/{policy_id}.
func (s *Service) handleGetPolicyV5(w http.ResponseWriter, r *http.Request) error {
	p, err := s.getPolicy(r)
	if err != nil {
		return err
	}
	v, err := s.v5Policy(r.Context(), p)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v5PolicyResponse{v})
}

// PUT /v5/policies/{policy_id}: the description only. Huawei answers 204.
func (s *Service) handleUpdatePolicyV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Description *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.Description == nil || !validPolicyDescription(*b.Description) {
		return errV5Input
	}
	now := s.now().UTC()
	_, err := s.policies().Update(r.Context(), chi.URLParam(r, "policy_id"), func(p *policy) error {
		p.Description, p.UpdatedAt = *b.Description, now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errV5NoPolicy
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// DELETE /v5/policies/{policy_id}: refused while it is attached.
func (s *Service) handleDeletePolicyV5(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.getPolicy(r)
	if err != nil {
		return err
	}
	attached, err := s.attachmentsWhere(r.Context(), func(a policyAttachment) bool { return a.PolicyID == p.ID })
	if err != nil {
		return err
	}
	if len(attached) > 0 {
		return errV5DeleteConflict("the policy is attached to " + strconv.Itoa(len(attached)) + " entities")
	}
	if err := s.policies().Delete(r.Context(), p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Versions.

// POST /v5/policies/{policy_id}/versions.
func (s *Service) handleCreatePolicyVersionV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		PolicyDocument *string `json:"policy_document"`
		SetAsDefault   *bool   `json:"set_as_default"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.PolicyDocument == nil {
		return errV5Input
	}
	if err := checkDocument(*b.PolicyDocument); err != nil {
		return err
	}
	now := s.now().UTC()
	var created policyVersion
	_, err := s.policies().Update(r.Context(), chi.URLParam(r, "policy_id"), func(p *policy) error {
		if len(p.Versions) >= maxPolicyVersions {
			return errV5TooManyVersions
		}
		created = p.addVersion(*b.PolicyDocument, b.SetAsDefault != nil && *b.SetAsDefault, now)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errV5NoPolicy
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, v5VersionResponse{v5Version(created)})
}

// GET /v5/policies/{policy_id}/versions, newest first.
func (s *Service) handleListPolicyVersionsV5(w http.ResponseWriter, r *http.Request) error {
	p, err := s.getPolicy(r)
	if err != nil {
		return err
	}
	got, info, err := page(r, p.Versions, func(v policyVersion) string { return v.ID })
	if err != nil {
		return err
	}
	out := struct {
		Versions []v5VersionView `json:"versions"`
		PageInfo pageInfo        `json:"page_info"`
	}{make([]v5VersionView, 0, len(got)), info}
	for _, v := range got {
		out.Versions = append(out.Versions, v5Version(v))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func versionIndex(p policy, id string) int {
	return slices.IndexFunc(p.Versions, func(v policyVersion) bool { return v.ID == id })
}

// GET /v5/policies/{policy_id}/versions/{version_id}.
func (s *Service) handleGetPolicyVersionV5(w http.ResponseWriter, r *http.Request) error {
	p, err := s.getPolicy(r)
	if err != nil {
		return err
	}
	i := versionIndex(p, chi.URLParam(r, "version_id"))
	if i < 0 {
		return errV5NoVersion
	}
	return httpx.WriteJSON(w, http.StatusOK, v5VersionResponse{v5Version(p.Versions[i])})
}

// DELETE /v5/policies/{policy_id}/versions/{version_id}: not the default.
func (s *Service) handleDeletePolicyVersionV5(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "version_id")
	_, err := s.policies().Update(r.Context(), chi.URLParam(r, "policy_id"), func(p *policy) error {
		i := versionIndex(*p, id)
		switch {
		case i < 0:
			return errV5NoVersion
		case p.Versions[i].Default:
			return errV5DeleteConflict("the default version cannot be deleted")
		}
		p.Versions = slices.Delete(p.Versions, i, i+1)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errV5NoPolicy
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// POST /v5/policies/{policy_id}/versions/{version_id}/set-default.
func (s *Service) handleSetDefaultPolicyVersionV5(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "version_id")
	now := s.now().UTC()
	_, err := s.policies().Update(r.Context(), chi.URLParam(r, "policy_id"), func(p *policy) error {
		i := versionIndex(*p, id)
		if i < 0 {
			return errV5NoVersion
		}
		for j := range p.Versions {
			p.Versions[j].Default = j == i
		}
		p.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errV5NoPolicy
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// Attachments.

// policySubject is how attach, detach and list name a user or a group.
type policySubject struct {
	kind, bodyKey     string
	notFound, tooMany error
}

var (
	policyUser  = policySubject{subjectUser, "user_id", errV5NoUser, errV5UserPolicies}
	policyGroup = policySubject{subjectGroup, "group_id", errV5NoGroup, errV5GroupPolicies}
)

func (s *Service) subjectExists(ctx context.Context, sub policySubject, id string) (bool, error) {
	var err error
	switch sub.kind {
	case subjectUser:
		_, err = s.users().Get(ctx, id)
	case subjectGroup:
		_, err = s.groups().Get(ctx, id)
	}
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// attach answers POST /v5/policies/{policy_id}/attach-user and
// attach-group, and detach the detach- ones: 200, no body.
func (s *Service) attach(sub policySubject, on bool) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		var b map[string]*string
		if err := decodeV5(r, &b); err != nil {
			return err
		}
		id := b[sub.bodyKey]
		if id == nil || *id == "" {
			return errV5Input
		}
		ctx := r.Context()
		s.mu.Lock()
		defer s.mu.Unlock()
		p, err := s.getPolicy(r)
		if err != nil {
			return err
		}
		if ok, err := s.subjectExists(ctx, sub, *id); err != nil || !ok {
			if err == nil {
				err = sub.notFound
			}
			return err
		}
		aid := attachmentID(p.ID, sub.kind, *id)
		if !on {
			err := s.policyAttachments().Delete(ctx, aid)
			if errors.Is(err, store.ErrNotFound) {
				return errV5NoAttachment
			}
			if err != nil {
				return err
			}
			w.WriteHeader(http.StatusOK)
			return nil
		}
		held, err := s.attachmentsWhere(ctx, func(a policyAttachment) bool { return a.Subject == sub.kind && a.SubjectID == *id })
		if err != nil {
			return err
		}
		if slices.ContainsFunc(held, func(a policyAttachment) bool { return a.ID == aid }) {
			return errV5AttachmentExists
		}
		if len(held) >= maxPoliciesPerSubject {
			return sub.tooMany
		}
		a := policyAttachment{ID: aid, PolicyID: p.ID, Subject: sub.kind, SubjectID: *id, AttachedAt: s.now().UTC()}
		if err := s.policyAttachments().Create(ctx, a.ID, a); err != nil {
			return err
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// attachedPolicyView mirrors the SDK model iam/v5 AttachedPolicy.
type attachedPolicyView struct {
	PolicyName string `json:"policy_name"`
	PolicyID   string `json:"policy_id"`
	URN        string `json:"urn"`
	AttachedAt string `json:"attached_at"`
}

// listAttached answers GET /v5/users/{user_id}/attached-policies and
// /v5/groups/{group_id}/attached-policies.
func (s *Service) listAttached(sub policySubject) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		id := chi.URLParam(r, sub.bodyKey)
		if ok, err := s.subjectExists(r.Context(), sub, id); err != nil || !ok {
			if err == nil {
				err = sub.notFound
			}
			return err
		}
		held, err := s.attachmentsWhere(r.Context(), func(a policyAttachment) bool { return a.Subject == sub.kind && a.SubjectID == id })
		if err != nil {
			return err
		}
		views := make([]attachedPolicyView, 0, len(held))
		for _, a := range held {
			p, err := s.policies().Get(r.Context(), a.PolicyID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			views = append(views, attachedPolicyView{PolicyName: p.Name, PolicyID: p.ID, URN: s.policyURN(p), AttachedAt: v5At(a.AttachedAt)})
		}
		got, info, err := page(r, views, func(v attachedPolicyView) string { return v.PolicyID })
		if err != nil {
			return err
		}
		return httpx.WriteJSON(w, http.StatusOK, struct {
			AttachedPolicies []attachedPolicyView `json:"attached_policies"`
			PageInfo         pageInfo             `json:"page_info"`
		}{got, info})
	}
}

// GET /v5/policies/{policy_id}/attached-entities, optionally of one
// entity_type: user, group or agency.
func (s *Service) handleListEntitiesForPolicyV5(w http.ResponseWriter, r *http.Request) error {
	kind := r.URL.Query().Get("entity_type")
	if kind != "" && kind != subjectUser && kind != subjectGroup && kind != "agency" {
		return errV5Input
	}
	p, err := s.getPolicy(r)
	if err != nil {
		return err
	}
	all, err := s.attachmentsWhere(r.Context(), func(a policyAttachment) bool {
		return a.PolicyID == p.ID && (kind == "" || a.Subject == kind)
	})
	if err != nil {
		return err
	}
	got, info, err := page(r, all, func(a policyAttachment) string { return a.ID })
	if err != nil {
		return err
	}
	type userRef struct {
		UserID     string `json:"user_id"`
		AttachedAt string `json:"attached_at"`
	}
	type groupRef struct {
		GroupID    string `json:"group_id"`
		AttachedAt string `json:"attached_at"`
	}
	out := struct {
		PolicyAgencies []struct{} `json:"policy_agencies"`
		PolicyGroups   []groupRef `json:"policy_groups"`
		PolicyUsers    []userRef  `json:"policy_users"`
		PageInfo       pageInfo   `json:"page_info"`
	}{PolicyAgencies: []struct{}{}, PolicyGroups: []groupRef{}, PolicyUsers: []userRef{}, PageInfo: info}
	for _, a := range got {
		switch a.Subject {
		case subjectUser:
			out.PolicyUsers = append(out.PolicyUsers, userRef{a.SubjectID, v5At(a.AttachedAt)})
		case subjectGroup:
			out.PolicyGroups = append(out.PolicyGroups, groupRef{a.SubjectID, v5At(a.AttachedAt)})
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// policyRoutes registers the identity policy operations.
func (s *Service) policyRoutes(r chi.Router) {
	r.Post("/v5/policies", s.handle("CreatePolicyV5", s.handleCreatePolicyV5))
	r.Get("/v5/policies", s.handle("ListPoliciesV5", s.handleListPoliciesV5))
	r.Get("/v5/policies/{policy_id}", s.handle("GetPolicyV5", s.handleGetPolicyV5))
	r.Put("/v5/policies/{policy_id}", s.handle("UpdatePolicyV5", s.handleUpdatePolicyV5))
	r.Delete("/v5/policies/{policy_id}", s.handle("DeletePolicyV5", s.handleDeletePolicyV5))

	r.Post("/v5/policies/{policy_id}/versions", s.handle("CreatePolicyVersionV5", s.handleCreatePolicyVersionV5))
	r.Get("/v5/policies/{policy_id}/versions", s.handle("ListPolicyVersionsV5", s.handleListPolicyVersionsV5))
	r.Get("/v5/policies/{policy_id}/versions/{version_id}", s.handle("GetPolicyVersionV5", s.handleGetPolicyVersionV5))
	r.Delete("/v5/policies/{policy_id}/versions/{version_id}", s.handle("DeletePolicyVersionV5", s.handleDeletePolicyVersionV5))
	r.Post("/v5/policies/{policy_id}/versions/{version_id}/set-default", s.handle("SetDefaultPolicyVersionV5", s.handleSetDefaultPolicyVersionV5))

	r.Post("/v5/policies/{policy_id}/attach-user", s.handle("AttachUserPolicyV5", s.attach(policyUser, true)))
	r.Post("/v5/policies/{policy_id}/detach-user", s.handle("DetachUserPolicyV5", s.attach(policyUser, false)))
	r.Post("/v5/policies/{policy_id}/attach-group", s.handle("AttachGroupPolicyV5", s.attach(policyGroup, true)))
	r.Post("/v5/policies/{policy_id}/detach-group", s.handle("DetachGroupPolicyV5", s.attach(policyGroup, false)))
	r.Get("/v5/policies/{policy_id}/attached-entities", s.handle("ListEntitiesForPolicyV5", s.handleListEntitiesForPolicyV5))
	r.Get("/v5/users/{user_id}/attached-policies", s.handle("ListAttachedUserPoliciesV5", s.listAttached(policyUser)))
	r.Get("/v5/groups/{group_id}/attached-policies", s.handle("ListAttachedGroupPoliciesV5", s.listAttached(policyGroup)))
}

// IAM 5.0's policy codes.
var (
	errV5Malformed        = apierr.New(http.StatusBadRequest, "PAP5.0011", "malformed policy document")
	errV5Path             = apierr.New(http.StatusBadRequest, "PAP5.0030", "invalid path")
	errV5NoPolicy         = apierr.New(http.StatusNotFound, "PAP5.0018", "no such policy")
	errV5NoAttachment     = apierr.New(http.StatusNotFound, "PAP5.0019", "no such policy attachment")
	errV5NoVersion        = apierr.New(http.StatusNotFound, "PAP5.0020", "no such policy version")
	errV5GroupPolicies    = apierr.New(http.StatusConflict, "PAP5.0004", "attached policies per group limit exceeded")
	errV5UserPolicies     = apierr.New(http.StatusConflict, "PAP5.0005", "attached policies per user limit exceeded")
	errV5TooManyPolicies  = apierr.New(http.StatusConflict, "PAP5.0024", "policies limit exceeded")
	errV5PolicyExists     = apierr.New(http.StatusConflict, "PAP5.0025", "policy already exists")
	errV5AttachmentExists = apierr.New(http.StatusConflict, "PAP5.0026", "policy attachment already exists")
	errV5PolicySize       = apierr.New(http.StatusConflict, "PAP5.0027", "policy size limit exceeded")
	errV5TooManyVersions  = apierr.New(http.StatusConflict, "PAP5.0028", "versions per policy limit exceeded")
)
