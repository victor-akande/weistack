package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Role assignments: classic IAM grants a role to a user group for the
// account's global services (the domain), for one region's project, or
// for all projects, and to a group or a user for an enterprise project.

const kindAssignment = "iam.assignment"

// Assignment scopes.
const (
	scopeDomain    = "domain"
	scopeProject   = "project"
	scopeInherited = "inherited" // all projects, now and future
	scopeEP        = "enterprise_project"
)

// Subjects.
const (
	subjectGroup = "group"
	subjectUser  = "user"
)

// defaultEP is the ID of the default enterprise project, the only one
// WeiStack has.
const defaultEP = "0"

// assignment grants a role to a subject in a scope. Its ID is derived
// from those, so granting twice is one assignment.
type assignment struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	SubjectID string    `json:"subject_id"`
	RoleID    string    `json:"role_id"`
	Scope     string    `json:"scope"`
	ScopeID   string    `json:"scope_id"`
	CreatedAt time.Time `json:"created_at"`
}

func assignmentID(subject, subjectID, roleID, scope, scopeID string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + subjectID + "\x00" + roleID + "\x00" + scope + "\x00" + scopeID))
	return hex.EncodeToString(sum[:16])
}

func (s *Service) assignments() store.Collection[assignment] {
	return store.Of[assignment](s.store, global(kindAssignment))
}

func (s *Service) assignmentsOf(ctx context.Context, keep func(assignment) bool) ([]assignment, error) {
	return s.assignments().List(ctx, keep)
}

// deleteAssignments removes those keep selects. The caller holds s.mu.
func (s *Service) deleteAssignments(ctx context.Context, keep func(assignment) bool) error {
	all, err := s.assignmentsOf(ctx, keep)
	if err != nil {
		return err
	}
	for _, a := range all {
		if err := s.assignments().Delete(ctx, a.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// grantTarget is what a grant, check, revoke or list names in its path.
type grantTarget struct {
	subject, subjectID, scope, scopeID string
}

func (t grantTarget) matches(a assignment) bool {
	return a.Subject == t.subject && a.SubjectID == t.subjectID && a.Scope == t.scope && a.ScopeID == t.scopeID
}

// target reads and checks the subject and scope in the path: each must
// exist, or IAM.0004 names it.
func (s *Service) target(r *http.Request, subject, scope string) (grantTarget, error) {
	ctx := r.Context()
	t := grantTarget{subject: subject, scope: scope}
	switch scope {
	case scopeDomain, scopeInherited:
		t.scopeID = chi.URLParam(r, "domain_id")
		if t.scopeID != s.account().ID {
			return t, errNotFound("domain", t.scopeID)
		}
	case scopeProject:
		t.scopeID = chi.URLParam(r, "project_id")
		if _, err := s.projects().Get(ctx, t.scopeID); errors.Is(err, store.ErrNotFound) {
			return t, errNotFound("project", t.scopeID)
		} else if err != nil {
			return t, err
		}
	case scopeEP:
		t.scopeID = chi.URLParam(r, "enterprise_project_id")
		if t.scopeID != defaultEP {
			return t, errNotFound("enterprise project", t.scopeID)
		}
	}
	switch subject {
	case subjectGroup:
		t.subjectID = chi.URLParam(r, "group_id")
		if _, err := s.groups().Get(ctx, t.subjectID); errors.Is(err, store.ErrNotFound) {
			return t, errNotFound("group", t.subjectID)
		} else if err != nil {
			return t, err
		}
	case subjectUser:
		t.subjectID = chi.URLParam(r, "user_id")
		if _, err := s.users().Get(ctx, t.subjectID); errors.Is(err, store.ErrNotFound) {
			return t, errNotFound("user", t.subjectID)
		} else if err != nil {
			return t, err
		}
	}
	return t, nil
}

// grant answers PUT: 204, also when the role is already granted.
func (s *Service) grant(subject, scope string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		// Under s.mu, so a grant cannot race the delete of its subject
		// or its custom role.
		s.mu.Lock()
		defer s.mu.Unlock()
		t, err := s.target(r, subject, scope)
		if err != nil {
			return err
		}
		ro, err := s.getRole(r)
		if err != nil {
			return err
		}
		a := assignment{
			ID: assignmentID(t.subject, t.subjectID, ro.ID, t.scope, t.scopeID), Subject: t.subject,
			SubjectID: t.subjectID, RoleID: ro.ID, Scope: t.scope, ScopeID: t.scopeID, CreatedAt: s.now().UTC(),
		}
		if err := s.assignments().Create(r.Context(), a.ID, a); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// granted finds the assignment a HEAD or DELETE names, or IAM.0004.
func (s *Service) granted(r *http.Request, subject, scope string) (assignment, error) {
	t, err := s.target(r, subject, scope)
	if err != nil {
		return assignment{}, err
	}
	roleID := chi.URLParam(r, "role_id")
	a, err := s.assignments().Get(r.Context(), assignmentID(t.subject, t.subjectID, roleID, t.scope, t.scopeID))
	if errors.Is(err, store.ErrNotFound) {
		return assignment{}, errNotFound("role assignment", roleID)
	}
	return a, err
}

// check answers HEAD: 204 if granted.
func (s *Service) check(subject, scope string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if _, err := s.granted(r, subject, scope); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// revoke answers DELETE: 204.
func (s *Service) revoke(subject, scope string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		a, err := s.granted(r, subject, scope)
		if err != nil {
			return err
		}
		if err := s.assignments().Delete(r.Context(), a.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// rolesOf resolves the roles of assignments, skipping any whose role is
// gone.
func (s *Service) rolesOf(ctx context.Context, as []assignment) ([]role, error) {
	out := make([]role, 0, len(as))
	seen := map[string]bool{}
	for _, a := range as {
		if seen[a.RoleID] {
			continue
		}
		seen[a.RoleID] = true
		ro, ok, err := s.findRole(ctx, a.RoleID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ro)
		}
	}
	return out, nil
}

// listGranted answers GET on a subject's roles in a scope.
func (s *Service) listGranted(subject, scope string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		t, err := s.target(r, subject, scope)
		if err != nil {
			return err
		}
		as, err := s.assignmentsOf(r.Context(), t.matches)
		if err != nil {
			return err
		}
		roles, err := s.rolesOf(r.Context(), as)
		if err != nil {
			return err
		}
		if scope == scopeEP {
			out := struct {
				Roles []roleView `json:"roles"`
			}{make([]roleView, 0, len(roles))}
			for _, ro := range roles {
				out.Roles = append(out.Roles, s.roleView(r, ro))
			}
			return httpx.WriteJSON(w, http.StatusOK, out)
		}
		out := struct {
			Roles []roleView `json:"roles"`
			Links links      `json:"links"`
		}{make([]roleView, 0, len(roles)), links{Self: selfURL(r, r.URL.Path)}}
		for _, ro := range roles {
			out.Roles = append(out.Roles, s.roleView(r, ro))
		}
		return httpx.WriteJSON(w, http.StatusOK, out)
	}
}

// Enterprise project queries.

type epRef struct {
	ProjectID string `json:"projectId"`
}

type epRefs struct {
	EnterpriseProjects []epRef `json:"enterprise-projects"`
}

// GET /v3.0/OS-PERMISSION/{users,groups}/{id}/enterprise-projects: the
// enterprise projects the subject has roles in.
func (s *Service) listEPsOf(subject string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		t, err := s.target(r, subject, "")
		if err != nil {
			return err
		}
		as, err := s.assignmentsOf(r.Context(), func(a assignment) bool {
			return a.Scope == scopeEP && a.Subject == t.subject && a.SubjectID == t.subjectID
		})
		if err != nil {
			return err
		}
		out := epRefs{EnterpriseProjects: []epRef{}}
		for _, a := range as {
			if !slices.ContainsFunc(out.EnterpriseProjects, func(e epRef) bool { return e.ProjectID == a.ScopeID }) {
				out.EnterpriseProjects = append(out.EnterpriseProjects, epRef{a.ScopeID})
			}
		}
		return httpx.WriteJSON(w, http.StatusOK, out)
	}
}

// epSubjects returns, for an enterprise project, the IDs of the subjects
// with roles in it, each with its assignments, in order of first grant.
func (s *Service) epSubjects(r *http.Request, subject string) ([]string, map[string][]assignment, error) {
	ep := chi.URLParam(r, "enterprise_project_id")
	if ep != defaultEP {
		return nil, nil, errNotFound("enterprise project", ep)
	}
	as, err := s.assignmentsOf(r.Context(), func(a assignment) bool {
		return a.Scope == scopeEP && a.ScopeID == ep && a.Subject == subject
	})
	if err != nil {
		return nil, nil, err
	}
	slices.SortStableFunc(as, func(a, b assignment) int { return a.CreatedAt.Compare(b.CreatedAt) })
	var ids []string
	by := map[string][]assignment{}
	for _, a := range as {
		if by[a.SubjectID] == nil {
			ids = append(ids, a.SubjectID)
		}
		by[a.SubjectID] = append(by[a.SubjectID], a)
	}
	return ids, by, nil
}

// GET /v3.0/OS-PERMISSION/enterprise-projects/{ep}/users.
func (s *Service) handleListEPUsers(w http.ResponseWriter, r *http.Request) error {
	ids, by, err := s.epSubjects(r, subjectUser)
	if err != nil {
		return err
	}
	type epUser struct {
		DomainID         string `json:"domain_id"`
		ID               string `json:"id"`
		Name             string `json:"name"`
		Enabled          bool   `json:"enabled"`
		Description      string `json:"description"`
		PolicyNum        int    `json:"policy_num"`
		LatestPolicyTime int64  `json:"lastest_policy_time"`
	}
	out := struct {
		Users []epUser `json:"users"`
	}{[]epUser{}}
	for _, id := range ids {
		u, err := s.users().Get(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		as := by[id]
		out.Users = append(out.Users, epUser{
			DomainID: s.account().ID, ID: u.ID, Name: u.Name, Enabled: u.Enabled, Description: u.Description,
			PolicyNum: len(as), LatestPolicyTime: as[len(as)-1].CreatedAt.UnixMilli(),
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// GET /v3.0/OS-PERMISSION/enterprise-projects/{ep}/groups.
func (s *Service) handleListEPGroups(w http.ResponseWriter, r *http.Request) error {
	ids, _, err := s.epSubjects(r, subjectGroup)
	if err != nil {
		return err
	}
	type epGroup struct {
		CreateTime  int64   `json:"createTime"`
		Description *string `json:"description"`
		DomainID    string  `json:"domainId"`
		ID          string  `json:"id"`
		Name        string  `json:"name"`
	}
	out := struct {
		Groups []epGroup `json:"groups"`
	}{[]epGroup{}}
	for _, id := range ids {
		g, err := s.groups().Get(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		v := epGroup{CreateTime: g.CreatedAt.UnixMilli(), DomainID: s.account().ID, ID: g.ID, Name: g.Name}
		if g.Description != "" {
			v.Description = &g.Description
		}
		out.Groups = append(out.Groups, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// GET /v3.0/OS-PERMISSION/role-assignments.

type idRef struct {
	ID string `json:"id"`
}

type assignmentScopeView struct {
	Project           *idRef `json:"project,omitempty"`
	Domain            *idRef `json:"domain,omitempty"`
	EnterpriseProject *idRef `json:"enterprise_project,omitempty"`
}

// assignmentView mirrors the SDK model RoleAssignmentBody.
type assignmentView struct {
	User        *idRef              `json:"user,omitempty"`
	Group       *idRef              `json:"group,omitempty"`
	Role        idRef               `json:"role"`
	Scope       assignmentScopeView `json:"scope"`
	IsInherited bool                `json:"is_inherited"`
}

func viewAssignment(a assignment) assignmentView {
	v := assignmentView{Role: idRef{a.RoleID}, IsInherited: a.Scope == scopeInherited}
	switch a.Subject {
	case subjectUser:
		v.User = &idRef{a.SubjectID}
	case subjectGroup:
		v.Group = &idRef{a.SubjectID}
	}
	switch a.Scope {
	case scopeProject:
		v.Scope.Project = &idRef{a.ScopeID}
	case scopeDomain, scopeInherited:
		v.Scope.Domain = &idRef{a.ScopeID}
	case scopeEP:
		v.Scope.EnterpriseProject = &idRef{a.ScopeID}
	}
	return v
}

// handleListRoleAssignments filters assignment records by role, subject
// and scope, as ShowDomainRoleAssignments documents.
func (s *Service) handleListRoleAssignments(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	page, perPage, err := readPaging(r, 50)
	if err != nil {
		return err
	}
	for _, flag := range []string{"is_inherited", "include_group"} {
		if v := q.Get(flag); v != "" && v != "true" && v != "false" {
			return errInvalidParam(flag)
		}
	}
	subject, subjectID := q.Get("subject"), ""
	for _, kind := range []string{"user", "group", "agency"} {
		if id := q.Get("subject." + kind + "_id"); id != "" {
			subject, subjectID = kind, id
		}
	}
	if subject != "" && subject != subjectUser && subject != subjectGroup && subject != "agency" {
		return errInvalidParam("subject")
	}
	scope, scopeID := q.Get("scope"), ""
	for _, k := range []struct{ param, scope string }{
		{"scope.project_id", scopeProject}, {"scope.domain_id", scopeDomain}, {"scope.enterprise_projects_id", scopeEP},
	} {
		if id := q.Get(k.param); id != "" {
			scope, scopeID = k.scope, id
		}
	}
	if scope != "" && scope != scopeProject && scope != scopeDomain && scope != scopeEP {
		return errInvalidParam("scope")
	}
	inherited := q.Get("is_inherited") == "true"

	// A user's records include those of their groups, unless
	// include_group is false.
	var groupsOfUser []string
	if subject == subjectUser && subjectID != "" && q.Get("include_group") != "false" {
		gs, err := s.groupsOf(r.Context(), subjectID)
		if err != nil {
			return err
		}
		for _, g := range gs {
			groupsOfUser = append(groupsOfUser, g.ID)
		}
	}

	if d := q.Get("domain_id"); d != "" && d != s.account().ID {
		return httpx.WriteJSON(w, http.StatusOK, assignmentsResponse{RoleAssignments: []assignmentView{}})
	}
	keep := func(a assignment) bool {
		if role := q.Get("role_id"); role != "" && a.RoleID != role {
			return false
		}
		direct := a.Subject == subject && (subjectID == "" || a.SubjectID == subjectID)
		viaGroup := a.Subject == subjectGroup && slices.Contains(groupsOfUser, a.SubjectID)
		if subject != "" && !direct && !viaGroup {
			return false
		}
		switch scope {
		case "":
		case scopeDomain:
			want := scopeDomain
			if inherited {
				want = scopeInherited
			}
			if a.Scope != want || scopeID != "" && a.ScopeID != scopeID {
				return false
			}
		default:
			if a.Scope != scope || scopeID != "" && a.ScopeID != scopeID {
				return false
			}
		}
		return true
	}
	all, err := s.assignmentsOf(r.Context(), keep)
	if err != nil {
		return err
	}
	got := pageOf(all, page, perPage)
	out := assignmentsResponse{RoleAssignments: make([]assignmentView, 0, len(got)), TotalNum: len(all)}
	for _, a := range got {
		out.RoleAssignments = append(out.RoleAssignments, viewAssignment(a))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

type assignmentsResponse struct {
	RoleAssignments []assignmentView `json:"role_assignments"`
	TotalNum        int              `json:"total_num"`
}

// effectiveRoles returns the roles a user holds, through their groups, in
// a project (including all-projects grants) or, with projectID empty, in
// the domain. Tokens list them.
func (s *Service) effectiveRoles(ctx context.Context, userID, projectID string) ([]role, error) {
	gs, err := s.groupsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(gs))
	for _, g := range gs {
		ids = append(ids, g.ID)
	}
	as, err := s.assignmentsOf(ctx, func(a assignment) bool {
		if a.Subject != subjectGroup || !slices.Contains(ids, a.SubjectID) {
			return false
		}
		if projectID == "" {
			return a.Scope == scopeDomain
		}
		return a.Scope == scopeInherited || a.Scope == scopeProject && a.ScopeID == projectID
	})
	if err != nil {
		return nil, err
	}
	return s.rolesOf(ctx, as)
}

// projectsOf returns the IDs of the projects a user has roles in, through
// their groups; all reports an all-projects grant.
func (s *Service) projectsOf(ctx context.Context, userID string) (ids []string, all bool, err error) {
	gs, err := s.groupsOf(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	groupIDs := make([]string, 0, len(gs))
	for _, g := range gs {
		groupIDs = append(groupIDs, g.ID)
	}
	as, err := s.assignmentsOf(ctx, func(a assignment) bool {
		return a.Subject == subjectGroup && slices.Contains(groupIDs, a.SubjectID)
	})
	if err != nil {
		return nil, false, err
	}
	for _, a := range as {
		switch {
		case a.Scope == scopeInherited:
			all = true
		case a.Scope == scopeProject && !slices.Contains(ids, a.ScopeID):
			ids = append(ids, a.ScopeID)
		}
	}
	return ids, all, nil
}

// roleRoutes registers the permission operations.
func (s *Service) roleRoutes(r chi.Router) {
	r.Get("/v3/roles", s.handle("KeystoneListPermissions", s.handleListRoles))
	r.Get("/v3/roles/{role_id}", s.handle("KeystoneShowPermission", s.handleShowRole))

	r.Post("/v3.0/OS-ROLE/roles", s.handle("CreateCloudServiceCustomPolicy", s.handleCreateCustomRole))
	r.Get("/v3.0/OS-ROLE/roles", s.handle("ListCustomPolicies", s.handleListCustomRoles))
	r.Get("/v3.0/OS-ROLE/roles/{role_id}", s.handle("ShowCustomPolicy", s.handleShowCustomRole))
	r.Patch("/v3.0/OS-ROLE/roles/{role_id}", s.handle("UpdateCloudServiceCustomPolicy", s.handleUpdateCustomRole))
	r.Delete("/v3.0/OS-ROLE/roles/{role_id}", s.handle("DeleteCustomPolicy", s.handleDeleteCustomRole))

	type scoped struct {
		prefix, scope, op string
	}
	for _, sc := range []scoped{
		{"/v3/domains/{domain_id}/groups/{group_id}/roles", scopeDomain, "Domain"},
		{"/v3/projects/{project_id}/groups/{group_id}/roles", scopeProject, "Project"},
	} {
		r.Get(sc.prefix, s.handle("KeystoneList"+sc.op+"PermissionsForGroup", s.listGranted(subjectGroup, sc.scope)))
		r.Put(sc.prefix+"/{role_id}", s.handle("KeystoneAssociateGroupWith"+sc.op+"Permission", s.grant(subjectGroup, sc.scope)))
		r.Head(sc.prefix+"/{role_id}", s.handle("KeystoneCheck"+sc.op+"PermissionForGroup", s.check(subjectGroup, sc.scope)))
		r.Delete(sc.prefix+"/{role_id}", s.handle("KeystoneRemove"+sc.op+"PermissionFromGroup", s.revoke(subjectGroup, sc.scope)))
	}
	const inherited = "/v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles"
	r.Get(inherited+"/inherited_to_projects", s.handle("KeystoneListAllProjectPermissionsForGroup", s.listGranted(subjectGroup, scopeInherited)))
	r.Put(inherited+"/{role_id}/inherited_to_projects", s.handle("UpdateDomainGroupInheritRole", s.grant(subjectGroup, scopeInherited)))
	r.Head(inherited+"/{role_id}/inherited_to_projects", s.handle("KeystoneCheckroleForGroup", s.check(subjectGroup, scopeInherited)))
	r.Delete(inherited+"/{role_id}/inherited_to_projects", s.handle("DeleteDomainGroupInheritedRole", s.revoke(subjectGroup, scopeInherited)))

	const ep = "/v3.0/OS-PERMISSION/enterprise-projects/{enterprise_project_id}"
	r.Get(ep+"/groups/{group_id}/roles", s.handle("ListRolesForGroupOnEnterpriseProject", s.listGranted(subjectGroup, scopeEP)))
	r.Put(ep+"/groups/{group_id}/roles/{role_id}", s.handle("AssociateRoleToGroupOnEnterpriseProject", s.grant(subjectGroup, scopeEP)))
	r.Delete(ep+"/groups/{group_id}/roles/{role_id}", s.handle("RevokeRoleFromGroupOnEnterpriseProject", s.revoke(subjectGroup, scopeEP)))
	r.Get(ep+"/users/{user_id}/roles", s.handle("ListRolesForUserOnEnterpriseProject", s.listGranted(subjectUser, scopeEP)))
	r.Put(ep+"/users/{user_id}/roles/{role_id}", s.handle("AssociateRoleToUserOnEnterpriseProject", s.grant(subjectUser, scopeEP)))
	r.Delete(ep+"/users/{user_id}/roles/{role_id}", s.handle("RevokeRoleFromUserOnEnterpriseProject", s.revoke(subjectUser, scopeEP)))
	r.Get(ep+"/groups", s.handle("ListGroupsForEnterpriseProject", s.handleListEPGroups))
	r.Get(ep+"/users", s.handle("ListUsersForEnterpriseProject", s.handleListEPUsers))
	r.Get("/v3.0/OS-PERMISSION/groups/{group_id}/enterprise-projects", s.handle("ListEnterpriseProjectsForGroup", s.listEPsOf(subjectGroup)))
	r.Get("/v3.0/OS-PERMISSION/users/{user_id}/enterprise-projects", s.handle("ListEnterpriseProjectsForUser", s.listEPsOf(subjectUser)))
	r.Get("/v3.0/OS-PERMISSION/role-assignments", s.handle("ShowDomainRoleAssignments", s.handleListRoleAssignments))
}
