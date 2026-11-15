package iam

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// IAM's routes, each with the IAM action it needs. The actions are those
// of IAM's action table (usermanual-permissions iam_11_0085), and for
// IAM 5.0 of each operation's API page (api-iam5). Classic IAM's API
// pages say which operations need no permission: signing in, a user's own
// password and contact details, and reading oneself; those are Public or
// SelfOr. A user also manages its own access keys without permission
// (keys.go).

// Classic IAM denies with its documented IAM.0003 "Policy doesn't allow
// %(actions)s to be performed."; IAM 5.0 with PAP5.0001, whose documented
// body carries encoded_authorization_message (api-iam5 ErrorCode).
func classicDenied(d *authz.Denial) *apierr.Error {
	return apierr.New(http.StatusForbidden, "IAM.0003", "%s", d.Message()).WithAuthorizationMessage(d.Encoded)
}

func v5Denied(d *authz.Denial) *apierr.Error {
	return apierr.New(http.StatusForbidden, "PAP5.0001", "access denied: %s", d.Message()).WithAuthorizationMessage(d.Encoded)
}

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "iam", Global: true, Style: apierr.StyleFlat, Deny: classicDenied}))
		s.classicRoutes(r)
		s.roleRoutes(r)
		s.classicAgencyRoutes(r)
	})
	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "iam", Global: true, Style: apierr.StyleFlat, Deny: v5Denied}))
		s.v5Routes(r)
		s.policyRoutes(r)
		s.v5AgencyRoutes(r)
	})
}

func (s *Service) classicRoutes(r chi.Router) {
	act, public := authz.Action, authz.Public
	self := func(name string) func(http.Handler) http.Handler { return authz.SelfOr("user_id", name) }

	r.With(public()).Get("/v3/auth/domains", s.handle("KeystoneListAuthDomains", s.handleListAuthDomains))
	r.With(public()).Get("/v3/auth/projects", s.handle("KeystoneListAuthProjects", s.handleListAuthProjects))
	r.With(act("iam:projects:list")).Get("/v3/projects", s.handle("KeystoneListProjects", s.handleListProjects))
	r.With(public()).Get("/v3/projects/{project_id}", s.handle("KeystoneShowProject", s.handleShowProject))

	r.With(public()).Post("/v3/auth/tokens", s.handle("KeystoneCreateUserToken", s.handleCreateToken))
	// Validating a token names no action in IAM's table: a holder of
	// the token may check it.
	r.With(public()).Get("/v3/auth/tokens", s.handle("KeystoneValidateToken", s.handleValidateToken))

	r.With(act("iam:users:create")).Post("/v3.0/OS-USER/users", s.handle("CreateUser", s.handleCreateUser))
	r.With(self("iam:users:get")).Get("/v3.0/OS-USER/users/{user_id}", s.handle("ShowUser", s.handleShowUser))
	r.With(act("iam:users:update")).Put("/v3.0/OS-USER/users/{user_id}", s.handle("UpdateUser", s.handleUpdateUser))
	r.With(public()).Put("/v3.0/OS-USER/users/{user_id}/info", s.handle("UpdateUserInformation", s.handleUpdateUserInformation))
	r.With(self("iam:users:getLoginProtectSetting")).Get("/v3.0/OS-USER/users/{user_id}/login-protect", s.handle("ShowUserLoginProtect", s.handleShowLoginProtect))
	r.With(act("iam:users:updateLoginProtectSetting")).Put("/v3.0/OS-USER/users/{user_id}/login-protect", s.handle("UpdateLoginProtect", s.handleUpdateLoginProtect))
	r.With(act("iam:users:create")).Post("/v3/users", s.handle("KeystoneCreateUser", s.handleKeystoneCreateUser))
	r.With(act("iam:users:list")).Get("/v3/users", s.handle("KeystoneListUsers", s.handleKeystoneListUsers))
	r.With(self("iam:users:get")).Get("/v3/users/{user_id}", s.handle("KeystoneShowUser", s.handleKeystoneShowUser))
	r.With(act("iam:users:update")).Patch("/v3/users/{user_id}", s.handle("KeystoneUpdateUserByAdmin", s.handleKeystoneUpdateUser))
	r.With(act("iam:users:delete")).Delete("/v3/users/{user_id}", s.handle("KeystoneDeleteUser", s.handleKeystoneDeleteUser))
	r.With(public()).Post("/v3/users/{user_id}/password", s.handle("KeystoneUpdateUserPassword", s.handleChangePassword))
	r.With(self("iam:users:listGroups")).Get("/v3/users/{user_id}/groups", s.handle("KeystoneListGroupsForUser", s.handleListGroupsForUser))
	r.With(self("iam:projects:listForUser")).Get("/v3/users/{user_id}/projects", s.handle("KeystoneListProjectsForUser", s.handleListProjectsForUser))

	r.With(act("iam:groups:create")).Post("/v3/groups", s.handle("KeystoneCreateGroup", s.handleCreateGroup))
	r.With(act("iam:groups:list")).Get("/v3/groups", s.handle("KeystoneListGroups", s.handleListGroups))
	r.With(act("iam:groups:get")).Get("/v3/groups/{group_id}", s.handle("KeystoneShowGroup", s.handleShowGroup))
	r.With(act("iam:groups:update")).Patch("/v3/groups/{group_id}", s.handle("KeystoneUpdateGroup", s.handleUpdateGroup))
	r.With(act("iam:groups:delete")).Delete("/v3/groups/{group_id}", s.handle("KeystoneDeleteGroup", s.handleDeleteGroup))
	r.With(act("iam:groups:listUsers")).Get("/v3/groups/{group_id}/users", s.handle("KeystoneListUsersForGroupByAdmin", s.handleListUsersInGroup))
	r.With(act("iam:groups:addUser")).Put("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneAddUserToGroup", s.handleAddUserToGroup))
	r.With(act("iam:groups:checkUser")).Head("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneCheckUserInGroup", s.handleCheckUserInGroup))
	r.With(act("iam:groups:removeUser")).Delete("/v3/groups/{group_id}/users/{user_id}", s.handle("KeystoneRemoveUserFromGroup", s.handleRemoveUserFromGroup))

	// A user's own keys need no permission, so the handlers check once
	// they know whose key it is.
	r.With(authz.Defer()).Post("/v3.0/OS-CREDENTIAL/credentials", s.handle("CreatePermanentAccessKey", s.handleCreateCredential))
	// Temporary credentials for oneself need no permission; assuming an
	// agency is checked in the handler (iam:tokens:assume).
	r.With(authz.Defer()).Post("/v3.0/OS-CREDENTIAL/securitytokens", s.handle("CreateTemporaryAccessKey", s.handleCreateSecurityToken))
	r.With(authz.Defer()).Get("/v3.0/OS-CREDENTIAL/credentials", s.handle("ListPermanentAccessKeys", s.handleListCredentials))
	r.With(authz.Defer()).Get("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("ShowPermanentAccessKey", s.handleShowCredential))
	r.With(authz.Defer()).Put("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("UpdatePermanentAccessKey", s.handleUpdateCredential))
	r.With(authz.Defer()).Delete("/v3.0/OS-CREDENTIAL/credentials/{access_key}", s.handle("DeletePermanentAccessKey", s.handleDeleteCredential))
}

// roleRoutes registers the classic permission operations.
func (s *Service) roleRoutes(r chi.Router) {
	act := authz.Action
	r.With(act("iam:roles:list")).Get("/v3/roles", s.handle("KeystoneListPermissions", s.handleListRoles))
	r.With(act("iam:roles:get")).Get("/v3/roles/{role_id}", s.handle("KeystoneShowPermission", s.handleShowRole))

	r.With(act("iam:roles:create")).Post("/v3.0/OS-ROLE/roles", s.handle("CreateCloudServiceCustomPolicy", s.handleCreateCustomRole))
	r.With(act("iam:roles:list")).Get("/v3.0/OS-ROLE/roles", s.handle("ListCustomPolicies", s.handleListCustomRoles))
	r.With(act("iam:roles:get")).Get("/v3.0/OS-ROLE/roles/{role_id}", s.handle("ShowCustomPolicy", s.handleShowCustomRole))
	r.With(act("iam:roles:update")).Patch("/v3.0/OS-ROLE/roles/{role_id}", s.handle("UpdateCloudServiceCustomPolicy", s.handleUpdateCustomRole))
	r.With(act("iam:roles:delete")).Delete("/v3.0/OS-ROLE/roles/{role_id}", s.handle("DeleteCustomPolicy", s.handleDeleteCustomRole))

	// Grants to groups, by scope: the actions are named <op>On<Scope>
	// for domains and projects, and plain for all projects.
	type scoped struct {
		prefix, scope, op, action string
	}
	for _, sc := range []scoped{
		{"/v3/domains/{domain_id}/groups/{group_id}/roles", scopeDomain, "Domain", "OnDomain"},
		{"/v3/projects/{project_id}/groups/{group_id}/roles", scopeProject, "Project", "OnProject"},
	} {
		r.With(act("iam:groups:listRoles"+sc.action)).Get(sc.prefix, s.handle("KeystoneList"+sc.op+"PermissionsForGroup", s.listGranted(subjectGroup, sc.scope)))
		r.With(act("iam:groups:grantRole"+sc.action)).Put(sc.prefix+"/{role_id}", s.handle("KeystoneAssociateGroupWith"+sc.op+"Permission", s.grant(subjectGroup, sc.scope)))
		r.With(act("iam:groups:checkRole"+sc.action)).Head(sc.prefix+"/{role_id}", s.handle("KeystoneCheck"+sc.op+"PermissionForGroup", s.check(subjectGroup, sc.scope)))
		r.With(act("iam:groups:revokeRole"+sc.action)).Delete(sc.prefix+"/{role_id}", s.handle("KeystoneRemove"+sc.op+"PermissionFromGroup", s.revoke(subjectGroup, sc.scope)))
	}
	const inherited = "/v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles"
	r.With(act("iam:groups:listRoles")).Get(inherited+"/inherited_to_projects", s.handle("KeystoneListAllProjectPermissionsForGroup", s.listGranted(subjectGroup, scopeInherited)))
	r.With(act("iam:groups:grantRole")).Put(inherited+"/{role_id}/inherited_to_projects", s.handle("UpdateDomainGroupInheritRole", s.grant(subjectGroup, scopeInherited)))
	r.With(act("iam:groups:checkRole")).Head(inherited+"/{role_id}/inherited_to_projects", s.handle("KeystoneCheckroleForGroup", s.check(subjectGroup, scopeInherited)))
	r.With(act("iam:groups:revokeRole")).Delete(inherited+"/{role_id}/inherited_to_projects", s.handle("DeleteDomainGroupInheritedRole", s.revoke(subjectGroup, scopeInherited)))

	const ep = "/v3.0/OS-PERMISSION/enterprise-projects/{enterprise_project_id}"
	r.With(act("iam:groups:listRolesOnEnterpriseProject")).Get(ep+"/groups/{group_id}/roles", s.handle("ListRolesForGroupOnEnterpriseProject", s.listGranted(subjectGroup, scopeEP)))
	r.With(act("iam:groups:grantRoleOnEnterpriseProject")).Put(ep+"/groups/{group_id}/roles/{role_id}", s.handle("AssociateRoleToGroupOnEnterpriseProject", s.grant(subjectGroup, scopeEP)))
	r.With(act("iam:groups:revokeRoleOnEnterpriseProject")).Delete(ep+"/groups/{group_id}/roles/{role_id}", s.handle("RevokeRoleFromGroupOnEnterpriseProject", s.revoke(subjectGroup, scopeEP)))
	r.With(act("iam:users:listRolesOnEnterpriseProject")).Get(ep+"/users/{user_id}/roles", s.handle("ListRolesForUserOnEnterpriseProject", s.listGranted(subjectUser, scopeEP)))
	r.With(act("iam:users:grantRoleOnEnterpriseProject")).Put(ep+"/users/{user_id}/roles/{role_id}", s.handle("AssociateRoleToUserOnEnterpriseProject", s.grant(subjectUser, scopeEP)))
	r.With(act("iam:users:revokeRoleOnEnterpriseProject")).Delete(ep+"/users/{user_id}/roles/{role_id}", s.handle("RevokeRoleFromUserOnEnterpriseProject", s.revoke(subjectUser, scopeEP)))
	r.With(act("iam::listGroupsAssignedEnterpriseProject")).Get(ep+"/groups", s.handle("ListGroupsForEnterpriseProject", s.handleListEPGroups))
	r.With(act("iam::listUsersAssignedEnterpriseProject")).Get(ep+"/users", s.handle("ListUsersForEnterpriseProject", s.handleListEPUsers))
	r.With(act("iam:groups:listAssignedEnterpriseProjects")).Get("/v3.0/OS-PERMISSION/groups/{group_id}/enterprise-projects", s.handle("ListEnterpriseProjectsForGroup", s.listEPsOf(subjectGroup)))
	r.With(act("iam:users:listAssignedEnterpriseProjects")).Get("/v3.0/OS-PERMISSION/users/{user_id}/enterprise-projects", s.handle("ListEnterpriseProjectsForUser", s.listEPsOf(subjectUser)))
	r.With(act("iam::listRoleAssignments")).Get("/v3.0/OS-PERMISSION/role-assignments", s.handle("ShowDomainRoleAssignments", s.handleListRoleAssignments))
}

// The resources of IAM 5.0 operations, whose URNs name users, groups and
// policies (iam::<account>:user:<name>): found by the ID in the path. An
// operation that lists or creates them acts on every one ("*"). A path
// naming nothing that exists is checked on no particular resource, and
// the handler then answers that it does not exist.
func (s *Service) userResource(r *http.Request) (authz.Resource, bool) {
	ctx := r.Context()
	u, err := s.users(ctx).Get(ctx, chi.URLParam(r, "user_id"))
	return authz.Resource{Type: "user", Path: u.Name}, err == nil
}

func (s *Service) groupResource(r *http.Request) (authz.Resource, bool) {
	ctx := r.Context()
	g, err := s.groups(ctx).Get(ctx, chi.URLParam(r, "group_id"))
	return authz.Resource{Type: "group", Path: g.Name}, err == nil
}

func (s *Service) policyResource(r *http.Request) (authz.Resource, bool) {
	ctx := r.Context()
	p, err := s.policies(ctx).Get(ctx, chi.URLParam(r, "policy_id"))
	return authz.Resource{Type: "policy", Path: p.Path + p.Name}, err == nil
}

func (s *Service) v5Routes(r chi.Router) {
	act := authz.Action
	user, group, anyUser, anyGroup := s.userResource, s.groupResource, authz.Fixed("user", "*"), authz.Fixed("group", "*")

	r.With(act("iam:users:createUserV5", anyUser)).Post("/v5/users", s.handle("CreateUserV5", s.handleCreateUserV5))
	r.With(act("iam:users:listUsersV5", anyUser)).Get("/v5/users", s.handle("ListUsersV5", s.handleListUsersV5))
	r.With(act("iam:users:getUserV5", user)).Get("/v5/users/{user_id}", s.handle("ShowUserV5", s.handleShowUserV5))
	r.With(act("iam:users:updateUserV5", user)).Put("/v5/users/{user_id}", s.handle("UpdateUserV5", s.handleUpdateUserV5))
	r.With(act("iam:users:deleteUserV5", user)).Delete("/v5/users/{user_id}", s.handle("DeleteUserV5", s.handleDeleteUserV5))
	r.With(act("iam:users:showUserLastLoginV5", user)).Get("/v5/users/{user_id}/last-login", s.handle("ShowUserLastLoginV5", s.handleShowUserLastLoginV5))
	r.With(act("iam:credentials:createCredentialV5", user)).Post("/v5/users/{user_id}/access-keys", s.handle("CreateAccessKeyV5", s.handleCreateAccessKeyV5))
	r.With(act("iam:credentials:listCredentialsV5", user)).Get("/v5/users/{user_id}/access-keys", s.handle("ListAccessKeysV5", s.handleListAccessKeysV5))
	r.With(act("iam:credentials:updateCredentialV5", user)).Put("/v5/users/{user_id}/access-keys/{access_key_id}", s.handle("UpdateAccessKeyV5", s.handleUpdateAccessKeyV5))
	r.With(act("iam:credentials:deleteCredentialV5", user)).Delete("/v5/users/{user_id}/access-keys/{access_key_id}", s.handle("DeleteAccessKeyV5", s.handleDeleteAccessKeyV5))
	r.With(act("iam:credentials:showAccessKeyLastUsedV5", user)).Get("/v5/users/{user_id}/access-keys/{access_key_id}/last-used", s.handle("ShowAccessKeyLastUsedV5", s.handleShowAccessKeyLastUsedV5))

	r.With(act("iam:groups:createGroupV5", anyGroup)).Post("/v5/groups", s.handle("CreateGroupV5", s.handleCreateGroupV5))
	r.With(act("iam:groups:listGroupsV5", anyGroup)).Get("/v5/groups", s.handle("ListGroupsV5", s.handleListGroupsV5))
	r.With(act("iam:groups:getGroupV5", group)).Get("/v5/groups/{group_id}", s.handle("ShowGroupV5", s.handleShowGroupV5))
	r.With(act("iam:groups:updateGroupV5", group)).Put("/v5/groups/{group_id}", s.handle("UpdateGroupV5", s.handleUpdateGroupV5))
	r.With(act("iam:groups:deleteGroupV5", group)).Delete("/v5/groups/{group_id}", s.handle("DeleteGroupV5", s.handleDeleteGroupV5))
	r.With(act("iam:permissions:addUserToGroupV5", group)).Post("/v5/groups/{group_id}/add-user", s.handle("AddUserToGroupV5", s.v5Membership(true)))
	r.With(act("iam:permissions:removeUserFromGroupV5", group)).Post("/v5/groups/{group_id}/remove-user", s.handle("RemoveUserFromGroupV5", s.v5Membership(false)))
}

func (s *Service) policyRoutes(r chi.Router) {
	act := authz.Action
	pol, anyPolicy := s.policyResource, authz.Fixed("policy", "*")

	r.With(act("iam:policies:createV5", anyPolicy)).Post("/v5/policies", s.handle("CreatePolicyV5", s.handleCreatePolicyV5))
	r.With(act("iam:policies:listV5", anyPolicy)).Get("/v5/policies", s.handle("ListPoliciesV5", s.handleListPoliciesV5))
	r.With(act("iam:policies:getV5", pol)).Get("/v5/policies/{policy_id}", s.handle("GetPolicyV5", s.handleGetPolicyV5))
	r.With(act("iam:policies:updateV5", pol)).Put("/v5/policies/{policy_id}", s.handle("UpdatePolicyV5", s.handleUpdatePolicyV5))
	r.With(act("iam:policies:deleteV5", pol)).Delete("/v5/policies/{policy_id}", s.handle("DeletePolicyV5", s.handleDeletePolicyV5))

	r.With(act("iam:policies:createVersionV5", pol)).Post("/v5/policies/{policy_id}/versions", s.handle("CreatePolicyVersionV5", s.handleCreatePolicyVersionV5))
	r.With(act("iam:policies:listVersionsV5", pol)).Get("/v5/policies/{policy_id}/versions", s.handle("ListPolicyVersionsV5", s.handleListPolicyVersionsV5))
	r.With(act("iam:policies:getVersionV5", pol)).Get("/v5/policies/{policy_id}/versions/{version_id}", s.handle("GetPolicyVersionV5", s.handleGetPolicyVersionV5))
	r.With(act("iam:policies:deleteVersionV5", pol)).Delete("/v5/policies/{policy_id}/versions/{version_id}", s.handle("DeletePolicyVersionV5", s.handleDeletePolicyVersionV5))
	r.With(act("iam:policies:setDefaultVersionV5", pol)).Post("/v5/policies/{policy_id}/versions/{version_id}/set-default", s.handle("SetDefaultPolicyVersionV5", s.handleSetDefaultPolicyVersionV5))

	// Attaching acts on the user, group or agency the body names; it is
	// checked on every user, group or agency.
	r.With(act("iam:users:attachPolicyV5", authz.Fixed("user", "*"))).Post("/v5/policies/{policy_id}/attach-user", s.handle("AttachUserPolicyV5", s.attach(policyUser, true)))
	r.With(act("iam:users:detachPolicyV5", authz.Fixed("user", "*"))).Post("/v5/policies/{policy_id}/detach-user", s.handle("DetachUserPolicyV5", s.attach(policyUser, false)))
	r.With(act("iam:groups:attachPolicyV5", authz.Fixed("group", "*"))).Post("/v5/policies/{policy_id}/attach-group", s.handle("AttachGroupPolicyV5", s.attach(policyGroup, true)))
	r.With(act("iam:groups:detachPolicyV5", authz.Fixed("group", "*"))).Post("/v5/policies/{policy_id}/detach-group", s.handle("DetachGroupPolicyV5", s.attach(policyGroup, false)))
	r.With(act("iam:policies:listEntitiesV5", pol)).Get("/v5/policies/{policy_id}/attached-entities", s.handle("ListEntitiesForPolicyV5", s.handleListEntitiesForPolicyV5))
	r.With(act("iam:users:listAttachedPoliciesV5", s.userResource)).Get("/v5/users/{user_id}/attached-policies", s.handle("ListAttachedUserPoliciesV5", s.listAttached(policyUser)))
	r.With(act("iam:groups:listAttachedPoliciesV5", s.groupResource)).Get("/v5/groups/{group_id}/attached-policies", s.handle("ListAttachedGroupPoliciesV5", s.listAttached(policyGroup)))
	r.With(act("iam:agencies:attachPolicyV5", authz.Fixed("agency", "*"))).Post("/v5/policies/{policy_id}/attach-agency", s.handle("AttachAgencyPolicyV5", s.attach(policyAgency, true)))
	r.With(act("iam:agencies:detachPolicyV5", authz.Fixed("agency", "*"))).Post("/v5/policies/{policy_id}/detach-agency", s.handle("DetachAgencyPolicyV5", s.attach(policyAgency, false)))
	r.With(act("iam:agencies:listAttachedPoliciesV5", s.agencyResource)).Get("/v5/agencies/{agency_id}/attached-policies", s.handle("ListAttachedAgencyPoliciesV5", s.listAttached(policyAgency)))
}

// classicAgencyRoutes are classic IAM's agencies and their grants
// (agencies.go).
func (s *Service) classicAgencyRoutes(r chi.Router) {
	act := authz.Action
	const agencies = "/v3.0/OS-AGENCY/agencies"
	r.With(act("iam:agencies:create")).Post(agencies, s.handle("CreateAgency", s.handleCreateAgency))
	r.With(act("iam:agencies:list")).Get(agencies, s.handle("ListAgencies", s.handleListAgencies))
	r.With(act("iam:agencies:get")).Get(agencies+"/{agency_id}", s.handle("ShowAgency", s.handleShowAgency))
	r.With(act("iam:agencies:update")).Put(agencies+"/{agency_id}", s.handle("UpdateAgency", s.handleUpdateAgency))
	r.With(act("iam:agencies:delete")).Delete(agencies+"/{agency_id}", s.handle("DeleteAgency", s.handleDeleteAgency))

	type scoped struct {
		prefix, scope, op, action string
	}
	for _, sc := range []scoped{
		{"/v3.0/OS-AGENCY/domains/{domain_id}/agencies/{agency_id}/roles", scopeDomain, "Domain", "OnDomain"},
		{"/v3.0/OS-AGENCY/projects/{project_id}/agencies/{agency_id}/roles", scopeProject, "Project", "OnProject"},
	} {
		r.With(act("iam:agencies:listRoles"+sc.action)).Get(sc.prefix, s.handle("List"+sc.op+"PermissionsForAgency", s.listGranted(subjectAgency, sc.scope)))
		r.With(act("iam:agencies:grantRole"+sc.action)).Put(sc.prefix+"/{role_id}", s.handle("AssociateAgencyWith"+sc.op+"Permission", s.grant(subjectAgency, sc.scope)))
		r.With(act("iam:agencies:checkRole"+sc.action)).Head(sc.prefix+"/{role_id}", s.handle("Check"+sc.op+"PermissionForAgency", s.check(subjectAgency, sc.scope)))
		r.With(act("iam:agencies:revokeRole"+sc.action)).Delete(sc.prefix+"/{role_id}", s.handle("Remove"+sc.op+"PermissionFromAgency", s.revoke(subjectAgency, sc.scope)))
	}
	const inherited = "/v3.0/OS-INHERIT/domains/{domain_id}/agencies/{agency_id}/roles"
	r.With(act("iam:agencies:listRoles")).Get(inherited+"/inherited_to_projects", s.handle("ListAllProjectsPermissionsForAgency", s.listGranted(subjectAgency, scopeInherited)))
	r.With(act("iam:agencies:grantRole")).Put(inherited+"/{role_id}/inherited_to_projects", s.handle("AssociateAgencyWithAllProjectsPermission", s.grant(subjectAgency, scopeInherited)))
	r.With(act("iam:agencies:checkRole")).Head(inherited+"/{role_id}/inherited_to_projects", s.handle("CheckAllProjectsPermissionForAgency", s.check(subjectAgency, scopeInherited)))
	r.With(act("iam:agencies:revokeRole")).Delete(inherited+"/{role_id}/inherited_to_projects", s.handle("RemoveAllProjectsPermissionFromAgency", s.revoke(subjectAgency, scopeInherited)))

	// The enterprise-project grants name their agencies in the body.
	const ep = "/v3.0/OS-PERMISSION/subjects/agency/scopes/enterprise-project/role-assignments"
	r.With(act("iam:agencies:grantRoleOnEnterpriseProject")).Put(ep, s.handle("AssociateRoleToAgencyOnEnterpriseProject", s.agencyEPGrants(true)))
	r.With(act("iam:agencies:revokeRoleOnEnterpriseProject")).Delete(ep, s.handle("RevokeRoleFromAgencyOnEnterpriseProject", s.agencyEPGrants(false)))
}

func (s *Service) v5AgencyRoutes(r chi.Router) {
	act := authz.Action
	agency, anyAgency := s.agencyResource, authz.Fixed("agency", "*")
	r.With(act("iam:agencies:createV5", anyAgency)).Post("/v5/agencies", s.handle("CreateAgencyV5", s.handleCreateAgencyV5))
	r.With(act("iam:agencies:listV5", anyAgency)).Get("/v5/agencies", s.handle("ListAgenciesV5", s.handleListAgenciesV5))
	r.With(act("iam:agencies:getV5", agency)).Get("/v5/agencies/{agency_id}", s.handle("GetAgencyV5", s.handleGetAgencyV5))
	r.With(act("iam:agencies:updateV5", agency)).Put("/v5/agencies/{agency_id}", s.handle("UpdateAgencyV5", s.handleUpdateAgencyV5))
	r.With(act("iam:agencies:deleteV5", agency)).Delete("/v5/agencies/{agency_id}", s.handle("DeleteAgencyV5", s.handleDeleteAgencyV5))
	r.With(act("iam:agencies:updateTrustPolicyV5", agency)).Put("/v5/agencies/{agency_id}/trust-policy", s.handle("UpdateTrustPolicyV5", s.handleUpdateTrustPolicyV5))
	r.With(act("iam:agencies:createServiceLinkedAgencyV5", anyAgency)).Put("/v5/service-linked-agencies", s.handle("CreateServiceLinkedAgencyV5", s.handleCreateServiceLinkedAgencyV5))
	r.With(act("iam:agencies:deleteServiceLinkedAgencyV5", agency)).Delete("/v5/service-linked-agencies/{agency_id}", s.handle("DeleteServiceLinkedAgencyV5", s.handleDeleteServiceLinkedAgencyV5))
	r.With(act("iam:agencies:getServiceLinkedAgencyDeletionStatusV5", anyAgency)).Get("/v5/service-linked-agencies/deletion-task/{deletion_task_id}", s.handle("GetServiceLinkedAgencyDeletionStatusV5", s.handleGetDeletionTaskV5))
}

func (s *Service) agencyResource(r *http.Request) (authz.Resource, bool) {
	ctx := r.Context()
	a, err := s.agencies(ctx).Get(ctx, chi.URLParam(r, "agency_id"))
	return authz.Resource{Type: "agency", Path: a.Path + a.Name}, err == nil
}

// authorizeOwn checks action unless the caller is ownerID: IAM users
// manage their own access keys without permission (api-iam
// OS-CREDENTIAL pages, "Authorization Information").
func (s *Service) authorizeOwn(r *http.Request, ownerID, action string) error {
	if authz.IsCaller(r, ownerID) {
		return nil
	}
	return authz.Check(r, action)
}
