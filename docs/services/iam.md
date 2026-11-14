# IAM coverage

Endpoint: `iam.myhuaweicloud.com` (the region-less host the SDKs and
Terraform use by default), `iam.{region}.myhuaweicloud.com`, or the `/iam`
path prefix. STS: `sts.{region}.myhuaweicloud.com` or `/sts`.

IAM belongs to the account, not to a project. WeiStack has one account
(Huawei Cloud's "domain"), named `weistack`; `/_weistack/services` shows its
ID. **Credentials are not checked**: every caller acts for that account.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

## Discovery

These are the calls Huawei's SDKs and the Terraform provider make to find
the account and a region's project when they are not configured, so a
client needs only an access key and a secret key.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| KeystoneListAuthDomains | `GET /v3/auth/domains` | Yes | The account |
| KeystoneListProjects | `GET /v3/projects` | Yes | Filters `name`, `domain_id`, `parent_id`, `enabled`, `is_domain`; `page` with `per_page` |
| KeystoneShowProject | `GET /v3/projects/{project_id}` | Yes | |
| KeystoneListAuthProjects | `GET /v3/auth/projects` | Yes | |
| GetCallerIdentity (STS) | `GET /v5/caller-identity` | Yes | The account and the caller |

## Users and groups

Classic IAM and IAM 5.0 share one set of users and groups: a user created
through either API is visible, and can be changed, through both.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateUser | `POST /v3.0/OS-USER/users` | Yes | What Terraform uses; `domain_id` is required |
| ShowUser, UpdateUser | `GET`, `PUT /v3.0/OS-USER/users/{user_id}` | Yes | |
| UpdateUserInformation | `PUT /v3.0/OS-USER/users/{user_id}/info` | Yes | `mobile` as `<country code>-<number>` |
| ShowUserLoginProtect, UpdateLoginProtect | `GET`, `PUT /v3.0/OS-USER/users/{user_id}/login-protect` | Yes | Kept, not enforced |
| KeystoneCreateUser, KeystoneListUsers | `POST`, `GET /v3/users` | Yes | Filters `name`, `enabled`, `domain_id` |
| KeystoneShowUser, KeystoneUpdateUserByAdmin, KeystoneDeleteUser | `GET`, `PATCH`, `DELETE /v3/users/{user_id}` | Yes | |
| KeystoneUpdateUserPassword | `POST /v3/users/{user_id}/password` | Yes | Needs the current password |
| KeystoneListGroupsForUser | `GET /v3/users/{user_id}/groups` | Yes | |
| KeystoneListProjectsForUser | `GET /v3/users/{user_id}/projects` | Yes | Every project for the root user; for others, the projects their groups have roles in (all of them with an all-projects grant) |
| KeystoneCreateGroup, KeystoneListGroups | `POST`, `GET /v3/groups` | Yes | Filters `name`, `domain_id` |
| KeystoneShowGroup, KeystoneUpdateGroup, KeystoneDeleteGroup | `GET`, `PATCH`, `DELETE /v3/groups/{group_id}` | Yes | |
| KeystoneListUsersForGroupByAdmin | `GET /v3/groups/{group_id}/users` | Yes | |
| KeystoneAddUserToGroup, KeystoneCheckUserInGroup, KeystoneRemoveUserFromGroup | `PUT`, `HEAD`, `DELETE /v3/groups/{group_id}/users/{user_id}` | Yes | |
| CreateUserV5, ListUsersV5 | `POST`, `GET /v5/users` | Yes | Filters `group_id`, `access_key_id`; `limit` and `marker` |
| ShowUserV5, UpdateUserV5, DeleteUserV5 | `GET`, `PUT`, `DELETE /v5/users/{user_id}` | Yes | |
| ShowUserLastLoginV5 | `GET /v5/users/{user_id}/last-login` | Yes | The last password sign-in |
| CreateGroupV5, ListGroupsV5 | `POST`, `GET /v5/groups` | Yes | Filter `user_id`; `limit` and `marker` |
| ShowGroupV5, UpdateGroupV5, DeleteGroupV5 | `GET`, `PUT`, `DELETE /v5/groups/{group_id}` | Yes | |
| AddUserToGroupV5, RemoveUserFromGroupV5 | `POST /v5/groups/{group_id}/add-user`, `remove-user` | Yes | |

The account's **root user** is named `weistack`, like the account. It
exists from the start, holds the administrator's keys, and cannot be
renamed, disabled or deleted. It has no password until one is set with
`UpdateUser`.

Names follow Huawei's rules: a username has at most 64 letters, digits,
spaces, `-`, `_` and `.`, and does not start with a digit or a space; a
group name has at most 128 letters, digits, spaces, `-` and `_`.
Descriptions have at most 255 characters and none of `@#%&<>\$^*`. An
account has at most 50 IAM users besides the root user.

**Passwords** are stored only as a salted hash. A password may not be the
username, or the username reversed. WeiStack also applies what it assumes
is the default password policy, not checked against Huawei's
documentation: 8 to 32 characters, with at least two of lowercase letters,
uppercase letters, digits and special characters.

## Access keys

Permanent access keys, through both APIs over one set of keys.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePermanentAccessKey, ListPermanentAccessKeys | `POST`, `GET /v3.0/OS-CREDENTIAL/credentials` | Yes | Without `user_id`, the list is the caller's own keys |
| ShowPermanentAccessKey, UpdatePermanentAccessKey, DeletePermanentAccessKey | `GET`, `PUT`, `DELETE /v3.0/OS-CREDENTIAL/credentials/{access_key}` | Yes | `status` and `description` |
| CreateAccessKeyV5, ListAccessKeysV5 | `POST`, `GET /v5/users/{user_id}/access-keys` | Yes | `limit` and `marker` |
| UpdateAccessKeyV5, DeleteAccessKeyV5 | `PUT`, `DELETE /v5/users/{user_id}/access-keys/{access_key_id}` | Yes | `status` |
| ShowAccessKeyLastUsedV5 | `GET /v5/users/{user_id}/access-keys/{access_key_id}/last-used` | Yes | |
| Temporary keys | `POST /v3.0/OS-CREDENTIAL/securitytokens` | No | |

A key is 20 characters, its secret 40, as on Huawei Cloud. The secret is
returned only when the key is created. A user has at most 2 keys.

- **A key acts as its user.** A request signed with an active key is
  known as that user's, for example to STS's caller identity. An inactive
  key is treated like any unknown key. Signatures are still not checked.
- **Secrets are sealed.** WeiStack keeps each secret key, since checking
  signatures will need it, but encrypted (AES-256-GCM), so it never
  appears in the data file or in `/_weistack/state`. With `-persist` the
  encryption key is `vault-key.json` in the data directory: keep it with
  the data, which cannot be used without it.
- **Last use** is the last request made with the key. It is kept in
  memory, so a restart loses it, except that it is saved when a key is
  deactivated. Classic IAM shows a never-used key's creation time as its
  last use, as documented; IAM 5.0 shows no time.
- **Deleting a user deletes its keys.** Huawei documents a 409 for
  `DeleteUserV5` without saying when; WeiStack does not refuse.
- The administrator's key (`weistack credentials`) is not an IAM access
  key and is not listed.

## Permissions

Classic IAM's permissions are the system-defined roles and policies every
account has, and the account's custom policies. They are granted to user
groups, and in an enterprise project also to users.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| KeystoneListPermissions | `GET /v3/roles` | Yes | System permissions; with `domain_id`, the account's custom policies. Filters `name`, `display_name` (an exact name, or part of one), `type` (`domain`, `project`, `all`), `permission_type` (`role`, `policy`), `catalog`; `page` with `per_page` (at most 500) |
| KeystoneShowPermission | `GET /v3/roles/{role_id}` | Yes | |
| CreateCloudServiceCustomPolicy, ListCustomPolicies | `POST`, `GET /v3.0/OS-ROLE/roles` | Yes | `page` with `per_page` (at most 300) |
| ShowCustomPolicy, UpdateCloudServiceCustomPolicy, DeleteCustomPolicy | `GET`, `PATCH`, `DELETE /v3.0/OS-ROLE/roles/{role_id}` | Yes | Show includes `references`, the number of grants. Delete also removes the grants |
| CreateAgencyCustomPolicy, UpdateAgencyCustomPolicy | | No | Agencies are not emulated |
| KeystoneListDomainPermissionsForGroup, KeystoneAssociateGroupWithDomainPermission, KeystoneCheckDomainPermissionForGroup, KeystoneRemoveDomainPermissionFromGroup | `GET /v3/domains/{domain_id}/groups/{group_id}/roles`, `PUT`, `HEAD`, `DELETE .../roles/{role_id}` | Yes | Global services |
| KeystoneListProjectPermissionsForGroup, KeystoneAssociateGroupWithProjectPermission, KeystoneCheckProjectPermissionForGroup, KeystoneRemoveProjectPermissionFromGroup | `GET /v3/projects/{project_id}/groups/{group_id}/roles`, `PUT`, `HEAD`, `DELETE .../roles/{role_id}` | Yes | One region's project |
| KeystoneListAllProjectPermissionsForGroup | `GET /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/inherited_to_projects` | Yes | |
| UpdateDomainGroupInheritRole, KeystoneCheckroleForGroup, DeleteDomainGroupInheritedRole | `PUT`, `HEAD`, `DELETE /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects` | Yes | All projects, including later ones |
| ShowDomainRoleAssignments | `GET /v3.0/OS-PERMISSION/role-assignments` | Yes | Filters `role_id`, `subject` or `subject.user_id` / `subject.group_id`, `scope` or `scope.project_id` / `scope.domain_id` / `scope.enterprise_projects_id`, `is_inherited`, `include_group`; `page` with `per_page` (at most 50) |
| Agency grants | `/v3.0/OS-AGENCY/...`, `/v3.0/OS-INHERIT/.../agencies/...` | No | Agencies are not emulated |

A grant answers 204 even when the role is already granted. A check answers
204 if the role is granted and 404 if not.

**The system permissions** are those of the services WeiStack emulates, and
the account-wide ones: FullAccess, Tenant Administrator, Tenant Guest and
Security Administrator. Their names, display names and descriptions are
Huawei's. Each has a stable ID, which is WeiStack's own: look permissions up
by name or display name, as Terraform's `huaweicloud_identity_role` does.

- **Scope (`type`)** follows Huawei's table of system permissions: `AX` for
  global services (such as OBS), `XA` for region-specific projects (such as
  ECS), `AA` for both.
- **Kind:** fine-grained policies have `flag` `fine_grained` and policy
  version `1.1`; roles have version `1.0`.
- **Catalog:** `BASE` for the account-wide permissions and Server
  Administrator, as Huawei's examples show; otherwise the service's
  abbreviation, which is assumed.
- **Statements** are not emulated yet: every system permission's policy has
  an empty `Statement` list.

**Custom policies** are checked as Huawei documents:

- `display_name` is required: at most 128 letters, digits, spaces and
  `-_.,`.
- `type` is `AX` or `XA`.
- The policy has `Version` `1.1` and 1 to 8 statements, is at most 6,144
  characters, and each statement has an `Effect` of `Allow` or `Deny` and an
  `Action` (or `NotAction`) list of at most 100 actions such as
  `obs:bucket:GetBucketAcl`.

A custom policy is named `custom_<account ID>_<n>`, with catalog
`CUSTOMED`, and its times are Unix milliseconds, as on Huawei Cloud. The
documented quota of 200 custom policies is not enforced: no error code is
documented for it.

Deleting a user group, a user or a custom policy removes its grants.

**Tokens** list the roles their user holds through their groups: in a
project, those granted for that project and for all projects; in the
domain, those granted for global services.

Permissions are not enforced yet: credentials are still not checked.

### Enterprise projects

WeiStack has one enterprise project, the default (ID `0`), served by
[EPS](eps.md). Roles can be granted in it to user groups and to users.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListRolesForGroupOnEnterpriseProject, AssociateRoleToGroupOnEnterpriseProject, RevokeRoleFromGroupOnEnterpriseProject | `GET /v3.0/OS-PERMISSION/enterprise-projects/{enterprise_project_id}/groups/{group_id}/roles`, `PUT`, `DELETE .../roles/{role_id}` | Yes | |
| ListRolesForUserOnEnterpriseProject, AssociateRoleToUserOnEnterpriseProject, RevokeRoleFromUserOnEnterpriseProject | `GET /v3.0/OS-PERMISSION/enterprise-projects/{enterprise_project_id}/users/{user_id}/roles`, `PUT`, `DELETE .../roles/{role_id}` | Yes | |
| ListGroupsForEnterpriseProject, ListUsersForEnterpriseProject | `GET /v3.0/OS-PERMISSION/enterprise-projects/{enterprise_project_id}/groups`, `.../users` | Yes | Those with roles in it |
| ListEnterpriseProjectsForGroup, ListEnterpriseProjectsForUser | `GET /v3.0/OS-PERMISSION/groups/{group_id}/enterprise-projects`, `/v3.0/OS-PERMISSION/users/{user_id}/enterprise-projects` | Yes | |
| Agency grants | `/v3.0/OS-PERMISSION/subjects/agency/scopes/enterprise-project/role-assignments` | No | |

## Identity policies (IAM 5.0)

IAM 5.0's custom identity policies, attached to users and groups.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePolicyV5, ListPoliciesV5 | `POST`, `GET /v5/policies` | Yes | Filters `policy_type`, `path_prefix`, `only_attached`; `limit` and `marker` |
| GetPolicyV5, UpdatePolicyV5, DeletePolicyV5 | `GET`, `PUT`, `DELETE /v5/policies/{policy_id}` | Yes | Update sets the description. Delete is refused while the policy is attached |
| CreatePolicyVersionV5, ListPolicyVersionsV5 | `POST`, `GET /v5/policies/{policy_id}/versions` | Yes | Newest first; `limit` and `marker` |
| GetPolicyVersionV5, DeletePolicyVersionV5 | `GET`, `DELETE /v5/policies/{policy_id}/versions/{version_id}` | Yes | The default version cannot be deleted |
| SetDefaultPolicyVersionV5 | `POST /v5/policies/{policy_id}/versions/{version_id}/set-default` | Yes | |
| AttachUserPolicyV5, DetachUserPolicyV5, AttachGroupPolicyV5, DetachGroupPolicyV5 | `POST /v5/policies/{policy_id}/attach-user`, `detach-user`, `attach-group`, `detach-group` | Yes | |
| ListAttachedUserPoliciesV5, ListAttachedGroupPoliciesV5 | `GET /v5/users/{user_id}/attached-policies`, `/v5/groups/{group_id}/attached-policies` | Yes | `limit` and `marker` |
| ListEntitiesForPolicyV5 | `GET /v5/policies/{policy_id}/attached-entities` | Yes | Filter `entity_type`; `limit` and `marker` |
| Agency attachments, trust policies | `/v5/policies/{policy_id}/attach-agency`, `/v5/agencies/...` | No | Agencies are not emulated |
| Password and login policies | `/v5/password-policy`, `/v5/login-policy` | No | |

- **Documents** follow IAM 5.0's grammar: `Version` `5.0` and a non-empty
  `Statement` list. Each statement has an optional `Sid`, an `Effect` of
  `Allow` or `Deny`, exactly one of `Action` and `NotAction`, at most one
  of `Resource` and `NotResource`, and an optional `Condition` map.
  Anything else is `PAP5.0011`. A document is at most 6,144 bytes once
  compacted.
- **Names** have 1 to 128 letters, digits and `_+=.@-`, and are unique in
  the account. A path is empty or segments that each end with `/`. The URN
  is `iam::<account ID>:policy:<path><name>`.
- **Versions** are numbered `v1`, `v2` and so on, and numbers are not
  reused. A policy has at most 5 versions, and a version becomes the
  default when created with `set_as_default` or by `set-default`.
- **Quotas:** 1,500 custom policies per account, and 10 policies attached
  to a user or a group.
- **System policies** are not emulated: their names and IDs in IAM 5.0 are
  not published, so `policy_type=system` lists none. Classic IAM's
  [system permissions](#permissions) are.
- Deleting a user or a group detaches its policies.

## Tokens

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| KeystoneCreateUserTokenByPassword | `POST /v3/auth/tokens` | Yes | `methods: ["password"]`, the user by name with the account's domain, or by ID |
| KeystoneCreateScopedToken | `POST /v3/auth/tokens` | Yes | `methods: ["token"]`, to rescope a token |
| KeystoneValidateToken | `GET /v3/auth/tokens` | Yes | `X-Subject-Token` |
| Agency tokens, MFA | `POST /v3/auth/tokens` | No | |

A token is returned in the `X-Subject-Token` header and lasts 24 hours.
Its scope is a project (by ID, or by name: a region's name) or the
account's domain. The catalog is empty. The roles are those the user holds
in the token's scope, as [Permissions](#permissions) describes. Tokens are kept in memory, so a restart or a
reset ends them. A token also ends when its user is deleted or disabled,
or changes password. Users with `access_mode` `console` cannot get one.
Tokens are not yet accepted in place of a signature: credentials are
still not checked.

## Projects

The account has a project in every region:

- The emulator's region (`-region`) keeps the configured project ID, so
  nothing changes for existing set-ups.
- Any other region's project has an ID derived from the account. It is
  the same on every start, and is listed once a client has asked for it
  by name, as the SDKs do.

Each project's `parent_id` and `domain_id` are the account's ID.

## Caller identity

STS reports the account's ID. A key that belongs to a user names that
user. Since credentials are not checked, any other key, including the
administrator's (`weistack credentials`), stands for the account's root
user, `iam::<account-id>:user:weistack`.

## Error codes

Only codes from Huawei's published IAM error table are used. Classic IAM's
error envelope is not documented; WeiStack uses the flat
`{"error_code", "error_msg"}` form IAM 5.0 documents, which the SDKs read
for both.

Classic IAM:

| Code | Status | When |
| --- | --- | --- |
| `1100` | 400 | `CreateUser` without `name` or `domain_id` |
| `1101` | 400 | An invalid username |
| `1102`, `1104`, `1106` | 400 | An invalid email address or mobile number, or only one of `areacode` and `phone` |
| `1103` | 400 | A wrong current password when changing it |
| `1107` | 400 | Deleting the root user |
| `1108` | 400 | A new password the same as the current one |
| `1109` | 400 | The username is taken |
| `1115` | 400 | The 50-user quota is reached (from IAM 5.0 too, which documents no code for it) |
| `1117` | 400 | An invalid user description |
| `1118` | 400 | A weak password |
| `1120` | 400 | An `access_mode` other than `default`, `console` or `programmatic` |
| `akSkNumExceed` | 400 | A third access key for a user. This one is documented in Keystone's envelope, `{"error": {"message": "akSkNumExceed", "code": 400, "title": "Bad Request", ...}}`, and WeiStack answers it that way |
| `IAM.0001` | 401 | A token request for an unknown user or another domain |
| `IAM.0002` | 403 | Renaming or disabling the root user |
| `IAM.0004` | 404 | `Could not find <project, user, group, credential, role, role assignment, domain or enterprise project>: <id>.`, also removing or checking a non-member, and from IAM 5.0 for an access key the user does not have (IAM 5.0 documents no code for it) |
| `IAM.0005` | 409 | The group name is taken |
| `IAM.0007` | 400 | `Request parameter <key> is invalid.`: `page`, `per_page`, `enabled`, `is_domain`, `type`, `permission_type`, `subject`, `scope`, `is_inherited` or `include_group` |
| `IAM.0009` | 400 | Validating without `X-Subject-Token` |
| `IAM.0011` | 400 | A body that is not JSON |
| `IAM.0062` | 401 | A wrong password at sign-in |
| `IAM.0066`, `IAM.0067` | 401 | An expired, or unknown or ended, token |
| `IAM.0072` | 400 | `'<key>' is a required property.` |
| `IAM.0073` | 400 | An invalid group name or description, another account's `domain_id`, an unknown `verification_method`, or an access key `status` other than `active` or `inactive` |
| `IAM.1001` to `IAM.1004`, `IAM.1009` | 400 | A custom policy's `display_name` is blank, too long or has invalid characters; its `type` is missing or not `AX` or `XA` |
| `IAM.1018`, `IAM.1019` | 400 | A custom policy's `description` or `description_cn` is not a string |
| `IAM.1020`, `IAM.1021`, `IAM.1024`, `IAM.1027` to `IAM.1031`, `IAM.1033` to `IAM.1035`, `IAM.1037` | 400 | A custom policy document that is not an object, is too large, has the wrong `Version`, or has an invalid statement, `Effect`, `Action` or `Resource` list |
| `IAM.0081` | 403 | A token for a console-only user |
| `IAM.0082` | 403 | A token for a disabled user |

IAM 5.0:

| Code | Status | When |
| --- | --- | --- |
| `PAP5.0001` | 403 | Renaming or disabling the root user |
| `PAP5.0004`, `PAP5.0005` | 409 | A group or a user already has 10 policies attached |
| `PAP5.0007` | 409 | Deleting the root user, an attached policy, or a policy's default version |
| `PAP5.0010` | 400 | An unknown `marker` |
| `PAP5.0011` | 400 | A malformed policy document |
| `PAP5.0016` | 404 | No such group |
| `PAP5.0018`, `PAP5.0019`, `PAP5.0020` | 404 | No such policy, policy attachment or policy version |
| `PAP5.0021` | 404 | No such user, also removing a non-member |
| `PAP5.0042` | 409 | The username is taken |
| `PAP5.0043` | 409 | The group name is taken |
| `PAP5.0044` | 409 | Adding a member again |
| `PAP5.0024` | 409 | The account has 1,500 custom policies |
| `PAP5.0025` | 409 | The policy name is taken |
| `PAP5.0026` | 409 | Attaching a policy again |
| `PAP5.0027` | 409 | A policy document over 6,144 bytes |
| `PAP5.0028` | 409 | A sixth version |
| `PAP5.0030` | 400 | An invalid `path` or `path_prefix` |
| `PAP5.0257` | 400 | Any invalid input, also a third access key for a user (IAM 5.0 documents a 400 but no code for it) |
