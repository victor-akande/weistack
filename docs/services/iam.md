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
| Users, groups, access keys, tokens, policies | `/v3/...`, `/v3.0/...`, `/v5/...` | No | Coming next |

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

| Code | Status | When |
| --- | --- | --- |
| `IAM.0004` | 404 | `Could not find project: <id>.` |
| `IAM.0007` | 400 | `Request parameter <key> is invalid.`: `page`, `per_page`, `enabled` or `is_domain` |
