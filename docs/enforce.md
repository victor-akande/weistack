# Checking credentials (`-iam=enforce`)

By default WeiStack accepts any credentials: any access key and secret key
work, and signatures are not checked. That keeps setups simple, but it
also means a client that signs wrongly, or uses the wrong keys, works
against WeiStack and fails against Huawei Cloud.

With `-iam=enforce` WeiStack checks every request to an emulated service
the way Huawei Cloud does. The signature must be valid and made with a key
WeiStack knows, or the request must carry a valid IAM token; and the
caller's permissions, the policies IAM grants it, must allow the
operation. A failure gets the error Huawei documents for it, so your
client's error handling sees what it would see in the cloud.

```bash
weistack -iam=enforce
# or
WEISTACK_IAM=enforce weistack
```

The banner and the start log show the mode. Enforcement checks **who** is
calling and **what they may do**: see [Permissions](#permissions).

## Which credentials work

- **The administrator's keys.** They are generated on first start and kept
  beside the CA, so they stay the same across restarts. The banner shows
  them, and `weistack credentials` prints them as shell exports for the SDKs
  and Terraform:

  ```bash
  eval "$(weistack credentials)"
  ```

  To fix them, for example in CI, set `WEISTACK_ADMIN_ACCESS_KEY` and
  `WEISTACK_ADMIN_SECRET_KEY` (or `-admin-access-key` and
  `-admin-secret-key`).
- **IAM users' access keys**, created through IAM
  ([access keys](services/iam.md#access-keys)): active keys of enabled
  users. An inactive key, or a key of a disabled user, is refused.
- **IAM tokens** from WeiStack's IAM (`POST /v3/auth/tokens`), sent in
  `X-Auth-Token`. Signing in with a password needs no credentials.

- **Temporary credentials** from IAM or STS
  ([temporary credentials](services/iam.md#temporary-credentials)), with
  their security token in `X-Security-Token` (OBS: `x-obs-security-token`
  or `x-amz-security-token`, also in a pre-signed URL). A missing, invalid
  or expired security token makes the key unknown. Temporary keys are not
  locked out after failed signatures.

The CI suites drive permissions with the SDK too: a user in a group with
`VPC ReadOnlyAccess` lists VPCs but cannot create one, an attached IAM 5.0
`Deny` overrides the group's `Allow`, and IAM, STS and OBS refuse with
their own codes.

## What is checked

| Signature | Sent by | Where |
| --- | --- | --- |
| `SDK-HMAC-SHA256` | Huawei's SDKs, the Terraform provider, KooCLI | Every service but OBS |
| IAM token (`X-Auth-Token`) | Clients that sign in with a password | Every service but OBS |
| OBS (`OBS AK:signature`) and S3 v2 (`AWS AK:signature`) | Huawei's OBS SDKs, older S3 tools | OBS, in the `Authorization` header or a pre-signed URL |
| S3 signature version 4 (`AWS4-HMAC-SHA256`) | AWS SDKs and CLI, the OBS SDK's v4 mode | OBS, in the `Authorization` header or a pre-signed URL |

For OBS uploads, WeiStack also checks:

- each chunk's signature in an `aws-chunked` upload
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), as it arrives;
- that a body matches the SHA-256 its client declared in
  `x-amz-content-sha256`.

Either failure ends the upload, and nothing is stored.

**Your clock matters.** A request signed more than 15 minutes from
WeiStack's clock is refused, as on Huawei Cloud. A pre-signed URL works
until it expires.

The CI suites drive enforcement with Huawei's Go SDK, the OBS SDK for Go,
the AWS SDK for Go v2 and the Terraform provider, against signatures those
clients make themselves.

## Errors

Every service but OBS answers as Huawei's API gateway does: 401 with
`{"error_msg", "error_code", "request_id"}`.

| Code | Message | When |
| --- | --- | --- |
| `APIGW.0301` | `Incorrect IAM authentication information: verify aksk signature fail` | A wrong signature, or a clock more than 15 minutes off |
| `APIGW.0301` | `Incorrect IAM authentication information: Get secretKey failed,ak:<AK>,err:ak not exist` | An unknown or inactive key, or a disabled user's |
| `APIGW.0301` | `Incorrect IAM authentication information: decrypt token fail` | An unknown token, or one that has ended |
| `APIGW.0301` | `Incorrect IAM authentication information: AK access failed to reach the limit,forbidden.` | A locked key (see below) |
| `APIGW.0307` | `The token must be updated.` | An expired token |
| `APIGW.0305` | `Incorrect authentication information.` | No credentials |

OBS answers with its own codes, in its XML envelope:

| Code | Status | When |
| --- | --- | --- |
| `InvalidAccessKeyId` | 403 | An unknown or inactive key, or a disabled user's |
| `SignatureDoesNotMatch` | 403 | A wrong signature, or a chunk of an upload with a wrong one |
| `RequestTimeTooSkewed` | 403 | A clock more than 15 minutes off |
| `AccessDenied` | 403 | No credentials, no date, or an expired pre-signed URL |
| `TooManyWrongSignature` | 400 | A locked key |
| `ContentSHA256Mismatch` | 400 | A body that does not match its `x-amz-content-sha256` |

**Lockout.** As Huawei documents, more than five wrong signatures in a row
lock a key for five minutes; a right one clears the count. The
administrator's key is never locked, so a typo in CI cannot lock you out
of the emulator.

## Permissions

Once a caller is known, the operation's IAM action must be allowed. Each
operation has the action Huawei documents for it, in each service's
"Identity Policy-based Authorization" table and on its API page: listing
VPCs is `vpc:vpcs:list`, creating servers `ecs:cloudServers:createServers`
(in classic policies also its alias, `ecs:cloudServers:create`).

**Who holds everything:** the administrator's keys, the account's root
user, and the members of the built-in `admin` group. Add an IAM user to
`admin` to make it an administrator. Everything is within the caller's own
account: a request on another account's project is refused to everyone,
the administrator included (see [IAM: accounts](services/iam.md#accounts)).

**Everyone else holds what IAM grants them:**

- Classic permissions (system-defined, such as `VPC ReadOnlyAccess`, or
  custom) granted to the user's groups, by scope, as on the console:
  - granted for global services (the domain): OBS, IAM, EPS and STS;
  - granted in a project: requests in that project;
  - granted for all projects: requests in every project;
  - granted in the default enterprise project (`0`): every service but IAM.
- IAM 5.0 identity policies attached to the user or its groups, everywhere.

**Temporary credentials** hold what their user or assumed agency holds
(an agency: the classic roles granted to it, by the same scopes, and the
identity policies attached to it), narrowed by the session policies they
were issued with: a request must be allowed by both, even for a root
user's or the administrator's. STS's session policies apply to every
service; classic IAM's, as Huawei documents, to OBS only.

Evaluation follows Huawei's documented rules: a request is denied unless a
statement allows it, and a `Deny` anywhere wins. Statements may name
resources (`vpc:*:*:vpc:<id>`, `obs:*:*:object:my-bucket/logs/*`) and use
conditions with the global keys `g:UserId`, `g:UserName`, `g:DomainId`,
`g:DomainName`, `g:ProjectId`, `g:ProjectName`, `g:CurrentTime`,
`g:SourceIp` and `g:MFAPresent` (always `false`); other keys are absent,
so an `...IfExists` condition on them holds and a plain one does not.

A user's permissions are gathered once per scope and kept until a change
is made through IAM, which takes effect on the next request. Evaluating
them costs about a microsecond per request.

Huawei does not publish the statements of its system-defined permissions,
only what each allows. WeiStack's are written to match those tables (see
[IAM: permissions](services/iam.md#permissions)), and tested against them.

Some operations need no permission, as Huawei documents: signing in,
listing one's own projects and domains, changing one's own password and
contact details, reading oneself, managing one's own access keys, polling
an ECS job, and asking STS who one is.

**A new IAM user can do almost nothing until you grant it something.** This
includes the SDKs' automatic discovery of the project ID
(`GET /v3/projects`, `iam:projects:list`): give such a user's clients the
project ID, as Huawei advises, or grant it the permission.

### Denials

| Service | Status | Body |
| --- | --- | --- |
| VPC, ECS, EVS, IMS, RDS, EPS | 403 | `WeiStack.0403`, `Policy doesn't allow <action> to be performed.`, in the service's envelope |
| IAM (classic) | 403 | `IAM.0003`, `Policy doesn't allow <action> to be performed.` |
| IAM 5.0 | 403 | `PAP5.0001`, `access denied: ...` |
| STS | 403 | `STS5.1001`, `you are not authorized to perform this operation` |
| KMS | 403 | `KMS.0306`, `No access permissions.`, in KMS's envelope |
| OBS | 403 | `AccessDenied` (XML); in a batch delete, per refused key |

Huawei documents no permission error for the first group of services, so
WeiStack answers with its own code, `WeiStack.0403`, as it does
`WeiStack.0501` for what it does not implement.

Every JSON denial carries `encoded_authorization_message`, as Huawei's do.
STS's `POST /v5/decode-authorization-message` (which needs
`sts::decodeAuthorizationMessage`; the administrator has it) turns it into
the reason, in the fields of Huawei's example:

```json
{"context":{"user_profile":{"user_id":"...","user_name":"dev","domain_id":"..."},
 "action":"vpc:vpcs:create"},"failure":"implicit deny by identity-based policy"}
```

An explicit Deny says `explicit deny by identity-based policy` and names
the policy and statement (`Sid`). The emulator's log also records every
denial at the `info` level, with the action, resources, user and reason.

## Not covered

- **Resource policies.** OBS bucket policies and ACLs are not evaluated,
  and requests without credentials are refused, even to buckets whose ACL
  would allow them.
- **Service-specific condition keys** (such as `ecs:FlavorId` or
  `obs:prefix`) and resource tags (`g:ResourceTag/<key>`) are absent from
  requests.
- **Resources named in request bodies.** An operation that creates a
  resource, or acts on one its body names (a subnet's VPC, the user a
  policy is attached to), is checked on no particular resource, or on all
  of their type: a statement limited to named resources does not allow it.
  Operations on resources named in the path are checked on them.
- **Agency tokens** (`POST /v3/auth/tokens` with `assume_role`) and
  federation (`AssumeAgencyWithSAML`, `AssumeAgencyWithOIDC`) are not
  emulated.
- **The admin API** (`/_weistack/*`) is not protected by `-iam`: keep the
  emulator's port to yourself.
- **Other algorithms.** The SDKs' opt-in algorithms (`V11-HMAC-SHA256`,
  `SDK-HMAC-SM3`, ECDSA and SM2) are refused as signatures that do not
  match. In uploads signed with trailing headers
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`), the request's signature
  is checked but its chunks' are not.
