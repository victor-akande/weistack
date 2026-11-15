# Checking credentials (`-iam=enforce`)

By default WeiStack accepts any credentials: any access key and secret key
work, and signatures are not checked. That keeps setups simple, but it
also means a client that signs wrongly, or uses the wrong keys, works
against WeiStack and fails against Huawei Cloud.

With `-iam=enforce` WeiStack checks every request to an emulated service
the way Huawei Cloud does: the signature must be valid and made with a key
WeiStack knows, or the request must carry a valid IAM token. A failure gets
the error Huawei documents for it, so your client's error handling sees
what it would see in the cloud.

```bash
weistack -iam=enforce
# or
WEISTACK_IAM=enforce weistack
```

The banner and the start log show the mode. Enforcement checks **who** is
calling, not what they may do: any valid key or token of the account may
use every API.

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

Temporary credentials (`X-Security-Token`) are not supported yet: a
temporary access key is refused as unknown.

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

## Not covered

- **Permissions.** Any valid principal may use every API; policies and
  role assignments are recorded but not evaluated.
- **Anonymous OBS access.** Requests without credentials are refused, even
  to buckets whose ACL would allow them.
- **The admin API** (`/_weistack/*`) is not protected by `-iam`: keep the
  emulator's port to yourself.
- **Other algorithms.** The SDKs' opt-in algorithms (`V11-HMAC-SHA256`,
  `SDK-HMAC-SM3`, ECDSA and SM2) are refused as signatures that do not
  match. In uploads signed with trailing headers
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`), the request's signature
  is checked but its chunks' are not.
