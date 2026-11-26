# CSMS coverage

Endpoint: `kms.{region}.myhuaweicloud.com`, or the `/kms` path prefix.
CSMS (Cloud Secret Management Service) is part of Data Encryption Workshop
(DEW) and shares the KMS host, with every CSMS operation under
`/v1/{project_id}`.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

## Secrets, deletion, and backup

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSecret | `POST /v1/{project_id}/secrets` | Yes | `COMMON` secrets only; seals `v1` (`SYSCURRENT`) under [KMS](kms.md) |
| ListSecrets | `GET /v1/{project_id}/secrets` | Yes | `limit` (1 to 1000, default 50), `marker`, `event_name`, `with_shared` |
| ShowSecret | `GET /v1/{project_id}/secrets/{secret_name}` | Yes | `404 CSMS.0005` when missing |
| UpdateSecret | `PUT /v1/{project_id}/secrets/{secret_name}` | Yes | `kms_key_id` (applies to new versions), `description`, `event_subscriptions` |
| DeleteSecret | `DELETE /v1/{project_id}/secrets/{secret_name}` | Yes | `204 No Content`; immediate, regardless of state |
| DeleteSecretForSchedule | `POST /v1/{project_id}/secrets/{secret_name}/scheduled-deleted-tasks/create` | Yes | `recovery_window_in_days` 7 to 30 (default 30) |
| RestoreSecret | `POST /v1/{project_id}/secrets/{secret_name}/scheduled-deleted-tasks/cancel` | Yes | Cancels pending deletion and returns the secret to `ENABLED` |
| DownloadSecretBlob | `POST /v1/{project_id}/secrets/{secret_name}/backup` | Yes | Vault-sealed backup envelope bound to account and region |
| UploadSecretBlob | `POST /v1/{project_id}/secrets/restore` | Yes | Restores as `ENABLED`; `409 CSMS.0101` if the name exists |
| RotateSecret, ListSecretTask | `POST .../rotate`, `GET .../csms/tasks` | No | |
| BatchGetSecretValue, BatchImportSecrets | | No | Undocumented in the English API reference |

## Versions and stages

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSecretVersion | `POST /v1/{project_id}/secrets/{secret_name}/versions` | Yes | `secret_string` or `secret_binary` (up to 64 KB); optional `version_stages` and `expire_time` |
| ListSecretVersions | `GET /v1/{project_id}/secrets/{secret_name}/versions` | Yes | Metadata only (never values); `limit` and `marker` |
| ShowSecretVersion | `GET /v1/{project_id}/secrets/{secret_name}/versions/{version_id}` | Yes | Returns the plaintext value (`v1`, `v2`, ... or `latest`); updates `last_used_time` |
| UpdateVersion | `PUT /v1/{project_id}/secrets/{secret_name}/versions/{version_id}` | Yes | Updates `expire_time` |
| ShowSecretStage | `GET /v1/{project_id}/secrets/{secret_name}/stages/{stage_name}` | Yes | `404 CSMS.0005` when missing |
| UpdateSecretStage | `PUT /v1/{project_id}/secrets/{secret_name}/stages/{stage_name}` | Yes | Creates or moves a stage to `version_id` |
| DeleteSecretStage | `DELETE /v1/{project_id}/secrets/{secret_name}/stages/{stage_name}` | Yes | `204 No Content`; `SYSCURRENT` and `SYSPREVIOUS` return `400 CSMS.0105` |

## Tags, passwords, and other APIs

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSecretTag | `POST /v1/{project_id}/csms/{secret_id}/tags` | Yes | `204 No Content`; keyed by secret UUID |
| ListSecretTags | `GET /v1/{project_id}/csms/{secret_id}/tags` | Yes | Returns `tags` and `sys_tags` |
| BatchCreateOrDeleteTags | `POST /v1/{project_id}/csms/{secret_id}/tags/action` | Yes | `204 No Content`; `action` `create` or `delete` |
| DeleteSecretTag | `DELETE /v1/{project_id}/csms/{secret_id}/tags/{key}` | Yes | `204 No Content`; `404 CSMS.0005` when the secret or key is absent |
| ListProjectSecretsTags | `GET /v1/{project_id}/csms/tags` | Yes | Distinct tag keys and values across the project |
| ListResourceInstances | `POST /v1/{project_id}/csms/resource_instances/action` | Yes | `action` `filter` or `count`; `tags`, `matches` on `resource_name`, `limit`, `offset` |
| GenerateRandomPassword | `POST /v1/{project_id}/csms/generate-password` | Yes | Length 1 to 255 (default 32); no IAM permission required |
| Secret events and notification records | `/v1/{project_id}/csms/events...`, `.../notification-records` | No | Requires SMN topic delivery |
| Grants, agencies, users, function templates, secret checker | | No | |

## Behaviour

- **KMS-backed encryption.** Each secret version gets its own [KMS](kms.md)
  data key and seals its value with AES-256-GCM using additional
  authenticated data `weistack:csms:<secret-id>:<version-id>`. Only the
  KMS-sealed data key and the ciphertext are persisted; plaintext secret
  values are never stored or written to logs.
  - When `kms_key_id` is omitted, CSMS uses the account's default
    `csms/default` key, which KMS creates on first use.
  - Passing an unknown, disabled, or pending-deletion `kms_key_id` when
    creating or updating a secret (or creating a version under such a key)
    returns `400 CSMS.0002`.
  - Reading a version whose KMS key is disabled or pending deletion fails
    with `400 CSMS.0401`; re-enabling the key makes the version readable
    again.
- **Secret types and rotation.** Only `COMMON` secrets are supported.
  Requesting `RDS-FG`, `GaussDB-FG`, or `RDS`, or setting
  `auto_rotation: true`, `rotation_period`, `rotation_config`, or
  `rotation_func_urn`, returns `501 WeiStack.0501` naming the unsupported
  setting so the gap is visible rather than silently ignored.
- **Values and versions.** Secret and stage names match
  `^[a-zA-Z0-9_-]{1,64}$`. Every version requires at most 64 KB of decoded
  data in either `secret_string` or Base64-encoded `secret_binary` (neither
  or both is `400 CSMS.0002`). Version IDs are `v1`, `v2`, ... per secret,
  and `latest` addresses the newest version in `ShowSecretVersion`. Reading
  a value sets `last_used_time`.
- **Stages and version pruning.** A new version receives `SYSCURRENT` unless
  explicit `version_stages` are supplied; the version that previously held
  `SYSCURRENT` moves to `SYSPREVIOUS`, and any older `SYSPREVIOUS` loses the
  stage. Each stage points to at most one version, so assigning an existing
  stage to another version moves it. Deleting `SYSCURRENT` or `SYSPREVIOUS`
  returns `400 CSMS.0105`. A secret holds at most 12 stages (`400 CSMS.0203`)
  and 20 versions: creating a 21st version deletes the oldest stage-less
  (deprecated) version.
- **States and scheduled deletion.** Only `ENABLED` and `PENDING_DELETE` are
  reachable (`DISABLED` and `FROZEN` are not entered by any operation in
  scope). `DeleteSecretForSchedule` schedules deletion 7 to 30 days ahead
  (default 30 days) in real clock time via lifecycle transition
  `csms.secret.delete`, resumed after restarts under `-persist` (see
  [Injecting faults](../faults.md)). While `PENDING_DELETE`:
  - reading a value returns `403 CSMS.0109`;
  - updating the secret, adding a version, or modifying stages returns
    `400 CSMS.0103`;
  - scheduling deletion again returns `400 CSMS.0107`.
  `RestoreSecret` cancels the scheduled deletion and returns the secret to
  `ENABLED` (`400 CSMS.0108` if not pending). When the scheduled time
  passes, the secret and all its versions are deleted (`404 CSMS.0005`).
- **Backup and restore.** `DownloadSecretBlob` returns a
  `)CloudSecretManagementBackupV1.com...` token whose payload is sealed by
  the emulator's vault (label `weistack:csms:backup`) and bound to the
  caller's account and region. It carries the secret metadata, stages, tags,
  and still-KMS-encrypted versions — never plaintext. `UploadSecretBlob`
  restores the secret in `ENABLED` state, rejecting blobs from another
  account or region (`400 CSMS.0002`) and existing names (`409 CSMS.0101`).
- **Tags.** Single-secret tag endpoints take `{secret_id}` (the secret's
  UUID) rather than `{secret_name}`. A secret holds up to 20 tags
  (`400 CSMS.0002`), with keys of 1 to 128 characters (no leading or
  trailing whitespace, not prefixed with `_sys_`) and values up to 255
  characters.
- **Random passwords.** `GenerateRandomPassword` draws from `crypto/rand`
  (length 1 to 255, default 32) and supports `exclude_lowercase`,
  `exclude_uppercase`, `exclude_numbers`, `exclude_punctuation`,
  `exclude_characters`, `include_space`, and `require_each_included_type`
  (including at least one character from every active class whenever the
  length allows). Excluding every class or naming a `password_policy_name`
  returns `400 CSMS.0002`. Passwords are never stored or logged.
- **Metadata.** `domain_id` is the caller's account ID, `replica_type` is
  `STANDALONE`, and `enterprise_project_id` defaults to `"0"`.
  `event_subscriptions` (at most one name) is accepted and stored,
  `ListSecrets?event_name=...` returns an empty list while events are out of
  scope, and `with_shared` is accepted and ignored.

## Quotas

`csms.secret` counts secrets per project (including `PENDING_DELETE`) and is
configurable with `-quotas` (see [Quotas](../quotas.md)). Per-secret limits
are fixed to Huawei's documented bounds: 20 versions (pruning the oldest
stage-less version on the 21st), 12 stages (`400 CSMS.0203`), 20 tags
(`400 CSMS.0002`), and 64 KB per secret value (`400 CSMS.0002`).

| Key | Default | Error | Enforced |
| --- | --- | --- | --- |
| `csms.secret` | 5000 | `400 CSMS.0202` | Yes |

## Errors

Huawei's CSMS API pages do not show an error response body; WeiStack assumes
the flat envelope `{"error_code": "...", "error_msg": "..."}`, matching
[KPS](kps.md), which works with both the official SDKs and the Terraform
provider.

| Code | HTTP | When |
| --- | --- | --- |
| `CSMS.0002` | 400 | Invalid parameter, unknown or unusable `kms_key_id`, invalid value, or >20 tags |
| `CSMS.0004` | 400 | Malformed or unreadable JSON request body |
| `CSMS.0005` | 404 | Secret, version, stage, or tag does not exist (HTTP 404 to match Huawei Cloud and the Terraform provider) |
| `CSMS.0101` | 409 | Secret name already exists (`ENABLED` or `PENDING_DELETE`) |
| `CSMS.0103` | 400 | Updating a secret, creating a version, or changing a stage while `PENDING_DELETE` |
| `CSMS.0105` | 400 | Deleting built-in stage `SYSCURRENT` or `SYSPREVIOUS` |
| `CSMS.0107` | 400 | Scheduling deletion on a secret already in `PENDING_DELETE` |
| `CSMS.0108` | 400 | Restoring a secret that is not in `PENDING_DELETE` |
| `CSMS.0109` | 403 | Reading a secret value or downloading a backup while not `ENABLED` |
| `CSMS.0202` | 400 | Project secret quota (`csms.secret`) reached |
| `CSMS.0203` | 400 | Stage limit (12 per secret) reached |
| `CSMS.0302` | 403 | Permission denied under `-iam=enforce`, with `encoded_authorization_message` |
| `CSMS.0401` | 400 | Reading a version whose KMS key is disabled, pending deletion, or missing |
| `WeiStack.0501` | 501 | Unsupported secret type, rotation setting, or unimplemented operation |

## Permissions

Under `-iam=enforce`, each operation checks Huawei's IAM 5.0 action and its
classic alias against resource URN
`csms:<region>:<account-id>:secretName:<secret-name>` (or `*` for
`csms::listProjectTags` and `csms::getSecretQuota`). For the tag endpoints
keyed by `{secret_id}`, CSMS resolves the secret's name from its ID before
evaluating the `secretName` URN. `GenerateRandomPassword` requires no
identity permission.

Operations that seal or open values also check KMS dependencies on the key
`kms:<region>:<account-id>:KeyId:<key-id>`:

- `CreateSecret` and `CreateSecretVersion` require `kms:cmk:createDataKey`;
- `ShowSecretVersion` and `UploadSecretBlob` require `kms:cmk:decryptDataKey`;
- `DownloadSecretBlob` requires `kms:cmk:createDataKey` and
  `kms:cmk:decryptDataKey`.

Two classic system policies are provided alongside `Tenant Administrator`
and `Tenant Guest`:

- `CSMS FullAccess` (`csms_full`): `csms:*:*`;
- `CSMS ReadOnlyAccess` (`csms_readonly`): `csms:secret:get` (which also
  covers `DownloadSecretBlob`), `csms:secret:list`, `csms:secretVersion:get`,
  `csms:secretVersion:list`, `csms:secretStage:get`, `csms:tag:getAll`,
  `csms:tag:getSecretByTag`, and `csms:tag:getBySecret`.

### Allowing agents to manage secrets without reading values

As on Huawei Cloud, `CSMS ReadOnlyAccess` and `Tenant Guest` include
`csms:secretVersion:get` (`ShowSecretVersion`), so any caller granted those
roles can read plaintext secret values.

Because reading a value has its own action (`csms:secret:getVersion`, alias
`csms:secretVersion:get`) and its own KMS dependency
(`kms:cmk:decryptDataKey`), an automated agent can be allowed to create,
list, tag, stage, and reference secrets by name while never reading a
plaintext value. Attach an IAM 5.0 identity policy that explicitly denies
`csms:secret:getVersion` (and grant only `kms:cmk:createDataKey`, not
`kms:cmk:decryptDataKey`, on the KMS key so backups cannot be downloaded or
decrypted either):

```json
{
  "Version": "5.0",
  "Statement": [
    {
      "Sid": "ManageSecretsByName",
      "Effect": "Allow",
      "Action": [
        "csms:secret:*",
        "csms::listProjectTags"
      ],
      "Resource": ["*"]
    },
    {
      "Sid": "DenyPlaintextValueReads",
      "Effect": "Deny",
      "Action": [
        "csms:secret:getVersion"
      ],
      "Resource": ["*"]
    },
    {
      "Sid": "AllowSealingNewValuesOnly",
      "Effect": "Allow",
      "Action": [
        "kms:cmk:createDataKey"
      ],
      "Resource": ["*"]
    }
  ]
}
```
