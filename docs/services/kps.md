# KPS coverage

Endpoint: `kms.{region}.myhuaweicloud.com`, or the `/kms` path prefix.
KPS is part of Data Encryption Workshop (DEW) and shares the KMS host,
with every KPS v3 operation under `/v3/{project_id}`.

The historical Nova SSH key pairs API (`/v2.1/{project_id}/os-keypairs`)
is served on `ecs.{region}.myhuaweicloud.com` and shares KPS's store.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

## Key pairs

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateKeypair | `POST /v3/{project_id}/keypairs` | Yes | Generates an RSA 2048 key pair, or imports `public_key`; optional `key_protection` |
| ListKeypairs | `GET /v3/{project_id}/keypairs` | Yes | `limit` (1 to 1000, default 1000), `marker`, `page_info` |
| ListKeypairDetail | `GET /v3/{project_id}/keypairs/{keypair_name}` | Yes | `404 KPS.6004` when missing |
| UpdateKeypairDescription | `PUT /v3/{project_id}/keypairs/{keypair_name}` | Yes | Up to 255 characters |
| DeleteKeypair | `DELETE /v3/{project_id}/keypairs/{keypair_name}` | Yes | Servers keep their `key_name` |
| BatchImportKeypair | `POST /v3/{project_id}/keypairs/batch-import` | Yes | Up to 10 key pairs; failures reported per item |
| Key pair tags | | No | |

## Private key protection

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ImportPrivateKey | `POST /v3/{project_id}/keypairs/private-key/import` | Yes | Rejects a private key that does not match the public key (`400 KPS.6011`) |
| ExportPrivateKey | `POST /v3/{project_id}/keypairs/private-key/export` | Yes | `400 KPS.6005` when no private key is held |
| BatchExportPrivateKey | `POST /v3/{project_id}/keypairs/private-key/batch-export` | Yes | Up to 10 key pairs; returns a ZIP archive (`<name>.pem`) |
| ClearPrivateKey | `DELETE /v3/{project_id}/keypairs/{keypair_name}/private-key` | Yes | Removes the stored private key |

## ECS association and tasks

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| AssociateKeypair | `POST /v3/{project_id}/keypairs/associate` | Yes | `202 Accepted` with `task_id`; unknown key pair is `400 KPS.4016` |
| DisassociateKeypair | `POST /v3/{project_id}/keypairs/disassociate` | Yes | `202 Accepted` with `task_id` |
| BatchAssociateKeypair | `POST /v3/{project_id}/keypairs/batch-associate` | Yes | Up to 10 items; one task per valid item |
| ListKeypairTask | `GET /v3/{project_id}/tasks/{task_id}` | Yes | Unknown task is `400 KPS.0001` |
| ListRunningTask | `GET /v3/{project_id}/running-tasks` | Yes | `limit` and `offset` |
| ListFailedTask | `GET /v3/{project_id}/failed-tasks` | Yes | `limit` and `offset` |
| DeleteFailedTask | `DELETE /v3/{project_id}/failed-tasks/{task_id}` | Yes | Unknown failed task is `400 KPS.0005` |
| DeleteAllFailedTask | `DELETE /v3/{project_id}/failed-tasks` | Yes | |

## Nova v2.1 API (ECS host)

Served on `ecs.{region}.myhuaweicloud.com` against the same key pair records:

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| NovaCreateKeypair | `POST /v2.1/{project_id}/os-keypairs` | Yes | Creates a `user`-scope key pair or imports `public_key`; supports `key_protection` |
| NovaListKeypairs | `GET /v2.1/{project_id}/os-keypairs` | Yes | `limit` (1 to 1000) and `marker`; each item wrapped in `{"keypair": {...}}` |
| NovaShowKeypair | `GET /v2.1/{project_id}/os-keypairs/{keypair_name}` | Yes | `404 KPS.6004` when missing |
| NovaDeleteKeypair | `DELETE /v2.1/{project_id}/os-keypairs/{keypair_name}` | Yes | `202 Accepted` |
| Nova v2 API (`/v2/{project_id}/os-keypairs`) | | No | |

## Behaviour

- **Real keys.** Generated key pairs are real RSA 2048 keys: the public key
  is in OpenSSH format (`ssh-rsa ...`) and the private key is PKCS#1 PEM
  (`-----BEGIN RSA PRIVATE KEY-----`). `fingerprint` is the legacy MD5
  colon-hex digest (`ssh.FingerprintLegacyMD5`).
- **Importing public keys.** Imported public keys are parsed with
  `golang.org/x/crypto/ssh` (RSA, Ed25519, ECDSA, and other OpenSSH key
  types). Invalid public keys return `400 KPS.0002`. `algorithm` reports
  the key type (`ssh-rsa`, `ssh-ed25519`, ...).
- **Private key protection.** Private keys are stored only when
  `key_protection` is enabled at creation or imported later
  (`is_key_protection` reports whether one is held). Without protection, a
  generated private key is returned once in the create response and never
  stored.
  - `encryption.type = "default"` seals the private key with the emulator's
    vault (label `weistack:kps:private-key`), surviving `-persist`.
  - `encryption.type = "kms"` encrypts the private key with a [KMS](kms.md)
    data key under `kms_key_id` or `kms_key_name` (`kps/default` resolves to
    the account's default `kps/default` key, created on first use). Disabling
    or deleting that KMS key causes export to fail (`400 KPS.6008`).
  - Private keys are never written to logs.
- **Scope and visibility.** `scope` defaults to `user`. `user` key pairs
  belong to the caller's IAM `user_id`; `domain` key pairs belong to the
  account and are visible to every caller in the project. Listing returns
  the caller's `user` key pairs plus the project's `domain` key pairs in
  creation order. Under `-iam=accept`, every caller acts as the account's
  root user. Key pairs created through the Nova v2.1 API always have
  `scope: "user"`.
- **Asynchronous association tasks.** `AssociateKeypair`,
  `DisassociateKeypair` and `BatchAssociateKeypair` return `202 Accepted`
  with a `task_id` and run after `-lifecycle-delay`. On success,
  [ECS](ecs.md) sets or clears the server's `key_name`. If the target
  server does not exist or a lifecycle fault fails the task, a failed task
  record is written and returned by `ListFailedTask`. Lifecycle fault kinds
  are `kps.keypair.associate` and `kps.keypair.disassociate` (see
  [Injecting faults](../faults.md)). Running tasks resume after a restart
  with `-persist`.
- **ECS `key_name` validation.** Creating an ECS server with a `key_name`
  that does not exist (or is not visible to the caller) fails with
  `400 Ecs.0314`. Deleting a key pair leaves existing servers' `key_name`
  unchanged.
- **Quotas and state.** Huawei documents no KPS quota, so none is enforced.
  `frozen_state` is always `0` (`"0"` in list responses).
- **Gaps.** The Nova v2 API (`/v2/{project_id}/os-keypairs`) and key pair
  tags are not emulated. Servers are state only, so associating or
  disassociating a key pair updates ECS's record rather than modifying a
  running guest.

## Errors

KPS v3 renders errors in the flat envelope
`{"error_code": "...", "error_msg": "..."}`. Nova v2.1 routes on the ECS
host render errors in ECS's nested envelope
`{"error": {"code": "...", "message": "..."}}`.

| Code | HTTP | When |
| --- | --- | --- |
| `KPS.0001` | 400 | Task ID is missing or does not exist |
| `KPS.0002` | 400 | Malformed body, invalid key pair name, invalid public key, or invalid parameter |
| `KPS.0005` | 400 | Failed task does not exist |
| `KPS.4016` | 400 | Key pair named in an associate request does not exist |
| `KPS.6004` | 404 | Key pair does not exist (HTTP 404 to match Huawei Cloud and the Terraform provider) |
| `KPS.6005` | 400 | Exporting a private key when none is managed |
| `KPS.6008` | 400 | Encrypting or decrypting the private key failed (for example, disabled KMS key) |
| `KPS.6010` | 400 | Saving the private key failed |
| `KPS.6011` | 400 | Imported private key does not match the key pair's public key |
| `KPS.7004` | 400 | Key pair with that name already exists |
| `KPS.9003` | 403 | Permission denied under `-iam=enforce`, with `encoded_authorization_message` |

## Permissions

Each KPS v3 operation checks Huawei's IAM 5.0 action and its classic
`kps:domainKeypairs:*` alias:

- Key pairs (`SSHKeyPair` resource): `kps:SSHKeyPair:create`, `list`,
  `get`, `update`, `delete`, `importPrivateKey`, `exportPrivateKey`,
  `clearPrivateKey`, `bind`, `unbind`.
- Tasks: `kps::getTask`, `kps::getRunningTask`, `kps::getFailedTask`,
  `kps::deleteFailedTask`.
- Nova v2.1 routes (`keypair` resource): `ecs:serverKeypairs:create`,
  `ecs:serverKeypairs:list`, `ecs:serverKeypairs:get`,
  `ecs:serverKeypairs:delete`.

`Tenant Administrator` and `Tenant Guest` include KPS.
