# KMS coverage

Endpoint: `kms.{region}.myhuaweicloud.com`, or the `/kms` path prefix.
Every operation is under `/v1.0/{project_id}/kms/`.

KMS keys are real: WeiStack generates their material with the algorithm
asked for, encrypts with it, and keeps it sealed by the emulator's vault
(the same one that seals IAM secret keys), so `-persist` keeps keys and
what they encrypted. Ciphertexts are WeiStack's own envelopes: they open
only in the emulator that made them.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

## Keys

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateKey | `POST .../create-key` | Yes | Every `key_spec`; `origin` `kms` only |
| ListKeyDetail | `POST .../describe-key` | Yes | |
| ListKeys | `POST .../list-keys` | Yes | Filters `key_state`, `key_spec`, `enterprise_project_id`; `limit` and `marker` |
| EnableKey, DisableKey | `POST .../enable-key`, `disable-key` | Yes | |
| DeleteKey, CancelKeyDeletion | `POST .../schedule-key-deletion`, `cancel-key-deletion` | Yes | `pending_days` 7 to 1,096 |
| UpdateKeyAlias, UpdateKeyDescription | `POST .../update-key-alias`, `update-key-description` | Yes | |
| ShowUserInstances, ShowUserQuotas | `GET .../user-instances`, `user-quotas` | Yes | 100 keys per project by default; see [Quotas](#quotas) |
| Aliases, key policies, keystores, importing key material, replication | | No | |

- **Specs.** `AES_256` (the default) and `SM4` keys encrypt;
  `RSA_2048`, `RSA_3072`, `RSA_4096` and `SM2` keys sign by default or
  encrypt (`key_usage`); `EC_P256`, `EC_P384`, `SECP256K1` and `ED25519`
  keys sign; `HMAC_256`, `HMAC_384`, `HMAC_512` and `HMAC_SM3` keys make
  MACs, and are shown with `key_usage` `GENERATE_VERIFY_MAC`. SM2, SM3
  and SM4 use the [gmsm](https://github.com/emmansun/gmsm) library,
  secp256k1 [dcrd's](https://github.com/decred/dcrd).
- **States** (`key_state`): `2` enabled, `3` disabled, `4` pending
  deletion. A disabled key (`KMS.0209`) or one pending deletion
  (`KMS.0210`) does not encrypt or decrypt. Cancelling a deletion leaves
  the key disabled, as on Huawei Cloud. When its date comes, the key is
  gone (`KMS.0207`), and so is anything only it could decrypt.
- **Aliases** are 1 to 255 of `a-zA-Z0-9:/_-`, unique in the project, and
  cannot end in `/default`.
- **Default keys** (`<service>/default`, `default_key_flag` `1`) are made
  by the services that encrypt with KMS on first use. They cannot be
  disabled, deleted, renamed or rotated (`KMS.0211`).
- `creation_date` and `scheduled_deletion_date` are milliseconds since the
  epoch, as strings.

## Cryptography

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| EncryptData, DecryptData | `POST .../encrypt-data`, `decrypt-data` | Yes | Symmetric keys (`SYMMETRIC_DEFAULT`), RSA (`RSAES_OAEP_SHA_256`) and SM2 (`SM2_ENCRYPT`) keys |
| CreateDatakey, CreateDatakeyWithoutPlaintext | `POST .../create-datakey`, `create-datakey-without-plaintext` | Yes | `datakey_length` 8 to 8,192 bits, or `key_spec` |
| EncryptDatakey, DecryptDatakey | `POST .../encrypt-datakey`, `decrypt-datakey` | Yes | |
| CreateRandom | `POST .../gen-random` | Yes | 512 bits |
| Sign, ValidateSignature | `POST .../sign`, `verify` | Yes | See below |
| ShowPublicKey | `POST .../get-publickey` | Yes | PEM `PUBLIC KEY`, CRLF line ends |
| GenerateMac, VerifyMac | `POST .../generate-mac`, `verify-mac` | Yes | HMAC keys; the MAC in hexadecimal |
| Data key pairs, ReEncrypt, DeriveSharedSecret | | No | |

- `encrypt-data` takes 1 to 4,096 bytes and returns Base64. The ciphertext
  names its key, so `decrypt-data` needs no `key_id`; a `key_id` that does
  not match it, another account's key, wrong
  `additional_authenticated_data` or any change to the ciphertext is
  `KMS.2201`.
- Each ciphertext has its own data key, sealed with the key's material in
  AES-256-GCM, or SM4-GCM for an SM4 key; the data is sealed with that
  data key and the additional authenticated data.
- Data keys and their ciphertexts are upper-case hexadecimal.
  `encrypt-datakey` takes the data key followed by its SHA-256 (SM3 for an
  SM4 key), checked (`KMS.2103`); `decrypt-datakey` returns it with that
  digest in `datakey_dgst`.

- **Asymmetric encryption.** RSA keys with `key_usage`
  `ENCRYPT_DECRYPT` encrypt with OAEP and SHA-256, up to the key size
  less 66 bytes (`KMS.2108`); SM2 keys with SM2 (ASN.1, C1C3C2). Their
  ciphertexts do not name the key: `decrypt-data` needs `key_id` and
  `encryption_algorithm`. EC and Ed25519 keys do not encrypt
  (`KMS.1114`).
- **Signing.** `message` is Base64, up to 4,096 bytes: a digest
  (`message_type` `DIGEST`, the default) of the algorithm's hash size
  (`KMS.0329`), or the message itself (`RAW`), which KMS hashes. RSA keys
  sign with `RSASSA_PSS_*` or `RSASSA_PKCS1_V1_5_*`; EC and secp256k1
  keys with `ECDSA_*` (ASN.1 DER); SM2 keys with `SM2DSA_SM3`, digests
  only (`KMS.0333`); Ed25519 keys with `ED25519_SHA_512` (a `RAW`
  message) or `ED25519_PH_SHA_512` (Ed25519ph, a SHA-512 digest). Another
  pairing is `KMS.0332`. Signatures are Base64; `verify` answers
  `signature_valid` `"true"` or `"false"`. The public key verifies them
  outside KMS too.
- **MACs.** `HMAC_SHA_256`, `HMAC_SHA_384`, `HMAC_SHA_512` and `HMAC_SM3`
  with an HMAC key of that size; `verify-mac` answers `mac_valid`.

## Rotation

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| EnableKeyRotation, DisableKeyRotation | `POST .../enable-key-rotation`, `disable-key-rotation` | Yes | |
| UpdateKeyRotationInterval | `POST .../update-key-rotation-interval` | Yes | 30 to 365 days |
| ShowKeyRotationStatus | `POST .../get-key-rotation-status` | Yes | |
| RotateKeyOnDemand | `POST .../rotate-on-demand` | No | |

Only symmetric keys KMS made, other than default keys, rotate. A key with
rotation enabled gets new material the first time it is used after its
interval (365 days by default) has passed; older material still decrypts
what it encrypted. `number_of_rotations` counts them.

## Tags

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ShowKmsTags, CreateKmsTag, DeleteTag | `GET`, `POST .../{key_id}/tags`; `DELETE .../{key_id}/tags/{key}` | Yes | |
| BatchCreateKmsTags | `POST .../{key_id}/tags/action` | Yes | `action` `create` or `delete` |
| ListKmsTags | `GET .../tags` | Yes | The project's tag keys and values |
| ListKmsByTags | `POST .../resource_instances/action` | Yes | `filter` or `count`; `tags`; `matches` on `resource_name` (the alias); `limit` and `offset` |

A key has at most 20 tags. Keys are 1 to 36 characters, values up to 43,
without control characters or `*<>\=`.

## Grants

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateGrant | `POST .../create-grant` | Yes | `grantee_principal_type` `user` (default) or `domain` |
| ListGrants | `POST .../list-grants` | Yes | `limit` (up to 100) and `marker` |
| CancelGrant (revoke) | `POST .../revoke-grant` | Yes | |
| CancelSelfGrant (retire) | `POST .../retire-grant` | Yes | By the retiring principal, or a grantee allowed `retire-grant` |
| ListRetirableGrants | `POST .../list-retirable-grants` | Yes | The grants the caller may retire |

A grant lets a user, or every caller of another account (`domain`), use
a key for its `operations`: `create-datakey`,
`create-datakey-without-plaintext`, `encrypt-datakey`, `decrypt-datakey`,
`describe-key`, `create-grant`, `retire-grant`, `encrypt-data` and
`decrypt-data` (not `create-grant` alone, `KMS.2401`).

- **A grant is a permission.** Its grantee may perform those operations
  on the key with no IAM policy, also under `-iam=enforce`, as Huawei
  documents grants. Anything else on the key still needs IAM.
- **Another account** names the key by its ID in requests to its own
  project, and decrypts what the key's owner encrypted (and the reverse).
  Without a grant, another account's key is not found (`KMS.0207`).
- Grantees and retiring principals are 1 to 64 letters and digits
  (`KMS.2402`); a key has at most 100 grants (`KMS.2404`). Default keys
  cannot be granted (`KMS.0211`). `issuing_principal` is the user that
  made the grant, or the account for the root user and the administrator.
- Revoking or retiring a grant ends the grantee's access at once.

## Services that use KMS

| Service | What uses a key |
| --- | --- |
| [OBS](obs.md#server-side-encryption) | SSE-KMS objects are encrypted at rest with a data key under the key; disabling or deleting the key makes them unreadable |
| [ECS](ecs.md#disks) and [EVS](evs.md) | Encrypted system and data disks (`__system__cmkid`) |
| [RDS](rds.md#creating-instances) | Encrypted storage (`disk_encryption_id`) |

Each checks that the key exists in the caller's project, is enabled and
is a symmetric encryption key; with none named, OBS and ECS use the
account's `obs/default` and `evs/default` keys, which KMS makes on first
use.

## Quotas

`ShowUserQuotas` (`GET /v1.0/{project_id}/kms/user-quotas`, action
`kms::getQuota`) reports the project's customer master key limit (`kms.CMK`)
and usage, plus the fixed `grant_per_CMK` limit (100). `kms.CMK` is per
project and configurable with `-quotas` (see [Quotas](../quotas.md)).

| Key | Default | Error | Enforced |
| --- | --- | --- | --- |
| `kms.CMK` | 100 | `400 KMS.1105` | Yes |

## Errors

Only codes from Huawei's published DEW error table are used, in KMS's
envelope: `{"error": {"error_code": "KMS.0207", "error_msg": "The key does
not exist."}}`. A key of another project or account is not found
(`KMS.0207`). With `-iam=enforce`, a refused operation is `KMS.0306`
(403), with an `encoded_authorization_message`.

## Permissions

Each operation has the action Huawei's KMS permissions table lists, on
the key `kms:<region>:<account-id>:KeyId:<key-id>`: `kms:cmk:create`,
`kms:cmk:get`, `kms:cmk:encryptData` (in classic policies also
`kms:cmk:crypto` and `kms:cmk:encrypt`), `kms:cmk:createDataKey`
(`kms:dek:create`), and so on. The system permission `KMS Administrator`
grants them all.
