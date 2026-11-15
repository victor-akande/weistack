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
| ShowUserInstances, ShowUserQuotas | `GET .../user-instances`, `user-quotas` | Yes | 100 keys per project |
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
| EncryptData, DecryptData | `POST .../encrypt-data`, `decrypt-data` | Yes | Symmetric keys (`SYMMETRIC_DEFAULT`) |
| CreateDatakey, CreateDatakeyWithoutPlaintext | `POST .../create-datakey`, `create-datakey-without-plaintext` | Yes | `datakey_length` 8 to 8,192 bits, or `key_spec` |
| EncryptDatakey, DecryptDatakey | `POST .../encrypt-datakey`, `decrypt-datakey` | Yes | |
| CreateRandom | `POST .../gen-random` | Yes | 512 bits |
| Asymmetric encryption, Sign, ValidateSignature, GenerateMac, VerifyMac, ShowPublicKey, data key pairs, ReEncrypt | | No | |

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
