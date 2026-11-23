# OBS coverage

OBS is S3-compatible object storage with its own dialect. WeiStack serves
both dialects from one handler written for this project; it does not embed
MinIO (AGPL) or gofakes3 (which has no OBS support and would add the AWS SDK
to the binary).

Legend: **Yes** implemented, **No** returns `501 NotImplemented`.

| Operation | Request | Status | Notes |
| --- | --- | --- | --- |
| ListBuckets | `GET /` | Yes | The caller's buckets, sorted by name |
| CreateBucket | `PUT /{bucket}` | Yes | Optional location body |
| HeadBucket | `HEAD /{bucket}` | Yes | |
| GetBucketLocation | `GET /{bucket}?location` | Yes | |
| DeleteBucket | `DELETE /{bucket}` | Yes | Must be empty |
| PutObject | `PUT /{bucket}/{key}` | Yes | Streamed to disk; `Content-MD5` checked; `aws-chunked` decoded |
| GetObject | `GET /{bucket}/{key}` | Yes | Single `Range`; conditional headers; `response-*` overrides |
| HeadObject | `HEAD /{bucket}/{key}` | Yes | |
| CopyObject | `PUT /{bucket}/{key}` with `x-obs-copy-source` | Yes | `COPY` or `REPLACE` metadata directive |
| DeleteObject | `DELETE /{bucket}/{key}` | Yes | |
| DeleteObjects | `POST /{bucket}?delete` | Yes | Up to 1000 keys; quiet mode |
| ListObjects | `GET /{bucket}` | Yes | `prefix`, `delimiter`, `marker`, `max-keys`, `encoding-type` |
| ListObjectsV2 | `GET /{bucket}?list-type=2` | Yes | `continuation-token`, `start-after`, `fetch-owner` |
| InitiateMultipartUpload | `POST /{bucket}/{key}?uploads` | Yes | |
| UploadPart | `PUT /{bucket}/{key}?partNumber=N&uploadId=ID` | Yes | |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId=ID` | Yes | |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId=ID` | Yes | |
| ListParts | `GET /{bucket}/{key}?uploadId=ID` | Yes | `max-parts`, `part-number-marker` |
| ListMultipartUploads | `GET /{bucket}?uploads` | Partial | `prefix`, `key-marker`, `upload-id-marker`, `max-uploads`; `delimiter`: `501` |
| UploadPartCopy | `PUT ...?uploadId=` with a copy source | No | |
| Browser POST uploads, appendable objects, object ACLs and tags, versions | | No | |
| Bucket configuration reads | `GET /{bucket}?acl`, `?policy`, `?versioning`, ... | Yes | See "Bucket configuration" |
| Bucket configuration writes | `PUT` or `DELETE /{bucket}?acl`, `?policy`, ... | No | |
| Replication, inventory, object lock, direct cold access | `?replication`, `?inventory`, ... | No | |

## Addressing

| Style | Example |
| --- | --- |
| Virtual-hosted | `http://my-bucket.obs.ap-southeast-1.myhuaweicloud.com/key` |
| Path | `http://obs.ap-southeast-1.myhuaweicloud.com/my-bucket/key` |
| Local, virtual-hosted | `http://my-bucket.obs.localhost:8780/key` |
| Local, path | `http://obs.localhost:8780/my-bucket/key` or `http://localhost:8780/obs/my-bucket/key` |

A bucket name may contain periods; in the virtual-hosted style everything
before the `obs` label is the bucket.

## Dialects

The dialect is chosen per request:

| | OBS | S3 |
| --- | --- | --- |
| Selected by | `Authorization: OBS ...`, or no AWS evidence | `Authorization: AWS ...` / `AWS4-HMAC-SHA256 ...`, or any `x-amz-` header |
| Vendor headers | `x-obs-request-id`, `x-obs-id-2`, ... | `x-amz-request-id`, `x-amz-id-2`, ... |
| XML namespace | `http://obs.myhwclouds.com/doc/2015-06-30/` | `http://s3.amazonaws.com/doc/2006-03-01/` |
| Bucket listing | includes `Location` and `BucketType` | includes owner `DisplayName` |
| Location response | `<Location>` | `<CreateBucketConfiguration><LocationConstraint>` |

Huawei's OBS SDK uses the S3 dialect by default (signature `v2`) and the OBS
dialect with `obs.WithSignature(obs.SignatureObs)`.

## Buckets and owners

- Bucket names are global, as in the real service: one namespace across all
  regions and callers. Names have 3 to 63 characters of lowercase letters,
  digits, hyphens and periods, start and end with a letter or digit, are not
  shaped like an IP address, and have no `..`, `.-` or `-.`.
- A bucket's region is that of the endpoint it was created through. A
  location in the request body must name the same region.
- **Credentials.** By default signatures are not verified. With
  `-iam=enforce`, OBS and S3 v2 signatures and S3 signature version 4
  are, in the `Authorization` header and in pre-signed URLs (see
  [Checking credentials](../enforce.md)), and so is each
  chunk of an `aws-chunked` upload. Failures get OBS's documented codes:
  `InvalidAccessKeyId`, `SignatureDoesNotMatch` (also for a chunk, which
  ends the upload), `RequestTimeTooSkewed` (a clock more than 15 minutes
  off), `AccessDenied` (no credentials, no date, or an expired URL),
  `TooManyWrongSignature` (a locked key) and `ContentSHA256Mismatch` (a
  body whose SHA-256 is not the `x-amz-content-sha256` the client sent;
  nothing is stored).
- **Ownership follows the access key.** A key WeiStack knows (the
  administrator's or an IAM user's) acts for the account, so all of them
  share the account's buckets, as on Huawei Cloud. Any other key, as
  before, is an owner of its own: it owns the buckets it creates, lists
  only those, and gets `AccessDenied` on anyone else's. Requests without
  credentials share one `anonymous` identity. The owner ID shown in
  listings is the account's, or one derived from the key, never the key
  itself.

## Bucket configuration

WeiStack stores no bucket configuration but default encryption (see
[Server-side encryption](#server-side-encryption)), so every bucket is
otherwise in the state of a bucket nobody has configured. Reading
configuration returns what OBS returns for such a bucket. Tools that read everything after a create, such
as Terraform's `huaweicloud_obs_bucket`, therefore work.

| Subresource | Answer |
| --- | --- |
| `?acl` | The owner has `FULL_CONTROL` |
| `?versioning`, `?logging`, `?notification`, `?customdomain` | An empty document: unversioned, no logging, no notifications, no custom domains |
| `?quota` | `StorageQuota` 0, meaning no quota |
| `?storageinfo` | The bucket's real size and object count |
| `?storageClass` (OBS), `?storagePolicy` (S3) | `STANDARD` |
| `?requestPayment` | `BucketOwner` |
| `?policy`, `?lifecycle`, `?cors`, `?tagging`, `?website` | `404` `NoSuchBucketPolicy`, `NoSuchLifecycleConfiguration`, `NoSuchCORSConfiguration`, `NoSuchTagSet`, `NoSuchWebsiteConfiguration` |
| `?encryption` | The default encryption, set with `PUT` and removed with `DELETE`; without one, `404` `NoSuchEncryptionConfiguration`, or `ServerSideEncryptionConfigurationNotFoundError` in the S3 dialect |

## Objects

- Keys are at most 1024 bytes. Any character may appear in a key; encode it
  in the URL as usual.
- **Upload.** The body is written to a temporary file as it arrives and moved
  into place only when complete, so a failed or aborted upload leaves
  nothing behind and nothing large is held in memory. The ETag is the MD5 of
  the body. A `Content-MD5` header is checked (`BadDigest`). AWS SDK uploads
  in `aws-chunked` encoding (signed or unsigned, with or without trailing
  checksums) have their framing removed, and `aws-chunked` is dropped from
  the stored `Content-Encoding`.
- **Stored with the object:** `Content-Type` (default
  `binary/octet-stream`), `Cache-Control`, `Content-Disposition`,
  `Content-Encoding`, `Content-Language`, `Expires`, and user metadata from
  `x-obs-meta-*` or `x-amz-meta-*` headers. Metadata names are lowercased
  and returned with the caller's dialect prefix.
- **Overwrite** replaces the body and all metadata.
- **Download.** One byte range is honoured (`bytes=a-b`, `bytes=a-`,
  `bytes=-n`); a malformed range or several ranges serve the whole object, as
  S3 does, and a range starting past the end is `InvalidRange` (416).
  `If-Match`, `If-None-Match`, `If-Modified-Since` and `If-Unmodified-Since`
  give 412 or 304. `response-content-type` and the other `response-*` query
  parameters override the response headers.
- **Copy** within or across the caller's buckets. With the default `COPY`
  directive the source's metadata is kept; with `REPLACE` it is taken from
  the request. Copying an object onto itself is only allowed with
  `REPLACE`, which is how metadata is edited. The copy is independent of its
  source.
- **Delete** of a missing key succeeds, as in S3. `DeleteObjects` reports
  every key, or with `<Quiet>true</Quiet>` only failures.
- **List.** Keys come back in byte order. A `delimiter` rolls keys that
  contain it after the `prefix` into one `CommonPrefixes` entry, which
  counts as one entry towards `max-keys` (at most 1000, the default). Both
  listing versions page correctly with any page size: v1 by `NextMarker`,
  v2 by `NextContinuationToken`. With `encoding-type=url`, keys, prefixes
  and delimiters are percent-encoded, slashes kept.
- A bucket can only be deleted when it holds no objects and no multipart
  uploads in progress (`BucketNotEmpty`).
- One request uploads at most 5 GB (`EntityTooLarge`); larger objects are
  uploaded in parts.

## Multipart uploads

- `InitiateMultipartUpload` takes the object's `Content-Type`, stored
  headers and user metadata, and returns an upload ID of 32 uppercase hex
  characters.
- Parts are numbered 1 to 10,000 and may be uploaded in any order and in
  parallel. Uploading a part number again replaces it. A part's ETag is its
  MD5.
- `CompleteMultipartUpload` lists the parts to keep, in ascending order
  (`InvalidPartOrder`), each with its ETag (`InvalidPart`). Every part but
  the last must be at least **100 KB**, the OBS 3.0 rule, checked at
  completion (`EntityTooSmall`); S3 clients, which use 5 MiB parts, are
  unaffected. Parts not listed are discarded.
- The parts are assembled into one object by streaming, one file at a time.
  Its ETag is the MD5 of the parts' binary MD5s followed by `-` and the
  number of parts, as in S3. While assembly runs, the upload cannot be
  changed, aborted or completed again; if it fails the upload is released
  unchanged.
- Uploads survive a restart with `-persist`, so a resumable client can
  continue after one.

## Server-side encryption

| Request header | Values |
| --- | --- |
| `x-obs-server-side-encryption` (S3: `x-amz-server-side-encryption`) | `kms` (S3: `aws:kms`) or `AES256` |
| `x-obs-server-side-encryption-kms-key-id` (S3: `x-amz-server-side-encryption-aws-kms-key-id`) | A [KMS](kms.md) key ID, or `<region>:<account-id>:key/<key-id>`; none means the account's `obs/default` key, made on first use |
| `x-obs-server-side-data-encryption` | `AES256` (default) or `SM4`, with `kms` |

They apply to `PutObject`, `CopyObject` (for the copy),
`InitiateMultipartUpload` (for every part and the object) and
`CreateBucket` (as the bucket's default). An object written without them
takes the bucket's default encryption (`?encryption`), if any.

- **SSE-KMS encrypts at rest.** Each object, or multipart upload, gets
  its own data key from KMS, kept sealed beside it, and its body is stored
  encrypted with it (AES-256 or SM4 in CTR mode, so a range is read
  without the rest). A download asks KMS to open the data key: while the
  key is disabled or pending deletion the object cannot be read
  (`KMS.DisabledException`, 400), and once the key is deleted, never again
  (`KMS.NotFoundException`). An unknown key on upload is
  `KMS.NotFoundException`.
- **SSE-OBS** (`AES256`), whose keys OBS manages, is recorded and
  reported, but the body is stored as given.
- The response to an upload, a download and a `HEAD` carries the
  encryption headers back: the algorithm and, for SSE-KMS, the key as
  `<region>:<account-id>:key/<key-id>`.
- A copy is encrypted as its request or the target bucket says, not as
  its source: an encrypted source is decrypted and the copy encrypted
  with a data key of its own.
- With `-iam=enforce`, using a key also needs the KMS permission OBS
  depends on: `kms:cmk:createDataKey` to write, `kms:cmk:decryptDataKey`
  to read.
- SSE-C (customer-provided keys) is `501`. HTTPS is not required, unlike
  on Huawei Cloud.

## Storage

Bucket and object metadata are in the emulator's store. Object bodies are
files, streamed to and from disk: under `{data-dir}/objects` with
`-persist`, otherwise in a temporary directory removed when the emulator
stops. `POST /_weistack/reset` removes them.

## Quotas

Bucket count is enforced per account across all regions and configurable
with `-quotas` (see [Quotas](../quotas.md)). OBS has no quota API for
account bucket counts (the per-bucket `?quota` subresource reports storage
quota). Re-creating a bucket the account already owns keeps its existing
`409 BucketAlreadyOwnedByYou` response.

| Key | Default | Error | Enforced |
| --- | --- | --- | --- |
| `obs.buckets` | 100 | `400 TooManyBuckets` | Yes |

## Error codes

Errors are S3-style XML: `<Error><Code>..</Code><Message>..</Message>
<RequestId>..</RequestId><HostId>..</HostId><Resource>..</Resource></Error>`.
A `HEAD` error has no body; the code and message are in the
`x-obs-error-code` / `x-obs-error-message` headers (or `x-amz-`).

| Code | HTTP | When |
| --- | --- | --- |
| `InvalidBucketName` | 400 | Name breaks the naming rules |
| `InvalidLocationConstraint` | 400 | Location differs from the endpoint's region |
| `TooManyBuckets` | 400 | Account has reached its bucket quota (`obs.buckets`) |
| `MalformedXML` | 400 | Request body is not valid XML, or a batch delete names no key or more than 1000 |
| `InvalidArgument` | 400 | Bad `max-keys`, `encoding-type`, continuation token, copy source or metadata directive |
| `InvalidRequest` | 400 | Copying an object onto itself without `REPLACE` |
| `InvalidDigest` | 400 | `Content-MD5` is not a base64 MD5 |
| `BadDigest` | 400 | Body does not match `Content-MD5` |
| `IncompleteBody` | 400 | Chunked body malformed or shorter than declared |
| `KeyTooLongError` | 400 | Key longer than 1024 bytes |
| `AccessDenied` | 403 | Bucket belongs to another access key |
| `NoSuchBucket` | 404 | Bucket does not exist |
| `NoSuchKey` | 404 | Object does not exist |
| `MethodNotAllowed` | 405 | Method not valid for the resource |
| `BucketAlreadyOwnedByYou` | 409 | You already own a bucket of that name |
| `BucketAlreadyExists` | 409 | Another caller owns a bucket of that name |
| `BucketNotEmpty` | 409 | Deleting a bucket that still has objects or multipart uploads |
| `NoSuchUpload` | 404 | Upload ID unknown, for another key, aborted or completed |
| `InvalidPart` | 400 | A listed part was not uploaded, or its ETag differs |
| `InvalidPartOrder` | 400 | Listed parts are not in ascending order |
| `EntityTooSmall` | 400 | A part other than the last is under 100 KB |
| `EntityTooLarge` | 400 | One request uploads more than 5 GB |
| `PreconditionFailed` | 412 | `If-Match` or `If-Unmodified-Since` failed |
| `InvalidRange` | 416 | Range starts past the end of the object |
| `NotImplemented` | 501 | Feature not emulated; the message names it |
| `InternalError` | 500 | Unexpected failure in the emulator |

## Client compatibility

Two SDKs drive the emulator in `test/sdk`:

- **Huawei's OBS Go SDK** (`huaweicloud-sdk-go-obs`). `TestOBSBuckets` runs
  every bucket operation with OBS, v2 and v4 signatures, virtual-hosted and
  path style. `TestOBSObjects` runs plan scenario 3 (multipart aside) in
  both dialects: upload with metadata, list by prefix and delimiter, page
  by marker, download whole and by range, copy, the `BucketNotEmpty`
  dependency error, batch delete and bucket deletion.
- **The AWS SDK for Go v2.** `TestS3Compatibility` covers the same ground
  with signature v4, a 1 MiB upload, `ListObjectsV2` through the SDK's
  paginator with URL-encoded keys, and the error codes as the SDK decodes
  them.
- **Multipart.** `TestOBSLargeMultipartUpload` completes scenario 3: a
  100 MB file sent with the OBS SDK's resumable `UploadFile` (10 MB parts,
  4 in parallel, checkpoint file), read back whole and by a range across a
  part boundary, and compared byte for byte. `TestOBSMultipartCalls` (both
  dialects) and `TestS3MultipartCalls` drive every multipart operation
  directly, including `EntityTooSmall`, abort and `BucketNotEmpty`.

Measured on the release binary: a 100 MB upload and download raise peak
memory from 9.8 MB idle to 10.8 MB.

The AWS SDK only sends `aws-chunked` uploads over TLS, which the emulator
does not serve yet; that decoding is covered by unit tests built from the
documented wire format.

## Fidelity notes

- Real OBS ties buckets to accounts, not access keys; with no IAM emulated,
  the access key stands in for the account.
- The values of `x-obs-id-2`, `x-obs-version` and the owner ID are
  stand-ins.
- Real OBS serves `ListObjects` beyond 1000 entries per page in some
  configurations and reports `Location` in listings; the emulator caps at
  1000 and omits it.
- Real OBS also enforces the 100 KB minimum at completion; whether it
  reports `EntityTooSmall` with exactly this code and status is unverified.
- Listing reads every key of the bucket for each page. That is fine for
  thousands of objects; it is not built for millions.
- Real OBS redirects a request for a bucket sent to another region's
  endpoint; the emulator serves it.
