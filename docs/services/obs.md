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
| Multipart uploads | `?uploads`, `?uploadId=` | No | Next |
| Browser POST uploads, appendable objects, object ACLs and tags, versions | | No | |
| ACLs, policies, versioning, lifecycle, CORS, tags, website, logging, quota, storage info, encryption, replication | `?acl`, `?policy`, ... | No | |

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
- **Ownership follows the access key.** Signatures are not verified, but the
  access key a request claims is its identity: it owns the buckets it
  creates, lists only those, and gets `AccessDenied` on anyone else's.
  Requests without credentials share one `anonymous` identity. The owner ID
  shown in listings is derived from the access key, never the key itself.

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
- A bucket can only be deleted when it holds no objects (`BucketNotEmpty`).

## Storage

Bucket and object metadata are in the emulator's store. Object bodies are
files, streamed to and from disk: under `{data-dir}/objects` with
`-persist`, otherwise in a temporary directory removed when the emulator
stops. `POST /_weistack/reset` removes them.

## Error codes

Errors are S3-style XML: `<Error><Code>..</Code><Message>..</Message>
<RequestId>..</RequestId><HostId>..</HostId><Resource>..</Resource></Error>`.
A `HEAD` error has no body; the code and message are in the
`x-obs-error-code` / `x-obs-error-message` headers (or `x-amz-`).

| Code | HTTP | When |
| --- | --- | --- |
| `InvalidBucketName` | 400 | Name breaks the naming rules |
| `InvalidLocationConstraint` | 400 | Location differs from the endpoint's region |
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
| `BucketNotEmpty` | 409 | Deleting a bucket that still has objects |
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
- Listing reads every key of the bucket for each page. That is fine for
  thousands of objects; it is not built for millions.
- Real OBS redirects a request for a bucket sent to another region's
  endpoint; the emulator serves it.
