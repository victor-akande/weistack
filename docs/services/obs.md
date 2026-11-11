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
| DeleteBucket | `DELETE /{bucket}` | Yes | |
| Objects, multipart uploads, listing | | No | Next |
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
| `MalformedXML` | 400 | Request body is not valid XML |
| `AccessDenied` | 403 | Bucket belongs to another access key |
| `NoSuchBucket` | 404 | Bucket does not exist |
| `MethodNotAllowed` | 405 | Method not valid for the resource |
| `BucketAlreadyOwnedByYou` | 409 | You already own a bucket of that name |
| `BucketAlreadyExists` | 409 | Another caller owns a bucket of that name |
| `NotImplemented` | 501 | Feature not emulated; the message names it |
| `InternalError` | 500 | Unexpected failure in the emulator |

## Client compatibility

`TestOBSBuckets` in `test/sdk` runs every bucket operation through Huawei's
OBS Go SDK (`huaweicloud-sdk-go-obs`) with OBS, v2 and v4 signatures, in
virtual-hosted and path style.

## Fidelity notes

- Real OBS ties buckets to accounts, not access keys; with no IAM emulated,
  the access key stands in for the account.
- The values of `x-obs-id-2`, `x-obs-version` and the owner ID are
  stand-ins.
- Real OBS redirects a request for a bucket sent to another region's
  endpoint; the emulator serves it.
