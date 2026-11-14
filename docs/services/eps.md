# EPS coverage

Endpoint: `eps.myhuaweicloud.com` (the region-less host the SDKs use),
`eps.{region}.myhuaweicloud.com`, or the `/eps` path prefix.

WeiStack has one enterprise project, the account's default: ID `0`, named
`default`. It exists so that clients can look it up, and so that IAM can
grant roles in it ([IAM: enterprise projects](iam.md#enterprise-projects)).
Enterprise projects cannot be created, changed or deleted, and resources do
not record one.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListEnterpriseProject | `GET /v1.0/enterprise-projects` | Yes | Filters `id`, `name` (a substring), `status`, `type`; `limit` and `offset` |
| ShowEnterpriseProject, CreateEnterpriseProject, UpdateEnterpriseProject, DeleteEnterpriseProject, resource operations, quotas | `/v1.0/enterprise-projects/...` | No | |

The default project is enabled (`status` 1), of type `prod`, and shown as
created when the emulator started.

EPS's error codes are not emulated, so the list refuses nothing: a `limit`
or `offset` that is not a valid number counts as not given.
