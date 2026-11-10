# VPC coverage

Endpoint: `vpc.{region}.myhuaweicloud.com`, or the `/vpc` path prefix.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

## VPCs (v1)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateVpc | `POST /v1/{project_id}/vpcs` | Yes | `tags` accepted and ignored |
| ShowVpc | `GET /v1/{project_id}/vpcs/{vpc_id}` | Yes | |
| ListVpcs | `GET /v1/{project_id}/vpcs` | Yes | Filters `id`, `enterprise_project_id`; `marker`/`limit` |
| UpdateVpc | `PUT /v1/{project_id}/vpcs/{vpc_id}` | Yes | |
| DeleteVpc | `DELETE /v1/{project_id}/vpcs/{vpc_id}` | Yes | |
| VPC v3 API | `/v3/{project_id}/vpc/vpcs...` | No | |

Behaviour:

- A new VPC is `CREATING` and becomes `OK` after the lifecycle delay. It
  cannot be deleted while `CREATING` (`VPC.0103`).
- Names are optional, at most 64 characters (letters, digits, `_`, `-`, `.`)
  and unique within a project when not empty (`VPC.0115`).
- `cidr` is optional. When set it must be a canonical IPv4 block with a mask
  of 8 to 24 bits, outside `0.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
  `169.254.0.0/16`, `198.18.0.0/15`, `214.0.0.0/7` and `240.0.0.0/4`.

## Error codes

Errors of the v1 API are `{"code": "...", "message": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `VPC.0101` | 400 | Invalid body, field, ID, `limit` or `marker` |
| `VPC.0115` | 400 | VPC name already used in the project |
| `VPC.0105` | 404 | VPC does not exist |
| `VPC.0103` | 409 | VPC is still being created |

## Fidelity notes

Golden files under `internal/services/vpc/testdata/golden` are provisional:
they come from the SDK models and the API reference, not from recorded
traffic. Known open points:

- Which code a missing VPC returns (`VPC.0105` chosen from the error table's
  grouping) and the exact message texts are unverified.
- Real Huawei Cloud enforces a per-project VPC quota (`VPC.0114`); the
  emulator has no VPC quota yet.
