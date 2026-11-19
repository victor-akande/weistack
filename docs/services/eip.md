# EIP coverage

Endpoint: `vpc.{region}.myhuaweicloud.com`, or the `/vpc` path prefix. EIP
shares the [VPC](vpc.md) endpoint and has no host of its own.

Elastic IPs are state only: addresses come from documentation ranges and
nothing is routed.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

## Elastic IPs (v1)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePublicip | `POST /v1/{project_id}/publicips` | Partial | IPv4 only (`ip_version: 6` returns `501 WeiStack.0501`) |
| ShowPublicip | `GET /v1/{project_id}/publicips/{publicip_id}` | Yes | |
| ListPublicips | `GET /v1/{project_id}/publicips` | Yes | Filters `id` (repeatable), `port_id`, `public_ip_address`, `private_ip_address`, `ip_version`, `enterprise_project_id` (including `all_granted_eps`); `marker`/`limit` (default 2000) |
| UpdatePublicip | `PUT /v1/{project_id}/publicips/{publicip_id}` | Yes | Bind or unbind `port_id`; rename `alias`; `ip_version: 4` accepted as no-op |
| DeletePublicip | `DELETE /v1/{project_id}/publicips/{publicip_id}` | Yes | Must be unbound and not `PENDING_CREATE` |

Behaviour:

- **Lifecycle.** A new EIP starts in `PENDING_CREATE` and moves to `ACTIVE`
  (when created with a `port_id`) or `DOWN` (when unbound) after the
  lifecycle delay. Binding, unbinding or deleting while `PENDING_CREATE`
  returns `VPC.0512`. After creation, binding sets `ACTIVE` and unbinding
  sets `DOWN` immediately.
- **Types by region.** `5_bgp` is valid in every region except
  `cn-southwest-2`. `5_sbgp` is valid in `cn-south-1`, `cn-east-3`,
  `cn-east-2`, `cn-north-1`, `cn-north-4` and `cn-southwest-2`, where it is
  the only accepted type.
- **Aliases and enterprise projects.** `alias` is optional, 1 to 64
  characters from `[A-Za-z0-9_.-]`. `enterprise_project_id` defaults to
  `"0"` and accepts `"0"` or a UUID (`VPC.0011`).
- **Binding.** `port_id` must name a port of the same project (a NIC of an
  [ECS](ecs.md) server). An EIP binds to at most one port (`VPC.0510`) and
  a port takes at most one EIP (`VPC.0511`). On `UpdatePublicip`,
  `port_id: ""`, `port_id: null` or an empty `{"publicip": {}}` object
  unbinds the EIP; omitting `port_id` while updating `alias` leaves the
  binding intact. A bound EIP cannot be deleted (`VPC.0517`).
- **Response fields.** `CreatePublicip` returns `status: "PENDING_CREATE"`,
  `bandwidth_size: 0`, `ip_version: 4` and `public_border_group: "center"`.
  `ShowPublicip` and `ListPublicips` populate the bandwidth fields, `tags`
  as `"key=value"` strings, and `port_id` and `private_ip_address` when
  bound.
- **Quota.** 50 EIPs per project by default, configured with
  `-eip-max-per-project` (`WEISTACK_EIP_MAX_PER_PROJECT`). Reaching the
  limit returns `VPC.0521`.

## Address pool

EIP addresses are allocated per region from `192.0.2.0/24`,
`198.51.100.0/24` and `203.0.113.0/24` (`.1` to `.254` in order: 762
addresses per region).

- Claims are unique across all projects and accounts in a region.
- An explicit `ip_address` on create must fall inside one of those ranges
  and be free; otherwise `VPC.0522` is returned.
- When the region's pool is exhausted, create returns `VPC.0532`.
- Deleting an EIP releases its address back to the pool immediately.

## Bandwidths (v1 and v2.0)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListBandwidths | `GET /v1/{project_id}/bandwidths` | Yes | Filters `share_type`, `enterprise_project_id` (including `all_granted_eps`); `marker`/`limit` (default 2000) |
| ShowBandwidth | `GET /v1/{project_id}/bandwidths/{bandwidth_id}` | Yes | |
| UpdateBandwidth | `PUT /v1/{project_id}/bandwidths/{bandwidth_id}` | Yes | Optional `name`, `size`, `charge_mode` |
| CreateSharedBandwidth | `POST /v2.0/{project_id}/bandwidths` | Yes | `share_type: WHOLE`; `size` 5 to 2000 Mbit/s |
| UpdatePrePaidBandwidth | `PUT /v2.0/{project_id}/bandwidths/{bandwidth_id}` | Yes | Same fields as v1 update (`extendParam` accepted and ignored) |
| DeleteSharedBandwidth | `DELETE /v2.0/{project_id}/bandwidths/{bandwidth_id}` | Yes | Empty `WHOLE` bandwidths only |
| AddPublicipsIntoSharedBandwidth | `POST /v2.0/{project_id}/bandwidths/{bandwidth_id}/insert` | Yes | Moves `PER`-bandwidth EIPs into a `WHOLE` bandwidth atomically |
| RemovePublicipsFromSharedBandwidth | `POST /v2.0/{project_id}/bandwidths/{bandwidth_id}/remove` | Yes | Returns 204; creates a new `PER` bandwidth per removed EIP |

Behaviour:

- **Dedicated (`PER`) and shared (`WHOLE`).** Every EIP belongs to one
  bandwidth. A `PER` bandwidth (`bandwidth_type: "bgp"`, size 1 to 300
  Mbit/s) is created and deleted with its single EIP and cannot be deleted
  directly (`VPC.0323`). A `WHOLE` bandwidth (`bandwidth_type: "share"`,
  size 5 to 2000 Mbit/s) is created independently and holds up to 20 EIPs
  (`VPC.0323`).
- **Quota and deletion.** A project may hold at most 5 shared bandwidths
  (`VPC.0310`). Deleting a shared bandwidth that still contains EIPs
  returns `VPC.0304`.
- **Names and charge modes.** Names are 1 to 64 characters from
  `[A-Za-z0-9_.-]`. `charge_mode` is `bandwidth` (the default) or
  `traffic`. Responses report `status: "NORMAL"`,
  `public_border_group: "center"`, `enable_bandwidth_rules: false`,
  `rule_quota: 0` and `bandwidth_rules: []`.
- **Insert and remove.** Inserting validates every listed EIP before making
  any change: each EIP must exist in the project (`VPC.0301`) and belong to
  a `PER` bandwidth (`VPC.0323`), which is deleted as the EIP joins the
  shared bandwidth. Removing requires `charge_mode` and `size` (1 to 300)
  and gives each removed EIP a new `PER` bandwidth named
  `bandwidth-<first 8 characters of EIP ID>`.

## Tags (v2.0)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePublicipTag | `POST /v2.0/{project_id}/publicips/{publicip_id}/tags` | Yes | Returns 204; overwrites an existing key |
| ShowPublicipTags | `GET /v2.0/{project_id}/publicips/{publicip_id}/tags` | Yes | |
| DeletePublicipTag | `DELETE /v2.0/{project_id}/publicips/{publicip_id}/tags/{key}` | Yes | Returns 204; missing key is a no-op |
| BatchCreatePublicipTags / BatchDeletePublicipTags | `POST /v2.0/{project_id}/publicips/{publicip_id}/tags/action` | Yes | `action` `create` or `delete`; returns 204 |
| ListPublicipsByTags | `POST /v2.0/{project_id}/publicips/resource_instances/action` | Partial | `action` `filter` or `count`, `tags`, `limit`, `offset`; `matches` not emulated |
| ListPublicipTags | `GET /v2.0/{project_id}/publicips/tags` | Yes | All tag keys and distinct values in the project |

Tag keys are 1 to 36 characters and values 0 to 43 (`VPC.0501`), with no
limit on the number of tags per EIP. Creating an existing key replaces its
value, and deleting a key the EIP does not have succeeds with 204.

## Elastic IPs (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListPublicips (v3) | `GET /v3/{project_id}/eip/publicips` | Yes | Query filters; `marker`/`limit` with `page_info` |
| ShowPublicip (v3) | `GET /v3/{project_id}/eip/publicips/{publicip_id}` | Yes | Includes `vnic` (when bound), `bandwidth`, `associate_instance_type`/`id` |
| UpdatePublicip (v3) | `PUT /v3/{project_id}/eip/publicips/{publicip_id}` | Yes | `alias`, `description` (0 to 255 characters), and bind/unbind via `associate_instance_type`/`id` |
| AssociatePublicips | `POST /v3/{project_id}/eip/publicips/{publicip_id}/associate-instance` | Partial | `associate_instance_type` `PORT` only; other instance types return `501 WeiStack.0501` |
| DisassociatePublicips | `POST /v3/{project_id}/eip/publicips/{publicip_id}/disassociate-instance` | Yes | Unbinding an already unbound EIP succeeds |

Behaviour:

- v1 and v3 are views of the same stored EIPs. Every v3 response carries
  `request_id` and uses RFC 3339 UTC timestamps (`created_at`,
  `updated_at`); v1 uses `"2006-01-02 15:04:05"` (`create_time`).
- When bound to a port, `associate_instance_type` is `"PORT"`,
  `associate_instance_id` is the port ID, and `vnic` reports the port's
  `port_id`, `private_ip_address`, `device_id`, `device_owner`, `vpc_id`
  and `mac`.
- `AssociatePublicips` and `UpdatePublicip` accept only
  `associate_instance_type: "PORT"`; other types (`NATGW`, `ELB`, and so
  on) return `501 WeiStack.0501`.

## ECS integration

[ECS](ecs.md) servers use real EIPs from this service:

- **Create with `publicip`.** Passing `publicip.id` binds an existing EIP
  to the server's first NIC. Passing `publicip.eip` creates a new bound
  EIP—with a `PER` bandwidth named `<serverName>-bandwidth-<first 4
  characters of EIP ID>` or joining an existing `WHOLE` bandwidth—and
  records `delete_on_termination`. Any EIP validation or quota failure
  rejects the server create synchronously with `400 Ecs.0005` and rolls
  back the server.
- **Server addresses.** ECS includes a `"floating"` entry in `addresses`
  for every NIC bound to an EIP, including EIPs bound after creation
  through the v1 or v3 EIP API.
- **Delete.** Deleting a server releases an attached EIP if
  `delete_publicip` is true on the delete request or
  `delete_on_termination` was set when the server was created; otherwise
  the EIP is unbound and returns to `DOWN`.

## Not emulated

The following are outside scope; unregistered routes fall through to
`501 WeiStack.0501`:

- Prepaid billing (`/v2.0/{project_id}/publicips`, `change-to-period`)
- IPv6 EIPs (`ip_version: 6`)
- Global EIPs (GEIP) and EIP pools
- Bandwidth add-on packages and bandwidth rules
- Batch EIP and bandwidth operations
- NAT64
- v3 `attach-share-bandwidth` and `detach-share-bandwidth`
- Associating an EIP with non-`PORT` instance types (`NATGW`, `ELB`, etc.)

## Error codes

Errors on v1 and v2.0 routes use `{"code": "...", "message": "..."}`.
Errors on v3 routes use
`{"request_id": "...", "error_code": "...", "error_msg": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `VPC.0011` | 400 | Invalid `enterprise_project_id` |
| `VPC.0301` | 400 | Invalid bandwidth request, name, size, `charge_mode`, `limit`, or unknown `publicip_id` on insert |
| `VPC.0304` | 409 | Deleting a shared bandwidth that still has EIPs |
| `VPC.0306` | 404 | Bandwidth does not exist (or is not `WHOLE` on EIP create) |
| `VPC.0310` | 400 | Shared bandwidth quota exceeded (5 per project) |
| `VPC.0323` | 400 | Deleting a `PER` bandwidth, or invalid insert/remove (not `WHOLE`, EIP already shared or not in bandwidth, or more than 20 EIPs) |
| `VPC.0501` | 400 | Invalid EIP or tag request, type, `ip_version`, `alias`, `port_id` on v1 update, or `limit` |
| `VPC.0504` | 404 | EIP does not exist, or unknown list `marker` |
| `VPC.0508` | 500 | Port does not exist on create or v3 associate |
| `VPC.0510` | 409 | EIP is already bound to a different port |
| `VPC.0511` | 409 | Port is already bound to another EIP |
| `VPC.0512` | 409 | EIP is still `PENDING_CREATE` |
| `VPC.0517` | 409 | Deleting an EIP that is still bound to a port |
| `VPC.0521` | 409 | Per-project EIP quota exceeded (`-eip-max-per-project`) |
| `VPC.0522` | 409 | Requested `ip_address` is outside the pool or already in use |
| `VPC.0532` | 409 | Region address pool is exhausted |
| `EIP.7901` | 400 | Malformed body or invalid parameter on a v3 route |

## Permissions

Each route checks Huawei's EIP action (`eip:publicIps:*`,
`eip:bandwidths:*`) and its classic `vpc:*` alias (`vpc:publicIps:*`,
`vpc:publicipTags:*`, `vpc:bandwidths:*`) against VPC resource URNs
(`vpc:<region>:<account-id>:publicip:<id>` and
`vpc:<region>:<account-id>:bandwidth:<id>`). Under `-iam=enforce`, denials
use the route's v1 or v3 error envelope.

## Client compatibility

Every operation marked **Yes** or **Partial** is exercised through Huawei
Cloud's official Go SDK (`huaweicloud-sdk-go-v3`, `eip/v2` and `eip/v3`
clients) in `test/sdk`, and through Terraform (`huaweicloud_vpc_eip`,
`huaweicloud_vpc_bandwidth`, `huaweicloud_vpc_bandwidth_associate`,
`huaweicloud_vpc_eip_associate`, `huaweicloud_compute_instance`, and the
`huaweicloud_vpc_eip`, `huaweicloud_vpc_eips` and
`huaweicloud_vpc_bandwidth` data sources) in `test/terraform`, in both
default and `-iam=enforce` modes.

## Fidelity notes

Golden files under `internal/services/eip/testdata` are provisional: they
come from the SDK models and the API reference, not from recorded traffic.
Known open points:

- The API reference lists `VPC.0301` on `UpdateBandwidth` with HTTP 401;
  the emulator returns 400 so clients do not re-authenticate.
- No error code is documented for deleting a non-empty shared bandwidth;
  the emulator returns `409 VPC.0304`.
- ECS documents no EIP-specific error code for server creation; EIP errors
  during `CreatePostPaidServers` are returned as `400 Ecs.0005` with the
  EIP error message.
