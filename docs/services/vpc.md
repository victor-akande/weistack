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

## Subnets (v1)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSubnet | `POST /v1/{project_id}/subnets` | Yes | `tags` accepted and ignored |
| ShowSubnet | `GET /v1/{project_id}/subnets/{subnet_id}` | Yes | |
| ListSubnets | `GET /v1/{project_id}/subnets` | Yes | Filter `vpc_id`; `marker`/`limit` |
| UpdateSubnet | `PUT /v1/{project_id}/vpcs/{vpc_id}/subnets/{subnet_id}` | Yes | Returns `id` and `status` only, as the real API does |
| DeleteSubnet | `DELETE /v1/{project_id}/vpcs/{vpc_id}/subnets/{subnet_id}` | Yes | |
| Private IP API | `/v1/{project_id}/privateips...` | No | Addresses are allocated internally for ECS and RDS |

Behaviour:

- A new subnet is `UNKNOWN` and becomes `ACTIVE` after the lifecycle delay.
- `name`, `cidr`, `gateway_ip` and `vpc_id` are required. The CIDR must be a
  canonical IPv4 block with a mask of at most 29 bits, inside the VPC's block
  and not overlapping a sibling subnet. The gateway must be inside the
  subnet and not its network or broadcast address.
- A subnet's `id` equals its `neutron_network_id`, as in the real v1 API.
- `ipv6_enable` adds `cidr_v6`, `gateway_ip_v6` and `neutron_subnet_id_v6`
  with values from the documentation prefix `2001:db8::/32`. Nothing is
  routed.
- **Private IP allocation.** Each subnet reserves its network address, its
  gateway, its broadcast address and the two addresses below the broadcast
  address, so a `/24` has 251 usable addresses. Addresses are handed out
  lowest-free-first and `available_ip_address_count` tracks them.
- A VPC cannot be deleted while it has subnets, and its CIDR cannot be
  changed to a block that no longer covers them. A subnet cannot be deleted
  while any of its addresses is allocated.

## Security groups (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSecurityGroup | `POST /v3/{project_id}/vpc/security-groups` | Yes | `dry_run` supported |
| ShowSecurityGroup | `GET /v3/{project_id}/vpc/security-groups/{id}` | Yes | Includes the group's rules |
| ListSecurityGroups | `GET /v3/{project_id}/vpc/security-groups` | Yes | Filters `id`, `name`, `description` (repeatable), `enterprise_project_id`; `marker`/`limit`; `page_info` |
| UpdateSecurityGroup | `PUT /v3/{project_id}/vpc/security-groups/{id}` | Yes | `dry_run` supported |
| DeleteSecurityGroup | `DELETE /v3/{project_id}/vpc/security-groups/{id}` | Partial | No "in use by a port" check until ECS exists |
| Security groups v1 / Neutron v2.0 | `/v1/{project_id}/security-groups`, `/v2.0/security-groups` | No | |

## Security group rules (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSecurityGroupRule | `POST /v3/{project_id}/vpc/security-group-rules` | Partial | `remote_address_group_id` always fails: IP address groups are not emulated |
| ShowSecurityGroupRule | `GET /v3/{project_id}/vpc/security-group-rules/{id}` | Yes | |
| ListSecurityGroupRules | `GET /v3/{project_id}/vpc/security-group-rules` | Yes | All documented filters; `marker`/`limit`; `page_info` |
| DeleteSecurityGroupRule | `DELETE /v3/{project_id}/vpc/security-group-rules/{id}` | Yes | |
| BatchCreateSecurityGroupRules | `POST .../security-groups/{id}/security-group-rules/batch-create` | No | |

Behaviour:

- Every project owns a `default` security group, created the first time
  security groups are used in the project. It cannot be deleted.
- A new group gets four rules at priority 100: allow all egress and allow
  ingress from the group itself, each for IPv4 and IPv6.
- Rule defaults: `ethertype` IPv4, `action` allow, `priority` 1 (range
  1 to 100), `enabled` true. An empty `protocol` means all protocols;
  otherwise `tcp`, `udp`, `icmp` (IPv4 only), `icmpv6` (IPv6 only) or a
  number from 0 to 255. `multiport` needs `tcp` or `udp` and accepts `80`,
  `1-30` or `22,3389,80`.
- `remote_ip_prefix`, `remote_group_id` and `remote_address_group_id` are
  mutually exclusive. A bare address gains a full-length mask and host bits
  are cleared (`10.1.2.3/16` is stored as `10.1.0.0/16`).
- A rule identical to an existing rule of the group is rejected.
- Deleting a group deletes its rules and any rule of another group that
  names it as `remote_group_id`.
- `dry_run: true` validates the request and returns `202` with code
  `SYS.0202`; nothing is created.

## Error codes

Errors of the v1 API (VPCs, subnets) are `{"code": "...", "message": "..."}`.
Errors of the v3 API (security groups) are
`{"request_id": "...", "error_code": "...", "error_msg": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `VPC.0101` | 400 | Invalid body, field, ID, `limit` or `marker` |
| `VPC.0115` | 400 | VPC name already used in the project |
| `VPC.0105` | 404 | VPC does not exist |
| `VPC.0103` | 409 | VPC is still being created |
| `VPC.0104` | 409 | Deleting a VPC that has subnets |
| `VPC.0117` | 400 | New VPC CIDR does not cover an existing subnet |
| `VPC.0003` | 404 | `vpc_id` of a new subnet does not exist |
| `VPC.0201` | 400 | Invalid subnet body, field, ID, `limit` or `marker` |
| `VPC.0212` | 400 | Subnet CIDR malformed or mask longer than 29 bits |
| `VPC.0203` | 400 | Subnet CIDR outside the VPC CIDR |
| `VPC.0204` | 400 | Subnet CIDR overlaps a sibling subnet |
| `VPC.0207` | 400 | Subnet does not belong to the VPC in the path |
| `VPC.0202` | 404 | Subnet does not exist |
| `VPC.0205` | 500 | Subnet is still being created |
| `VPC.0208` | 500 | Deleting a subnet with private IPs in use |
| `VPC.9902` | 400 | Invalid security group or rule request |
| `VPC.9902` | 409 | Duplicate rule; deleting the default security group |
| `VPC.9904` | 404 | Security group, rule, remote group or address group does not exist |

## Fidelity notes

Golden files under `internal/services/vpc/testdata/golden` are provisional:
they come from the SDK models and the API reference, not from recorded
traffic. Known open points:

- Which code a missing VPC returns (`VPC.0105` chosen from the error table's
  grouping) and the exact message texts are unverified.
- The API reference lists `VPC.0205` and `VPC.0208` with HTTP 500 and
  `VPC.0202` with 500; the emulator follows it for the first two and returns
  404 for a missing subnet, which is what clients test for.
- The longest subnet mask is given as both 28 and 29 bits in the reference;
  the emulator accepts up to 29.
- The reference documents `VPC.9902` only for a bad ethertype (400) and for
  conflicts (409); the emulator uses it for every invalid v3 request.
- Whether real Huawei Cloud cascades the deletion of rules that reference a
  deleted group, as OpenStack Neutron does, is unverified.
- Real Huawei Cloud enforces per-project quotas for VPCs (`VPC.0114`),
  security groups and rules (`VPC.9905`); the emulator has none yet.
