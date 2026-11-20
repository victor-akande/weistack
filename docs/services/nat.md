# NAT Gateway coverage

Endpoint: `nat.{region}.myhuaweicloud.com`, or the `/nat` path prefix.

Public and private NAT gateways, SNAT and DNAT rules, transit subnets and
transit IPs are control-plane state linked to real [VPC](vpc.md) VPCs,
subnets and [ECS](ecs.md) ports and real [EIP](eip.md) elastic IPs; no
network packets are translated or routed.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

## Public NAT gateways (v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateNatGateway | `POST /v2/{project_id}/nat_gateways` | Partial | Postpaid only (`prepaid_options` returns `501 WeiStack.0501`) |
| ListNatGateways | `GET /v2/{project_id}/nat_gateways` | Yes | All SDK filters (`enterprise_project_id=all_granted_eps` matches all); `marker`/`limit` (default and max 2000); `sort_key`, `sort_dir` and `page_reverse` accepted and ignored |
| ShowNatGateway | `GET /v2/{project_id}/nat_gateways/{nat_gateway_id}` | Yes | |
| UpdateNatGateway | `PUT /v2/{project_id}/nat_gateways/{nat_gateway_id}` | Partial | Optional `name`, `description`, `spec`, `session_conf`; `prepaid_options` returns `501 WeiStack.0501` |
| DeleteNatGateway | `DELETE /v2/{project_id}/nat_gateways/{nat_gateway_id}` | Yes | Requires no SNAT or DNAT rules and status not `PENDING_CREATE` |
| ListNatGatewaySpecs | `GET /v2/{project_id}/nat_gateway_specs` | Yes | Public route (no permission required); returns `{"specs": ["1", "2", "3", "4"]}` |

Behaviour:

- **Lifecycle.** A new public NAT gateway starts in `PENDING_CREATE` and
  moves to `ACTIVE` after the lifecycle delay (`nat.gateway.create`), or to
  `INACTIVE` when a lifecycle fault is injected. Updating or deleting a
  `PENDING_CREATE` gateway, or creating rules on a gateway that is not
  `ACTIVE`, returns `NAT.0103`. Deleting a gateway that still has SNAT or
  DNAT rules returns `NAT.0006`.
- **VPC and subnet IP allocation.** `router_id` must name a VPC of the
  project (`NAT.0004`) and `internal_network_id` a subnet of the project
  (`NAT.0005`) inside that VPC (`NAT.0008`). The gateway reserves
  `ngport_ip_address` (or the lowest free address in the subnet when
  omitted) from the VPC subnet (`NAT.0002` when unusable or already in use,
  `NAT.1404` when the subnet is full) and releases the address when deleted.
  A VPC subnet with an allocated NAT gateway address cannot be deleted.
- **Specs and limits.** `spec` accepts `"1"` (Small), `"2"` (Medium), `"3"`
  (Large), `"4"` (Extra-large) or `"5"` (Extra-xlarge) (`NAT.0016`), each
  reporting `dnat_rules_limit: 200` and `snat_rule_public_ip_limit: 20`.
  `session_conf` fields default to `tcp_session_expire_time: 900`,
  `udp_session_expire_time: 300`, `icmp_session_expire_time: 10` and
  `tcp_time_wait_time: 5` (`NAT.0002` on negative values).
- **Common fields.** `name` is 1 to 64 characters from `[A-Za-z0-9_-]`
  (`NAT.0002`). `description` is at most 255 characters and cannot contain
  `<` or `>` (`NAT.0014`). `enterprise_project_id` defaults to `"0"` and
  accepts `"0"` or a UUID (`VPC.0011`). Create accepts up to 20 `"key*value"`
  tag strings split at the first `*` (`NAT.1015`, `NAT.1016`). Public NAT
  timestamps use `"2006-01-02 15:04:05.000000"` in UTC.

## Public SNAT rules (v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateNatGatewaySnatRule | `POST /v2/{project_id}/snat_rules` | Partial | EIPs only (`global_eip_id` returns `501 WeiStack.0501`) |
| ListNatGatewaySnatRules | `GET /v2/{project_id}/snat_rules` | Yes | All SDK filters (`floating_ip_id` matches any EIP on the rule, `floating_ip_address` matches the joined string); `marker`/`limit` (default and max 2000) |
| ShowNatGatewaySnatRule | `GET /v2/{project_id}/snat_rules/{snat_rule_id}` | Yes | |
| UpdateNatGatewaySnatRule | `PUT /v2/{project_id}/snat_rules/{snat_rule_id}` | Yes | Replaces the rule's EIP pool by comma-separated `public_ip_address` and updates `description` |
| DeleteNatGatewaySnatRule | `DELETE /v2/{project_id}/nat_gateways/{nat_gateway_id}/snat_rules/{snat_rule_id}` | Yes | Releases any EIP no longer used by another rule on the gateway |

Behaviour:

- **Lifecycle.** A new public SNAT rule starts in `PENDING_CREATE` and moves
  to `ACTIVE` after the lifecycle delay (`nat.snat.create`), or to
  `INACTIVE` on a lifecycle fault.
- **Source network or CIDR.** `source_type` is `0` (VPC subnet/CIDR, the
  default) or `1` (Direct Connect / Cloud Connect CIDR) (`NAT.0002`).
  Exactly one of `network_id` or `cidr` must be provided (`NAT.0202`).
  `network_id` requires `source_type: 0` (`NAT.0204`), must be a subnet of
  the project (`NAT.0019`) in the gateway's VPC (`NAT.0008`), cannot
  duplicate an existing rule for that subnet (`NAT.0208`), and cannot overlap
  another rule's CIDR on the gateway (`NAT.0207`). `cidr` must be a
  canonical IPv4 prefix (`NAT.0203`), must be a subset of one of the gateway
  VPC's subnets when `source_type` is `0` (`NAT.0205`), and cannot overlap
  any existing rule's `cidr` or `network_id` subnet on the gateway
  (`NAT.0207`).
- **EIPs.** `floating_ip_id` takes 1 to 20 comma-separated EIP UUIDs
  (`NAT.0210`, `NAT.0211`) without duplicates (`NAT.0403`). On update,
  `public_ip_address` takes 1 to 20 comma-separated EIP addresses in the
  project (`NAT.0026`), holding newly added EIPs and releasing dropped ones.
  An EIP used by a DNAT rule with protocol `any` on the same gateway cannot
  be used by an SNAT rule (`NAT.0409`).

## Public DNAT rules (v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateNatGatewayDnatRule | `POST /v2/{project_id}/dnat_rules` | Partial | EIPs only (`global_eip_id` returns `501 WeiStack.0501`) |
| BatchCreateNatGatewayDnatRules | `POST /v2/{project_id}/dnat_rules/batch` | Partial | Atomic validation across the batch; `global_eip_id` returns `501 WeiStack.0501` |
| ListNatGatewayDnatRules | `GET /v2/{project_id}/dnat_rules` | Yes | All SDK filters; `marker`/`limit` (default and max 2000) |
| ShowNatGatewayDnatRule | `GET /v2/{project_id}/dnat_rules/{dnat_rule_id}` | Yes | |
| UpdateNatGatewayDnatRule | `PUT /v2/{project_id}/dnat_rules/{dnat_rule_id}` | Yes | Revalidates conflicts excluding the rule itself and swaps EIP holds when `floating_ip_id` changes |
| DeleteNatGatewayDnatRule | `DELETE /v2/{project_id}/nat_gateways/{nat_gateway_id}/dnat_rules/{dnat_rule_id}` | Yes | Releases the EIP if no other rule on the gateway uses it |

Behaviour:

- **Lifecycle.** Each new public DNAT rule starts in `PENDING_CREATE` and
  moves to `ACTIVE` after the lifecycle delay (`nat.dnat.create`), or to
  `INACTIVE` on a lifecycle fault.
- **Target.** Exactly one of `port_id` or `private_ip` is required
  (`NAT.0310` when both are empty, `NAT.0317` when both are set). `port_id`
  must name an [ECS](ecs.md) port of the project (`NAT.0023`) in a subnet of
  the gateway's VPC (`NAT.0315`); deleting the ECS server does not delete
  DNAT rules pointing at its port. `private_ip` must be a valid IPv4 address
  (`NAT.0311`) and need not belong to the gateway's VPC.
- **Protocol and ports.** `protocol` accepts `tcp` (or `6`), `udp` (or `17`)
  and `any` (or `0`), stored as the protocol name (`NAT.0302`). Single ports
  (`internal_service_port`, `external_service_port`) are `0` to `65535`
  (`NAT.0303`). `any` requires both ports `0` and no port ranges, and port
  `0` requires `any` (`NAT.0306`). Port ranges
  (`internal_service_port_range`, `external_service_port_range`) take
  `"a-b"` with `1 <= a <= b <= 65535`, must both be given or both omitted
  with equal span (`NAT.0303`), and return the single port fields as `0`.
- **Conflicts and limits.** On a gateway (up to `dnat_rules_limit` rules,
  `NAT.0309`; batch create exceeding remaining capacity returns `NAT.0314`),
  two rules cannot overlap on the same EIP, external port/range and protocol
  (`NAT.0305`) or on the same target (`port_id` or `private_ip`), internal
  port/range and protocol (`NAT.0304`). An `any` (all-port) rule cannot
  coexist on the same `port_id` (`NAT.0307`), `private_ip` (`NAT.0308`) or
  EIP (`NAT.0408`) with any other DNAT rule, nor use an EIP already used by
  an SNAT rule on the gateway (`NAT.0409`).

## Public gateway tags (v3 and v2.0)

Both `/v3/{project_id}` and `/v2.0/{project_id}` serve the six public NAT
gateway tag operations from the same handlers (the Terraform provider uses
`/v2.0`).

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ShowNatGatewayTag | `GET /{v3,v2.0}/{project_id}/nat_gateways/{nat_gateway_id}/tags` | Yes | |
| CreateNatGatewayTag | `POST /{v3,v2.0}/{project_id}/nat_gateways/{nat_gateway_id}/tags` | Yes | Returns 204; overwrites an existing key |
| DeleteNatGatewayTag | `DELETE /{v3,v2.0}/{project_id}/nat_gateways/{nat_gateway_id}/tags/{key}` | Yes | Returns 204; missing key returns `400 NAT.0002` |
| BatchCreateDeleteNatGatewayTag | `POST /{v3,v2.0}/{project_id}/nat_gateways/{nat_gateway_id}/tags/action` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListNatGatewayTag | `GET /{v3,v2.0}/{project_id}/nat_gateways/tags` | Yes | All tag keys and distinct values across public gateways in the project |
| ListNatGatewayByTag | `POST /{v3,v2.0}/{project_id}/nat_gateways/resource_instances/action` | Yes | `action` `filter` or `count`, `tags`, `matches` (`resource_name`), `limit`, `offset` |

Each gateway holds up to 20 tags (`NAT.1016`). Tag keys are 1 to 128
characters and values 0 to 255 characters (`NAT.1015`).

## EIP integration

Public SNAT and DNAT rules hold real [EIPs](eip.md) from the EIP service:

- **Shared hold per gateway.** Multiple SNAT and DNAT rules on the same
  public NAT gateway may reference the same EIP. The gateway's hold on an
  EIP is released only when the last rule on that gateway stops referencing
  it.
- **Validation.** Referencing an unknown EIP returns `NAT.0026`; an EIP
  bound to an ECS port returns `NAT.0402`; an EIP held by another NAT
  gateway returns `NAT.0404`; an EIP still in `PENDING_CREATE` returns
  `NAT.0405`.
- **Effect on the EIP.** While held by a NAT gateway, the EIP reports
  `status: "ACTIVE"` with no `port_id` in the EIP v1 and v2.0 APIs (and
  returns to `DOWN` when released), and reports
  `associate_instance_type: "NATGW"` with `associate_instance_id` set to the
  gateway ID and `vnic: null` in the EIP v3 API. Binding a held EIP to a
  port fails with `409 VPC.0510`, and deleting it fails with `409 VPC.0517`.

## Private NAT gateways (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePrivateNat | `POST /v3/{project_id}/private-nat/gateways` | Yes | Immediately `ACTIVE` |
| ListPrivateNats | `GET /v3/{project_id}/private-nat/gateways` | Yes | Repeatable SDK filters (`enterprise_project_id=all_granted_eps` matches all); `marker`/`limit` (default and max 2000) with `page_info` |
| ShowPrivateNat | `GET /v3/{project_id}/private-nat/gateways/{gateway_id}` | Yes | |
| UpdatePrivateNat | `PUT /v3/{project_id}/private-nat/gateways/{gateway_id}` | Yes | Optional `name`, `description`, `spec` |
| DeletePrivateNat | `DELETE /v3/{project_id}/private-nat/gateways/{gateway_id}` | Yes | Requires no private SNAT or DNAT rules (`NAT.1202`) |
| ListSpecs | `GET /v3/{project_id}/private-nat/specs` | Yes | Public route (no permission required); returns the five private NAT specs |

Behaviour:

- **Downlink VPC and subnet IP allocation.** `downlink_vpcs` must contain
  exactly one element (`NAT.1010` when empty, `NAT.1201` when more than
  one). Its `virsubnet_id` must name a subnet of the project (`NAT.1002`),
  from which `vpc_id` is derived. The gateway reserves `ngport_ip_address`
  (or the lowest free address in the subnet when omitted) via VPC subnet IP
  allocation (`NAT.1405` when unusable, `NAT.1403` when already in use,
  `NAT.1404` when the subnet is full) and releases it on delete.
- **Specs.** `spec` defaults to `Small` and accepts `Small` (`rule_max: 20`),
  `Medium` (`50`), `Large` (`200`), `Extra-large` (`500`) and `Extra-xlarge`
  (`5000`) (`NAT.1010`), each with `transit_ip_pool_size_max: 1`. Updating a
  gateway to its current spec returns `NAT.1206`; updating to a spec whose
  `rule_max` is below the gateway's total SNAT and DNAT rules returns
  `NAT.1207`.
- **States and responses.** Every private NAT resource is `ACTIVE`
  immediately upon creation, includes `request_id` in its JSON envelope, and
  uses RFC 3339 UTC timestamps (`created_at`, `updated_at`,
  `"2006-01-02T15:04:05Z"`).

## Transit subnets and transit IPs (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateTransitSubnet | `POST /v3/{project_id}/private-nat/transit-subnets` | Partial | Same-project subnets only (`virsubnet_project_id` must match the URL project ID, `NAT.1010`) |
| ListTransitSubnet | `GET /v3/{project_id}/private-nat/transit-subnets` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowTransitSubnet | `GET /v3/{project_id}/private-nat/transit-subnets/{transit_subnet_id}` | Yes | Reports `ip_count` of transit IPs in the subnet |
| UpdateTransitSubnet | `PUT /v3/{project_id}/private-nat/transit-subnets/{transit_subnet_id}` | Yes | Optional `name`, `description` |
| DeleteTransitSubnet | `DELETE /v3/{project_id}/private-nat/transit-subnets/{transit_subnet_id}` | Yes | Requires no transit IPs in the subnet (`NAT.1202`) |
| CreateTransitIp | `POST /v3/{project_id}/private-nat/transit-ips` | Yes | Allocates a real IP from the transit subnet's VPC subnet |
| ListTransitIps | `GET /v3/{project_id}/private-nat/transit-ips` | Yes | Repeatable SDK filters (including `transit_subnet_id` and `gateway_id`); `marker`/`limit` with `page_info` |
| ShowTransitIp | `GET /v3/{project_id}/private-nat/transit-ips/{transit_ip_id}` | Yes | |
| DeleteTransitIp | `DELETE /v3/{project_id}/private-nat/transit-ips/{transit_ip_id}` | Yes | Must not be used by any private SNAT or DNAT rule (`NAT.1409`) |

Behaviour:

- **Transit subnets.** `virsubnet_id` must name a VPC subnet of the project
  (`NAT.1002`). A subnet that is already registered as a transit subnet or
  in which a private NAT gateway operates is rejected with `NAT.1101`.
  Responses copy `vpc_id` and `cidr` from the subnet, report `type: "VPC"`
  and `status: "ACTIVE"`, and compute `ip_count` from the project's transit
  IPs in that subnet.
- **Transit IPs.** `virsubnet_id` must name the VPC subnet of an existing
  transit subnet (`NAT.1101` when the subnet exists in the project but is
  not a transit subnet, `NAT.1002` when unknown). The transit IP reserves
  `ip_address` (or the lowest free address) from the VPC subnet (`NAT.1405`,
  `NAT.1403`, `NAT.1404`) and gets a generated `network_interface_id` UUID.
  Its `gateway_id` starts empty (`""`), is set to a private gateway's ID
  when a rule of that gateway first uses it, and is cleared back to `""`
  when no rule uses it. A transit IP already linked to another gateway is
  rejected with `409 NAT.1406`.

## Private SNAT and DNAT rules (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreatePrivateSnat | `POST /v3/{project_id}/private-nat/snat-rules` | Yes | |
| ListPrivateSnats | `GET /v3/{project_id}/private-nat/snat-rules` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowPrivateSnat | `GET /v3/{project_id}/private-nat/snat-rules/{snat_rule_id}` | Yes | |
| UpdatePrivateSnat | `PUT /v3/{project_id}/private-nat/snat-rules/{snat_rule_id}` | Yes | Optional `transit_ip_ids`, `description` |
| DeletePrivateSnat | `DELETE /v3/{project_id}/private-nat/snat-rules/{snat_rule_id}` | Yes | Unlinks transit IPs no longer used by any rule on the gateway |
| CreatePrivateDnat | `POST /v3/{project_id}/private-nat/dnat-rules` | Yes | |
| ListPrivateDnats | `GET /v3/{project_id}/private-nat/dnat-rules` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowPrivateDnat | `GET /v3/{project_id}/private-nat/dnat-rules/{dnat_rule_id}` | Yes | |
| UpdatePrivateDnat | `PUT /v3/{project_id}/private-nat/dnat-rules/{dnat_rule_id}` | Yes | Revalidates conflicts and updates transit IP links |
| DeletePrivateDnat | `DELETE /v3/{project_id}/private-nat/dnat-rules/{dnat_rule_id}` | Yes | Unlinks the transit IP if no other rule on the gateway uses it |

Behaviour:

- **Private SNAT rules.** Requires `gateway_id` (`NAT.1002`), exactly one of
  `virsubnet_id` or `cidr` (`NAT.1501`), and 1 to 20 `transit_ip_ids`
  (`NAT.1506`, `NAT.1507`, `NAT.1002`). `virsubnet_id` must belong to the
  gateway's VPC (`NAT.1003`) and cannot duplicate an existing SNAT rule on
  the gateway (`NAT.1503`); `cidr` must be a canonical IPv4 prefix
  (`NAT.1502`) and cannot duplicate an existing SNAT rule's CIDR on the
  gateway (`NAT.1505`). Each transit IP must lie outside the gateway's own
  VPC (`NAT.1303`), must not be used by a DNAT rule (`NAT.1305`), and must
  not be linked to another gateway (`NAT.1406`).
- **Private DNAT rules.** Requires `gateway_id` and `transit_ip_id`
  (`NAT.1002`, `NAT.1303`, `NAT.1406`, or `NAT.1308` when the transit IP is
  used by an SNAT rule), and exactly one of `network_interface_id` or
  `private_ip_address` (`NAT.1311`). `network_interface_id` must name an
  [ECS](ecs.md) port of the project (`NAT.1009`) in the gateway's VPC
  (`NAT.1304`), setting `type: "COMPUTE"` and populating
  `private_ip_address` from the port. `private_ip_address` must be a valid
  IPv4 address (`NAT.1405`), setting `type: "CUSTOMIZE"`. `protocol` is
  `tcp`, `udp` or `any` (default `any`, `NAT.1010`), and
  `internal_service_port` and `transit_service_port` are decimal strings
  `"0"` to `"65535"` (`NAT.1010`); `any` requires both `"0"`, and `"0"`
  requires `any` (`NAT.1306`). Conflict checks reject duplicate transit IP +
  transit port + protocol (`NAT.1310`), duplicate backend + internal port +
  protocol (`NAT.1307`), an `any` rule on a transit IP that has other DNAT
  rules or vice versa (`NAT.1410`), and an `any` rule on a port that has
  other DNAT rules or vice versa (`NAT.1309`).
- **Rule limits.** Creating a private SNAT or DNAT rule when the gateway's
  combined SNAT and DNAT rules have reached `rule_max` returns `NAT.1207`.

## Private tags (v3)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ShowPrivateNatTags | `GET /v3/{project_id}/private-nat-gateways/{resource_id}/tags` | Yes | Includes `request_id` |
| CreatePrivateNatTag | `POST /v3/{project_id}/private-nat-gateways/{resource_id}/tags` | Yes | Returns 204; overwrites an existing key |
| DeletePrivateNatTag | `DELETE /v3/{project_id}/private-nat-gateways/{resource_id}/tags/{key}` | Yes | Returns 204; missing key returns `400 NAT.1010` |
| BatchCreateDeletePrivateNatTags | `POST /v3/{project_id}/private-nat-gateways/{resource_id}/tags/action` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListPrivateNatTags | `GET /v3/{project_id}/private-nat-gateways/tags` | Yes | All tag keys and distinct values across private gateways in the project |
| ListPrivateNatsByTags | `POST /v3/{project_id}/private-nat-gateways/resource_instances/action` | Yes | `action` `filter` or `count`, `tags`, `matches` (`resource_name`), `limit`, `offset` |
| ShowTransitIpTags | `GET /v3/{project_id}/transit-ips/{resource_id}/tags` | Yes | Includes `request_id` |
| CreateTransitIpTag | `POST /v3/{project_id}/transit-ips/{resource_id}/tags` | Yes | Returns 204; overwrites an existing key |
| DeleteTransitIpTag | `DELETE /v3/{project_id}/transit-ips/{resource_id}/tags/{key}` | Yes | Returns 204; missing key returns `400 NAT.1010` |
| BatchCreateDeleteTransitIpTags | `POST /v3/{project_id}/transit-ips/{resource_id}/tags/action` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListTransitIpTags | `GET /v3/{project_id}/transit-ips/tags` | Yes | All tag keys and distinct values across transit IPs in the project |
| ListTransitIpsByTags | `POST /v3/{project_id}/transit-ips/resource_instances/action` | Yes | `action` `filter` or `count`, `tags`, `matches` (`resource_name`), `limit`, `offset` |
| ShowTransitSubnetTags | `GET /v3/{project_id}/transit-subnets/{resource_id}/tags` | Yes | Includes `request_id` |
| CreateTransitSubnetTag | `POST /v3/{project_id}/transit-subnets/{resource_id}/tags` | Yes | Returns 204; overwrites an existing key |
| DeleteTransitSubnetTag | `DELETE /v3/{project_id}/transit-subnets/{resource_id}/tags/{key}` | Yes | Returns 204; missing key returns `400 NAT.1010` |
| BatchCreateDeleteTransitSubnetTags | `POST /v3/{project_id}/transit-subnets/{resource_id}/tags/action` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListTransitSubnetTags | `GET /v3/{project_id}/transit-subnets/tags` | Yes | All tag keys and distinct values across transit subnets in the project |
| ListTransitSubnetsByTags | `POST /v3/{project_id}/transit-subnets/resource_instances/action` | Yes | `action` `filter` or `count`, `tags`, `matches` (`resource_name`), `limit`, `offset` |

Each private gateway, transit IP or transit subnet holds up to 20 tags
(`NAT.1016`). Tag keys are 1 to 128 characters and values 0 to 255
characters (`NAT.1015`). Unknown resources return `404 NAT.1002`, and
malformed bodies, invalid actions or deleting a missing tag key on single
delete return `400 NAT.1010`.

## Not emulated

The following are outside scope; unsupported options or unregistered routes
return `501 WeiStack.0501`:

- Prepaid billing (`prepaid_options`, `change_to_period`)
- Global EIPs (`global_eip_id` on public SNAT and DNAT rules)
- Cross-project transit subnets (`virsubnet_project_id` different from the
  project in the request path returns `400 NAT.1010`)
- v2.0 quota and version APIs

## Error codes

Every NAT route uses the flat request-ID envelope
`{"error_code": "...", "error_msg": "...", "request_id": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `VPC.0011` | 400 | Invalid `enterprise_project_id` |
| `VPC.2201` | 403 | IAM policy denial under `-iam=enforce` |
| `NAT.0002` | 400 | Invalid parameter on a public NAT or public tag route (name, `source_type`, `session_conf`, `ngport_ip_address` unusable or in use, `nat_gateway_id` mismatch on rule update, empty DNAT batch, invalid tag `action`, deleting a missing public tag key, or bad `limit`/`marker`) |
| `NAT.0004` | 404 | `router_id` (VPC) does not exist on `CreateNatGateway` |
| `NAT.0005` | 404 | `internal_network_id` (subnet) does not exist on `CreateNatGateway` |
| `NAT.0006` | 400 | Deleting a public NAT gateway that still has SNAT or DNAT rules |
| `NAT.0008` | 400 | Subnet does not belong to the gateway's VPC (`CreateNatGateway`, `CreateNatGatewaySnatRule`) |
| `NAT.0014` | 400 | Public NAT `description` exceeds 255 characters or contains `<` or `>` |
| `NAT.0016` | 400 | Public NAT `spec` is not in `["1", "2", "3", "4", "5"]` |
| `NAT.0019` | 404 | `network_id` subnet does not exist on `CreateNatGatewaySnatRule` |
| `NAT.0023` | 404 | `port_id` does not exist on public DNAT create or update |
| `NAT.0026` | 400 | EIP (`floating_ip_id` or `public_ip_address`) does not exist |
| `NAT.0103` | 400 | Public NAT gateway is not `ACTIVE` |
| `NAT.0105` | 404 | Public NAT gateway does not exist |
| `NAT.0202` | 400 | Both or neither of `network_id` and `cidr` specified on public SNAT create |
| `NAT.0203` | 400 | Invalid IPv4 CIDR on public SNAT create |
| `NAT.0204` | 400 | `network_id` specified with `source_type: 1` on public SNAT create |
| `NAT.0205` | 400 | Public SNAT `cidr` with `source_type: 0` is not inside any subnet of the gateway's VPC |
| `NAT.0207` | 400 | Public SNAT `cidr` or `network_id` overlaps an existing SNAT rule on the gateway |
| `NAT.0208` | 400 | Public SNAT rule for `network_id` already exists on the gateway |
| `NAT.0209` | 404 | Public SNAT rule does not exist (or does not belong to `nat_gateway_id` on delete) |
| `NAT.0210` | 400 | `floating_ip_id` is not a valid UUID |
| `NAT.0211` | 400 | More than 20 EIPs on a public SNAT rule |
| `NAT.0302` | 400 | Unsupported public DNAT `protocol` |
| `NAT.0303` | 400 | Invalid public DNAT port or port range |
| `NAT.0304` | 400 | Public DNAT target (`port_id` or `private_ip`), internal port and protocol conflict |
| `NAT.0305` | 400 | Public DNAT EIP, external port and protocol conflict |
| `NAT.0306` | 400 | Public DNAT protocol `any` and port `0` mismatch |
| `NAT.0307` | 400 | Public DNAT `port_id` all-port (`any`) conflict with another rule |
| `NAT.0308` | 400 | Public DNAT `private_ip` all-port (`any`) conflict with another rule |
| `NAT.0309` | 400 | Public NAT gateway `dnat_rules_limit` (200) reached |
| `NAT.0310` | 400 | Neither `port_id` nor `private_ip` specified on public DNAT create or update |
| `NAT.0311` | 400 | Invalid `private_ip` on public DNAT create or update |
| `NAT.0314` | 400 | Batch public DNAT create exceeds the gateway's remaining DNAT rule capacity |
| `NAT.0315` | 400 | Public DNAT `port_id` does not belong to the gateway's VPC |
| `NAT.0317` | 400 | Both `port_id` and `private_ip` specified on public DNAT create or update |
| `NAT.0319` | 404 | Public DNAT rule does not exist (or does not belong to `nat_gateway_id` on delete) |
| `NAT.0402` | 400 | EIP is already bound to an ECS port |
| `NAT.0403` | 400 | Duplicate EIP in a public SNAT rule |
| `NAT.0404` | 400 | EIP is already held by another NAT gateway |
| `NAT.0405` | 400 | EIP is not ready (`PENDING_CREATE`) |
| `NAT.0408` | 400 | EIP cannot be shared between an `any` DNAT rule and another DNAT rule |
| `NAT.0409` | 400 | EIP cannot be shared between an SNAT rule and an `any` DNAT rule |
| `NAT.1002` | 404 | Private NAT gateway, transit subnet, transit IP, private SNAT rule, private DNAT rule or subnet does not exist |
| `NAT.1003` | 404 | `virsubnet_id` does not exist in the private gateway's VPC on private SNAT create |
| `NAT.1009` | 404 | `network_interface_id` port does not exist on private DNAT create or update |
| `NAT.1010` | 400 | Malformed JSON body, or invalid parameter on a private NAT or private tag route |
| `NAT.1015` | 400 | Invalid tag key or value |
| `NAT.1016` | 400 | More than 20 tags on a resource |
| `NAT.1101` | 400 | Subnet cannot be used as a transit subnet or is not a registered transit subnet |
| `NAT.1201` | 400 | More than one entry in `downlink_vpcs` on `CreatePrivateNat` |
| `NAT.1202` | 400 | Deleting a private NAT gateway with rules or a transit subnet with transit IPs |
| `NAT.1206` | 400 | Updating a private NAT gateway to its current `spec` |
| `NAT.1207` | 400 | Private NAT gateway `rule_max` reached or exceeded by a spec downgrade |
| `NAT.1303` | 409 | Transit IP belongs to the private gateway's own VPC |
| `NAT.1304` | 409 | Private DNAT `network_interface_id` port is not in the private gateway's VPC |
| `NAT.1305` | 409 | Transit IP is already used by a private DNAT rule |
| `NAT.1306` | 400 | Private DNAT protocol `any` and port `"0"` mismatch |
| `NAT.1307` | 409 | Private DNAT internal target, internal port and protocol conflict |
| `NAT.1308` | 409 | Transit IP is already used by a private SNAT rule |
| `NAT.1309` | 409 | Private DNAT port all-port (`any`) conflict with another rule |
| `NAT.1310` | 409 | Private DNAT transit IP, transit port and protocol conflict |
| `NAT.1311` | 400 | Both or neither of `network_interface_id` and `private_ip_address` specified on private DNAT create or update |
| `NAT.1403` | 409 | Requested subnet IP address is already in use (`CreatePrivateNat`, `CreateTransitIp`) |
| `NAT.1404` | 400 | Subnet has no free IP addresses remaining (`CreateNatGateway`, `CreatePrivateNat`, `CreateTransitIp`) |
| `NAT.1405` | 400 | Invalid or unusable IP address for the subnet or private DNAT target |
| `NAT.1406` | 409 | Transit IP is already linked to another private NAT gateway |
| `NAT.1409` | 409 | Deleting a transit IP that is still used by private SNAT or DNAT rules |
| `NAT.1410` | 409 | Transit IP all-port (`any`) conflict with another private DNAT rule |
| `NAT.1501` | 400 | Both or neither of `virsubnet_id` and `cidr` specified on private SNAT create |
| `NAT.1502` | 400 | Invalid IPv4 CIDR on private SNAT create |
| `NAT.1503` | 409 | Private SNAT rule for `virsubnet_id` already exists on the gateway |
| `NAT.1505` | 409 | Private SNAT rule for `cidr` already exists on the gateway |
| `NAT.1506` | 400 | More than 20 transit IPs on a private SNAT rule |
| `NAT.1507` | 400 | `transit_ip_id` is not a valid UUID |

## Permissions

Each route checks Huawei's NAT IAM action (`nat:natGateways:*`,
`nat:snatRules:*`, `nat:dnatRules:*`, `nat:privateNatGateways:*`,
`nat:transitSubnets:*`, `nat:privateNatTransitIps:*`,
`nat:privateNatSnatRules:*`, `nat:privateNatDnatRules:*`) and its
documented alias (`nat:natGatewayTags:*`, `nat:privateNatGatewayTags:*`,
`nat:transitSubnetTags:*`, `nat:transitIps:*`, `nat:transitIpTags:*`)
against NAT resource URNs (`nat:<region>:<account-id>:gateway:<id>`,
`privateGateway:<id>`, `transitSubnet:<id>` and `privateTransitIp:<id>`).
`ListNatGatewaySpecs` and `ListSpecs` are public routes and require no
permission. Under `-iam=enforce`, denials return `403 VPC.2201`
(`"Policy doesn't allow <action> to be performed."`) with an
`encoded_authorization_message`. System roles `NAT FullAccess`,
`NAT ReadOnlyAccess` and `NAT Administrator` grant the corresponding
actions.

## Client compatibility

Every operation above is exercised through Huawei Cloud's official Go SDK
(`huaweicloud-sdk-go-v3`, `nat/v2` client) in `test/sdk`, and through
Terraform (`huaweicloud_nat_gateway`, `huaweicloud_nat_snat_rule`,
`huaweicloud_nat_dnat_rule`, `huaweicloud_nat_private_gateway`,
`huaweicloud_nat_private_transit_subnet`,
`huaweicloud_nat_private_transit_ip`, `huaweicloud_nat_private_snat_rule`,
`huaweicloud_nat_private_dnat_rule`, and the `huaweicloud_nat_gateways`,
`huaweicloud_nat_snat_rules`, `huaweicloud_nat_dnat_rules`,
`huaweicloud_nat_private_gateways` and `huaweicloud_nat_gateway_specs` data
sources) in `test/terraform`, in both default and `-iam=enforce` modes.
