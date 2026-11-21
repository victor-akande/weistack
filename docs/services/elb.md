# ELB coverage

Endpoint: `elb.{region}.myhuaweicloud.com`, or the `/elb` path prefix.

Dedicated Elastic Load Balance (v3) resources are control-plane state linked
to real [VPC](vpc.md) VPCs and subnets, real [EIP](eip.md) elastic IPs, and
real [ECS](ecs.md) servers, with real X.509 certificate parsing and encrypted
private-key storage; no network traffic is proxied or load-balanced.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

Common behaviour across ELB v3 APIs:

- **Immediate states.** Resources with a `provisioning_status` (load
  balancers, L7 policies, L7 rules, and entries in `ShowLoadBalancerStatus`)
  are `ACTIVE` immediately upon creation, and deletes complete immediately.
- **Responses and timestamps.** Every `/v3/{project_id}/elb/...` response
  body includes `request_id`. Timestamps (`created_at`, `updated_at`,
  `expire_time`) use RFC 3339 UTC (`"2006-01-02T15:04:05Z"`).
- **Lists and pagination.** List endpoints support repeatable SDK query
  filters (matching any supplied value), `enterprise_project_id=all_granted_eps`
  to match across enterprise projects, and `marker`/`limit` pagination
  (default and maximum 2000; `page_reverse` accepted) returning `page_info`
  (`previous_marker`, `next_marker`, `current_count`) ordered by ascending ID.
- **Common fields.** `name` and `description` are 0 to 255 characters;
  `enterprise_project_id` defaults to `"0"` and accepts `"0"` or a UUID.
  Inert routing or tuning fields (`http2_enable`, `insert_headers`,
  `keepalive_timeout`, `slow_start`, `connection_drain`, `quic_config`,
  `autoscaling`, `waf_failure_action`, and similar) are validated, stored,
  and returned unchanged.

## Load balancers (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateLoadBalancer | `POST /v3/{project_id}/elb/loadbalancers` | `elb:loadbalancers:create` | Partial | Dedicated IPv4 only; `prepaid_options`, `ipv6_*`, `log_*` and non-empty `charge_mode` return `501 WeiStack.0501` |
| ListLoadBalancers | `GET /v3/{project_id}/elb/loadbalancers` | `elb:loadbalancers:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowLoadBalancer | `GET /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}` | `elb:loadbalancers:show` | Yes | |
| UpdateLoadBalancer | `PUT /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}` | `elb:loadbalancers:update` | Partial | Supports VIP move/removal, same-type flavor change, `ip_target_enable`; out-of-scope options return `501 WeiStack.0501` |
| DeleteLoadBalancer | `DELETE /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}` | `elb:loadbalancers:delete` | Yes | Requires `deletion_protection_enable: false` and no listeners or pools (`ELB.8907`) |
| DeleteLoadBalancerForce | `DELETE /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}/force-elb` | `elb:loadbalancers:delete` | Yes | Cascade-deletes listeners, pools, members, health monitors, L7 policies and L7 rules; deletion protection still applies |
| ShowLoadBalancerStatus | `GET /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}/statuses` | `elb:loadbalancers:show` | Yes | Returns full status tree with dynamically computed member `operating_status` |
| BatchAddAvailableZones | `POST /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}/availability-zone/batch-add` | `elb:loadbalancers:update` | Yes | Each AZ must exist in the region and not already be attached (`ELB.8902`) |
| BatchRemoveAvailableZones | `POST /v3/{project_id}/elb/loadbalancers/{loadbalancer_id}/availability-zone/batch-remove` | `elb:loadbalancers:update` | Yes | Each AZ must be attached and at least one AZ must remain (`ELB.8902`) |

Behaviour:

- **Availability zones and flavors.** `availability_zone_list` is required
  with one or more distinct valid zones for the region (`ELB.8902`). At
  least one of `l4_flavor_id` (an L4 flavor) or `l7_flavor_id` (an L7
  flavor) is required (`ELB.8904` if unknown, `ELB.8902` on wrong type).
  Updating a flavor across L4/L7 types returns `ELB.8959`.
- **Network and VIP IP allocation.** Requires at least one of
  `vip_subnet_cidr_id` (a VPC subnet's `neutron_subnet_id`, `ELB.8904`) or
  `elb_virsubnet_ids` (VPC subnet IDs, `ELB.8904`), plus `vpc_id` when
  neither implies it; every subnet must belong to the same VPC (`ELB.8902`).
  When `vip_subnet_cidr_id` is set, the load balancer reserves `vip_address`
  (or the lowest free address) from the VPC subnet (`ELB.8902` if unusable,
  `ELB.8907` if already in use, `ELB.8934` if the subnet is full) and
  generates a `vip_port_id` UUID. On update, changing `vip_subnet_cidr_id`
  or `vip_address` moves the VIP, and `vip_subnet_cidr_id: null` removes it
  (refused with `ELB.8907` while an EIP is bound). Turning
  `ip_target_enable` off while any pool contains IP members returns
  `ELB.8907`.
- **Response fields.** `loadbalancer_type` is `"dedicated"`,
  `elb_virsubnet_type` is `"ipv4"`, `provider` defaults to `"vlb"`,
  `guaranteed` defaults to `true`, `provisioning_status` is `"ACTIVE"`, and
  `operating_status` is `"ONLINE"`.

## Listeners (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateListener | `POST /v3/{project_id}/elb/listeners` | `elb:listeners:create` | Partial | Protocols `TCP`, `UDP`, `HTTP`, `HTTPS` (`TERMINATED_HTTPS` stored as `HTTPS`), `QUIC`, `TLS`; `IP` returns `ELB.8902` |
| ListListeners | `GET /v3/{project_id}/elb/listeners` | `elb:listeners:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowListener | `GET /v3/{project_id}/elb/listeners/{listener_id}` | `elb:listeners:show` | Yes | |
| UpdateListener | `PUT /v3/{project_id}/elb/listeners/{listener_id}` | `elb:listeners:update` | Yes | Revalidates certificates, security policies, IP groups and default pool |
| DeleteListener | `DELETE /v3/{project_id}/elb/listeners/{listener_id}` | `elb:listeners:delete` | Yes | Refused with `ELB.8907` if `default_pool_id` or L7 policies exist |
| DeleteListenerForce | `DELETE /v3/{project_id}/elb/listeners/{listener_id}/force` | `elb:listeners:delete` | Yes | Deletes L7 policies and rules and unbinds `default_pool_id` (pool remains) |

Behaviour:

- **Flavors and port spaces.** `TCP`, `UDP`, `TLS` and `QUIC` listeners
  require the load balancer to have an L4 flavor; `HTTP` and `HTTPS`
  require an L7 flavor (`ELB.8902`). `protocol_port` is 1 to 65535 (or
  `port_ranges` for `TCP`, `UDP` and `TLS`). Ports must be unique per
  protocol family on the load balancer: `TCP`/`HTTP`/`HTTPS`/`TLS` share
  one port namespace and `UDP`/`QUIC` share another (`ELB.8907`).
- **TLS, certificates, security policies and IP groups.** `HTTPS`, `TLS`
  and `QUIC` listeners require `default_tls_container_ref` referencing a
  `server` certificate of the project (`ELB.8904`, wrong type `ELB.8902`)
  and optionally accept `sni_container_refs` (`server` certificates) and
  `client_ca_tls_container_ref` (a `client` CA certificate).
  `tls_ciphers_policy` (a system policy name, defaulting to `tls-1-2`) and
  `security_policy_id` (a custom security policy of the project) are
  mutually exclusive and valid only on TLS-terminating protocols.
  `ipgroup` references an existing IP group (`ELB.8904`) with `type`
  `"white"` or `"black"`.
- **Default pool.** `default_pool_id` must name a pool on the same load
  balancer, unused by another listener, with a compatible protocol
  (`ELB.8902` or `ELB.8907`).

## Pools (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreatePool | `POST /v3/{project_id}/elb/pools` | `elb:pools:create` | Yes | Supports `TCP`, `UDP`, `HTTP`, `HTTPS`, `QUIC`, `GRPC`, `TLS` |
| ListPools | `GET /v3/{project_id}/elb/pools` | `elb:pools:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowPool | `GET /v3/{project_id}/elb/pools/{pool_id}` | `elb:pools:show` | Yes | |
| UpdatePool | `PUT /v3/{project_id}/elb/pools/{pool_id}` | `elb:pools:update` | Yes | Supports optional null-clearing of `session_persistence`, `slow_start`, `connection_drain`, `pool_health`, `az_affinity` |
| DeletePool | `DELETE /v3/{project_id}/elb/pools/{pool_id}` | `elb:pools:delete` | Yes | Refused with `ELB.8907` if members, a health monitor, a listener or an L7 policy uses it |
| DeletePoolCascade | `DELETE /v3/{project_id}/elb/pools/{pool_id}/delete-cascade` | `elb:pools:delete` | Yes | Deletes members and health monitor and unbinds from listeners and L7 policies |

Behaviour:

- **Placement and protocol pairing.** A pool attaches via `listener_id`
  (setting the listener's default pool; the listener must have none,
  `ELB.8907`), `loadbalancer_id`, or `type: "ip"` with `vpc_id` (detached
  IP pool). When attached to a listener, allowed listener → pool pairings
  are: `UDP` → `UDP`/`QUIC`; `TCP` → `TCP`; `HTTP` → `HTTP`; `HTTPS` →
  `HTTP`/`HTTPS`/`GRPC`; `TLS` → `TCP`/`TLS`; `QUIC` → `UDP`/`QUIC`
  (`ELB.8902` otherwise).
- **Algorithms and session persistence.** `lb_algorithm` accepts
  `ROUND_ROBIN`, `LEAST_CONNECTIONS`, `SOURCE_IP` or `QUIC_CID` (`QUIC_CID`
  only on `QUIC` pools). `session_persistence` supports `SOURCE_IP`,
  `HTTP_COOKIE` and `APP_COOKIE` (`cookie_name` only with `APP_COOKIE`;
  `persistence_timeout` 1 to 60 minutes for `TCP`/`UDP` pools and 1 to 1440
  otherwise).

## Members and member health (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateMember | `POST /v3/{project_id}/elb/pools/{pool_id}/members` | `elb:members:create` | Yes | Instance members (with `subnet_cidr_id`) and IP members (without) |
| ListMembers | `GET /v3/{project_id}/elb/pools/{pool_id}/members` | `elb:members:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowMember | `GET /v3/{project_id}/elb/pools/{pool_id}/members/{member_id}` | `elb:members:show` | Yes | |
| UpdateMember | `PUT /v3/{project_id}/elb/pools/{pool_id}/members/{member_id}` | `elb:members:update` | Yes | Updates `name`, `weight`, `admin_state_up`, `protocol_port`, `availability_zone` |
| DeleteMember | `DELETE /v3/{project_id}/elb/pools/{pool_id}/members/{member_id}` | `elb:members:delete` | Yes | |
| ListAllMembers | `GET /v3/{project_id}/elb/members` | `elb:members:list` | Yes | Cross-pool listing with repeatable SDK filters and `page_info` |

Behaviour:

- **Instance vs. IP members.** `address` must be an IPv4 address
  (`ELB.8902`). With `subnet_cidr_id` (a subnet's `neutron_subnet_id`,
  `ELB.8904`), the subnet must belong to the load balancer's VPC and
  `address` must fall inside its CIDR (`ELB.8902`), creating an `instance`
  member. Without `subnet_cidr_id`, it is an `ip` member, requiring
  `ip_target_enable: true` on the load balancer (`ELB.8939`) and a pool
  protocol in `TCP`, `UDP`, `HTTP`, `HTTPS`, `GRPC`, `QUIC`, `TLS`
  (`ELB.8938`). `protocol_port` is 1 to 65535 (optional when the pool has
  `any_port_enable: true`); duplicate `(address, protocol_port)` in a pool
  returns `ELB.8907`. `weight` is 0 to 100 (default 1).
- **Member health semantics.** A member's `operating_status` (and each
  per-listener entry in `status`) is computed dynamically on every read
  (`ShowMember`, `ListMembers`, `ListAllMembers`, `ShowLoadBalancerStatus`)
  and never stored:
  1. If the member, its pool, or the pool's health monitor has
     `admin_state_up: false`: `OFFLINE`.
  2. If the pool has no health monitor: `NO_MONITOR`.
  3. For an `instance` member: look up an [ECS](ecs.md) server in the
     project with a NIC in the member's subnet at `address`. If found and
     `ACTIVE`, `ONLINE`; otherwise (no matching server, or `BUILD`,
     `SHUTOFF`, `ERROR`), `OFFLINE`.
  4. For an `ip` member: `ONLINE` if an `ACTIVE` ECS server in the load
     balancer's VPC has a NIC at `address`, else `OFFLINE`.

  Stopping an ECS server turns its monitored members `OFFLINE` on the next
  read; starting it turns them `ONLINE` again. The load balancer's and
  pool's own `operating_status` remain `ONLINE`.

## Health monitors (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateHealthMonitor | `POST /v3/{project_id}/elb/healthmonitors` | `elb:healthmonitors:create` | Yes | One monitor per pool (`ELB.8907` if pool already has one) |
| ListHealthMonitors | `GET /v3/{project_id}/elb/healthmonitors` | `elb:healthmonitors:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowHealthMonitor | `GET /v3/{project_id}/elb/healthmonitors/{healthmonitor_id}` | `elb:healthmonitors:show` | Yes | |
| UpdateHealthMonitor | `PUT /v3/{project_id}/elb/healthmonitors/{healthmonitor_id}` | `elb:healthmonitors:update` | Yes | |
| DeleteHealthMonitor | `DELETE /v3/{project_id}/elb/healthmonitors/{healthmonitor_id}` | `elb:healthmonitors:delete` | Yes | Unbinds the health monitor from its pool |

Behaviour:

- `pool_id` must exist (`ELB.8904`) and have no existing health monitor
  (`ELB.8907`). `type` accepts `TCP`, `UDP_CONNECT`, `HTTP`, `HTTPS`,
  `GRPC` or `TLS`; `UDP` and `QUIC` pools accept only `UDP_CONNECT`
  (`ELB.8902`).
- `delay` is 1 to 50 seconds, `timeout` ≥ 1, `max_retries` 1 to 10,
  `max_retries_down` 1 to 10 (default 3), and `monitor_port` 1 to 65535
  when set. `http_method` (`GET`, `HEAD`, `POST`), `url_path` (starting
  with `/`), `expected_codes` and `domain_name` apply only to `HTTP`,
  `HTTPS` and `GRPC` monitors.

## Certificates (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateCertificate | `POST /v3/{project_id}/elb/certificates` | `elb:certificates:create` | Partial | `server` and `client` (CA) certificates; `server_sm`, `enc_*` and `scm_certificate_id` return `501 WeiStack.0501` |
| ListCertificates | `GET /v3/{project_id}/elb/certificates` | `elb:certificates:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowCertificate | `GET /v3/{project_id}/elb/certificates/{certificate_id}` | `elb:certificates:show` | Yes | `private_key` is always returned as `""` |
| UpdateCertificate | `PUT /v3/{project_id}/elb/certificates/{certificate_id}` | `elb:certificates:update` | Yes | Updates `name`, `description`, `domain`, or replaces the certificate/key pair |
| DeleteCertificate | `DELETE /v3/{project_id}/elb/certificates/{certificate_id}` | `elb:certificates:delete` | Yes | Refused with `ELB.8907` while referenced by any listener |

Behaviour:

- **Real X.509 validation.** `type` defaults to `server` (`certificate` PEM
  chain up to 20,000 characters and 11 certificates, leaf first, plus
  matching PKCS#1, PKCS#8 or SEC 1 PEM `private_key` up to 8,192 characters;
  parse errors or key/leaf mismatches return `ELB.1011`). For `client`
  certificates, `certificate` must parse as a CA certificate (`IsCA: true`,
  otherwise `ELB.5051`) and any `private_key` is ignored.
- **Derived metadata.** `expire_time` (`NotAfter`), `common_name`,
  `subject_alternative_names`, and `fingerprint` (40 lower-case hex SHA-1
  of the leaf DER) are parsed from the leaf certificate. `domain` uses the
  supplied comma-separated hostnames (up to 100 names, 10,000 characters
  total) or defaults to `common_name`.
- **Private-key protection.** Private keys are encrypted with WeiStack's
  vault before storage and are never stored in clear, logged, or echoed in
  API responses (`private_key` is always `""`).

## L7 policies and rules (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateL7Policy | `POST /v3/{project_id}/elb/l7policies` | `elb:l7policies:create` | Yes | Supports inline `rules` creation |
| ListL7Policies | `GET /v3/{project_id}/elb/l7policies` | `elb:l7policies:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowL7Policy | `GET /v3/{project_id}/elb/l7policies/{l7policy_id}` | `elb:l7policies:show` | Yes | |
| UpdateL7Policy | `PUT /v3/{project_id}/elb/l7policies/{l7policy_id}` | `elb:l7policies:update` | Yes | |
| DeleteL7Policy | `DELETE /v3/{project_id}/elb/l7policies/{l7policy_id}` | `elb:l7policies:delete` | Yes | Cascade-deletes the policy's rules |
| CreateL7Rule | `POST /v3/{project_id}/elb/l7policies/{l7policy_id}/rules` | `elb:l7rules:create` | Yes | |
| ListL7Rules | `GET /v3/{project_id}/elb/l7policies/{l7policy_id}/rules` | `elb:l7rules:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowL7Rule | `GET /v3/{project_id}/elb/l7policies/{l7policy_id}/rules/{l7rule_id}` | `elb:l7rules:show` | Yes | |
| UpdateL7Rule | `PUT /v3/{project_id}/elb/l7policies/{l7policy_id}/rules/{l7rule_id}` | `elb:l7rules:update` | Yes | |
| DeleteL7Rule | `DELETE /v3/{project_id}/elb/l7policies/{l7policy_id}/rules/{l7rule_id}` | `elb:l7rules:delete` | Yes | |
| ListAllL7Rules | `GET /v3/{project_id}/elb/l7policies/rules` | `elb:l7rules:list` | Yes | Cross-policy listing with repeatable SDK filters and `page_info` |

Behaviour:

- **Policies.** `listener_id` must name an `HTTP` or `HTTPS` listener
  (`ELB.8902`). `action` supports `REDIRECT_TO_POOL` (requires
  `redirect_pool_id` on the same load balancer with an HTTP-family
  protocol), `REDIRECT_TO_LISTENER` (requires `redirect_listener_id` to be
  an `HTTPS` listener on the same load balancer, from an `HTTP` listener),
  `REDIRECT_TO_URL` (`redirect_url_config`) and `FIXED_RESPONSE`
  (`fixed_response_config`). `priority` (integer ≥ 0) requires
  `enhance_l7policy_enable: true` on the listener (`ELB.8902`) and must be
  unique per listener (`ELB.8907`). Deprecated `position` is accepted and
  ignored.
- **Rules.** `type` accepts `HOST_NAME`, `PATH`, `METHOD`, `HEADER`,
  `QUERY_STRING` or `SOURCE_IP`. `compare_type` accepts `EQUAL_TO`,
  `REGEX` or `STARTS_WITH` (`HOST_NAME` and `METHOD` allow only
  `EQUAL_TO`; `PATH` allows all three). `key` is accepted only for `HEADER`
  and `QUERY_STRING`. Duplicate rule types on the same policy return
  `ELB.8907`.

## IP groups and security policies (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| CreateIpGroup | `POST /v3/{project_id}/elb/ipgroups` | `elb:ipgroups:create` | Yes | IPv4 addresses and canonical CIDRs in `ip_list` |
| ListIpGroups | `GET /v3/{project_id}/elb/ipgroups` | `elb:ipgroups:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowIpGroup | `GET /v3/{project_id}/elb/ipgroups/{ipgroup_id}` | `elb:ipgroups:show` | Yes | Includes `listeners` referencing the IP group |
| UpdateIpGroup | `PUT /v3/{project_id}/elb/ipgroups/{ipgroup_id}` | `elb:ipgroups:update` | Yes | |
| DeleteIpGroup | `DELETE /v3/{project_id}/elb/ipgroups/{ipgroup_id}` | `elb:ipgroups:delete` | Yes | Refused with `ELB.8907` while used by any listener |
| CreateSecurityPolicy | `POST /v3/{project_id}/elb/security-policies` | `elb:security-policies:create` | Yes | Custom TLS protocols and cipher suites |
| ListSecurityPolicies | `GET /v3/{project_id}/elb/security-policies` | `elb:security-policies:list` | Yes | Repeatable SDK filters; `marker`/`limit` with `page_info` |
| ShowSecurityPolicy | `GET /v3/{project_id}/elb/security-policies/{security_policy_id}` | `elb:security-policies:show` | Yes | Includes `listeners` referencing the policy |
| UpdateSecurityPolicy | `PUT /v3/{project_id}/elb/security-policies/{security_policy_id}` | `elb:security-policies:update` | Yes | |
| DeleteSecurityPolicy | `DELETE /v3/{project_id}/elb/security-policies/{security_policy_id}` | `elb:security-policies:delete` | Yes | Refused with `ELB.8907` while used by any listener |
| ListSystemSecurityPolicies | `GET /v3/{project_id}/elb/system-security-policies` | `elb:security-policies:list` | Yes | Returns the built-in system TLS security policies |

Behaviour:

- **IP groups.** Each `ip_list` entry takes an IPv4 address or canonical
  IPv4 CIDR without duplicates (`ELB.8902`). Deleting an IP group bound to
  a listener returns `ELB.8907`.
- **Custom security policies.** `protocols` must be a non-empty subset of
  `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`; `ciphers` must be a non-empty
  list of ciphers present in the system security policy catalogue (including
  TLS 1.3 suites). Deleting a security policy bound to a listener returns
  `ELB.8907`.
- **Seeded system security policies.** `ListSystemSecurityPolicies` returns
  ten read-only policies: `tls-1-0`, `tls-1-0-inherit`, `tls-1-1`,
  `tls-1-2`, `tls-1-2-strict`, `tls-1-2-fs`, `tls-1-0-with-1-3`,
  `tls-1-2-fs-with-1-3`, `hybrid-policy-1-0` and `tls-1-2-strict-no-cbc`.

## Flavors and availability zones (v3)

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| ListFlavors | `GET /v3/{project_id}/elb/flavors` | `elb:flavors:list` | Yes | Filters `id`, `name`, `type`, `shared`, `public_border_group`, `category`, `flavor_sold_out`; `marker`/`limit` with `page_info` |
| ShowFlavor | `GET /v3/{project_id}/elb/flavors/{flavor_id}` | `elb:flavors:show` | Yes | `ELB.8904` if unknown |
| ListAvailabilityZones | `GET /v3/{project_id}/elb/availability-zones` | `elb:availability-zones:list` | Yes | Returns region zones as an array of arrays (`public_border_group: "center"`) |

Seeded read-only flavors (per region, with deterministic UUIDv5 IDs stable
across restarts):

| Name | Type | Connection | CPS | QPS | HTTPS CPS | Bandwidth | LCU |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `L7_flavor.elb.s1.small` | `L7` | 200,000 | 2,000 | 4,000 | 200 | 50,000 | 10 |
| `L7_flavor.elb.s1.medium` | `L7` | 400,000 | 4,000 | 8,000 | 400 | 100,000 | 20 |
| `L4_flavor.elb.s2.small` | `L4` | 1,000,000 | 20,000 | — | — | 100,000 | 20 |
| `L4_flavor.elb.s1.medium` | `L4` | 2,000,000 | 40,000 | — | — | 200,000 | 40 |

Availability zones are derived from the region's configured zones, each
reporting `state: "ACTIVE"`, `protocol: ["L4", "L7"]`,
`public_border_group: "center"` and `category: 0`.

## Tags (v3 and v2.0)

Load balancer and listener tags are served by shared handlers across
`/v2.0/{project_id}` (used by the Terraform provider) and
`/v3/{project_id}` (used by the v3 SDK).

| Operation | Method and path | IAM action | Status | Notes |
| --- | --- | --- | --- | --- |
| ShowLoadbalancerTags | `GET /{v2.0,v3}/{project_id}/loadbalancers/{loadbalancer_id}/tags` | `elb:loadbalancerTags:get` | Yes | Returns `{"tags": [...]}` |
| ChangeLoadbalancerTags | `POST /{v2.0,v3}/{project_id}/loadbalancers/{loadbalancer_id}/tags/action` | `elb:loadbalancerTags:create` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListLoadbalancerTags | `GET /{v2.0,v3}/{project_id}/loadbalancers/tags` | `elb:loadbalancerTags:get` | Yes | All tag keys and distinct values across load balancers in the project |
| CreateLoadbalancerTag | `POST /v2.0/{project_id}/loadbalancers/{loadbalancer_id}/tags` | `elb:loadbalancerTags:create` | Yes | Returns 204; overwrites an existing key |
| DeleteLoadbalancerTag | `DELETE /v2.0/{project_id}/loadbalancers/{loadbalancer_id}/tags/{key}` | `elb:loadbalancerTags:delete` | Yes | Returns 204; missing key returns `400 ELB.8902` |
| ListLoadbalancersByTags | `POST /v2.0/{project_id}/loadbalancers/resource_instances/action` | `elb:loadbalancerTags:get` | Yes | `action` `filter` or `count`, `tags`, `tags_any`, `not_tags`, `not_tags_any`, `matches` (`resource_name`, `resource_id`), `limit`, `offset` |
| ShowListenerTags | `GET /{v2.0,v3}/{project_id}/listeners/{listener_id}/tags` | `elb:listenerTags:get` | Yes | Returns `{"tags": [...]}` |
| ChangeListenerTags | `POST /{v2.0,v3}/{project_id}/listeners/{listener_id}/tags/action` | `elb:listenerTags:create` | Yes | `action` `create` or `delete`; returns 204; missing key on delete is ignored |
| ListListenerTags | `GET /{v2.0,v3}/{project_id}/listeners/tags` | `elb:listenerTags:get` | Yes | All tag keys and distinct values across listeners in the project |
| CreateListenerTag | `POST /v2.0/{project_id}/listeners/{listener_id}/tags` | `elb:listenerTags:create` | Yes | Returns 204; overwrites an existing key |
| DeleteListenerTag | `DELETE /v2.0/{project_id}/listeners/{listener_id}/tags/{key}` | `elb:listenerTags:delete` | Yes | Returns 204; missing key returns `400 ELB.8902` |
| ListListenersByTags | `POST /v2.0/{project_id}/listeners/resource_instances/action` | `elb:listenerTags:get` | Yes | `action` `filter` or `count`, `tags`, `tags_any`, `not_tags`, `not_tags_any`, `matches` (`resource_name`, `resource_id`), `limit`, `offset` |

Behaviour:

- Each load balancer or listener holds at most 20 tags. Tag keys are 1 to
  128 characters from `[A-Za-z0-9_-]` and tag values are 0 to 255
  characters from `[A-Za-z0-9_.-]`. Any invalid tag, duplicate key in a
  batch create, overflow past 20 tags, invalid `action`, invalid
  `limit`/`offset`, or single delete of a missing key returns `400 ELB.8902`.
  Unknown load balancer or listener IDs return `404 ELB.8904`.
- `resource_instances/action` supports `action: "filter"` (default and
  maximum `limit` 1000, default `offset` 0; both integer and decimal string
  values accepted) and `action: "count"` (returns only `total_count`). Tag
  filter values prefixed with `*` perform substring matching; empty value
  lists match any value for the key.

## EIP and VPC integration

- **VPC subnets.** Creating a load balancer with `vip_subnet_cidr_id`
  allocates a real IP from the subnet in [VPC](vpc.md) and releases it on
  delete or VIP removal. A VPC subnet with an allocated load balancer VIP
  cannot be deleted. Instance members validate that `subnet_cidr_id`
  belongs to the load balancer's VPC and that `address` falls in its CIDR.
- **EIPs.** Creating a load balancer with `publicip_ids` binds an existing
  [EIP](eip.md) to the VIP; creating with `publicip` allocates a new EIP
  (with a `PER` or `WHOLE` bandwidth) and binds it. `publicip` and
  `publicip_ids` are mutually exclusive and require a VIP (`ELB.8902`).
  While bound, the EIP reports `status: "ACTIVE"` with the load balancer's
  `vip_port_id` in EIP v1/v2.0 and `associate_instance_type: "ELB"` with
  `associate_instance_id` set to the load balancer ID in EIP v3. Binding
  the EIP elsewhere fails with `VPC.0510` and deleting it fails with
  `VPC.0517`. Deleting the load balancer unbinds its EIPs without deleting
  them.

## Not emulated

The following are outside scope; unsupported options or unregistered routes
return `501 WeiStack.0501`:

- Shared ELB (v2 `lb` resources)
- Log tanks (`log_group_id`, `log_topic_id`), recycle bin, clone, DNS,
  async jobs, active-standby pools, quotas, feature configs, member
  health-check jobs, private-key echo settings, charge-mode changes,
  prepaid billing (`prepaid_options`), upgrade, and batch APIs other than
  AZ add and remove
- IPv6 VIPs, subnets and public IPs (`ipv6_*`)
- Gateway load balancer `IP` protocol listeners
- SM (`server_sm`, `enc_*`) and CCM/SCM (`scm_certificate_id`) certificates

## Error codes

Every ELB route uses the flat request-ID envelope
`{"error_code": "...", "error_msg": "...", "request_id": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `ELB.8902` | 400 | Malformed JSON body, missing required field, invalid parameter, invalid tag or tag action, or unsupported listener/pool pairing |
| `ELB.8904` | 404 | Resource (`loadbalancer`, `listener`, `pool`, `member`, `healthmonitor`, `certificate`, `l7policy`, `l7rule`, `ipgroup`, `securityPolicy`, `flavor`, `subnet`, `vpc`, `publicip`, `bandwidth`) does not exist |
| `ELB.8907` | 409 | Conflict: resource in use, duplicate port/member/priority/rule type, VIP or EIP already bound, or deletion protection enabled |
| `ELB.8959` | 400 | Changing a load balancer's L4 or L7 flavor across flavor types |
| `ELB.8938` | 400 | Adding an IP member to a pool whose protocol does not support IP members |
| `ELB.8939` | 400 | Adding an IP member when the load balancer has `ip_target_enable: false` |
| `ELB.1011` | 400 | Unparseable server certificate or private key PEM, or key does not match leaf certificate |
| `ELB.5051` | 400 | Unparseable CA certificate PEM or certificate is not a CA |
| `ELB.8909` | 400 | Certificate with multiple domains where a single domain is required |
| `ELB.8934` | 400 | No free IP addresses remaining in the VIP subnet |
| `WeiStack.0403` | 403 | IAM policy denial under `-iam=enforce` |
| `WeiStack.0501` | 501 | Unimplemented route or out-of-scope option |

## Permissions

Every route checks Huawei's ELB IAM actions (`elb:loadbalancers:*`,
`elb:listeners:*`, `elb:pools:*`, `elb:members:*`, `elb:healthmonitors:*`,
`elb:certificates:*`, `elb:l7policies:*`, `elb:l7rules:*`,
`elb:ipgroups:*`, `elb:security-policies:*`, `elb:flavors:*`,
`elb:availability-zones:list`, `elb:loadbalancerTags:*`,
`elb:listenerTags:*`) and their documented classic aliases (`:get` for
`:show`, `:put` for `:update`) against ELB resource URNs
(`elb:<region>:<account-id>:<type>:<id>`). `ListAllL7Rules` checks
`elb:l7rules:list`, and both `/v2.0` and `/v3` tag routes check the
documented `elb:loadbalancerTags:*` and `elb:listenerTags:*` actions.
Under `-iam=enforce`, denials return `403 WeiStack.0403` with an
`encoded_authorization_message`. System roles `ELB FullAccess`,
`ELB ReadOnlyAccess` and `ELB Administrator` grant the corresponding
actions.

## Client compatibility

Every operation above is exercised through Huawei Cloud's official Go SDK
(`huaweicloud-sdk-go-v3`, `elb/v3` client) in `test/sdk`, and through
Terraform (`huaweicloud_elb_loadbalancer`, `huaweicloud_elb_listener`,
`huaweicloud_elb_pool`, `huaweicloud_elb_member`, `huaweicloud_elb_monitor`,
`huaweicloud_elb_certificate`, `huaweicloud_elb_security_policy`,
`huaweicloud_elb_l7policy`, `huaweicloud_elb_l7rule`,
`huaweicloud_elb_ipgroup`, and the `huaweicloud_elb_flavors`,
`huaweicloud_elb_loadbalancers`, `huaweicloud_elb_listeners` and
`huaweicloud_elb_pools` data sources) in `test/terraform`, in both default
and `-iam=enforce` modes.
