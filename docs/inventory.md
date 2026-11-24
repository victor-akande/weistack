# Inventory

The inventory lists every resource WeiStack holds, in every account,
region and project, with its tags and how it relates to other resources:
which VPC a server is in, which volumes are attached to it, which listeners
a load balancer has. It answers "what is there?" in one call, for people,
scripts and agents.

```bash
weistack admin GET inventory
curl -s 'http://127.0.0.1:8780/_weistack/inventory?type=ecs.cloudservers'
```

Under `-iam=enforce`, and always over `-lan`, it answers only the
administrator, as all of the admin API does: `weistack admin` signs the
call.

## The response

Resources and relationships have the fields and names of Huawei Cloud's
Config service (RMS), plus `account_id`:

```json
{
  "resources": [
    {
      "id": "a3a3c3f0-...",
      "name": "web",
      "provider": "ecs",
      "type": "cloudservers",
      "account_id": "6c2e...",
      "region_id": "ap-southeast-1",
      "project_id": "0123456789abcdef0123456789abcdef",
      "ep_id": "0",
      "created": "2026-11-24T09:30:15Z",
      "updated": "2026-11-24T09:30:15Z",
      "provisioning_state": "Succeeded",
      "tags": {"env": "dev"},
      "relations": [
        {
          "relation_type": "isContainedIn",
          "from_resource_type": "ecs.cloudservers",
          "to_resource_type": "vpc.vpcs",
          "from_resource_id": "a3a3c3f0-...",
          "to_resource_id": "4b1e..."
        }
      ]
    }
  ],
  "count": 1
}
```

- **Order:** by type, region, project and ID.
- **`relations`:** every relationship from the resource. Each one is also
  listed from the other resource, the other way round: a VPC `contains`
  the server that `isContainedIn` it.
- **Where a resource lives:** most resources belong to a project in a
  region. OBS buckets belong to an account in a region, with an empty
  `project_id`. IAM resources are global: `region_id` is `global`, and
  `project_id` is empty.
- **`account_id`:** the account the project or resource belongs to. It is
  empty when no account owns it, which happens in accept mode, where
  clients may use any project ID and any access key.
- **`ep_id`:** the enterprise project; `0` is the default one.
- **`provisioning_state`:** `Succeeded`, `Processing` while the resource
  is being created or changed, or `Failed`.
- **`created` and `updated`:** UTC, to the second. They are left out when
  the service does not record them.
- **A snapshot:** WeiStack reads the services one after another. A
  resource created or deleted during the call may be missing or listed.

## Selecting resources

Every query parameter is optional, and they combine:

| Parameter | Selects |
| --- | --- |
| `type` | One type, as `provider.type`, such as `vpc.vpcs`. An unknown type gets `400 WeiStack.0400`. |
| `account_id` | One account |
| `region_id` | One region; `global` for IAM |
| `project_id` | One project |
| `ep_id` | One enterprise project |
| `id` | One resource ID |

## Types

The names are those of Huawei Cloud's Config. Where Huawei documents no
name for a type, WeiStack follows the convention every documented name
keeps: the provider Config files the service under, and the collection in
the service's API path, in lower camel case. Those names may change if
Huawei documents different ones.

Every resource of an account is listed, including those the cloud makes
for it, such as a project's default security group. Public images, system
policies, jobs, tasks and access keys are not.

| Type | Service | Huawei name |
| --- | --- | --- |
| `ecs.cloudservers` | ECS | Documented |
| `elb.certificates` | ELB | WeiStack's |
| `elb.healthmonitors` | ELB | WeiStack's |
| `elb.ipgroups` | ELB | WeiStack's |
| `elb.l7policies` | ELB | WeiStack's |
| `elb.listeners` | ELB | Documented |
| `elb.loadbalancers` | ELB | Documented |
| `elb.members` | ELB | Documented |
| `elb.pools` | ELB | WeiStack's |
| `elb.securityPolicies` | ELB | WeiStack's |
| `evs.snapshots` | EVS | WeiStack's |
| `evs.volumes` | EVS | Documented |
| `iam.agencies` | IAM | Documented |
| `iam.groups` | IAM | Documented |
| `iam.policies` | IAM (IAM 5.0 policies) | Documented |
| `iam.roles` | IAM (classic custom policies) | Documented |
| `iam.users` | IAM | Documented |
| `ims.images` | IMS (private images) | Documented |
| `kms.keys` | KMS | Documented |
| `kps.keypairs` | KPS | WeiStack's |
| `nat.dnatRules` | NAT | WeiStack's |
| `nat.natGateways` | NAT | Documented |
| `nat.privateDnatRules` | NAT | WeiStack's |
| `nat.privateNatGateways` | NAT | Documented |
| `nat.privateSnatRules` | NAT | WeiStack's |
| `nat.snatRules` | NAT | WeiStack's |
| `nat.transitIps` | NAT | WeiStack's |
| `nat.transitSubnets` | NAT | WeiStack's |
| `obs.buckets` | OBS | Documented |
| `rds.backups` | RDS | WeiStack's |
| `rds.instances` | RDS | Documented |
| `vpc.bandwidths` | EIP (shared bandwidths) | Documented |
| `vpc.networks` | VPC (subnets) | Documented |
| `vpc.publicips` | EIP | Documented |
| `vpc.securityGroupRules` | VPC | WeiStack's |
| `vpc.securityGroups` | VPC | Documented |
| `vpc.vpcs` | VPC | Documented |

## Relationships

Only the relationships in Config's table of relationships are listed, so
WeiStack shows none that Huawei Cloud would not. The table relates no VPC
to its subnets, for example.

| Resource | Relationship | Other resource |
| --- | --- | --- |
| `ecs.cloudservers` | `isContainedIn` | `vpc.vpcs` |
| `ecs.cloudservers` | `isAttachedTo` | `vpc.publicips` |
| `ecs.cloudservers` | `isAttachedTo` | `evs.volumes` |
| `ecs.cloudservers` | `isAssociatedWith` | `vpc.securityGroups` |
| `ecs.cloudservers` | `isAssociatedWith` | `ims.images` |
| `elb.loadbalancers` | `contains` | `elb.listeners` |
| `elb.loadbalancers` | `isAttachedTo` | `vpc.publicips` |
| `elb.loadbalancers` | `isAttachedTo` | `elb.pools` |
| `elb.listeners` | `contains` | `elb.l7policies` |
| `elb.listeners` | `isAttachedTo` | `elb.pools` |
| `elb.pools` | `contains` | `elb.members` |
| `vpc.vpcs` | `contains` | `vpc.publicips` |
| `vpc.bandwidths` | `contains` | `vpc.publicips` |
| `vpc.publicips` | `isAttachedTo` | `nat.natGateways` |
| `iam.groups` | `contains` | `iam.users` |
| `iam.agencies` | `isAssociatedWith` | `iam.policies` |
| `iam.agencies` | `isAssociatedWith` | `iam.roles` |
| `iam.groups` | `isAssociatedWith` | `iam.policies` |
| `iam.groups` | `isAssociatedWith` | `iam.roles` |
| `iam.users` | `isAssociatedWith` | `iam.policies` |
| `iam.users` | `isAssociatedWith` | `iam.roles` |

Each is listed from both ends. From the other end, `contains` reads
`isContainedIn`, and the others read the same.
