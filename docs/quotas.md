# Quotas

Every service limits what one project may hold, as Huawei Cloud does. The
defaults are those of a new Huawei Cloud account, so a setup that would
exceed a real account's quota fails against WeiStack first.

## Changing a limit

```bash
weistack -quotas vpc.vpc=500,elb.loadbalancer=-1
```

or `WEISTACK_QUOTAS=vpc.vpc=500,elb.loadbalancer=-1`. `-1` is unlimited. An
unknown key stops WeiStack at startup. Four limits have flags of their own,
which `-quotas` does not accept: `-ecs-max-servers` (`ecs.instances`),
`-ecs-max-vcpus` (`ecs.cores`), `-eip-max-per-project` (`vpc.publicIp`) and
`-rds-max-instances` (`rds.instance`).

Limits apply to new resources only. Resources that already exist are kept
when a limit is lowered or when persisted data holds more than the limit:
the quota APIs then report more used than allowed, and creating one more
fails.

## Limits

Limits count per project (a region of an account), except `obs.buckets`,
which counts the account's buckets in every region. Where Huawei publishes
no default, the default is the value in Huawei's own quota API example.

| Key | Default | Source |
| --- | --- | --- |
| `vpc.vpc` | 150 | VPC quota API example |
| `vpc.subnet` | 400 | VPC quota API example |
| `vpc.securityGroup` | 100 | VPC quota API example |
| `vpc.securityGroupRule` | 5000 | VPC quota API example |
| `vpc.publicIp` | 50 | WeiStack before v0.3 (-eip-max-per-project) |
| `vpc.shareBandwidth` | 5 | VPC quota API example |
| `vpc.shareBandwidthIP` | 20 | VPC quota API example |
| `ecs.instances` | 20 | WeiStack before v0.3 (-ecs-max-servers) |
| `ecs.cores` | 80 | WeiStack before v0.3 (-ecs-max-vcpus) |
| `evs.volumes` | -1 (unlimited) | EVS quota API example |
| `evs.gigabytes` | 42790 | EVS quota API example |
| `evs.snapshots` | 10 | EVS quota API example |
| `elb.loadbalancer` | 50 | ELB quotas and constraints |
| `elb.listener` | 100 | ELB quotas and constraints |
| `elb.l7policy` | 500 | ELB quotas and constraints |
| `elb.pool` | 500 | ELB quotas and constraints |
| `elb.member` | 500 | ELB quotas and constraints |
| `elb.certificate` | 120 | ELB quotas and constraints |
| `elb.l7policies_per_listener` | 100 | ELB quotas and constraints |
| `nat.nat_gateway` | 15 | NAT quota API: the default value is 15 |
| `ims.image` | 20 | IMS quota API example |
| `obs.buckets` | 100 | OBS notes and constraints |
| `rds.instance` | 20 | WeiStack before v0.3 (-rds-max-instances) |
| `kms.CMK` | 100 | KMS constraints |
| `csms.secret` | 5000 | CSMS user guide: Creating a Secret |
| `iam.user` | 50 | IAM: the default quota of users |
| `iam.group` | 20 | IAM account quota API example |
| `iam.agency` | 50 | IAM account quota API example |
