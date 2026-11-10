# ECS coverage

Endpoint: `ecs.{region}.myhuaweicloud.com`, `ecs.localhost`, or the `/ecs`
path prefix.

Servers are state only: nothing boots and nothing listens on a server's
address.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListFlavors | `GET /v1/{project_id}/cloudservers/flavors` | Yes | `availability_zone`, `flavor_id`, `marker`, `limit` |
| NovaListAvailabilityZones | `GET /v2.1/{project_id}/os-availability-zone` | Yes | |
| Servers, actions, jobs, tags | | No | Next |

## Availability zones

Every region has three zones, named as Huawei Cloud names them: the region
followed by `a`, `b` or `c` (`ap-southeast-1a`, ...). All are available.

## Flavors

The same flavors are sold in every zone of every region. vCPU and memory
values are those of the real flavors.

| Family | Flavors (vCPUs / GiB) |
| --- | --- |
| `s6` general computing | `s6.small.1` (1/1), `s6.medium.2` (1/2), `s6.medium.4` (1/4), `s6.large.2` (2/4), `s6.large.4` (2/8), `s6.xlarge.2` (4/8), `s6.xlarge.4` (4/16), `s6.2xlarge.2` (8/16), `s6.2xlarge.4` (8/32) |
| `c7` general computing-plus | `c7.large.2` (2/4), `c7.large.4` (2/8), `c7.xlarge.2` (4/8), `c7.xlarge.4` (4/16), `c7.2xlarge.2` (8/16), `c7.2xlarge.4` (8/32) |
| `m7` memory-optimized | `m7.large.8` (2/16), `m7.xlarge.8` (4/32), `m7.2xlarge.8` (8/64) |
| `kc1` Kunpeng (ARM) | `kc1.large.2` (2/4), `kc1.xlarge.2` (4/8) |

### Adding your own

Put a file named `flavors.yaml` in the directory given by `-seed-dir` (or
`WEISTACK_SEED_DIR`). Entries are added to the built-in list; an entry with
the name of a built-in flavor replaces it.

```yaml
flavors:
  - name: t6.small.1
    vcpus: 1
    ram: 1024                 # MiB
    # performance_type: normal   (ecs:performancetype)
    # arch: x86 | arm            (default x86)
```

## Error codes

ECS errors are `{"error": {"code": "...", "message": "..."}}`.

| Code | HTTP | When |
| --- | --- | --- |
| `Ecs.0005` | 400 | Invalid `limit` or `marker` |

## Client compatibility

`ListFlavors` and `NovaListAvailabilityZones` are exercised through the
official Go SDK (`huaweicloud-sdk-go-v3`, `ecs/v2` client) in `test/sdk`.

## Fidelity notes

Golden files are provisional (SDK models and API reference, not recorded
traffic). Known open points:

- Real flavors carry many more `os_extra_specs` keys, and which zones sell a
  flavor varies; the emulator returns a common subset and sells everything
  everywhere.
- `resource_type` values are synthesised from the flavor family.
- Real regions have differing numbers of zones, and some use other naming.
