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
| CreatePostPaidServers | `POST /v1/{project_id}/cloudservers` | Partial | See "Creating servers" |
| CreateServers | `POST /v1.1/{project_id}/cloudservers` | Partial | Same body and behaviour; pay-per-use only |
| ShowServer | `GET /v1/{project_id}/cloudservers/{server_id}` | Yes | |
| ListServersDetails | `GET /v1/{project_id}/cloudservers/detail` | Yes | See "Listing servers" |
| DeleteServers | `POST /v1/{project_id}/cloudservers/delete` | Yes | `delete_publicip`, `delete_volume` accepted; disks and EIPs are data only |
| ShowJob | `GET /v1/{project_id}/jobs/{job_id}` | Yes | |
| UpdateServer | `PUT /v1/{project_id}/cloudservers/{server_id}` | Partial | `name`, `description`, `user_data`. `hostname` cannot be changed |
| BatchStartServers | `POST /v1/{project_id}/cloudservers/action` (`os-start`) | Yes | |
| BatchStopServers | `POST /v1/{project_id}/cloudservers/action` (`os-stop`) | Yes | `SOFT` and `HARD` behave alike |
| BatchRebootServers | `POST /v1/{project_id}/cloudservers/action` (`reboot`) | Yes | |
| ResizePostPaidServer | `POST /v1/{project_id}/cloudservers/{server_id}/resize` | Partial | `dry_run`: `501` |
| ShowServerTags | `GET /v1/{project_id}/cloudservers/{server_id}/tags` | Yes | |
| BatchCreateServerTags / BatchDeleteServerTags | `POST /v1/{project_id}/cloudservers/{server_id}/tags/action` | Yes | |
| ListServerTags | `GET /v1/{project_id}/cloudservers/tags` | Yes | |
| ListServerBlockDevices | `GET /v1/{project_id}/cloudservers/{server_id}/block_device` | Yes | The server's disks; see "Disks" |
| ShowServerBlockDevice | `GET /v1/{project_id}/cloudservers/{server_id}/block_device/{volume_id}` | Yes | |
| Batch resize, rename, redeploy, NICs, attaching and detaching disks, key pairs, server groups, metadata, password, console | | No | |
| Nova-native server API (`/v2.1/{project_id}/servers...`) | | No | |

## Creating servers

A create request is validated completely before anything is written; a
rejected request creates no server and consumes no address.

- **Required:** `name`, `imageRef`, `flavorRef`, `vpcid`, `nics` (1 to 12,
  each with a `subnet_id` of that VPC), `root_volume.volumetype`.
- **Image:** must exist, be `active` and match the flavor's CPU
  architecture. Private images of the project can be used.
- **Network:** each NIC takes a private address from its subnet, the lowest
  free one or the requested `ip_address`. Without `security_groups` the
  project's `default` group is used.
- **Disks:** `volumetype` is one of `SATA`, `SAS`, `GPSSD`, `SSD`, `ESSD`,
  `GPSSD2`, `ESSD2`. The root disk defaults to the image's `min_disk` and
  cannot be smaller; up to 23 data disks of 10 to 32768 GB.
- **`count`:** 1 to 500. With more than one, names get the suffixes `-0001`,
  `-0002`, ... and `ip_address` cannot be given.
- **`availability_zone`:** optional; the region's first zone when omitted.
- **`adminPass`:** checked for complexity, then discarded. It is never
  stored or returned.
- **`publicip`:** the server shows a `floating` address from
  `198.51.100.0/24`. No EIP service stands behind it.
- **`key_name`, `user_data`, `metadata`:** stored and returned as given. Key
  pairs are not emulated, so any key name is accepted.
- **Tags:** `server_tags` (`key`/`value`) or the older `tags` (`key.value`),
  at most 10, shown as `key=value`.
- **Quota:** 20 servers and 80 vCPUs per project by default
  (`-ecs-max-servers`, `-ecs-max-vcpus`).
- `dry_run` is not emulated (`501`).

The response carries a `job_id` and the `serverIds`. Each server is `BUILD`
and becomes `ACTIVE` after the lifecycle delay; the job (`createServer`, with
one `createSingleServer` sub-job per server) then reports `SUCCESS`.

## Disks

A server's system and data disks are part of the server: they are created
with it and deleted with it. ECS shows them as block devices: the system
disk has `bootIndex` 0 and device `/dev/vda`, data disks have -1 and
`/dev/vdb` onwards. [EVS](evs.md) shows the same disks as volumes, named
`{server name}-volume-0000` onwards. A volume that is not attached to the
server is `400 Ecs.0111`.

## Deleting servers

`DeleteServers` takes a list and returns a job. Every listed server must
exist, or none is touched. Servers show `OS-EXT-STS:task_state: deleting`
until the lifecycle delay passes; then they are gone and their addresses are
free. A server can be deleted while still `BUILD`: the build is abandoned and
its create job fails.

## Server status

| Operation | Needs | While running | Ends in |
| --- | --- | --- | --- |
| Create | | `BUILD`, task `spawning` | `ACTIVE` |
| Stop | `ACTIVE` | `ACTIVE`, task `powering-off` | `SHUTOFF` |
| Start | `SHUTOFF` | `SHUTOFF`, task `powering-on` | `ACTIVE` |
| Reboot (`SOFT`) | `ACTIVE` | `REBOOT`, task `rebooting` | `ACTIVE` |
| Reboot (`HARD`) | `ACTIVE` | `HARD_REBOOT`, task `rebooting` | `ACTIVE` |
| Resize | `SHUTOFF` | `RESIZE`, task `resize_prep` | `SHUTOFF` |
| Resize, `mode: withStopServer` | `ACTIVE` | `RESIZE`, task `resize_prep` | `ACTIVE` |
| Delete | any | task `deleting` | gone |

- Each operation returns a job and completes after the lifecycle delay.
- An operation on a server in the wrong status, or with another operation
  in flight, is refused with `Ecs.0100`. Delete is the exception: it
  abandons whatever is in flight, and that operation's job fails.
- Start, stop and reboot take up to 1000 servers. Every listed server must
  exist and be in the right status, or none is touched.
- Resize needs a different flavor of the same CPU architecture and room in
  the vCPU quota. The flavor changes when the job finishes.
- An injected fault leaves the server `ERROR` and the job `FAIL`.

## Tags

A server has at most 10 tags. A key has 1 to 36 characters and a value at
most 43; neither may contain `= * < > \ , | /`. Creating a tag whose key
exists replaces its value. Deleting matches by key and ignores keys the
server does not have. `ListServerTags` returns every key in the project with
the values it takes.

## Listing servers

- Filters: `name` (substring), `status`, `flavor`, `ip` (prefix), `ip_eq`,
  `server_id`, `reservation_id`, `enterprise_project_id`, `tags` and
  `not-tags` (comma-separated; `key` or `key=value`).
- `offset` is a **page number** starting at 1 (0 means 1); `limit` is the
  page size, 25 by default and at most 1000. `count` is the total number of
  matching servers.

## Images of servers

`CreateImage` in [IMS](ims.md) with a server's ID as `instance_id` now
works: the image inherits the server's operating system, and its `min_disk`
is the server's root disk size.

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
| `Ecs.0005` | 400 | Malformed body or invalid parameter value |
| `Ecs.0001` | 400 | Server or vCPU quota exceeded |
| `Ecs.0007` | 400 | Image and flavor have different CPU architectures |
| `Ecs.0010` | 400 | Requested private IP already in use |
| `Ecs.0011` | 400 | `adminPass` too simple |
| `Ecs.0012` | 400 | Subnet has too few free addresses |
| `Ecs.0014` | 400 | VPC or security group does not exist |
| `Ecs.0029` | 400 | Flavor does not exist |
| `Ecs.0031` | 400 | Image does not exist |
| `Ecs.0032` | 400 | Image is not `active` |
| `Ecs.0038` | 400 | Subnet does not exist |
| `Ecs.0039` | 400 | Requested private IP not usable in the subnet |
| `Ecs.0042` | 400 | More than 23 data disks |
| `Ecs.0043` | 400 | Unknown disk type |
| `Ecs.0050` | 400 | More than 12 NICs |
| `Ecs.0064` | 400 | Subnet belongs to another VPC |
| `Ecs.0100` | 400 | Server status does not allow the operation, or another is in flight |
| `Ecs.0114` | 404 | Server does not exist |
| `Ecs.0118` | 400 | More than 1000 servers in a batch |
| `Ecs.0804` | 400 | Resize to a flavor of another CPU architecture |
| `Ecs.0810` | 400 | Resize to the current flavor |
| `Ecs.0905` to `Ecs.0908` | 400 | Too many tags; invalid tag; forbidden character; duplicate key |
| `Ecs.0913` | 400 | `count` above 500 |
| `Ecs.0914`, `Ecs.0915` | 400 | Name too long; name empty or with invalid characters |
| `Common.0011` | 400 | Job does not exist |

A failed job reports `error_code` `Ecs.0000`.

## Client compatibility

Every operation marked **Yes** or **Partial** is exercised through the
official Go SDK (`huaweicloud-sdk-go-v3`, `ecs/v2` client) in `test/sdk`.
`TestServerEndToEnd` runs the whole path across three services: network,
server from a public image, private image of that server, second server from
the image, and teardown in reverse order. `TestServerOperations` stops,
starts, reboots, resizes, renames and tags a server, waiting on each job.

## Fidelity notes

Golden files are provisional (SDK models and API reference, not recorded
traffic). Known open points:

- The server detail is the common subset of what real servers return. Values
  such as `hostId`, `OS-EXT-SRV-ATTR:host` and the system `metadata` keys
  are plausible stand-ins.
- Real Huawei Cloud names the servers of a multi-server request by its own
  rules, which depend on `isAutoRename`; the emulator always uses `-0001`
  style suffixes.
- Whether deleting a list containing an unknown server fails the request
  (as here) or only that sub-job is unverified.
- Job type names other than `createServer`/`createSingleServer` (delete,
  start, stop, reboot, resize) are assumed by analogy.
- Real Huawei Cloud may accept a batch start/stop/reboot and fail only the
  sub-jobs of servers in the wrong status; the emulator refuses the request.
- The `task_state` values and the transient `RESIZE` status are those of
  OpenStack Nova; a real resize also passes through `VERIFY_RESIZE`.
- The update response follows the SDK model (`image` as an ID string); the
  API reference has no example to compare with.
- Real flavors carry many more `os_extra_specs` keys, and which zones sell a
  flavor varies; the emulator returns a common subset and sells everything
  everywhere.
- `resource_type` values are synthesised from the flavor family.
- Real regions have differing numbers of zones, and some use other naming.
