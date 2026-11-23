# EVS coverage

Endpoint: `evs.{region}.myhuaweicloud.com`, `evs.localhost`, or the `/evs`
path prefix.

EVS owns every disk in WeiStack, both standalone volumes and disks created with
an [ECS](ecs.md#disks) server. Volumes, snapshots, tags and KMS encryption
metadata are control-plane state only: no block storage is provisioned and no
data is written or encrypted.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

## Volumes (v2 and v2.1)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateVolume | `POST /v2.1/{project_id}/cloudvolumes` | Partial | Returns `202`; pay-per-use only (`bssParam` `prePaid` returns `400 EVS.2147`, `backup_id` returns `400 EVS.1006`, `OS-SCH-HNT:scheduler_hints` ignored) |
| ShowVolume | `GET /v2/{project_id}/cloudvolumes/{volume_id}` | Yes | |
| ListVolumes | `GET /v2/{project_id}/cloudvolumes/detail` | Yes | Filters: `id`, `ids`, `name` (substring), `server_id`, `status`, `availability_zone`, `multiattach`, `volume_type_id`, `enterprise_project_id` (`all_granted_eps` matches all); `offset` and `limit` (default and max 1000); creation order |
| UpdateVolume | `PUT /v2/{project_id}/cloudvolumes/{volume_id}` | Yes | `name` (1–64) and `description` (0–85); returns the volume flat |
| DeleteVolume | `DELETE /v2/{project_id}/cloudvolumes/{volume_id}` | Yes | Deletes the volume and its snapshots (`cascade` accepted and always applied) |
| ResizeVolume | `POST /v2.1/{project_id}/cloudvolumes/{volume_id}/action` | Partial | `os-extend.new_size`; returns `202`; `bssParam` ignored |

Behaviour:

- **Validation on create.** Every check runs before anything is written; a
  rejected request creates nothing. `volume` is required (`EVS.1008`),
  `availability_zone` must exist in the region (`EVS.1036`), and
  `volume_type` must be one of `SATA`, `SAS`, `GPSSD`, `SSD`, `ESSD`,
  `GPSSD2` or `ESSD2` (`EVS.1020`). `name` is at most 64 characters
  (`EVS.1003`), `description` at most 85 (`EVS.1004`), and `count` 1 to 100
  (`EVS.1021`; when `count > 1`, names get `-0001`, `-0002`, ...).
- **Sources and size.** At most one of `imageRef`, `snapshot_id` or
  `backup_id` may be given (`EVS.1016`). `backup_id` is rejected (`EVS.1006`).
  `imageRef` must name an `active` [IMS](ims.md) image (`EVS.2046`) and marks
  the volume `bootable` with `volume_image_metadata` (`image_id`, `image_name`).
  `snapshot_id` must name an `available` snapshot of the project (`EVS.2045`
  if missing, `EVS.2043` if not `available`) in the same AZ (`EVS.2054`) and
  of the same `volume_type` (`EVS.2096`), and inherits its KMS key. An empty
  disk accepts 10 to 32768 GB (`EVS.1010`), an image-backed disk accepts the
  image's `min_disk` to 1024 GB, and a snapshot-backed disk must be at least
  the snapshot's size.
- **QoS.** `GPSSD2` requires both `iops` and `throughput` (`EVS.2233`);
  `ESSD2` requires `iops` and no `throughput` (`EVS.2232`); any other type
  rejects `iops` or `throughput` (`EVS.2235`); values below 1 are rejected
  (`EVS.2231`).
- **Encryption and metadata.** `metadata.__system__encrypted` must be `"0"` or
  `"1"`, and `__system__cmkid` requires `"1"` (`EVS.2041`). With `"1"`, the
  [KMS](kms.md) key named by `__system__cmkid` (or the account's `evs/default`
  key) must be usable (`EVS.2040`). Setting encryption metadata alongside
  `imageRef` or `snapshot_id` is rejected (`EVS.1043`). `hw:passthrough` must
  be `"true"` or `"false"` (`EVS.1057`). Other metadata keys (such as
  `create_for_volume_id`) are stored and returned.
- **Attaching at create.** If `server_id` is set, `count` must be 1
  (`EVS.1021`) and the [ECS](ecs.md) server must exist (`EVS.2229`) in the
  same AZ (`EVS.2263`). Once `evs.volume.create` finishes, EVS calls ECS to
  attach the volume, moving it through `attaching` to `in-use`. Attaching
  and detaching existing volumes use [ECS](ecs.md#disks) (`AttachServerVolume`,
  `DetachServerVolume`, `UpdateServerBlockDevice`).
- **Resize.** `os-extend` is required (`EVS.1011`), `new_size` must exceed the
  current size (`EVS.1015`) and stay within the disk kind's limit (`EVS.1010`).
  The volume must be `available`, or `in-use` with `multiattach: false`
  (`EVS.1065`) on an `ACTIVE` or `SHUTOFF` server (`EVS.1066`); any other
  status returns `EVS.1064`.
- **Delete.** Only `available`, `error`, `error_extending`, `error_restoring`
  and `error_rollbacking` volumes with no operation in flight can be deleted
  (`EVS.1046`).

## Snapshots (v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CreateSnapshot | `POST /v2/{project_id}/cloudsnapshots` | Yes | Returns `202` with status `creating`; starts `evs.snapshot.create` |
| ShowSnapshot | `GET /v2/{project_id}/cloudsnapshots/{snapshot_id}` | Yes | |
| ListSnapshots | `GET /v2/{project_id}/cloudsnapshots/detail` | Yes | Filters: `id`, `name` (exact), `status`, `volume_id`, `availability_zone`, `enterprise_project_id`; `offset` and `limit` (max 1000) |
| UpdateSnapshot | `PUT /v2/{project_id}/cloudsnapshots/{snapshot_id}` | Yes | `name` (1–64) and `description` (0–85); immediate |
| DeleteSnapshot | `DELETE /v2/{project_id}/cloudsnapshots/{snapshot_id}` | Yes | Returns `202` empty body; immediate |
| RollbackSnapshot | `POST /v2/{project_id}/cloudsnapshots/{snapshot_id}/rollback` | Yes | Returns `202` `{"rollback": {"volume_id": ...}}`; starts `evs.snapshot.rollback` |

Behaviour:

- **Create.** `volume_id` must name a project volume (`EVS.5404`) in
  `available` or `in-use`, or `attaching` when `force: true` (`EVS.1031`).
  `name` and `description` follow volume limits. Size, `volume_type` and
  `availability_zone` are copied from the source volume.
  `os-extended-snapshot-attributes:progress` is `"0%"` while `creating` and
  `"100%"` once `available`.
- **Delete.** Snapshot status must be `available` or `error` (`EVS.1047`).
  Deleting a volume also deletes all of its snapshots.
- **Rollback.** `rollback.volume_id` must match the snapshot's source volume
  (`EVS.1032`), the snapshot must be `available` (`EVS.2043`), the volume must
  be `available` or `error_rollbacking` with nothing pending (`EVS.1031`), and
  snapshot names starting with `autobk_snapshot_` are rejected (`EVS.1031`).

## Tags (v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| BatchCreateVolumeTags / BatchDeleteVolumeTags | `POST /v2/{project_id}/cloudvolumes/{volume_id}/tags/action` | Yes | `action` `create` or `delete` (other values return `400 EVS.1070`); returns `204` |
| ShowVolumeTags | `GET /v2/{project_id}/cloudvolumes/{volume_id}/tags` | Yes | Sorted by key |
| ListVolumeTags | `GET /v2/{project_id}/cloudvolumes/tags` | Yes | Map of each key to its sorted distinct values across the project |

Each volume holds up to 10 tags (`EVS.1061`). Keys are 1 to 36 characters and
values 0 to 43 characters (`EVS.1062`). `create` overwrites existing keys;
`delete` ignores absent keys.

## Types, zones and jobs (v1 and v2)

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CinderListVolumeTypes | `GET /v2/{project_id}/types` | Yes | Returns `SATA`, `SAS`, `GPSSD`, `SSD`, `ESSD`, `GPSSD2` and `ESSD2` |
| CinderListAvailabilityZones | `GET /v2/{project_id}/os-availability-zone` | Yes | Public route; returns the region's zones from `zones.Of(region)` |
| ShowJob | `GET /v1/{project_id}/jobs/{job_id}` | Yes | Public route; unknown job returns `400 Common.0011` |

Jobs report `status` `RUNNING`, then `SUCCESS` or `FAIL` with `error_code` and
`fail_reason`. Single-volume create returns a `createVolume` job; multi-volume
create returns `batchCreateVolume` with one `createVolume` sub-job per volume;
resize returns `extendVolume`; delete returns `deleteVolume`.

## Lifecycle and statuses

Asynchronous operations run on the shared lifecycle engine and can be failed
with [lifecycle faults](faults.md):

| Task kind | Target status during | Success | Fault |
| --- | --- | --- | --- |
| `evs.volume.create` | Volume `creating` | `available` (or attaches if `server_id` was given) | Volume `error`; job `FAIL` (`EVS.2024`) |
| `evs.volume.extend` | Volume `extending` | New size applied; previous status restored | Volume `error_extending`; job `FAIL` (`EVS.2026`) |
| `evs.volume.delete` | Volume `deleting` | Volume and its snapshots removed | Volume `error_deleting`; job `FAIL` (`EVS.2020`) |
| `evs.snapshot.create` | Snapshot `creating` | Snapshot `available` (`100%`) | Snapshot `error` (no job) |
| `evs.snapshot.rollback` | Volume `rollbacking` | Volume `available` | Volume `error_rollbacking` (no job) |

Disks created with an ECS server start in `in-use` immediately. Attaching and
detaching existing volumes run ECS tasks (`ecs.volume.attach`,
`ecs.volume.detach`), moving the volume through `attaching` to `in-use` or
`detaching` to `available` (or `in-use` if other attachments remain on a
`multiattach` volume).

- **Disk statuses:** `creating`, `available`, `in-use`, `attaching`,
  `detaching`, `extending`, `deleting`, `rollbacking`, `error`,
  `error_extending`, `error_deleting`, `error_rollbacking` (plus
  `error_restoring` accepted on delete).
- **Snapshot statuses:** `creating`, `available`, `error`.

## Quotas

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| CinderListQuotas | `GET /v2/{project_id}/os-quota-sets/{target_project_id}` | Yes | Reports `volumes`, `gigabytes`, `snapshots` and per-type usage (`limit: -1`); `backups` and `backup_gigabytes` omitted (`evs:quotas:get`) |

Limits are per project and configurable with `-quotas` (see
[Quotas](../quotas.md)).

| Key | Default | Error | Enforced |
| --- | --- | --- | --- |
| `evs.volumes` | -1 (unlimited) | `400 EVS.1034` | Yes |
| `evs.gigabytes` | 42790 | `400 EVS.1042` | Yes |
| `evs.snapshots` | 10 | `400 EVS.1034` | Yes |

Extending a volume checks the added GiB against `evs.gigabytes`
(`400 EVS.1042`). Disks created with an [ECS](ecs.md#quotas) server check
`evs.volumes` and `evs.gigabytes`, which ECS maps to `400 Ecs.0021`.

## Not emulated

The following are outside scope and return `501 WeiStack.0501` unless noted:

- v3 and v5 EVS APIs
- Cinder-native `/v2/{project_id}/volumes...` and `/v2/{project_id}/snapshots...` routes
- Volume retype, QoS change, and batch expand
- Recycle bin and volume transfers
- Charge mode (`prePaid` `bssParam` on create returns `400 EVS.2147`; `bssParam` on resize is ignored)
- Volume metadata APIs (`/v2/{project_id}/cloudvolumes/{volume_id}/metadata`)
- Tag-filtered resource queries (`resource_instances/action`)
- Backups (`backup_id` on create returns `400 EVS.1006`)

## Error codes

Every EVS route uses the nested error envelope
`{"error": {"code": "...", "message": "..."}}`.

| Code | HTTP | When |
| --- | --- | --- |
| `WeiStack.0403` | 403 | IAM policy denial under `-iam=enforce` (EVS uses `WeiStack.0403` rather than `EVS.5403`) |
| `WeiStack.0501` | 501 | Unimplemented operation |
| `Common.0011` | 400 | Job not found on `ShowJob` |
| `EVS.1003` | 400 | Invalid volume or snapshot `name` |
| `EVS.1004` | 400 | Invalid volume or snapshot `description` |
| `EVS.1006` | 400 | `backup_id` specified on create (backups are not emulated) |
| `EVS.1007` | 400 | Both `name` and `description` omitted on update |
| `EVS.1008` | 400 | Missing `volume` object on create |
| `EVS.1010` | 400 | Volume `size` or `new_size` out of range |
| `EVS.1011` | 400 | Missing `os-extend` object on resize |
| `EVS.1015` | 400 | Resize `new_size` is not greater than current size |
| `EVS.1016` | 400 | More than one of `imageRef`, `snapshot_id` and `backup_id` specified |
| `EVS.1020` | 400 | Unsupported `volume_type` |
| `EVS.1021` | 400 | Invalid `count` (must be 1–100, and 1 when `server_id` is set) |
| `EVS.1023` | 400 | `limit` is not a positive integer |
| `EVS.1031` | 400 | Volume or snapshot state/name does not allow snapshot create or rollback |
| `EVS.1032` | 400 | Rollback `volume_id` does not match the snapshot's source volume |
| `EVS.1034` | 400 | Volume or snapshot count quota exceeded |
| `EVS.1036` | 400 | Invalid `availability_zone` |
| `EVS.1042` | 400 | Total volume gigabytes quota exceeded |
| `EVS.1043` | 400 | Encryption metadata specified with `imageRef` or `snapshot_id` |
| `EVS.1046` | 400 | Volume status does not allow deletion |
| `EVS.1047` | 400 | Snapshot status does not allow deletion |
| `EVS.1057` | 400 | Invalid `hw:passthrough` value in metadata |
| `EVS.1061` | 400 | More than 10 tags on a volume |
| `EVS.1062` | 400 | Invalid tag key or value |
| `EVS.1064` | 400 | Volume status does not allow resize |
| `EVS.1065` | 400 | Shared (`multiattach`) volume cannot be resized while `in-use` |
| `EVS.1066` | 400 | Attached server status is not `ACTIVE` or `SHUTOFF` on resize |
| `EVS.1070` | 400 | Invalid request (malformed body, invalid `offset`, or unsupported tag `action`) |
| `EVS.2020` | 400 | Job failure code when `evs.volume.delete` fails on an injected fault |
| `EVS.2024` | 400 | Job failure code when `evs.volume.create` fails on an injected fault |
| `EVS.2026` | 400 | Job failure code when `evs.volume.extend` fails on an injected fault |
| `EVS.2040` | 400 | KMS key is missing, disabled or unavailable for encryption |
| `EVS.2041` | 400 | Invalid `__system__encrypted` or `__system__cmkid` metadata |
| `EVS.2043` | 400 | Source snapshot is not `available` |
| `EVS.2045` | 400 | Source snapshot does not exist in the project |
| `EVS.2046` | 400 | Source `imageRef` does not exist or is not `active` |
| `EVS.2054` | 400 | Source snapshot is in a different `availability_zone` |
| `EVS.2096` | 400 | Source snapshot has a different `volume_type` |
| `EVS.2142` | 400 | `limit` is greater than 1000 |
| `EVS.2147` | 400 | `prePaid` `bssParam` is not supported |
| `EVS.2229` | 400 | `server_id` does not exist in ECS |
| `EVS.2231` | 400 | `iops` or `throughput` is below 1 |
| `EVS.2232` | 400 | `ESSD2` requires `iops` and forbids `throughput` |
| `EVS.2233` | 400 | `GPSSD2` requires both `iops` and `throughput` |
| `EVS.2235` | 400 | `iops` or `throughput` is not supported for this `volume_type` |
| `EVS.2263` | 400 | `availability_zone` does not match the target server's AZ |
| `EVS.5404` | 404 | Volume or snapshot does not exist in the project |

## Permissions

Each route checks Huawei's EVS IAM 5.0 action (`evs:volumes:*`,
`evs:snapshots:*`, `evs:types:get`, `evs:quotas:get`) and its classic alias
(`evs:volumes:extend`, `evs:volumeTags:*`) against `evs:<region>:<account-id>:volume:<id>` or
`snapshot:<id>` where resource-scoped. `BatchCreateVolumeTags` and
`BatchDeleteVolumeTags` defer authorization until the request body names
`create` or `delete`. `CinderListAvailabilityZones` and `ShowJob` are public
routes and require no permission. The `evs:volumes:use` dependency is not
checked. Under `-iam=enforce`, denials return `403 WeiStack.0403`.

## Client compatibility

Every operation above is exercised through Huawei Cloud's official Go SDK
(`huaweicloud-sdk-go-v3`, `evs/v2` client) in `test/sdk`, and through
Terraform (`huaweicloud_evs_volume`, `huaweicloud_evs_snapshot`,
`huaweicloud_evs_volumes`, `huaweicloud_evs_snapshots`,
`huaweicloud_evs_availability_zones`, `huaweicloud_evs_volume_types`, and
`huaweicloud_compute_volume_attach` via [ECS](ecs.md#disks)) in
`test/terraform`, in both default and `-iam=enforce` modes.
