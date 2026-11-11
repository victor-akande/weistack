# EVS coverage

Endpoint: `evs.{region}.myhuaweicloud.com`, `evs.localhost`, or the `/evs`
path prefix.

WeiStack has no standalone volumes. Every disk belongs to the
[ECS](ecs.md#disks) server it was created with and lives exactly as long as
that server. EVS shows those disks read-only. Clients that read a server's
disks through EVS, such as Terraform's `huaweicloud_compute_instance`,
therefore work.

Legend: **Yes** implemented, **No** returns `501 WeiStack.0501`.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ShowVolume | `GET /v2/{project_id}/cloudvolumes/{volume_id}` | Yes | |
| ListVolumes | `GET /v2/{project_id}/cloudvolumes/detail` | Yes | `id`, `ids`, `name` (substring), `server_id`, `status`, `availability_zone`, `limit` (at most 1000), `offset` |
| Creating, attaching, detaching, expanding and deleting volumes; snapshots; backups; tags | | No | |

## Volumes

| Field | Value |
| --- | --- |
| `status` | `in-use`: every disk is attached |
| `attachments` | The server, with the disk's device |
| `bootable` | `"true"` for the system disk |
| `volume_image_metadata` | The image's `image_id` and `image_name`, on the system disk |
| `volume_type`, `size`, `availability_zone` | As requested when the server was created |
| `enterprise_project_id` | The server's, or `"0"` |

## Error codes

| Code | Status | When |
| --- | --- | --- |
| `EVS.5404` | 404 | No disk with that ID in the project |
| `EVS.1023` | 400 | `limit` is not a positive integer |
| `EVS.2142` | 400 | `limit` is greater than 1000 |
| `EVS.1070` | 400 | `offset` is not a non-negative integer |
