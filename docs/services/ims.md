# IMS coverage

Endpoint: `ims.{region}.myhuaweicloud.com`, `ims.localhost`, or the `/ims`
path prefix.

IMS paths do not contain a project ID. The emulator takes the project from
the `X-Project-Id` header, which the SDKs send, and falls back to its default
project.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListImages | `GET /v2/cloudimages` | Partial | See filters below |
| GlanceShowImage | `GET /v2/images/{image_id}` | Yes | |
| CreateImage | `POST /v2/cloudimages/action` | No | Next |
| UpdateImage | `PATCH /v2/cloudimages/{image_id}` | No | Next |
| GlanceDeleteImage | `DELETE /v2/images/{image_id}` | No | Next |
| ShowJob | `GET /v1/{project_id}/jobs/{job_id}` | No | Next |
| GlanceListImages | `GET /v2/images` | No | |
| Tags, members, copy, export, import, quotas, OS versions | | No | |

## Public images

Every region starts with these public images (`__imagetype=gold`,
`visibility=public`, `status=active`). IDs are derived from the image name,
so they are identical on every machine and survive restarts and resets: a
script or Terraform file can hard-code them.

| Name | `__platform` | `__os_type` | Notes |
| --- | --- | --- | --- |
| Ubuntu 22.04 server 64bit | Ubuntu | Linux | |
| Ubuntu 20.04 server 64bit | Ubuntu | Linux | |
| CentOS 7.9 64bit | CentOS | Linux | |
| Debian 12.0.0 64bit | Debian | Linux | |
| EulerOS 2.5 64bit | EulerOS | Linux | |
| Huawei Cloud EulerOS 2.0 Standard 64 bit | Huawei Cloud EulerOS | Linux | |
| Huawei Cloud EulerOS 2.0 Standard 64 bit for kAi2p | Huawei Cloud EulerOS | Linux | ARM, UEFI |
| Windows Server 2019 Standard 64bit English | Windows | Windows | |

### Adding your own

Put a file named `images.yaml` in a directory and start the emulator with
`-seed-dir <dir>` (or `WEISTACK_SEED_DIR`). Entries are added to the built-in
list; an entry with the name of a built-in image replaces it.

```yaml
images:
  - name: Rocky Linux 9.0 64bit
    os_version: Rocky Linux 9.0 64bit
    platform: Rocky
    min_disk: 40        # GB, default 40
    min_ram: 1024       # MB, default 0
    # os_type: Linux | Windows | Other   (default Linux)
    # arch: x86 | arm                    (default x86)
    # firmware: bios | uefi              (default bios)
    # id: fixed UUID                     (default: derived from the name)
```

An invalid seed file stops the emulator at startup with a message naming the
entry.

## ListImages

- Filters: `__imagetype`, `visibility`, `id`, `name`, `status`, `__platform`,
  `__os_type`, `__os_bit`, `owner`, `tag`, `disk_format`,
  `container_format`, `virtual_env_type`, `protected`. All are exact
  matches. Other documented filters (`min_disk`, `min_ram`, `member_status`,
  `created_at`, `updated_at`, `flavor_id`, `architecture`,
  `enterprise_project_id`, the `__support_*` flags) are accepted and ignored.
- `sort_key`: `name`, `container_format`, `disk_format`, `status`, `id`,
  `size`, `created_at` (default); `sort_dir`: `asc` or `desc` (default).
- `limit`: 1 to 1000, default 1000. `marker`: ID of the last image of the
  previous page. `page_info.next_marker` is present only when another page
  follows.
- A caller sees the region's public images and its own project's private
  images.

## Error codes

IMS errors are `{"error": {"code": "...", "message": "..."}}`.

| Code | HTTP | When |
| --- | --- | --- |
| `IMG.0001` | 400 | Invalid `limit`, `marker`, `sort_key`, `sort_dir` or `protected` |
| `IMG.0027` | 404 | Image does not exist or belongs to another project |

## Client compatibility

`ListImages` (filters, sorting, paging) and `GlanceShowImage` are exercised
through the official Go SDK (`huaweicloud-sdk-go-v3`, `ims/v2` client) in
`test/sdk`.

## Fidelity notes

Golden files are provisional (SDK models and API reference, not recorded
traffic). Known open points:

- The reference documents HTTP 400 for every IMS error code. The emulator
  returns 404 with `IMG.0027` for a missing image on the native OpenStack
  path `/v2/images/{id}`, which is what clients of that API test for.
- Which optional fields real public images carry varies by image
  (`__support_fc_inject`, `__support_kvm`, `__productcode`, ...). The
  emulator returns the common set from the reference's example plus
  `active_at`.
- Whether `page_info` is present on the last page is unverified; the
  emulator omits it.
- `__platform` for Huawei Cloud EulerOS images is assumed to be
  `Huawei Cloud EulerOS`.
