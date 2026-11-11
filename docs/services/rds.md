# RDS coverage

Endpoint: `rds.{region}.myhuaweicloud.com`, `rds.localhost`, or the `/rds`
path prefix.

Instances are metadata only: nothing listens on an instance's address and no
SQL is accepted.

Legend: **Yes** implemented, **Partial** implemented with the listed gaps,
**No** returns `501 WeiStack.0501`.

| Operation | Method and path | Status | Notes |
| --- | --- | --- | --- |
| ListDatastores | `GET /v3/{project_id}/datastores/{database_name}` | Yes | MySQL and PostgreSQL |
| ListFlavors | `GET /v3/{project_id}/flavors/{database_name}` | Yes | `version_name`, `spec_code` |
| CreateInstance | `POST /v3/{project_id}/instances` | Partial | See "Creating instances" |
| ListInstances | `GET /v3/{project_id}/instances` | Yes | The way to read one instance, as in the real API |
| DeleteInstance | `DELETE /v3/{project_id}/instances/{instance_id}` | Yes | |
| ListJobInfo | `GET /v3/{project_id}/jobs?id=` | Yes | |
| ShowStorageUsedSpace | `GET /v3/{project_id}/instances/{instance_id}/storage-used-space` | Yes | Always `"0"`: no database stores data |
| StartInstanceRestartAction | `POST .../instances/{id}/action` `{"restart": {}}` | Yes | Options (`delay`, `restart_server`) ignored |
| StartResizeFlavorAction | `POST .../instances/{id}/action` `{"resize_flavor": ...}` | Yes | `is_delay` ignored |
| StartInstanceEnlargeVolumeAction | `POST .../instances/{id}/action` `{"enlarge_volume": ...}` | Yes | |
| CreateManualBackup | `POST /v3/{project_id}/backups` | Partial | Metadata only; `backup_database_individually` ignored |
| ListBackups | `GET /v3/{project_id}/backups` | Yes | `instance_id` (required), `backup_id`, `backup_type`, `status`, `offset`, `limit` |
| DeleteManualBackup | `DELETE /v3/{project_id}/backups/{backup_id}` | Yes | |
| Stop/start, storage shrinking, automated backups, restore | | No | |
| SQL Server, MariaDB | | No | |
| Read replicas, restore, parameter templates, accounts, databases, logs, SSL, EIPs | | No | |

## Engines and specifications

| Engine | Versions | Default port | Port range | Storage (GB) | Backup retention |
| --- | --- | --- | --- | --- | --- |
| MySQL | 5.7, 8.0 | 3306 | 1024–65535, not 12017 or 33071 | 20–10000 | 1–732 days |
| PostgreSQL | 13, 14, 15, 16, 17, 18 | 5432 | 2100–9500 | 40–4000 | 1–3660 days |

Each engine has six general-purpose sizes, each as a single instance and, with
the `.ha` suffix, as a primary/standby pair:

| Size | vCPUs | Memory (GB) | MySQL spec code | PostgreSQL spec code |
| --- | --- | --- | --- | --- |
| large.2 | 2 | 4 | `rds.mysql.n1.large.2` | `rds.pg.n1.large.2` |
| large.4 | 2 | 8 | `rds.mysql.n1.large.4` | `rds.pg.n1.large.4` |
| xlarge.2 | 4 | 8 | `rds.mysql.n1.xlarge.2` | `rds.pg.n1.xlarge.2` |
| xlarge.4 | 4 | 16 | `rds.mysql.n1.xlarge.4` | `rds.pg.n1.xlarge.4` |
| 2xlarge.2 | 8 | 16 | `rds.mysql.n1.2xlarge.2` | `rds.pg.n1.2xlarge.2` |
| 2xlarge.4 | 8 | 32 | `rds.mysql.n1.2xlarge.4` | `rds.pg.n1.2xlarge.4` |

## Creating instances

A request is validated completely before anything is written.

- **Name:** 4 to 64 characters, starting with a letter; letters, digits, `-`
  and `_`, plus `.` for MySQL. Unique within the project.
- **Password** (optional): 8 to 32 characters. MySQL needs all four of
  uppercase, lowercase, digits and `~!@#$%^*-_=+?,()&.|`; PostgreSQL needs
  three of uppercase, lowercase, digits and `~!@#$%^*-_=+?,`. It is checked
  and then discarded: never stored or returned.
- **Specification and HA:** `flavor_ref` must be a spec code of the engine.
  An `.ha` spec requires `ha.mode: Ha` and two availability zones
  (`"ap-southeast-1a,ap-southeast-1b"`), and the other way round. MySQL
  replication is `semisync` (default) or `async`; PostgreSQL `async`
  (default) or `sync`.
- **Storage:** `volume.type` is `ULTRAHIGH`, `CLOUDSSD`, `ESSD` or `ESSD2`;
  the size is a multiple of 10 within the engine's range.
- **Placement:** `region` must be the endpoint's region; zones must exist.
- **Network:** the VPC, a subnet of that VPC and the security group must
  exist. The instance takes one private address from the subnet, so the
  subnet cannot be deleted while the instance exists.
- **Backups:** `backup_strategy.start_time` is a one-hour UTC window on a
  quarter hour (`08:15-09:15`); default `02:00-03:00`, keeping 7 days.
- **Quota:** 20 instances per project (`-rds-max-instances`).
- Read replicas, restore, `dry_run`, `count` other than 1, yearly/monthly
  billing, SQL Server and MariaDB return `501` naming the gap.

The response (HTTP 202) carries the instance in status `BUILD` and a
`job_id`. After the lifecycle delay the instance is `ACTIVE` and the job
`Completed`.

## Instances

| Field | Value |
| --- | --- |
| `id` | 32 hex characters + `in01` |
| `type` | `Single` or `Ha` |
| `nodes` | One per zone: `{name}_node0` (master), `{name}_node1` (slave) |
| `private_ips` | The address taken from the subnet |
| `db_user_name` | `root` |
| `switch_strategy` | `reliability` for HA, empty otherwise |
| `maintenance_window` | `02:00-06:00` |
| `created`, `updated` | `2026-11-10T09:30:00+0000` |

`ListInstances` filters by `id` and `name` (exact, or a substring when the
value starts with `*`), `type`, `datastore_type`, `vpc_id`, `subnet_id`,
`eps_id` and `tags` (`key` or `key=value`, comma-separated, all must match).
`offset` is an index; `limit` is 1 to 100 (default 100). `total_count` is the
number of matches.

An instance cannot be deleted, or changed, while it is being created or has
another operation in flight (`DBS.200011`). A failed creation leaves it in
`CREATE FAIL`, which can be deleted.

## Operations

| Operation | Needs | While running | Ends in |
| --- | --- | --- | --- |
| Restart | `ACTIVE` | `REBOOTING` | `ACTIVE` |
| Resize | `ACTIVE` | `MODIFYING` | `ACTIVE`, with the new specification |
| Storage scaling | `ACTIVE` | `MODIFYING` | `ACTIVE`, with the new size |
| Manual backup | `ACTIVE` | `BACKING UP` | `ACTIVE` |
| Delete | any but `BUILD` | unchanged | gone |

- One operation at a time: a second one, or anything on an instance still
  `BUILD`, is refused with `DBS.200011`. An instance in another status
  (`FAILED`, `CREATE FAIL`) refuses the operations that need `ACTIVE` with
  `DBS.200086`.
- Each returns a `job_id` (HTTP 202) and completes after the lifecycle delay.
  The change lands only when the job completes.
- **Resize** goes to another specification of the same engine and the same
  mode: a single instance cannot become HA this way (`DBS.200054`).
- **Storage** only grows, in multiples of 10 GB, up to the engine's maximum
  (`DBS.200306`, `DBS.200027`, `DBS.200023`). The job's `entities.volume`
  reports the original and target sizes.
- **Backups** are named 4 to 64 characters (starting with a letter; letters,
  digits, `-`, `_`), and go `BUILDING` → `COMPLETED`. They are metadata: no
  data exists to back up, so every backup reports 2048 KB. Manual backups
  outlive their instance, as in the real service; a backup still `BUILDING`
  cannot be deleted (`DBS.201208`). `ListBackups` returns the newest first.
- An injected fault leaves the instance `FAILED` (a failed backup leaves it
  `ACTIVE`, with the backup `FAILED`) and the job `Failed`.
- `Resume` continues an interrupted operation after a restart.

## Jobs

`GET /v3/{project_id}/jobs?id={job_id}` returns `Running`, `Completed` (with
`ended` and `process: 100%`) or `Failed` (with `fail_reason`). Creation jobs
are named `CreateMysqlInstance`, as in the API reference's example; the others
`DeleteInstance`, `RestartInstance`, `ResizeFlavor`, `EnlargeVolume` and
`CreateManualBackup`.

## Error codes

Errors are `{"error_code": "...", "error_msg": "..."}`.

| Code | HTTP | When |
| --- | --- | --- |
| `DBS.200001` | 400 | Invalid parameter (body, HA mode, region, backup window, tags, paging); subnet has no free address |
| `DBS.200002` | 404 | Instance does not exist |
| `DBS.200011` | 409 | Instance is being created or has another operation in flight |
| `DBS.200021` | 400 | Invalid instance name |
| `DBS.200022` | 409 | Instance name already used in the project |
| `DBS.200023` | 400 | Storage size outside the engine's range |
| `DBS.200025` | 400 | Unknown availability zone, or wrong number of zones |
| `DBS.200027` | 400 | Storage size not a multiple of 10 |
| `DBS.200040` | 400 | Engine or version not supported |
| `DBS.200046` | 413 | Instance quota reached |
| `DBS.200050` | 404 | Security group does not exist |
| `DBS.200052` | 400 | Password does not meet the engine's rules |
| `DBS.200053` | 400 | Specification does not exist |
| `DBS.200054` | 400 | Specification is for another engine or mode |
| `DBS.200086` | 400 | Instance status does not allow the operation |
| `DBS.200306` | 400 | New storage size not larger than the current size |
| `DBS.201010` | 404 | Backup does not exist |
| `DBS.201208` | 400 | Deleting a backup that is still running |
| `DBS.200501` | 404 | Subnet does not exist or is in another VPC |
| `DBS.200503` | 404 | VPC does not exist |
| `DBS.200543` | 400 | Job does not exist |
| `DBS.280364` | 400 | Invalid port |

## Client compatibility

Every operation marked **Yes** or **Partial** runs through the official Go
SDK (`huaweicloud-sdk-go-v3`, `rds/v3` client) in `test/sdk`:

- `TestRDSInstances` lists engines and flavors, creates a MySQL instance and
  an HA PostgreSQL pair in a network built with the VPC SDK, waits on their
  jobs, finds them with filters, checks four error codes, and deletes
  everything.
- `TestRDSScenario` is plan scenario 4: create a MySQL instance in a subnet,
  wait for `ACTIVE`, resize, scale storage, reboot, back up, delete, and
  confirm the manual backup survives until it is deleted.

## Fidelity notes

Golden files are provisional (SDK models and API reference, not recorded
traffic). Known open points:

- The `n1` spec codes and their sizes are modelled on the real general-purpose
  family; real regions sell many more families and sizes, and not in every
  zone.
- Which code a full subnet produces is undocumented; `DBS.200001` is used.
- Job names other than `CreateMysqlInstance` are assumed; real jobs also
  report `process` while running.
- An HA instance takes one address (its floating IP). Real HA nodes also hold
  addresses of their own.
- Real instances also report `private_dns_names`; the emulator omits them.
- The HTTP status of the restart, resize and storage actions and of backup
  creation is assumed to be 202, as for creation; deleting a backup returns
  200 with `{}`. The SDK accepts either.
- Real resizing reboots the instance and may fail over; the emulator only
  shows `MODIFYING`.
