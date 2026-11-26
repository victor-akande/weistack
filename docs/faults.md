# Injecting faults

Clients fail in ways that are hard to reproduce against Huawei Cloud: a
server that never builds, an RDS instance stuck in a failed state, API
Gateway throttling a busy script. WeiStack lets you ask for these
failures, so you can test how your code, retry logic or Terraform runs
handle them.

Faults are managed through the admin API at `/_weistack/faults`, and are
not stored: a restart or `POST /_weistack/reset` removes them. Under
`-iam=enforce` the admin API needs the administrator's credentials: use
`weistack admin POST faults '{...}'` instead of `curl`, which signs the
request (see [Checking credentials](enforce.md)).

## Two kinds of fault

### Lifecycle faults

A lifecycle fault makes the next asynchronous transitions of a kind fail.
The resource ends the way a failed operation leaves it in the cloud, for
example a VPC in `ERROR` or an ECS job in `FAIL`.

```bash
curl -X POST http://localhost:8780/_weistack/faults \
  -d '{"type": "lifecycle", "transition": "ecs.server.build"}'
```

| Field | Meaning |
| --- | --- |
| `transition` | A kind from the table below, or a pattern with `*`, such as `ecs.server.*` or `*.*.create` |
| `resource` | Optional: only the transition of this resource ID |
| `times` | How many transitions fail: 1 if omitted, `0` until the fault is removed |

The kinds of transition:

| Service | Kinds |
| --- | --- |
| ECS | `ecs.server.build`, `ecs.server.delete`, `ecs.server.start`, `ecs.server.stop`, `ecs.server.reboot`, `ecs.server.resize`, `ecs.volume.attach`, `ecs.volume.detach` |
| EVS | `evs.volume.create`, `evs.volume.extend`, `evs.volume.delete`, `evs.snapshot.create`, `evs.snapshot.rollback` |
| RDS | `rds.instance.create`, `rds.instance.delete`, `rds.instance.restart`, `rds.instance.resize`, `rds.instance.enlarge`, `rds.instance.backup` |
| IMS | `ims.image.save`, `ims.image.activate` |
| VPC | `vpc.vpc.create`, `vpc.subnet.create` |
| NAT | `nat.gateway.create`, `nat.snat.create`, `nat.dnat.create` (leaves the gateway or rule `INACTIVE`) |
| KPS | `kps.keypair.associate`, `kps.keypair.disassociate` |
| CSMS | `csms.secret.delete` (leaves the secret `PENDING_DELETE`) |

### Request faults

A request fault answers the next matching requests with an error, after
an optional delay, or only delays them. It applies before the request's
credentials are checked, where API Gateway throttles.

```bash
# The next two VPC creations are throttled.
curl -X POST http://localhost:8780/_weistack/faults \
  -d '{"type": "request", "service": "vpc", "method": "POST", "path": "/v1/*/vpcs", "status": 429, "times": 2}'

# Every OBS request takes two seconds, until the fault is removed.
curl -X POST http://localhost:8780/_weistack/faults \
  -d '{"type": "request", "service": "obs", "delay_ms": 2000, "times": 0}'
```

| Field | Meaning |
| --- | --- |
| `service` | An enabled service, as `/_weistack/services` names it |
| `method` | Optional: an HTTP method; any if omitted |
| `path` | Optional: a path pattern where `*` matches one segment, such as `/v1/*/vpcs`; any if omitted |
| `status` | The error's HTTP status, 400 to 599; omit it to only delay |
| `code`, `message` | Optional: the error's code and message |
| `delay_ms` | Optional: wait this long first, up to 60000 |
| `times` | How many requests are affected: 1 if omitted, `0` until the fault is removed |

Without a `code`, the error is a documented one where Huawei has one:

| Request | Status | Error |
| --- | --- | --- |
| OBS | 503 | `SlowDown`, "Please reduce your request rate." |
| Other services | 429 | `APIGW.0308`, "The throttling threshold has been reached." |
| Any other case | the status | `WeiStack.0<status>`, such as `WeiStack.0502` |

OBS errors are XML; the others are JSON with `error_code`, `error_msg`
and `request_id`.

## Managing faults

| Endpoint | Purpose |
| --- | --- |
| `POST /_weistack/faults` | Add a fault; answers 201 with it and its ID |
| `GET /_weistack/faults` | List the faults, with `remaining` and `hits` |
| `DELETE /_weistack/faults/{id}` | Remove one fault |
| `DELETE /_weistack/faults` | Remove every fault |

A fault is dropped once it has applied `times` times. At most 100 faults
can be active.
