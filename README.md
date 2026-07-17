# railbird

railbird is an internal TCP gateway between Railway's private network and a
[NetBird](https://netbird.io/) mesh. It embeds NetBird's userspace client, so it
does not need a kernel WireGuard interface or elevated serving privileges.

- `egress`: Railway-private listeners forward to targets on the mesh.
- `ingress`: mesh listeners forward to Railway-private targets.

railbird intentionally adds no per-consumer authentication. Railway project and
environment membership, the private network, and NetBird ACLs are the trust
boundary. Do not attach a Railway public domain or TCP proxy to this service.

## Availability contract

`GET /ready` returns 200 only after the health server, NetBird, every listener,
every accept loop, and the selected startup probe policy have passed. It returns
503 during startup and as soon as draining begins. With the default
`PROBE_POLICY=required`, each target receives one bounded TCP connect/close
probe; no application payload is sent. `listener-only` skips target probes and
therefore proves listener/lifecycle readiness only.

After activation, `/ready` reports lifecycle freshness, not continuous target
reachability. A target, DNS, route, or ACL outage makes affected new connections
fail within configured budgets without deliberately restarting the process.

On SIGTERM, railbird becomes unready, closes listeners, waits up to
`DRAIN_TIMEOUT` for established sessions, force-closes the remainder, then gives
NetBird `NB_STOP_TIMEOUT` to stop. This improves planned replacement behavior;
it does **not** guarantee uninterrupted TCP sessions across process exit,
SIGKILL, target failover, mesh loss, or route changes. Consumers must use
retry-capable connection pools and reconnect broken sessions.

The release defaults are fixed at 90s startup, 120s Railway healthcheck, 45s
application drain, 5s NetBird stop, and 60s Railway drain. Keep at least 15s
between startup and the healthcheck timeout, and at least 10s kill margin after
application drain plus NetBird stop.

## Egress profile (Railway default)

The checked-in [`railway.json`](railway.json) is the egress profile: Dockerfile
build, `/ready`, 120s health timeout, on-failure restart with bounded retries,
30s revision overlap, and 60s draining. Do not attach a Volume. Each revision
uses a distinct ephemeral NetBird identity derived from
`RAILWAY_DEPLOYMENT_ID` unless `NB_DEVICE_NAME` is explicitly set.

```env
MODE=egress
FORWARDS=5432=mydb.abc123.ap-southeast-1.rds.amazonaws.com:5432
NB_MANAGEMENT_URL=https://api.netbird.io
NB_SETUP_KEY=<secret>
NB_DNS_OVER_TCP=true
NB_DNS_RESOLVER=10.32.0.2:53
PROBE_POLICY=required
STARTUP_TIMEOUT=90s
DRAIN_TIMEOUT=45s
NB_STOP_TIMEOUT=5s
```

For an RDS hostname, keep the hostname in `FORWARDS`. DNS-over-TCP queries the
VPC resolver through NetBird's mesh dial path and preserves DNS failover. The
default resolver is `10.32.0.2:53`. `NB_STATIC_HOSTS=host=ip` is an explicit
emergency fallback only; it overrides DNS and accepts stale-IP/failover risk.
There is no host-DNS or direct-network fallback.

The egress setup key must be reusable, configured to create ephemeral peers,
have an expiry and finite use limit sized for overlap, and assign exactly one
narrow auto-group. Record its rotation/revocation owner, verify automatic peer
expiry, and delete a peer immediately during a compromise response.

Railway consumers connect only to the gateway's private domain, never to the
RDS endpoint directly:

```env
DATABASE_URL=postgresql://user:pass@${{railbird.RAILWAY_PRIVATE_DOMAIN}}:5432/dbname
```

## Persistent ingress profile

Ingress uses one non-ephemeral identity on a dedicated Railway Volume. Attach
the Volume at a clean absolute root such as `/data`; railbird stores identity in
the direct child `/data/netbird`. Configure one replica and override the Railway
deployment overlap to `0`. Keep `/ready`, the on-failure restart policy, and the
60s drain after bootstrap completes.

Persistent ingress has a planned rollout gap by default because the stable
identity/Volume cannot safely overlap. Do not claim zero downtime. Nonzero
ingress overlap is prohibited until a separate real-mesh canary proves that one
stable NetBird label/service routes old and new peers without blackholes,
ambiguity, or broader ACLs.

```env
MODE=ingress
NB_IDENTITY_MODE=persistent
FORWARDS=3000=app.railway.internal:3000
NB_MANAGEMENT_URL=https://api.netbird.io
NB_EXPECTED_PEER_PUBLIC_KEY=<protected-base64-public-key>
RAILWAY_VOLUME_MOUNT_PATH=/data
PROBE_POLICY=required
STARTUP_TIMEOUT=90s
DRAIN_TIMEOUT=45s
NB_STOP_TIMEOUT=5s
```

Persistent mode forbids `NB_SETUP_KEY`. It validates the promoted private key,
file ownership/modes, and the separately protected expected public key before
NetBird or any listener starts. Deleting the NetBird peer causes startup to fail
rather than silently registering a replacement. Recovery requires explicit
state/remote-peer reconciliation followed by the bootstrap procedure.

## One-shot ingress bootstrap

Bootstrap must be a temporary deployed Railway revision because Volumes are not
available to pre-deploy commands and `railway run` executes locally.

1. Attach one dedicated Volume, set one replica and overlap `0`, disable the
   healthcheck, set restart policy `NEVER`, and ensure there is no public route
   or TCP proxy. Use a non-ephemeral, narrowly grouped setup key.
2. Set `MODE=ingress`, `NB_IDENTITY_MODE=bootstrap`,
   `NB_MANAGEMENT_URL`, `NB_SETUP_KEY`, `RAILWAY_VOLUME_MOUNT_PATH`, and the
   Railway platform override `RAILWAY_RUN_UID=0`. Retained `FORWARDS`,
   `TARGET_ADDR`, `PORT`, and probe settings are inert: bootstrap binds no
   health or forward listener.
3. The initializer accepts only an exact `root:root` or `65532:65532` mount
   root. A safe root-owned mount changes ownership on the mount-root inode only;
   an already-65532 root causes no ownership mutation. Descendants are never
   recursively changed. It classifies the complete same-device contents before
   dropping irreversibly to UID/GID 65532 with no supplementary group identity
   beyond a runtime-provided duplicate of primary GID 65532.
4. Empty state starts a new candidate. One safe unprepared candidate may be
   removed. Before any remote effect, the candidate records a non-secret digest
   binding the SetupKey, management URL, device name, DNS labels, and mode. A
   prepared candidate resumes only when that profile digest and its
   private/public key are unchanged; configuration drift fails before NetBird
   construction. A receipt-bearing completed tree is finalized without
   NetBird/Management RPCs. Multiple, unsafe, conflicting, partial, or
   ambiguous state stops for manual repair; reconcile/delete any remote peer
   before discarding prepared state.
5. When bootstrap reports `Completed`, capture its public key into a separately
   protected Railway secret. Remove `NB_SETUP_KEY` and `RAILWAY_RUN_UID`, set
   `NB_IDENTITY_MODE=persistent` and `NB_EXPECTED_PEER_PUBLIC_KEY`, restore
   `/ready`, `ON_FAILURE`, 60s drain, one replica, and overlap `0`, then deploy.
   Confirm the serving process is UID:GID 65532 with no supplementary group
   identity beyond a runtime-provided duplicate of primary GID 65532.

Do not retry bootstrap blindly after a failure. Keep the original SetupKey and
registration profile available while a prepared candidate is recoverable,
inspect the classified state, and preserve the same candidate/key across
crashes after registration, status, stop, receipt creation, and before
promotion.

## Configuration

CLI flags take precedence over canonical environment variables, which take
precedence over defaults. Prefer environment variables for `NB_SETUP_KEY`; a
CLI secret is visible in process arguments. `TARGET_ADDR` remains a deprecated
single-forward alias, while `FORWARDS` wins when both are set.

### Required or profile-selecting inputs

| Variable | Default | Contract |
| --- | --- | --- |
| `MODE` | none | Required: `egress` or `ingress`. |
| `FORWARDS` / `--forwards` | none | Required for serving. Comma-separated `host:port` or `listen=host:port`; ports 1..65535, unique listeners, no collision with `PORT`. Inert in bootstrap. |
| `NB_MANAGEMENT_URL` / `--mgmt` | none | Required absolute HTTPS URL without userinfo, query, or fragment. |
| `NB_IDENTITY_MODE` / `--identity-mode` | egress: `ephemeral`; ingress: none | Ingress requires `bootstrap` or `persistent`. |
| `NB_SETUP_KEY` / `--setup-key` | empty | Required for egress and bootstrap; forbidden for persistent ingress. |
| `NB_EXPECTED_PEER_PUBLIC_KEY` | empty | Required only for persistent ingress. |
| `RAILWAY_VOLUME_MOUNT_PATH` | none | Required only for ingress; dedicated absolute Volume root. |

### Optional runtime inputs

| Variable | Default | Bounds / meaning |
| --- | --- | --- |
| `NB_DEVICE_NAME` | derived from deployment ID (egress) or service ID (ingress) | Lowercase DNS label; required off Railway when the matching platform ID is absent. |
| `NB_DNS_LABELS` | empty | Comma-separated unique DNS labels. |
| `NB_STATE_DIR` | egress: `/var/lib/railbird/netbird`; ingress: `<volume>/netbird` | Clean absolute non-symlink path; ingress must use exactly the derived child. |
| `NB_LOG_LEVEL` | `info` | `panic`, `fatal`, `error`, `warn`, `warning`, `info`, `debug`, or `trace`. |
| `NB_MTU` | `0` | `0` for NetBird default, otherwise 576..8192. |
| `NB_DNS_OVER_TCP` | `false` | Egress only. Required for hostname targets unless every hostname has a static override. |
| `NB_DNS_RESOLVER` | `10.32.0.2:53` when enabled | Egress DNS-over-TCP resolver. |
| `NB_STATIC_HOSTS` | empty | Egress-only comma-separated `host=literal-ip` emergency overrides. |
| `PORT` / `--health-port` | `8080` | Serving health port, 1..65535 and distinct from forward listeners. Inert in bootstrap. |
| `PROBE_POLICY` | `required` | `required` or warning-bearing `listener-only`; inert in bootstrap. |
| `STARTUP_TIMEOUT` | `90s` | 5s..240s. |
| `DNS_QUERY_TIMEOUT` | `5s` | 100ms..30s; active for egress DNS-over-TCP. |
| `DIAL_ATTEMPT_TIMEOUT` | `5s` | 100ms..30s per resolved address. |
| `DIAL_TOTAL_TIMEOUT` | `15s` | 1s..60s total. |
| `MAX_CONNECTIONS` | `256` | Required positive process cap, 1..4096. |
| `IDLE_TIMEOUT` | `0` | Disabled by default; explicit activity-based value 1s..24h. |
| `TCP_KEEPALIVE` | `30s` | `0` disables; otherwise 1s..10m. Failure detection only, not application liveness. |
| `DRAIN_TIMEOUT` | `45s` | 1s..10m. |
| `NB_STOP_TIMEOUT` | `5s` | 1s..30s. |

Timeouts must satisfy `DNS_QUERY_TIMEOUT <= DIAL_TOTAL_TIMEOUT <=
STARTUP_TIMEOUT` and `DIAL_ATTEMPT_TIMEOUT <= DIAL_TOTAL_TIMEOUT`.
`RAILWAY_DEPLOYMENT_ID`, `RAILWAY_SERVICE_ID`, and
`RAILWAY_VOLUME_MOUNT_PATH` are Railway-provided. `RAILWAY_RUN_UID=0` is allowed
only for the temporary ingress bootstrap profile; root serving is rejected.
Legacy observational `NB_PROBE_ADDR`, `NB_PROBE_PORTS`, and `NB_PROBE_DNS` are
not readiness controls and should be removed from deployments.

## `FORWARDS` syntax

```text
# listen port inferred from target
db.internal:5432

# explicit listen port
15432=db.internal:5432

# multiple forwards
5432=db.internal:5432,6379=cache.internal:6379
```

## Operations and recovery

- Startup stuck at 503: inspect ordered lifecycle/probe logs. Fix NetBird,
  resolver, ACL, target, or listener conflicts; do not lengthen timeouts after a
  failed canary merely to obtain a pass.
- Post-activation target outage: leave the healthy process running, restore the
  resolver/ACL/route/target, and let retrying clients reconnect.
- Saturation: excess sessions are rejected at `MAX_CONNECTIONS`; size the cap
  and consumer pools from measured production allocation.
- Planned rollout: confirm new readiness before the old egress revision drains.
  Persistent ingress intentionally uses zero overlap and may have a gap.
- Rollback egress: redeploy the previous image/config, allow it to enroll a new
  ephemeral peer, verify readiness, then remove the failed/compromised peer.
- Rollback ingress: stop the bad revision and redeploy the previous image against
  the same validated Volume identity with overlap 0. Never restore an older
  identity directory over live state or reintroduce a setup key to persistent
  mode. If identity is unsafe, reconcile the remote peer and bootstrap anew.

## Production evidence gates

A local build is necessary but not sufficient. Before calling either profile
production-ready, capture deployed evidence for all applicable acceptance
criteria in the PRD/test specification, including:

- exact image digest, non-root serving, writable owned state, `/ready`, fatal
  listener failures, bounded SIGTERM drain, and on-failure recovery;
- no Railway public domain/TCP proxy, least-privileged Railway membership, and
  NetBird ACLs limited to the TCP resolver and exact target ports;
- egress private-domain RDS traffic through hostname DNS-over-TCP, distinct
  ephemeral overlap identities, setup-key policy, cleanup, and compromise drill;
- both real Railway Volume presentations (`root:root` and `65532:65532`),
  bootstrap crash/retry states, same-key/single-peer recovery, zero-RPC final
  recovery, irreversible privilege drop, and persistent restart;
- target/DNS/ACL outage recovery without restart storms, consumer retry/pooling,
  and an ingress stable-label experiment before any overlap change;
- three frozen, paired, colocated gateway-vs-direct-NetBird performance runs with
  the specified attempt/sample floors and latency, error, throughput, CPU, RSS,
  and churn gates.

No profile is production-ready when external evidence is missing. There is no
zero-downtime or established-session preservation guarantee. Vulnerability
scanning is also not expected to be finding-free: the known residual
GO-2026-4479 requires a current, owner-approved, time-bounded exception; see
[`docs/security-exceptions.md`](docs/security-exceptions.md).

## Build

```sh
docker build -t railbird:canary .
```

The final image uses `scratch` and contains only the static railbird binary, the
CA bundle copied from the pinned Alpine builder, and the owned state directory.
Normal service runs as numeric UID/GID 65532 and owns
`/var/lib/railbird/netbird`; there is no shell or diagnostic tool in the image.
