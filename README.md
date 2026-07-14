# railbird

railbird is a TCP port forwarder for Railway workloads connecting to a
[NetBird](https://netbird.io/) mesh. It runs an embedded NetBird client and
bridges traffic in either direction between Railway's private network and the
mesh.

This project is inspired by [railtail](https://github.com/half0wl/railtail).
If you're already using NetBird (or a self-hosted control plane) instead of
Tailscale, this is the equivalent shim.

## Modes

railbird runs in one of two modes per process:

- **`ingress`** — listener binds **on the mesh**, dial reaches Railway-internal
  targets. Use this so a peer somewhere else on the NetBird mesh can reach a
  service running in Railway.
- **`egress`** — listener binds **locally in Railway**, dial reaches mesh peers.
  Use this so a Railway service can reach a database or app that lives on the
  NetBird mesh (this is the railtail-shaped use case).

You can run multiple forwards in a single process by passing a comma-separated
list to `FORWARDS`.

## Usage

1. Set up NetBird. Create a [setup key](https://docs.netbird.io/how-to/register-machines-using-setup-keys)
   and note your management URL. If you're using NetBird Cloud the URL is
   `https://api.netbird.io`; if you self-host, use your own.

2. Build and deploy the container. The repo includes a `Dockerfile` that
   produces a static binary on top of `alpine:3.22.0` (same as netbirdio/netbird:rootless-latest as of writing):

   ```sh
   docker build -t railbird .
   ```

   On Railway, deploy this image and set the environment variables described
   below.

3. From other Railway services, connect to railbird's `RAILWAY_PRIVATE_DOMAIN`
   on the listen port(s) you configured. For a Postgres on the mesh exposed at
   `5432=db.railway.internal:5432`:

   ```sh
   DATABASE_URL="postgresql://user:pass@${{railbird.RAILWAY_PRIVATE_DOMAIN}}:5432/dbname"
   ```

## Configuration

railbird reads configuration from CLI flags and environment variables. An
explicit CLI flag wins; otherwise the first non-empty env alias is used;
otherwise the default.

| Environment Variable             | CLI Flag         | Description                                                                                                                                       |
| -------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FORWARDS` (or `TARGET_ADDR`)    | `--forwards`     | Required. Comma-separated list of forwards. Each entry is `host:port` (listen on `:port`) or `lport=host:port` (listen on `:lport`).              |
| `MODE`                           | `--mode`         | Optional. `ingress` or `egress`. Defaults to `ingress`.                                                                                           |
| `NB_MANAGEMENT_URL`              | `--mgmt`         | Required. NetBird management URL (e.g. `https://api.netbird.io` for NetBird Cloud, or your self-hosted endpoint).                                 |
| `NB_SETUP_KEY`                   | `--setup-key`    | Required. NetBird setup key. Must be set in environment for security.                                                                             |
| `NB_DEVICE_NAME`                 | `--device-name`  | Optional. Peer name in the mesh. Defaults to `railbird`.                                                                                          |
| `NB_DNS_LABELS`                  | `--dns-labels`   | Optional. Comma-separated extra DNS labels for this peer.                                                                                         |
| `NB_STATE_DIR`                   | `--state`        | Optional. State directory for the embedded NetBird client. Defaults to `/var/lib/netbird` (the bundled Dockerfile overrides to `/tmp/netbird-embed`). |
| `NB_LOG_LEVEL`                   | `--log-level`    | Optional. NetBird client log level. Defaults to `info`.                                                                                           |
| `NB_PROBE_ADDR`                  | —                | Optional. After NetBird starts, TCP-dial this host/IP via userspace mesh (logs OK/FAIL). Use on Railway when kernel `ping` is misleading.          |
| `NB_PROBE_PORTS`                 | —                | Optional. Comma-separated ports for `NB_PROBE_ADDR` (default `80,443`).                                                                           |
| `NB_DNS_OVER_TCP`                | —                | Optional. `true` to resolve hostnames in egress `FORWARDS` via **DNS-over-TCP** over the mesh (bypasses NetBird UDP to `10.32.0.2`).             |
| `NB_DNS_RESOLVER`                | —                | Optional. VPC resolver for DNS-over-TCP (default `10.32.0.2:53`).                                                                                 |
| `NB_PROBE_DNS`                   | —                | Optional. When `NB_DNS_OVER_TCP=true`, resolve this name at startup and log OK/FAIL.                                                              |

_CLI flags take precedence over environment variables._

On platforms without a kernel WireGuard interface (e.g. Railway), the embedded NetBird client uses **userspace** networking: egress `FORWARDS` and `NB_PROBE_*` use mesh `Dial`, not host routes. For RDS hostnames, set `NB_DNS_OVER_TCP=true` so railbird queries `10.32.0.2` over **TCP** via the same mesh path._

### `FORWARDS` syntax

```
# single forward, listen port inferred from target
db.railway.internal:5432

# explicit listen port
5432=db.railway.internal:5432

# multiple forwards in one process
5432=db.railway.internal:5432, 6379=cache.railway.internal:6379, 9200=es.railway.internal:9200
```

The legacy single-target shape `TARGET_ADDR=host:port` is still accepted as an
alias for `FORWARDS`.

## About

This was built to bridge Railway workloads with services living on a NetBird
mesh — for example, a managed Postgres, an internal admin host, or a peer in
another cloud. NetBird gives you a WireGuard-based mesh with optional
self-hosted control, which we wanted instead of Tailscale.

railbird is intended to run as its own service on Railway, accessed only over
Railway's Private Network.

> ⚠️ **Warning**: do not expose this service on Railway publicly.
>
> The setup key is in the environment and railbird will happily forward
> traffic to whatever the `FORWARDS` list says — anything reachable from the
> public listener is reachable on the mesh. Keep it on the private network.

## Examples

### Reaching a Postgres on the mesh from Railway (egress)

NetBird peer (the database host) advertises `db.railway.internal:5432` on the mesh.
Deploy railbird with:

```sh
MODE=egress
FORWARDS=5432=db.railway.internal:5432
NB_MANAGEMENT_URL=https://api.netbird.io
NB_SETUP_KEY=XXXX...
```

Then in your Railway app:

```sh
DATABASE_URL="postgresql://user:pass@${{railbird.RAILWAY_PRIVATE_DOMAIN}}:5432/dbname"
```

### Exposing a Railway service to the mesh (ingress)

Your Railway app listens on `app.railway.internal:3000` and you want a peer
elsewhere on the mesh to reach it. Deploy railbird with:

```sh
MODE=ingress
FORWARDS=3000=app.railway.internal:3000
NB_MANAGEMENT_URL=https://api.netbird.io
NB_SETUP_KEY=XXXX...
NB_DEVICE_NAME=railbird-prod
```

The peer can now connect to `railbird-prod:3000` over the mesh (subject to
NetBird ACLs).

### Multiple forwards in one process

```sh
MODE=egress
FORWARDS=5432=pg.internal:5432, 6379=redis.internal:6379, 9200=es.internal:9200
```

One railbird, three listeners, three independent proxy goroutines.
