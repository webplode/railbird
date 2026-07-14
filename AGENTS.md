# railbird — agent notes

## Git remotes

After commits that should reach Sleek’s deployment source, **always push `main` to the `sleek2` remote**:

```sh
git push sleek2 main
```

- **sleek2** → `git@github.com-sleek:SleekTechPteLtd/sleek-railbird.git` (primary for Railway / Sleek)
- **origin** → `git@github.com:webplode/railbird.git` (public mirror; push when appropriate)

Do not assume `origin` alone updates Sleek’s repo.

## Railway / RDS (DNS path)

Prefer **hostname in `FORWARDS`** with DNS-over-TCP over the mesh (not NetBird UDP to `10.32.0.2`):

```env
MODE=egress
FORWARDS=5432=<rds-endpoint-hostname>:5432
NB_DNS_OVER_TCP=true
NB_DNS_RESOLVER=10.32.0.2:53
NB_PROBE_DNS=<same-rds-hostname>
```

`NB_STATIC_HOSTS` is a fallback only if VPC DNS-over-TCP still fails after code fixes.

Consumers connect to **`${{railbird.RAILWAY_PRIVATE_DOMAIN}}:5432`** (or `railbird.railway.internal`), not the RDS hostname directly.