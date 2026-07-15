# Security exceptions

## GO-2026-4479 (`github.com/pion/dtls/v2@v2.2.10`)

| Field | Value |
| --- | --- |
| Status | Proposed; release-blocking until owner approval and final-image reproduction are recorded |
| Security owner | Sleek Security (approval signature pending) |
| Created | 2026-07-15 |
| Review by | 2026-08-15 and before every release |
| Expires | 2026-10-15 |
| Upstream tracking | NetBird releases and its `pion/dtls/v2` dependency; Go vulnerability entry GO-2026-4479 |

### Disposition

NetBird v0.74.5 retains `github.com/pion/dtls/v2@v2.2.10`, so the advisory is
reachable in the compiled railbird graph. The compatible v2 line has no fixed
release at the time of this record. `pion/dtls/v3` is a different module/API and
must not be forced in with a `replace` directive. This record does not claim a
clean vulnerability scan or approve production deployment by itself.

Before approval, attach fresh `govulncheck` output from the final image and
record the exact symbol-level path. The expected high-level path is:

```text
railbird startup
  -> NetBird embedded client Start
  -> NetBird ICE/WebRTC transport setup
  -> Pion DTLS v2 handshake
  -> advisory-affected DTLS code
```

The final-image path, exact affected symbols, and image digest are mandatory;
a source-tree-only scan is insufficient.

### Protocol and exploit analysis

The affected package participates in DTLS negotiation used by NetBird's peer
transport stack. Approval must record which DTLS versions and cipher suites are
actually offered and negotiable by the pinned final image, whether the affected
path is reachable before peer authentication completes, and whether NetBird
configuration can disable that path. Until packet/call-path evidence is
attached, assume a remote party capable of reaching and influencing the DTLS
handshake may exercise the affected parser/state path. Also assess a malicious
or compromised authorized peer and an on-path attacker; local-only access must
not be assumed.

### Compensating controls

- Railway exposes no public domain or TCP proxy for railbird; local callers are
  restricted by project/environment membership and the private network.
- NetBird ACLs permit only the mesh DNS resolver and required target ports;
  unrelated peers and ports are denied and tested.
- Egress sets NetBird inbound blocking and uses a narrowly grouped, expiring,
  finite-use setup key with ephemeral peer cleanup and compromise deletion.
- Ingress uses a non-ephemeral one-shot bootstrap identity, removes the setup key
  for serving, and verifies the separately protected expected public key.
- Releases re-run `govulncheck`; any expanded reachable set, changed call path,
  expired exception, or loss of a compensating control blocks release.

### Approval checklist

- [ ] Security owner approval/signature recorded.
- [ ] Final image digest and `govulncheck` artifact recorded.
- [ ] Exact symbol call path reproduced from the final image.
- [ ] Negotiated/possible DTLS versions and cipher suites captured.
- [ ] Remote, malicious-peer, and on-path exploit preconditions reviewed.
- [ ] Railway private-only exposure and NetBird ACL evidence attached.
- [ ] Upstream NetBird/Pion fix status checked at review/release time.

Remove this exception as soon as NetBird provides and railbird verifies a
compatible dependency graph that eliminates the reachable finding.

## Scanner scope notes for the pinned dependency graph

Final-binary scanners may conservatively report the following module-level
findings even though their affected packages are not linked by railbird's
source dependency graph:

| Finding | Affected package boundary | Local reachability evidence |
| --- | --- | --- |
| GO-2026-5932 | `golang.org/x/crypto/openpgp` | `go list -deps ./...` excludes every `openpgp` package; `go mod why golang.org/x/crypto/openpgp` reports that the main module does not need it. |
| GO-2025-4233 | `github.com/quic-go/quic-go/http3` | `go list -deps ./...` excludes `http3`; `go mod why github.com/quic-go/quic-go/http3` reports that the main module does not need it. |
| GO-2026-5676 | `github.com/quic-go/quic-go/http3` | Same package-boundary evidence as GO-2025-4233. |

These are scoped non-reachability records, not blanket module suppressions.
Every release must rerun source-mode `govulncheck ./...`, `go list -deps`, and
the package-level `go mod why` checks with the production Go toolchain. Any
new import, newly reachable symbol, expanded advisory package set, or changed
dependency version invalidates the record. GO-2026-4479 is source-reachable
and must never be suppressed under this section.
