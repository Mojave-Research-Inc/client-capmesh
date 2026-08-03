# Security Policy

This is a private repository.

## Runtime Boundaries

- The authoritative node is the sole authoritative production server. Every production node
  must declare `CAPMESH_NODE_ROLE`; subordinate roles reject direct writes and
  identify the authority URL (env CAPMESH_AUTHORITY_URL) as their authority. Deployment ordering
  never transfers authority. See `docs/AUTHORITY-INVARIANT.md`.
- Production state and immutable releases live under encrypted
  `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)`; `current` is an atomic symlink to one release.
- Workers bind only to loopback. Tailscale Serve reaches root-owned nginx,
  which strips caller `X-Capmesh-*` assertions and authenticates its hop with a
  distinct `CAPMESH_TRUSTED_PROXY_TOKEN`.
- `/health/live` and `/health/ready` are unauthenticated. MCP, API, and SCIM
  accept a minted user session, the fixed service bearer, the authenticated
  reverse-proxy hop (`CAPMESH_TRUSTED_PROXY_TOKEN`), or verified tailnet whois
  (magic-install). The service bearer always maps to the least-privilege
  `capmesh-service` principal; it cannot assert end-user roles.
- Prometheus `/metrics` is stricter: it requires a minted session, the service
  bearer, optional dedicated `CAPMESH_METRICS_TOKEN`, or the authenticated
  proxy hop. Bare whois identity alone is not enough to scrape worker counters.
  Prefer scraping loopback/nginx with the service or metrics bearer.
- HTTP callers cannot supply a router `principal`; the server overwrites it
  with the transport-authenticated identity.
- Production sets `CAPMESH_ENVIRONMENT=production`, verifies Entra
  issuer/audience/tenant/signature, and fails closed on pending promotion gates.
- `cap.load` hashes and reads from one file descriptor and refuses content that
  differs from the indexed digest. A content change revokes prior approval,
  sharing, signature, provenance, and risk-review state.
- SQLite WAL is prohibited unless the worker and checkpoint runtime contains
  the WAL-reset fix. Install the pinned 3.53.3 runtime with
  `ops/install-safe-sqlite-runtime.sh`; deployment preflight verifies it.
- Restic recovery is staging-only under `/var/tmp/capmesh-restic-recovery`.
  Never restore directly over `/secure`.
- GitHub Actions joins the tailnet through Tailscale credentials stored as
  encrypted GitHub secrets. Secret values must never be printed in logs.

## Reporting

Report issues privately through the the operator GitHub organization or
the security operations channel. Do not open public disclosures for this
private system.
