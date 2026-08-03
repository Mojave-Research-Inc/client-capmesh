Entity: ASG
Scope: Capability Mesh
Status: ACCEPTED — NON-NEGOTIABLE
Owner: Jason / superadmin
Effective: 2026-07-19

# Capability Mesh Authority Invariant

## Decision

`the authoritative node` is the sole authoritative production Capability Mesh server. The
tailnet service `https://capmesh.the capmesh host (env: CAPMESH_HOST)` is served by the authoritative node. It owns the
active production catalog, governance writes, approvals, identity state,
audit trail, install/upgrade activation, and the 16-worker serving pool.

Every other Capmesh installation has exactly one subordinate role:

- `client`: consumes the authoritative node and owns no server authority;
- `non-voting-raft`: macOS and a replica node mirror the full governed catalog, serve
  local agents directly for low-latency reads, and reject authoritative writes;
- `read-replica`: any additional warm read-only copy;

"Non-voting Raft" describes the required authority behavior, not the current
database replication protocol: the implementation mirrors transactionally
consistent, hash-verified SQLite snapshots. It has no election, quorum, or
write-forwarding role and therefore cannot promote itself.

Repository source and runtime authority are distinct. `the developer home (env: CAPMESH_HOME)/GitHub/asg-os`
is the canonical authored source repository and `plugins/` contains the
canonical authored capability packages. A reviewed immutable snapshot of that
source is installed on the authoritative node, whose production database is the runtime serving
authority.

## Enforced properties

1. Production nodes carry an explicit `CAPMESH_NODE_ROLE`; absence is fatal.
2. Every node pins `CAPMESH_AUTHORITY_URL=https://capmesh.the capmesh host (env: CAPMESH_HOST)`.
3. Only `CAPMESH_NODE_ROLE=authoritative` accepts API, SCIM, webhook, delegation,
   reporting, install, upgrade, maintenance, third-party resync, or mutating
   capability writes. Agent bridges route all `cap.call`, `cap.delegate`, and
   `cap.report` traffic to the authoritative node; only search/load/list/describe may stay local.
4. Routine deployment may rehearse a replica node first for rollback safety.
   Deployment order never conveys authority. Its only replica-side write is an
   explicitly marked offline ingest into
   `the state directory (env: CAPMESH_STATE_DIR)/rehearsal/*.db`; that shadow database is never
   served and the exception cannot target the live replica database. Source
   lifecycle validation runs on the the authoritative node rehearsal because mirrored records
   intentionally retain authority-local source paths that do not exist on a
   replica.
5. Non-voting members may serve local search/load/list/describe traffic and
   mirror a hash-verified copy from the authoritative node. They may not rebuild, originate, or
   publish a competing catalog generation.
6. There is no automatic authority election or replica promotion. Restoring or
   replacing the authoritative node requires an explicit operator decision and a documented
   update to this decision record.
7. Health/readiness responses expose node role and the the authoritative node authority URL so
   topology drift is observable.
8. Verified Tailscale WhoIs/Serve identity is primary. Microsoft Entra ID and
   Google OIDC are fallback identity providers and cannot override a verified
   Tailscale caller. Corporate identities federate by their verified normalized
   `@example.com` email; external Google identities remain keyed by provider
   subject.
9. the operator admin (env: CAPMESH_SUPERADMIN_ACTOR) and the operator admin (env: CAPMESH_SUPERADMIN_ACTOR) are operator-policy tenant
   superadmins. Other verified ASG users own their private/shared stores and
   may submit owned capabilities to any active org or everyone namespace, but
   submission never grants publish/approve rights or bypasses promotion gates.
10. Services running on the authoritative node consume the authoritative server through
    `http://127.0.0.1:17778` with the protected `capmesh-service` bearer from
    `the state directory (env: CAPMESH_STATE_DIR)/the authoritative node-local.env`. Loopback is a transport
    optimization, not an authentication boundary: bearer-less same-host calls
    fail closed. Services must not read or write the production SQLite database
    directly. Tailscale WhoIs/Serve remains primary for user traffic.

## Verification

On the authoritative node, readiness must report `nodeRole=authoritative`. Every other server
node must report `nodeRole=non-voting-raft` (or `read-replica`), and a mutating request
must return `NOT_AUTHORITATIVE` with the the authoritative node authority URL. Tailscale Serve
for `svc:capmesh` must terminate on the authoritative node, not on a replica.

This record supersedes any older wording that calls a Mac, registry mirror,
replica, deployment canary, or row-count winner the Capability Mesh authority.

Catalog identity is the exact `catalog.generation` digest published by the
health contract. Row count is only a coarse corruption floor and must never be
used to elect authority or accept a near-enough replica. The production floor
is 3,000 capabilities: deliberately below the verified 3,312-capability
canonical authored corpus after historical aliases and superseded identities
are removed, and
high enough to fail closed on a partial-root rebuild. Changing this floor
requires a rehearsed canonical-corpus transition; it is not an alias for the
current row count.
