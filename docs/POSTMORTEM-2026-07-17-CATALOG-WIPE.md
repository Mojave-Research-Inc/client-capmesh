Entity: the operator
Scope: the operator
[CONFIDENTIAL]
[DRAFT — REQUIRES HUMAN REVIEW — v2026-07-18]

# Postmortem: the authoritative node Capability Catalog Replacement

## Impact

On July 17, a narrow-root ingest replaced the production catalog, reducing it from about 2,110
capabilities to 16. Process health remained green and parity automation repeatedly acted on the
wrong side. Discovery was materially unavailable for roughly 24 hours. Governance and source data
survived, and the catalog was rebuilt on July 18.

## Root cause

The `ingest --root` interface looked additive but implemented full replacement. Health checked
database connectivity rather than catalog correctness. Count-only parity detected the symptom but
always repaired the replica; the authoritative node, the deficient writer, had no local recovery path. Deployment
and refresh scripts used multiple conflicting layouts and could update code or DB in place.

## Corrective controls

- the authoritative node is explicitly and observably the sole production authority; replica
  rollout order and health can never transfer catalog authority.
- Narrow-root ingest is additive; full replacement is an explicit staged rebuild.
- Rebuild and recovery operate on shadow databases with integrity, non-shrink, coverage, retrieval,
  and FTS gates before atomic replacement.
- Readiness includes catalog size, generation, coverage, index parity, and freshness.
- HA parity compares a content generation digest, heals only a node below the explicit health
  floor, and refuses to select authority by row count when two healthy digests diverge.
- Releases are immutable, rehearsed replica-first for safety, canaried on the
  authoritative the authoritative node pool, and automatically rolled back.
- Restic restores are staged and verified; `/secure` is never an in-place restore target.

## Evidence and follow-up

Preserve July 17–18 journals, ingest audit JSONL, pre-swap databases, deployed manifests, Git SHAs,
and Restic snapshot metadata. Do not delete incident artifacts until the owner closes the review.
Production closure requires the pinned SQLite runtime and immutable-unit migration, incident
reproduction, restore drill, HA drift drill, client smoke tests, and 24-hour soak to pass. As of
2026-07-18 those production closure gates remain pending; the code-level controls are not a claim
that rollout occurred.
