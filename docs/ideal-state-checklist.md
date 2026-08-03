# Capability Mesh Ideal-State Checklist Sentinel

Source design: `docs/design/asg-capmesh-spec.md`

This sentinel is the production readiness ledger for the the Capability Mesh. A
checkbox is complete only when code, docs, and verification exist on this
system. Items marked "external gate" require credentials, OAuth infrastructure,
signing keys, launchd rollout approval, or a remote registry endpoint.

The governing topology invariant is non-negotiable: The authoritative node is the sole
authoritative production server; additional synchronized non-voting
fallbacks that serve local reads, and every other node is a client. See `AUTHORITY-INVARIANT.md`.

> Release status (2026-07-21): production on the authoritative node, fallback, and macOS release
> `20260721T123721Z-61166d5d9cc7`. Closure-verify **all checks passed** (authority
> ready, metrics bare 401, primary authoritative, replica non-voting + write
> reject). Host reclaim moved cold Capmesh data to `/data`; TEI capped 16 CPUs.
> Product backlog items below remain open; production exit §12 is closed for
> tailnet operation (see ADR-2026-07-21-remote-oauth-tailnet-only +
> EXTERNAL-GATES-REGISTRY.md).

## 0. Governance And Source Of Truth

- [x] Import the downloaded capability mesh spec into the operator OS as a design doc.
- [x] Keep the design doc under `docs/design/asg-capmesh-spec.md`.
- [x] Build implementation under `services/asg-capmesh`.
- [x] Keep canonical exported registry under `canonical/asg-capmesh/registry/`.
- [x] Track ideal-state acceptance criteria in this sentinel.
- [x] Avoid editing runtime mirrors in `~/.codex`, `~/.claude`, `~/.cursor`, or `~/.agents` as source.
- [x] Treat the operator OS plugin source as the authoring root.
- [x] Treat runtime mirrors as ingest sources, not edit targets.
- [x] Package the canonical plugin snapshot with the same immutable release SHA as the service.
- [x] Add ADR for remote deployment topology after OAuth provider is selected.
- [x] Add owner map for capability namespaces.
- [x] Add human approval workflow for replacing canonical capability records.

## 1. CAP Package Model

- [x] Add JSON Schema for `cap.json`.
- [x] Support skills as first-class capability records.
- [x] Support agents as first-class capability records.
- [x] Support plugin manifests as first-class capability records.
- [x] Support commands as first-class capability records.
- [x] Support `.mcp.json` manifests as protected MCP server capability records.
- [x] Support ad hoc `cap.json` manifests.
- [x] Generate deterministic `cap://` URIs.
- [x] Generate canonical keys for deduplication.
- [x] Record content hashes for source files.
- [x] Preserve source paths for every mirrored ecosystem source.
- [x] Bound file reads during load operations.
- [x] Prevent path traversal outside a capability package.
- [x] Add full semver conflict policy.
- [x] Add package dependency graph and compatibility constraints.
- [x] Add package lifecycle transitions: draft, active, deprecated, retired.
- [x] Add namespace transfer policy.
- [x] Add an internal Ed25519 signed provenance envelope for every approved capability version.

## 2. Ecosystem Ingestion

- [x] Ingest `CAPMESH_ROOTS/plugins`.
- [x] Ingest `~/.capmesh/skill-registry`.
- [x] Ingest `~/.capmesh/skills`.
- [x] Ingest `~/.capmesh/plugins/cache`.
- [x] Ingest `~/.capmesh/plugins/cache/personal`.
- [x] Deduplicate mirrored capabilities for routing.
- [x] Preserve every scanned source file in `capability_sources`.
- [x] Coverage check compares discovered source files to indexed source rows.
- [x] Coverage check reports missing sources.
- [x] Coverage check reports source counts by kind.
- [x] Coverage check reports capability counts by type.
- [x] CLI exposes `capmesh ingest`.
- [x] CLI exposes `capmesh check`.
- [x] CLI exports canonical JSONL registry.
- [x] Add automatic launchd/watchman trigger for mesh ingest after ecosystem sweeps.
- [x] Add CI gate requiring zero missing sources.
- [x] Add registry diff report between previous and current mesh snapshots.
- [x] Add stale mirror detector for mismatched source hashes with explicit source authority and fail-closed equal-rank collisions.
- [x] Add plugin authoring hook that emits `cap.json` automatically for new assets.

## 3. Index And Retrieval

- [x] Use SQLite as the local registry database.
- [x] Use FTS5 for lexical retrieval.
- [x] Optionally load `sqlite-vec`.
- [x] Create vector table when `sqlite-vec` is available.
- [x] Provide deterministic local lexical embeddings as a no-network baseline.
- [x] Use reciprocal-rank fusion across lexical and vector matches.
- [x] Return bounded top-k search results.
- [x] Filter search results server-side by entitlement.
- [x] Return locked stubs instead of full records when discovery is allowed but load is denied.
- [x] Replace deterministic lexical embeddings with approved local embedding model.
- [x] Add hybrid reranking evals with recall@k, MRR, nDCG, and critical-query thresholds.
- [x] Add query expansion using capability taxonomy.
- [x] Add cold-start benchmark for full the operator ecosystem ingest.
- [x] Add latency SLO tracking for search and load.

## 4. Router Tool Surface

- [x] Implement exactly seven tools.
- [x] Implement `cap.search`.
- [x] Implement `cap.load`.
- [x] Implement `cap.call`.
- [x] Implement `cap.list`.
- [x] Implement `cap.describe`.
- [x] Implement `cap.delegate`.
- [x] Implement `cap.report`.
- [x] Add tool schemas.
- [x] Add JSON-RPC stdio server for local adapter clients.
- [x] Keep logs off stdout in server mode.
- [x] Return structured JSON content with human-readable summaries.
- [x] Return actionable structured errors.
- [x] Make `cap.call` dry-run by default.
- [x] Make `cap.delegate` create audited task envelopes without bulk-loading all agents.
- [x] Add official MCP SDK server wrapper if dotted tool names are accepted by all target clients.
- [x] Add Streamable HTTP transport.
- [x] Add stateless 2026 MCP RC compatibility adapter when final spec ships.
- [x] Add MCP Inspector smoke test harness.
- [x] Add Cursor/Codex/Claude client registration docs.

## 5. Authorization And Entitlements

- [x] Model visibility: public, internal, protected, secret.
- [x] Model discovery: public, locked, hidden.
- [x] Model required scopes.
- [x] Model allowed groups.
- [x] Model allowed users.
- [x] Enforce load authorization.
- [x] Enforce search/discovery authorization.
- [x] Enforce delegate/report scopes.
- [x] Default stdio principal is local and authenticated.
- [x] Wire remote HTTP to OAuth 2.1 Authorization Code + PKCE.
- [x] Publish RFC 9728 protected resource metadata.
- [x] Enforce RFC 8707 resource indicators.
- [x] Validate token audience and issuer.
- [x] Bind Entra groups to mesh allow groups.
- [x] Add SCIM sync for entitlement groups.
- [x] Add step-up authorization for destructive or high-risk calls.
- [x] Add break-glass admin audit flow.

## 6. Security Hardening

- [x] Treat tool descriptions and capability metadata as untrusted indexed content.
- [x] Do not execute arbitrary package code from `cap.call`.
- [x] Require confirmation for mutating capability calls.
- [x] Use parameterized SQL queries.
- [x] Avoid shell interpolation.
- [x] Sanitize audit logs for token/password/secret fields.
- [x] Prevent path traversal on file loads.
- [x] Add bounded file content loading.
- [x] Keep stdio server logs on stderr.
- [x] Provide no token passthrough path in local router.
- [x] Add dependency audit job.
- [x] Add static prompt-injection scanner for capability content with security-testing context handling.
- [x] Add rug-pull protection that revokes approval, sharing, and attestations on content-hash change.
- [x] Add signed allowlist for executable call bindings.
- [x] Add malware scan for scripts/assets before indexing as callable.
- [x] Add security review checklist per NSA May 2026 MCP guidance.

## 7. Provenance And Supply Chain

- [x] Record source content hashes.
- [x] Record source system.
- [x] Record source kind.
- [x] Export canonical registry JSONL.
- [x] Verify approved capability attestations against the active internal signing-key ID.
- [x] Provision and preserve an explicit mode-`0600` production Ed25519 key across immutable upgrades.
- [x] Add Sigstore signing for registry exports.
- [x] Add SLSA provenance statements for generated registry artifacts.
- [x] Add verification summary artifact.
- [x] Add keyless signing policy.
- [x] Add tamper-evident append-only registry log.
- [x] Add source repo commit capture for each ingested package.
- [x] Add license capture for external/vendor-derived capabilities.

## 8. Observability

- [x] Write sanitized JSONL audit records.
- [x] Audit search calls.
- [x] Audit load calls.
- [x] Audit delegate calls.
- [x] Audit report calls.
- [x] Store router reports in SQLite.
- [x] Support `coverage.check` report event.
- [x] Add OpenTelemetry traces.
- [x] Add authenticated Prometheus metrics export.
- [x] Add correlation IDs across agent delegates.
- [x] Add dashboard for search/load/delegate volume.
- [x] Add semantic catalog watchdog and parity-drift alerting.

## 9. Testing

- [x] Unit test fixed seven-tool surface.
- [x] Unit test search then load flow.
- [x] Unit test delegate task envelope.
- [x] Unit test source coverage.
- [x] Add retrieval golden eval file.
- [x] Add full real-ecosystem ingestion result snapshot after first production ingest.
- [x] Add recall@k eval runner.
- [x] Add MCP client smoke test.
- [x] Add load test for large registry.
- [x] Add authorization negative tests for protected and secret capabilities.
- [x] Add path traversal tests.
- [x] Add malicious frontmatter parsing tests.

## 10. Operations

- [x] Provide `README.md`.
- [x] Provide example config.
- [x] Provide CLI entrypoints.
- [x] Default database location: `~/.capmesh/asg-capmesh.db`.
- [x] Default audit location: `~/.capmesh/audit.jsonl`.
- [x] Add launchd plist for periodic ingest.
- [x] Add encrypted tailnet systemd service on the operatorCode GPU host.
- [x] Add encrypted tailnet refresh timer for automatic remote ingest.
- [x] Add GitHub Actions deploy workflow for `main` capability changes.
- [x] Add shared autodeploy script used by CI and local autoupdate.
- [x] Add whole-catalog lifecycle rehearsal before bootstrap or routine release activation.
- [x] Add explicit, audited catalog-wide admin approval/backfill command.
- [x] Make production superadmin installs gate-checked, immediately approved, audited, and transactionally fail-closed.
- [x] Pin the authoritative node as sole authority and make subordinate nodes reject authoritative writes.
- [x] Add liveness/readiness health endpoints and catalog watchdog.
- [x] Add Restic inventory/check and staging-only restore verification workflow.
- [x] Add registry compaction command.
- [x] Add migration runner for future schema versions.
- [x] Add versioned release notes.

## 11. Cross-Coder Adoption

- [x] Router is tool/client neutral.
- [x] Capability source roots include Codex, Claude, and shared registry paths.
- [x] JSON-RPC stdio mode can be wrapped by Codex, Claude, Cursor, or the operatorCode clients.
- [x] No client needs all skills/agents/plugins loaded into context up front.
- [x] Add shared UserPromptSubmit router backed by Capability Mesh.
- [x] Replace Claude/the operatorCode semantic router source with mesh-backed wrapper.
- [x] Replace Codex semantic router source with mesh-backed wrapper.
- [x] Preserve existing hook paths so coder configs do not need manual edits.
- [x] Add ecosystem ingest step that rebuilds Capability Mesh after plugin/agent/skill sweeps.
- [x] Add doctor checks for Capability Mesh database coverage.
- [x] Flip the runtime hook to mesh-backed wrapper.
- [x] Flip the runtime hook to mesh-backed wrapper.
- [x] Prove live Claude hook emits `CAPABILITY MESH MATCHES`.
- [x] Prove live Codex hook emits `CAPABILITY MESH MATCHES`.
- [x] Add Cursor rule making Capability Mesh the primary routing source.
- [x] Run full ecosystem ingest after flip.
- [x] Run full doctor after flip.
- [x] Register mesh router in the operator MCP gateway (verified ready 2026-07-18).
- [x] Add `claude mcp list`, `codex mcp list`, and `cursor-agent mcp list` verification steps.
- [x] Add client-specific adapter examples.
- [x] Add Cursor approval smoke test.
- [x] Add agent-runner integration for `cap.delegate` task envelopes.

## 12. Production Exit Criteria

- [x] Full ecosystem ingest reports zero missing source files.
- [x] Unit tests pass.
- [x] Real search smoke tests return expected capabilities and agents.
- [x] Canonical JSONL export is generated.
- [x] Security checklist reviewed.
- [x] Launchd ingest trigger installed.
- [x] Live coder hooks flipped to Capability Mesh.
- [x] Full ecosystem ingest reports green after flip.
- [x] Doctor reports Capability Mesh green after flip.
- [x] Tailnet service deployed under encrypted `/secure`.
- [x] Migrate live units to loopback workers behind authenticated nginx/Tailscale Serve.
- [x] Remote encrypted ingest reports zero missing source files.
- [x] Re-run remote HTTP/MCP security/readiness smoke tests after immutable migration.
- [x] Install and prove the new immutable deploy/refresh path on both nodes.
- [x] Gateway registration completed and backend reports ready (2026-07-18).
- [x] Remote OAuth deployment decision recorded.
- [x] Internal provenance/signing policy implemented; Sigstore/SLSA remain separate unchecked goals above.
- [x] Every unchecked external gate has owner, date, and next action.
