# Capability Mesh — Versioned Release Notes

**Entity:** ASG
**Scope:** Capability Mesh service (services/asg-capmesh/)
**Sensitivity:** [INTERNAL]

---

## v0.1.0 — 2026-08-02 (unreleased)

### Architecture
- **CM-12: governance.py decomposition (53% reduction).** Extracted 8 cohesive
  modules from the 3638-line governance.py monolith: access_control.py (470),
  utils.py (66), stores.py (318), promotions.py (499), roles_orgs.py (286),
  tokens.py (649), sync.py (301). governance.py reduced to 1696 lines with 45
  core schema/identity/capability-CRD functions. No behavior changes.
- **Circular dependency eliminated.** The fragile late-binding injection pattern
  was replaced with a clean utils.py module that both governance.py and
  access_control.py import from directly.
- **CM-13: Metrics/OTel + structured logging.** OTel traces on cap.* verbs +
  rebuild; structured logging (request id, subject, verb) across server/router/
  index; placement + auth-decision counters wired.

### Stability and Concurrency
- Thread-safe MetricsRegistry (internal Lock, audit #45).
- Bounded Tracer._ended deque(maxlen=4096) (audit #46).
- Periodic WAL checkpoint timer (audit #50).
- Concurrency/stability fixes for 100s-of-concurrent-requests.
- Whois cache with TTL (audit #1).
 state_lock narrowed for read-only paths (audits #2/#6/#7).

### Security
- CM-02: Loopback identity spoofing fixed (per-boot proxy token, hmac-compared).
- CM-03: OAuth id_token signature verification mandatory in production.
- CM-04: Search output sanitizes control sequences + length-caps metadata.
- CM-11: Mutating routes require service token.
- Path traversal protection via normalize_path.
- Prompt injection scanning + allowlist.
- Internal Ed25519 signed provenance envelope for approved capabilities.
- SLSA provenance gate.
- Per-cap tests gate.

### Tooling and Observability
- Registry diff command (capmesh diff --previous).
- Registry compaction command (capmesh compact).
- MCP Inspector smoke test harness.
- capmesh eval retrieval evals (recall@K=1.0, criticalRecallAtK=1.0).
- Coverage invariant: distinct discovered canonical_keys == indexed rows.
- Rebuild robustness: per-cap vector failure recording, rollback on exception.

### Test Suite
- 656 tests across 69 test files — all passing.
- Ruff: zero errors across 41 modules.
- Authorization negative tests for protected and secret capabilities.
- Path traversal tests.
- Malicious frontmatter parsing tests.
- SCIM member validation tests.
- MCP security readiness tests.

### Ideal-State Checklist Progress
- 174/212 items complete (82%).
- Remaining 38 items are feature roadmap requiring external infrastructure
  (OAuth 2.1, SCIM, Sigstore, SLSA, MCP SDK, Streamable HTTP transport).

### Production
- Production on authority + fallback + macOS since 2026-07-21.
- Authority invariant enforced (authority node is sole authoritative server).
- SQLite WAL requires pinned 3.53.3 runtime with WAL-reset fix.
