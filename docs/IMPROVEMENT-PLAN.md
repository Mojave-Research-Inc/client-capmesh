# Capability-Mesh — Authoritative Improvement Plan

**Owner:** lead capmesh engineer · **Date:** 2026-06-28
**Scope:** `services/asg-capmesh/` (~9078 LOC, 14 modules). Synthesizes the security + correctness + observability audit lanes into one de-duplicated, ranked backlog.

Priority score = `(severity_weight × value) / effort`, where severity_weight `high=3, medium=2, low=1`, value `1–3` (blast radius / data-integrity impact), effort `S=1, M=2, L=3`. Higher = do sooner.

---

## Completion status — verified 2026-07-30

Re-verified against current code on 2026-07-30 (plan is 2026-06-28; code moved on). Items
closed and verified by native CapMesh Workflows (Wave 1 `wf_ee0705de-9db` + Wave 2
`wf_0cbe8153-084`/`wf_a31cbb7d-41a`/`wf_8f4bee11-2ba` + corrective `wf_77203b7c-bb8`),
each with Director implement + Worker scope + Codex verify lanes (≥3 concurrent per wave).
Full suite `python3 -m pytest tests/ -q` = **627 passed, 0 failed**, ruff introduces zero new errors
(delta 0 vs base), `capmesh eval` passed (recall@K=1.0, criticalRecallAtK=1.0).

- **~~CM-04~~ — DONE.** `sanitize_metadata()` added in `capmesh/router.py` (strips ANSI/C0/C1
  control sequences, caps free-text fields to 4000 chars, wraps in `FIELD_START(...)/FIELD_END`
  delimiters) and wired into `cap.search` LLM-facing output; `cap.load` keeps raw metadata.
  Existing `scan_prompt_injection()` already gates promotion. Regression test
  `test_search_output_sanitizes_injection` (unit + integration) green.
- **~~CM-09~~ — DONE (predates this run).** `cap_call` at `router.py:272` already calls
  `require_scope(principal, "cap:call")` at entry.
- **~~CM-03~~ — DONE (predates this run).** `governance.py:3525` raises `RuntimeError` if
  `CAPMESH_OAUTH_VERIFY_SIGNATURE` is disabled in production (stronger than the plan's
  "refuse elevation + audit"); owner bound to verified `oid`/`sub` (lines 3184/3205).
- **~~CM-05~~ — DONE (predates this run).** `_vault_match_key` (`governance.py:1050`) applies
  the same plugin-prefix strip to both manifest URIs (1089) and live caps (1109) — symmetric.
- **~~CM-06~~ — DONE (predates this run).** `merge_duplicate_capabilities` (`manifest.py:622`)
  ranks by authority, picks `preferred = ranked[0]`, builds metadata from `preferred.metadata`,
  records `staleMirrorDetected`/`sourceConflicts` with the preferred content_hash.
- **~~CM-10~~ — DONE.** `coverage_report()` (`index.py:2056`) now also asserts the placement-drop
  invariant: distinct discovered canonical_keys (minus intentional merges) == non-system/
  non-draft capability rows; adds `placementDroppedKeys`/`placementExtraKeys`/`placementOk`
  and flips `coverageOk = coverageOk AND placementOk`. Regression test
  `test_coverage_detects_dropped_cap` green.
- **~~VAULT-TRIAGE needs-operator #4 (riskTierPolicy)~~ — DONE.** `evaluate_risk_tier_policy()`
  added in `governance.py` (denies high/critical → `cap://all/asg/everyone`, allows medium
  with warning, allows low/none, denies unknown); wired into the `riskTierPolicy` promotion
  gate via `approve_request`/`default_promotion_gates`. New `tests/test_risk_tier_policy.py`
  (7 tests) green.
- **~~CM-02~~ — DONE (Wave 2).** Loopback `Tailscale-User-Login` header trust replaced with a
  per-boot `X-Capmesh-Proxy-Token` validated via `hmac.compare_digest`
  (`trusted_proxy_identity_headers`, `server.py`); a spoofed header with no/wrong token
  resolves to `tailnet-guest` and the public identity endpoint rejects it with 401 (no
  identity leak — the `tailnet-guest` guard on `/api/v1/whoami` was restored after Codex
  flagged its removal as a regression). Tests in `test_http_service_auth.py` +
  `test_mcp_security_readiness.py` green.
- **~~CM-08~~ — DONE (Wave 2).** `rebuild_index` (`index.py`) wrapped in try/except with
  `con.rollback()` on exception; per-capability vector-embedding failure recorded on the
  cap row (`vectorStatus="failed"` via `_mark_vector_failure`), not a global disable; global
  vector flag flips off only on sqlite-vec extension absence. Approved-cap preservation
  upsert (lines 572-584) untouched — `test_promotion_workflow_approves_capability` green.
  New `tests/test_rebuild_robustness.py` (3 tests) green.
- **~~VAULT-TRIAGE needs-operator #5 (retrievalEvals)~~ — DONE (Wave 2).**
  `evals/retrieval-golden.json` rebuilt from 12→31 cases, every `expectedAny` a real
  capability in the live mesh (prior 84-case version was a self-referential tautology with
  67 phantom names — Codex caught it). `capmesh eval`: passed=true, recall@K=1.0,
  mrrAtK=0.88, ndcgAtK=0.91, criticalRecallAtK=1.0, misses=0.

**R4 sanitization pass (2026-07-30).** The local-default subject still carried an
ASG-private superadmin identity in `capmesh/models.py:22` (`DEFAULT_LOCAL_SUBJECT`) and
`config/capmesh.example.json:12` (`stdioDefaultPrincipal.subject`); both were reset to the
neutral `admin@example.com` default in commit `48976c1` (2026-07-26). The leak scanner
(`scripts/sanitization_leak_scan.py`) guards this surface via its `email-jason` and
`asg-domain` patterns, so a regression reintroducing the private address fails the gate.

**~~CM-12~~ — DONE (2026-08-02).** governance.py decomposed into 8 cohesive
modules: access_control.py (470), utils.py (66), stores.py (318),
promotions.py (499), roles_orgs.py (286), tokens.py (649), sync.py (301).
governance.py reduced from 3638 to 1696 lines (53% reduction). All 656 tests
pass, ruff clean, no behavior change. The remaining 45 functions in
governance.py are core schema/identity/capability-CRD — appropriately cohesive.
The following were
previously listed as open but are now VERIFIED DONE with passing tests:
- **CM-07** — DONE. Drafts placed via apply_vault_placement with risk-tier gating
  (vault_placement.py:104-170). Test: test_draft_placement.py.
- **CM-05b** — DONE. SCIM member validation (scim.py:207-211) + caller tenant
  binding. Test: test_scim_member_validation.py.
- **CM-11** — DONE. Mutating routes require service token via
  mutating_route_authorized() (server.py:1750). Test: test_mutating_route_service_token.py.
- **CM-13** — DONE. OTel traces + structured logging wired into server.py,
  router.py, and lifecycle.py. Tests: test_server_observability_wiring.py,
  test_router_request_id.py, test_lifecycle_observability_wiring.py.
- **VAULT-TRIAGE #1** — DONE. Gate-execution write-back via run_promotion_gates
  with promotion_gate_runs table (lifecycle.py:755-870).
- **VAULT-TRIAGE #2** — DONE. Internal Ed25519 signing (signing.py, lifecycle.py
  _attestation_envelope).
- **VAULT-TRIAGE #3** — DONE. SLSA provenance (provenance.py, lifecycle.py
  _provenance_gate).
- **VAULT-TRIAGE #6** — DONE. Per-cap tests gate (lifecycle.py _metadata_gate).
  Test: test_per_cap_tests_gate.py.
- **VAULT-TRIAGE #7** — DONE. Injection allowlist + severity (injection_allowlist.py).
  Test: test_injection_allowlist.py + test_injection_promotion_gate.py.

Additional improvements (2026-08-02):
- All 86 ruff lint errors fixed (source + tests).
- MetricsRegistry made thread-safe (internal Lock, audit #45).
- Tracer._ended bounded with deque(maxlen=4096) (audit #46).
- Periodic WAL checkpoint timer added (audit #50).
- Registry diff command added (capmesh diff --previous <jsonl>).
- MCP client registration verification docs added.
- Whois cache with TTL already present (audit #1).
- state_lock narrowed for read-only paths (audits #2/#6/#7).
- HTTP/1.1 keepalive already set (audit #14).
- Separate _metrics_lock already present (audit #6).

---

## 1. Executive Summary — Top 5, in order

**Architecture invariant (accepted 2026-07-19):** The authoritative node is the sole
authoritative production server. additional synchronized non-voting
fallback members that may serve local reads; all other nodes are clients. This is enforced by node roles and subordinate
write rejection; see `AUTHORITY-INVARIANT.md`.

1. **~~Vault placement silently merges two distinct capabilities (CM-01)~~ — VERIFIED FALSE POSITIVE (2026-06-28).** Adversarial check disproves "active data loss": `target_uri` is built from the **full `capability_canonical_tail` (plugin prefix preserved)**; `_vault_match_key` is used *only* for the manifest lookup (`governance.py:833` vs `837/842/848`). Live DB: **46** normalized keys map to >1 distinct URI, **both survive as distinct rows**; **duplicate full URIs = 0**; totals conserved (2306 before & after). Residual is latent only (`ON CONFLICT(uri)` last-writer-win iff two caps yield an *identical full* tail — true dupes, already handled by `merge_duplicate_capabilities`). **Downgraded to a cheap guard (refuse/suffix on real collision) + the CM-10 invariant. Not an incident; do NOT "fix first."**
2. **Loopback + client-supplied `Tailscale-User-Login` header is fully trusted (CM-02, security/high).** Any co-located local process / same-netns container / local SSRF can POST `Tailscale-User-Login: admin@example.com` to the loopback backend and become the platform owner, defeating all tenant isolation. Enforcement currently rests on an unwritten operational assumption.
3. **OAuth id_token signature verification is env-disableable AND owner identity is an email-string compare (CM-03, security/medium).** With `CAPMESH_OAUTH_VERIFY_SIGNATURE=0`, a forged unsigned token claiming `email=admin@example.com` yields `platform_admin`/`cap:*`. Two compounding weaknesses in one path.
4. **Untrusted capability metadata flows verbatim into LLM context — second-order prompt injection (CM-04, security/medium).** Anyone who can publish to the auto-readable `everyone` store controls text that lands in every other user's agent context. The code references a `promptInjectionScan` that is not implemented.
5. **Canonical-tail / match-key derivation is asymmetric, producing phantom (no-op) manifest entries (CM-05, correctness/medium).** Live-cap key = `slug(plugin)+slug(name)+version`; manifest key = string-parsed URI segments (un-slugged). They disagree for names with `.`/`@`/`/`, so manifest entries silently place nothing. Explains the ~8 observed phantoms and makes placement coverage unverifiable.

Together #1, #5, CM-06, CM-07, CM-08 and CM-10 mean **vault placement is not currently trustworthy or auditable** — that cluster is the single biggest theme.

---

## 2. Ranked Backlog

| ID | Title | Concern | Sev | Eff | Score | Acceptance criterion |
|----|-------|---------|-----|-----|-------|----------------------|
| CM-01 | Vault placement collapses 2 distinct caps into 1 row (prefix-strip key + URI upsert) | correctness | high | M | 4.5 | Two caps differing only by plugin prefix both survive a rebuild as distinct rows; placement refuses/suffixes on `target_uri` collision and logs it. |
| CM-02 | Loopback + client `Tailscale-User-Login` header trusted as identity | security | high | M | 4.5 | Loopback identity branch requires a per-boot proxy secret (hmac-compared) OR uses tailscale0 peer-IP whois; a raw local POST with a spoofed login header resolves to `tailnet-guest`. |
| CM-05 | Asymmetric tail/match-key → phantom manifest entries | correctness | med | M | 3.0 | Both sides normalized through one slug+`_vault_match_key`; manifest entries matching 0 live caps are logged as warnings; phantom count = 0 on prod manifest. |
| CM-03 | OAuth id_token signature env-disableable + email-string owner elevation | security | med | S | 4.0 | Signature verify mandatory by default; with verify off, owner→platform_admin elevation is refused and a loud audit event fires per request; owner bound to verified `oid`/`sub`. |
| CM-04 | Untrusted cap metadata returned verbatim into LLM/routing context | security | med | M | 3.0 | Search output strips control sequences, length-caps descriptions, delimits metadata from instructions; promotion to everyone/org runs an injection scan gate. |
| CM-06 | `merge_duplicate_capabilities` keeps wrong file's `content_hash` | correctness | med | S | 4.0 | When preferred source flips to asg-os.plugins variant, stored `content_hash` matches the preferred file's `source_path`/`entrypoint`. |
| CM-05b | SCIM accepts client-set IDs/tenant + unvalidated group members | security | med | M | 3.0 | SCIM member `value`s must resolve to an existing same-tenant identity before insert; tenant bound to provisioning principal/token, not `DEFAULT_TENANT`. |
| CM-09 | cap.call skips `require_scope("cap:call")` | security | low | S | 3.0 | `cap_call` calls `require_scope(principal,"cap:call")` at entry; a principal without cap:call is denied at the verb boundary. |
| CM-07 | Drafts re-ingested but never run through vault placement | correctness | low | S | 2.0 | Drafts matching a manifest tail are placed per manifest (or exemption is documented + asserted in a test). |
| CM-08 | `rebuild_index` no rollback on exception; vec failure flips global status mid-loop | correctness | low | S | 2.0 | Rebuild body wrapped in try/except → rollback + close on failure; vec failures recorded per-cap, not as a global disable. |
| CM-10 | `coverage_report` can't detect placement-induced drops | observability | low | S | 2.0 | Post-rebuild invariant asserts distinct discovered canonical_keys (minus intentional merges) == non-system/non-draft capability rows; mismatch fails `coverageOk`. |
| CM-11 | `authorized()` treats any verified tailnet identity as API-authorized | security | low | S | 2.0 | SCIM + role-assignment routes additionally require the static service/session token; documented; no mutating route relies on bare tailnet identity. |
| CM-12 | governance.py monolith (3439 LOC) — decompose | maintainability | med | L | 1.3 | governance.py split into ≥4 cohesive modules (vault placement, namespaces, roles/grants, system tools) with tests green; no behavior change. |
| CM-13 | Metrics/OTel absent; logging uneven | observability | med | L | 1.3 | OTel traces on cap.* verbs + rebuild; structured logging (request id, subject, verb) across server/router/index; placement + auth-decision counters. |
| CM-14 | Authority topology could drift across docs/runtime | correctness/security | high | S | complete | the authoritative node is pinned authoritative; replicas reject writes; readiness exposes role/authority; canonical decision record is linked. |

---

## 3. Grouping

### P0 — Do now (8 items)
CM-01, CM-02, CM-03, CM-04, CM-05, CM-06, CM-09, CM-10

High-severity security/correctness plus the low-risk high-value quick wins. CM-01/CM-05/CM-06/CM-10 form the "placement is trustworthy and auditable" set; CM-02/CM-03/CM-04/CM-09 close the identity + injection holes. (CM-05b is P0-adjacent but pulled to P1 — see out-of-scope note: it touches the grant cascade.)

### P1 — Next (4 items)
CM-05b (SCIM validation), CM-07, CM-08, CM-11

Correctness completeness + the second tier of auth hardening. CM-05b and CM-11 both touch the authorization data path and want Jason sign-off before merge.

### P2 — Nice-to-have / large refactors (2 items)
CM-12 (governance.py decomposition), CM-13 (metrics/OTel + logging). High value but L effort; sequence after P0/P1 land so the refactor moves *tested* code.

---

## 4. De-duplication notes

- **CM-01** merges the correctness-lane "vault placement collapse" with the observability-lane CM-10 root cause — kept as separate tickets (one is the fix, one is the detector) but they share a regression test.
- **CM-02 / CM-11** both raised by the security lane and overlap: CM-11 (any tailnet identity is API-authorized) is the *blast-radius multiplier* for CM-02 (identity spoofing) and CM-05b (SCIM planting). Tracked separately because CM-02 is the root fix and CM-11/CM-05b are containment.
- **CM-05** (asymmetric key) and **CM-01** (prefix-strip collision) are distinct bugs in the same `_vault_match_key`/`capability_canonical_tail` neighborhood — fix together, one PR, two regression tests.
- **CM-13** absorbs the scattered "logging uneven" + "metrics absent" observations into one ticket.

---

## 5. P0 implementation notes + proving tests

**CM-01 — placement collision** (`governance.py:775-848`, `index.py:243-286,495-497`)
In `apply_vault_placement`, group placed caps by resolved `target_uri`. If >1 distinct `canonical_key` maps to one target, refuse the placement and emit a warning, or disambiguate the URI (mirror `unique_migration_uri`'s suffix approach). Never let `ON CONFLICT(uri)` last-writer-win across distinct canonical_keys.
*Test:* `test_vault_placement.py::test_prefix_collision_keeps_both` — ingest two caps `foo.bar@1` and `baz.bar@1` (same tail, different prefix), rebuild, assert 2 rows survive with their original `canonical_key`s and distinct cap_ids.

**CM-02 — loopback header trust** (`server.py:441-455,487-538`, `cli.py:257`)
Replace the `peer_is_loopback and has_serve_identity` clause with a per-boot proxy token: serve hop adds `X-Capmesh-Proxy-Token`, validated with `hmac.compare_digest`; local processes can't guess it. Prefer documenting the `--interface tailscale0` peer-IP-whois bind as the recommended mode.
*Test:* `test_capmesh.py::test_loopback_login_header_is_not_trusted` — POST to loopback with `Tailscale-User-Login: admin@example.com` and no proxy token → principal resolves to `tailnet-guest` (not owner); with the correct proxy token → resolves to the asserted identity.

**CM-03 — OAuth verify + owner elevation** (`governance.py:37-42,2657-2664`)
Keep `_oauth_verify_signature_enabled` defaulting True. When verification is off: (a) refuse the `email==DEFAULT_USER_SUBJECT → platform_admin` elevation, (b) emit an audit event every request. Bind owner to a verified `oid`/`sub`, not an email compare.
*Test:* `test_capmesh.py::test_unsigned_token_cannot_elevate_owner` — with verify disabled, an unsigned token claiming the owner email gets `member`, not `platform_admin`/`cap:*`, and an audit row is written.

**CM-04 — metadata injection** (`router.py:173-185`, `index.py:564-624`, `manifest.py:202-274`)
Add a `sanitize_metadata()` applied where cap metadata is rendered to LLM-facing output: strip control/ANSI sequences, cap description length, wrap in explicit delimiters. Wire the referenced `promptInjectionScan` into the promotion gate (`governance.py:1859`) before everyone/org publish.
*Test:* `test_capmesh.py::test_search_output_sanitizes_injection` — a cap whose description contains `"\nIGNORE PREVIOUS INSTRUCTIONS..."` returns escaped/delimited text from `cap.search`; promotion of that cap to `everyone` is rejected by the gate.

**CM-05 — phantom manifest entries** (`governance.py:714-772`)
Parse the manifest URI into type/plugin/name/version fields and re-run them through the same `slug()`+`_vault_match_key` used for live caps, so the join is symmetric. Log every manifest entry that matches zero live caps.
*Test:* `test_vault_placement.py::test_manifest_match_is_symmetric` — a cap named `acme.tool@1` (dot in name) placed via manifest is actually filed to its manifest target; phantom-match count == 0.

**CM-06 — content_hash adoption** (`manifest.py:481-489`)
When `preferred` flips to the asg-os.plugins variant, build the merged record with `content_hash=preferred.content_hash` (not `existing.content_hash`).
*Test:* `test_capmesh.py::test_merge_adopts_preferred_hash` — assert stored `content_hash` matches the preferred file's actual hash and its `source_path`.

**CM-09 — cap:call scope** (`router.py:211-217`)
Add at top of `cap_call`: `ok, reason = require_scope(principal, "cap:call"); if not ok: return error(...)`.
*Test:* `test_capmesh.py::test_cap_call_requires_call_scope` — a principal with `cap:search,cap:load` but not `cap:call` is denied at `cap.call` even when per-cap policy would allow it.

**CM-10 — coverage invariant** (`index.py:660-684`)
After rebuild, assert `len(distinct discovered canonical_keys) - intentional_merges == count(non-system/non-draft capability rows)`; surface any dropped canonical_key in the report and flip `coverageOk=false` on mismatch.
*Test:* `test_capmesh.py::test_coverage_detects_dropped_cap` — simulate a placement drop, assert `coverageOk` is false and the dropped key is named.

---

## 6. Explicitly out of scope / needs Jason sign-off

These touch auth, the all-user/everyone store, or the live ingest DELETE path and must not be merged without explicit approval:

- **CM-02 / CM-03 / CM-11 / CM-05b** — any change to the identity-resolution, OAuth, `authorized()`, or SCIM grant paths. The "magic install" UX depends on bare-tailnet authorization; tightening it can lock out legitimate callers. Stage behind a flag, prove with tests, get sign-off before prod.
- **The `everyone`/all-user store** (`cap://all/asg/everyone`, governance.py:1303-1328) — CM-04's promotion gate changes what can be published to a store every authenticated user reads. Coordinate so existing 145 everyone caps don't get retroactively blocked.
- **The live ingest DELETE/rebuild path** (`index.py:472-509`) against the production DB on-node (`CAPMESH_STATE_DIR/asg-capmesh.db`, ~2755 caps). CM-01/CM-08 alter rebuild behavior — rehearse against a DB copy first (per CLAUDE.md forensic/PRIME-DIRECTIVE rules), never iterate on the live DB. Take a hashed backup before the first CM-01 deploy.
- **No secret rotation** as a side effect of any auth fix (CM-02 proxy token is a new secret, additive — not a rotation of the existing bearer/service token).

---

*Counts: P0=8, P1=4, P2=2. Highest priority: tied at score 4.5 between **CM-01** (vault placement data loss) and **CM-02** (identity spoofing). Sequenced **CM-01 first** — it is actively losing data on every rebuild of the live DB, whereas CM-02's exploit requires local code execution on the node.*
