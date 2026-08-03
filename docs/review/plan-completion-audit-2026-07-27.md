# Capmesh Plan-Completion Audit — 2026-07-27

Entity: ASI  | Scope: Multi | [INTERNAL] | [DRAFT — REQUIRES HUMAN REVIEW — v2026-07-27]

**Source of truth for this audit.** Disk-verified against
`/Users/jasonw/GitHub/asg-os/services/asg-capmesh` on 2026-07-27.
The W3 audit lane had no shell; this artifact corrects two false negatives
the lane produced and records the on-disk command output that proves each verdict.

## Batch ledger

| Batch | Source/range | Status | Findings | Risk | Next |
|---|---|---|---|---|---|
| B1 | IMPROVEMENT-PLAN CM-01..CM-14 | done | 14 items | see table | drive OPEN items |
| B2 | VAULT-TRIAGE-REPORT #1..#7 | done | 7 items | see table | wire #2/#3/#7 |
| B3 | Cross-cutting wiring gap | done | 1 | high | wave5-wiring |
| B4 | Disjoint test re-run | done | 63 pass | none | — |

## B1 — IMPROVEMENT-PLAN CM-* (disk-verified)

| Item | Verdict | Evidence | Notes |
|---|---|---|---|
| CM-01 vault placement / prefix-strip | PARTIAL | governance.py:1050 `_vault_match_key`; symmetric (CM-05). No collision guard. | Plan downgraded to "VERIFIED FALSE POSITIVE"; guard not implemented. Relies on CM-10 invariant, which is OPEN. |
| CM-02 loopback X-Capmesh-Proxy-Token | DONE | server.py:925,1493,1548,1783 `X-Capmesh-Proxy-Token` via `hmac.compare_digest` | |
| CM-03 OAuth verify + owner elevation | DONE | governance.py:3623 `raise RuntimeError(...CAPMESH_OAUTH_VERIFY_SIGNATURE...)`; oid/sub bound | |
| CM-04 sanitize_metadata + injection gate | PARTIAL→W2 | router.py:75 `sanitize_metadata` (search-output); governance.py:3893 `scan_prompt_injection`; **`injection_allowlist.should_block` imported NOWHERE** | W2 (wf_244ca406) wiring `should_block` into governance.py `approve_request` promotion gate NOW. |
| CM-05 asymmetric match-key | DONE | governance.py:1050–1114 symmetric | |
| CM-05b SCIM member validation | OPEN→W1 | no SCIM member `value`→identity resolution; tenant from body/DEFAULT_TENANT | W1 (wf_c728ad7b) wiring server.py NOW. |
| CM-06 content_hash adoption | DONE | manifest.py:622 `merge_duplicate_capabilities`, `preferred.content_hash` | |
| CM-07 drafts through placement | DONE | governance.py:1093 `apply_vault_placement`; **tests/test_draft_placement.py 15 passed** | |
| CM-08 rebuild rollback + per-cap vectorStatus | DONE | **tests/test_rebuild_robustness.py green**; `_mark_vector_failure` (index.py) | |
| CM-09 cap:call scope | DONE | router.py:355 `require_scope(principal,"cap:call")` | |
| CM-10 coverage placement-drop invariant | **OPEN** | `coverage_report` (index.py:2226) returns `coverageOk` only; **`placementOk`/`placementDroppedKeys`/`placementExtraKeys` ABSENT**; no `test_coverage_detects_dropped_cap` | **REGRESSION vs plan's "DONE" claim.** Genuinely open. The audit lane's grep *also* missed, but the absence is real (disk-confirmed). |
| CM-11 mutating routes require service token | DONE | server.py:922 `service_token_authenticated` via `hmac.compare_digest`; **tests/test_mutating_route_service_token.py 7 passed** | |
| CM-12 governance.py decomposition | OPEN (P2) | governance.py monolith ~3900 LOC | Deferred. |
| CM-13 metrics/OTel + logging | OPEN (P2) | no OTel module | Deferred. |
| CM-14 authority topology pinning | DONE | node_role.py:37,70,75; router.py:366,434,473 reject writes on non-authoritative | |

## B2 — VAULT-TRIAGE-REPORT #1..#7 (disk-verified)

| Item | Verdict | Evidence | Notes |
|---|---|---|---|
| #1 gate-execution write-back | PARTIAL | `promotion_gate_runs` table (governance.py:495); `lifecycle.py` runs signature+provenance gates; **governance.py imports `lifecycle` (lines 3993,4024)** — audit lane wrongly said 0 | governance.py DOES import lifecycle (corrected). Gate runner exists; no `capmesh gates run` CLI. |
| #2 signature gate | DONE (module) / wired via lifecycle | `capmesh/signing.py` Ed25519; **tests/test_signing.py 3 passed**; lifecycle.py:21,322,693,714 `sign_attestation`/`verify_attestation` | Wired into lifecycle's gate runner, not directly into governance `approve_request`. |
| #3 provenance gate | PARTIAL (two schemas) | `capmesh/provenance.py` (SLSA, **tests/test_provenance.py 8 passed**); BUT lifecycle.py uses its OWN provenance schema (`asg.capmesh.internal-provenance/v1`, line 113), NOT `capmesh.provenance.compute_provenance_status` | **Two provenance implementations diverged.** capmesh/provenance.py is standalone-unwired; lifecycle.py has its own. |
| #4 riskTierPolicy | DONE | governance.py:2293 `evaluate_risk_tier_policy`; **tests/test_risk_tier_policy.py 7 passed** | |
| #5 retrievalEvals | DONE | evals/retrieval-golden.json 31 queries | |
| #6 per-cap tests gate | DONE | **tests/test_per_cap_tests_gate.py 5 passed** | |
| #7 injection allowlist | DONE (module) / UNWIRED | `capmesh/injection_allowlist.py`; **tests/test_injection_allowlist.py 8 passed**; `should_block` imported NOWHERE | W2 wiring into governance.py NOW. lifecycle.py declares `promptInjectionScan` in its gate list (line 33) but does NOT import `injection_allowlist`. |

## B3 — Cross-cutting WAVE5-WIRING gap (the real finding)

`capmesh/lifecycle.py` is the actual gate runner — it declares the full gate set
(`sourceIntegrity, tests, retrievalEvals, signature, provenance, promptInjectionScan, riskTierPolicy`)
and governance.py calls it via `approve_catalog` (line 3993, auto-approval path) and
`dispatch_gate_action` (line 4024, `system.gates` CLI). BUT:

1. `lifecycle.py` does NOT import `capmesh/injection_allowlist` → its `promptInjectionScan` gate is a stub/unwired.
2. `lifecycle.py` uses its OWN provenance schema, not `capmesh/provenance.py` → the wave4b SLSA module is standalone-unwired.
3. `governance.py` `approve_request` (the main promotion path, line 2341) does NOT call `lifecycle.approve_catalog` — only the `system.capabilities` create/draft.create auto-approval path does. The standard promotion-approval path evaluates only `riskTierPolicy` (line 2437) + `promptInjectionScan` (3896, via `scan_prompt_injection`, NOT via `should_block`).

**So the genuine remaining wiring work (wave5):**
- (a) wire `injection_allowlist.should_block` into the governance.py `promptInjectionScan` gate (W2 doing this now).
- (b) wire `capmesh.provenance.compute_provenance_status` + `capmesh.signing.compute_signature_status` into `lifecycle.py`'s signature/provenance gates (replace the diverged internal schema), OR remove the standalone modules as superseded.
- (c) wire `lifecycle.approve_catalog` into `governance.approve_request` so the full gate set runs on every promotion, not only auto-approval.

## B4 — Disjoint test re-run (command output)

```
$ python3 -m pytest tests/test_draft_placement.py tests/test_rebuild_robustness.py \
    tests/test_mutating_route_service_token.py tests/test_per_cap_tests_gate.py \
    tests/test_risk_tier_policy.py tests/test_signing.py tests/test_provenance.py \
    tests/test_injection_allowlist.py -q
...............................................................          [100%]
63 passed in 2.83s
```

## Genuinely OPEN P0/P1 work (authoritative)

- **CM-04** injection-scan promotion gate — W2 wiring now.
- **CM-05b** SCIM member validation + tenant binding — W1 wiring now.
- **CM-10** coverage placement-drop invariant — REGRESSION; `coverage_report` lacks `placementOk`/`placementDroppedKeys`/`placementExtraKeys`; no regression test. Needs a wave.
- **CM-01** collision guard — PARTIAL; depends on CM-10.
- **WAVE5-WIRING (a/b/c)** — see B3. The standalone modules (signing, provenance, injection_allowlist) are built+green but not all wired into the live promotion path.

## P2 (deferred): CM-12 (governance decomposition), CM-13 (OTel/metrics).

## Update 2026-07-27 18:00 — P0/P1 CLOSED, P2 wave in flight

Full suite: **412 passed, 0 failed, 0 skipped** (was 393+1 skipped at session start; +19 from this session's lanes). Ruff: **0 new errors on every lane** vs corrected HEAD baseline.

### Ruff baseline correction (binding for future verification)
The earlier "HEAD = 0 ruff" measurements in this session were **false zeros** from two traps (see `memory/ruff-stdin-baseline-gotcha.md` for the corrected method):
1. `git show HEAD:capmesh/x.py` from a subdirectory **silently fails** and writes an empty file (stderr was suppressed) → ruff on empty = 0. Correct: `git show HEAD:./capmesh/x.py` (cwd-relative with `./`).
2. `pyproject.toml` has `include = ["capmesh*"]`, so a baseline temp file at `.asgcode-tmp/x.py` is **silently skipped** by ruff → 0. Correct: write the temp baseline **inside `capmesh/`** so it matches the glob. Always probe the baseline is non-empty (inject a fake F401 and confirm ruff reports it).

Corrected HEAD baselines (disk-verified 2026-07-27 18:00): server.py 13, governance.py 15, index.py 12 — all identical to working tree → 0 new from CM-13-readiness / WAVE5-c / CM-10-merge respectively.

### P0/P1 status (all CLOSED)
- **CM-04** DONE — `injection_allowlist.should_block` wired (W2 governance + WAVE5-a lifecycle). 5 tests.
- **CM-05b** DONE — SCIM member validation + tenant bound to principal (W1). 15 tests.
- **CM-10** DONE — placement-drop invariant in `coverage_report` + merge-subtraction un-skip (CM-10-merge). 5 tests, no skips.
- **CM-01** DONE — `_vault_placement_collision` collision guard. 8 tests.
- **WAVE5-WIRING a/b/c** CLOSED — injection_allowlist wired into lifecycle; provenance gate rewired to `capmesh.provenance` (SLSA, internal schema removed); `governance.approve_request` calls `lifecycle.review_capability` (full 7-gate set on every promotion). 21 tests.
- **CM-13 slices** DONE — router request-id (4), server request-id thread (8), readiness gateRunner (4), observability module (8). + VAULT-#1 `capmesh gates run` CLI (5). prompt-gate-cleanup: 5 dead symbols removed from lifecycle.py.

### P2 in flight (3 concurrent disjoint lanes, launched 18:00)
| Lane | Task ID | File(s) | Item |
|---|---|---|---|
| CM-12-extract-vault-placement | w4jeh71yz | governance.py + new capmesh/vault_placement.py | first CM-12 decomposition slice (23 dedicated tests as safety net, API preserved via re-import) |
| CM-13-wire-observability-lifecycle | wtjryrc2b | lifecycle.py | wire observability into gate runner (best-effort) |
| CM-13-wire-observability-server | wikm8p81c | server.py + router.py | wire observability into request path (best-effort) |

### Remaining (genuinely-large tail, P2)
- **CM-12** further subsystem extractions after vault-placement: prompt-injection scan → `capmesh/prompt_injection.py`, risk-tier policy → `capmesh/risk_policy.py`. Each is a bounded slice with the same re-import-to-preserve-API pattern.
- **CM-13-full** OTel spans/traces export (the structured-logging + in-memory-metrics layer is built+wired by the in-flight lanes; distributed-trace export is the remaining tail).

## Update 2026-07-27 15:06 — CM-12 slice-1 DONE, CM-13 substantially complete

### CM-12 vault-placement extraction: DONE (despite impl-agent hang)
The CM-12 vault-placement lane (w4jeh71yz) impl agent **hung in its turn and never returned a prose result** (journal: only `type=started`; artifacts frozen at 14:59). Stopped the lane. **On-disk artifacts are complete and pass the real verify gate** — the impl agent wrote correct code before hanging; the prose summary was never the deliverable. Disk-verified acceptance:
- 27 tests pass: 23 dedicated UNCHANGED (`test_vault_match_collision_guard` 8 + `test_draft_placement` 15) + 4 new `test_vault_placement_module.py`.
- No circular import (`vault_placement` + `governance` import together).
- governance.py ruff 15 = 15 HEAD baseline (0 new); `vault_placement.py` + new test ruff-clean.
- Public API preserved: `from .vault_placement import apply_vault_placement, _manifest_uri_tail, _vault_match_key, _vault_placement_collision  # noqa: F401` at governance.py:23.
- Scope: only governance.py (M) + 2 new files (??). governance.py shrank by 122 deletions.
- Lesson reinforced: **prose is not proof; on-disk command output is the gate.** A hung lane with good artifacts is recovered by running the verify gate directly, not by re-running impl (which could overwrite good work). See [[ruff-stdin-baseline-gotcha]] for the corrected-HEAD-baseline method used here.

### CM-13 substantially complete
Built+wired+verified this session (all disk-verified, 0 new ruff):
- `capmesh/observability.py` module (8 tests) — structured log_event, redact, MetricsRegistry, GateDecision.
- `capmesh/metrics_export.py` module (9 tests) — Prometheus text exposition, stdlib-only, TYPE_CHECKING-guarded .observability.
- lifecycle.py wired to observability (gate.eval + GATE_METRICS, best-effort) — 30 tests.
- server.py + router.py wired to observability (http.request + request events, best-effort) — 6+58 tests.
- Cross-module integration test (24), gate-runner request_id contract test (8), redaction contract test (19).
- `/metrics` endpoint (wdmnv10me, in flight on server.py at time of writing).
- Remaining CM-13 tail: OTel distributed-trace *export* (the in-process structured-logging + metrics layer is done).

### P2 wave status (15:06)
- DONE: CM-12 vault-placement slice-1, CM-13 observability module, CM-13 lifecycle wiring, CM-13 server/router wiring, CM-13 metrics-export module, all 4 observability test lanes.
- IN FLIGHT: CM-13 `/metrics` endpoint (wdmnv10me, server.py).
- NEXT: CM-12 slice-2 (prompt-injection scan → `capmesh/prompt_injection.py`), then CM-12 slice-3 (risk-tier policy → `capmesh/risk_policy.py`).

## Update 2026-07-27 15:30 — Wave closed: 481 passed, CM-12 3/3 slices done, CM-13 complete modulo OTel tail

Full suite (tree settled, no in-flight edits): **481 passed, 0 failed, 0 skipped** (was 393+1 skipped at session start; +88 tests, 0 regressions). ruff across capmesh/: 64 (all pre-existing uncommitted-branch baseline; **0 new from any lane this session**, each verified individually vs its corrected HEAD baseline using `git show HEAD:./capmesh/x.py` inside the `include=["capmesh*"]` glob — see [[ruff-stdin-baseline-gotcha]]).

### CM-12 decomposition: 3 of 3 planned slices DONE
governance.py shed 3 subsystems via the move + re-import pattern (public API preserved, all safety-net tests pass UNCHANGED, no circular imports, 0 new ruff):
- **slice-1** `capmesh/vault_placement.py` — `apply_vault_placement`, `_vault_match_key`, `_vault_placement_collision`, `_manifest_uri_tail`. 27 tests (23 dedicated + 4 new).
- **slice-2** `capmesh/prompt_injection.py` — `scan_prompt_injection`, `evaluate_prompt_injection_scan`, `_ZERO_WIDTH`/`_HOMOGLYPHS`/`_INJECTION_PHRASES`. 56 tests (51 dedicated + 5 new). Removed now-unused `import unicodedata` from governance.py.
- **slice-3** `capmesh/risk_policy.py` — `evaluate_risk_tier_policy`, `default_promotion_gates`. 23 tests (18 dedicated + 5 new). Re-import has no `# noqa: F401` (names are called in governance, so F401 would be wrong) — dropped governance ruff 15→14.

governance.py: 4176 → ~4009 lines. CM-12 is "deferred P2-large"; further slices (e.g. extract `approve_request`'s ad-hoc gate enforcement) are possible but the 3 highest-value, best-tested subsystems are now modular. The remaining monolith is still large but no longer the dominant risk surface.

### CM-13: complete modulo OTel trace-export tail
Built+wired+verified this session (all disk-verified, 0 new ruff):
- `capmesh/observability.py` (8 tests) + `capmesh/metrics_export.py` (9 tests) — stdlib-only modules.
- lifecycle.py wired: `review_capability` emits `gate.eval` + `GATE_METRICS` (best-effort); **`run_promotion_gates` wired directly (GLM controller edit, this turn) to emit `gate.eval` with the REAL `request_id`** — closes the request-correlation gap the runbook documented. 34 lifecycle tests pass.
- server.py + router.py wired: `http.request` + `request` events (best-effort). `/metrics` public Prometheus scrape endpoint (Content-Type text/plain; version=0.0.4), old worker-counter route body replaced, old symbols kept for function-level test coverage. 25 + 61 server tests pass.
- Test lanes: cross-module integration (24), gate-runner request_id contract (8, updated to assert wired behavior), redaction contract (19), metrics endpoint (5), metrics auth-policy (5), readiness gateRunner (4), server request-id thread (8), router request-id (4).
- Ops runbook: `docs/runbooks/observability-scrape.md` (all code-level claims source-verified).
- Remaining CM-13 tail: **OTel distributed-trace export** (the in-process structured-logging + metrics + `/metrics` scrape layer is done). This is the genuinely-large P2 remainder.

### Recovery lessons logged this wave
- **Hung impl agent with good artifacts** (CM-12 slice-1, w4jeh71yz): journal showed only `type=started`, artifacts frozen, impl never returned prose. Stopped the lane; ran the verify gate directly on the on-disk artifacts → PASS. Lesson: a hung lane with good artifacts is recovered by direct verification, not by re-running impl (which could overwrite good work). Prose is not proof; on-disk command output is the gate.
- **Stop hook correction (2026-07-27 15:25)**: over 8 stop boundaries I ran 5 audit/spawn cycles but 0 working-tree changes. Corrected by making a direct state-changing edit (wired `run_promotion_gates` observability + updated the stale test) instead of spawning another lane. Going forward: when a bounded direct edit closes a known gap, do it inline rather than orchestrate a lane.
