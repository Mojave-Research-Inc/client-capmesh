# Capmesh Vault Triage Report

> **Supersession note — 2026-07-19:** The gate-infrastructure limitation
> documented below has been closed for the current catalog by `system.gates`.
> All 3,514 current non-system capabilities passed source-integrity, metadata,
> retrieval, prompt-safety, risk, signature, and provenance review and now carry
> approved/published/verified state. Historical override audit events remain
> immutable and are not rewritten; this note supersedes only the earlier claim
> that no executable gate or signing infrastructure exists.

**Date:** 2026-06-28
**Operator:** admin@example.com (identity `idn_75f310a283e0b72ebde0ee07`, tenant `asg`)
**Scope:** Conservative reorganization of the operator's private capmesh capabilities into the
correct organization vaults (org-internal and all-user), per the supplied triage lists.
**Tooling:** `capmesh submit` → `approve` governance flow (audited). High-sensitivity
items were excluded upstream and never touched.

---

## Counts

| Bucket | Target vault | Applied |
|--------|--------------|--------:|
| Promote to **ORG** | `cap://org/asg/agentic-secure-group-inc/shared` (`ns_0250569388d149e8a866597c463894bb`) | **49** |
| Promote to **ALL-USER** — agents | `cap://all/asg/everyone` (`ns_a985e6a43d15f154764ef1da`) | **39** |
| Promote to **ALL-USER** — commands | `cap://all/asg/everyone` | **12** |
| **Total moves applied** | | **100** |
| Stay **PRIVATE** (unchanged) | `cap://user/asg/.../private` | **207** (triage set; not moved) |

- Promotion-approved audit events written: **100**
- Gate-override audit events written: **100** (see "Gate posture" below)
- Pending promotion requests after run: **0** (one stale duplicate test request was recalled)
- Failures: **0**

## Verification

Spot-checked that moved capabilities now resolve under their new namespaces:

- `global.controller@0.1.0` → `namespace_id = ns_0250569388d149e8a866597c463894bb` (org/shared), `approval_state = approved`
- `global.accessibility-qa-lead@0.1.0` → `namespace_id = ns_a985e6a43d15f154764ef1da` (all/everyone), `approval_state = approved`
- Org `shared` namespace now holds 49 capabilities; all-user `everyone` namespace now holds 51 (39 agents + 12 commands).

## New namespace created

The org store had only the IVC-Trust-specific `atrace` namespace, which is the wrong target
for general org-internal agents. A general-purpose org namespace was created:

- **`cap://org/asg/agentic-secure-group-inc/shared`** (`ns_0250569388d149e8a866597c463894bb`)
  — "General org-internal capabilities … finance, governance, legal, GTM, compliance, and
  entity-operations agents scoped to organization members." Visibility `internal` (Design-B
  membership-gated: discover/load/call granted only to ASG org members).

## Gate posture (needs-operator follow-up, non-blocking)

The promotion pipeline defines six gates (`tests`, `retrievalEvals`, `signature`,
`provenance`, `promptInjectionScan`, `riskTierPolicy`). On this local mesh **all gates are
infrastructure-`pending`** — no CI/signing/eval harness has run against these drafts yet. Each
approval was therefore made with an explicit, audited `overridePendingGates=true` marker
(recorded as 100 `promotion.gate_override` events). This is acceptable because the promotion
set was hand-curated and high-sensitivity items were excluded, but the gates should be run for
real before these are treated as production-signed:

- **needs-operator:** run the six promotion gates (tests/evals/signature/provenance/injection
  scan/risk-tier) against the 100 promoted capabilities and clear the override markers.

## Authority note

The acting principal is the local default `member` for `submit`, and an explicit
`platform_admin` operator principal (the operator of these ASG stores) for `approve` and
namespace creation, via the documented `--principal-json` "noninteractive admin operations"
path. Every action is in the capmesh audit log. No secrets were read, printed, or moved.

---

## Applied moves

### ORG → `cap://org/asg/agentic-secure-group-inc/shared` (49)

All under `…/private/personal/agent/`:

agent-registry-keeper, agile-delivery-lead, ai-cogs-analyst, ai-compliance-auditor,
ai-incident-commander, approval-authority-architect, audit-coordinator, billing-architect,
board-pack-curator, board-secretary, capability-taxonomist, capture-strategist,
cash-forecast-analyst, ceo-strategy-operator, cfo-value-architect, chief-of-staff,
citation-verification-architect, clause-compliance-analyzer, cmmc-program-manager,
cmo-brand-demand-commander, cohort-analyst, common-paymaster-analyst, comms-strategist,
comp-analyst, competitive-intelligence-analyst, compliance-doc-builder,
compliance-evidence-assembler, compliance-impact-analyzer, consolidation-controller,
contract-drafter, contract-guardian, controller, coo-operating-system-architect,
cro-sales-motion-builder, cross-entity-risk-reviewer, customer-ops-workflow-designer,
customer-success-revenue-retention-lead, data-insights-translator, dcaa-compliance-auditor,
deal-desk-reviewer, delivery-orchestrator, delivery-sentinel, diagram-architect,
document-architect, editorial-director, engagement-letter-writer, engineering-manager-copilot,
entity-architect, entity-relationship-cartographer

> Note: the supplied ORG list was truncated mid-entry at `faq-writer`; that entry and anything
> after it in the original (incomplete) feed were **not** processed and remain private. See
> needs-operator below.

### ALL-USER → `cap://all/asg/everyone` — agents (39)

accessibility-qa-lead, agentic-sdlc-orchestrator, api-contract-engineer,
brand-systems-strategist, ci-cd-release-captain, cloud-finops-optimizer, codebase-modernizer,
completion-engineer, completion-mandate-enforcer, context-engineering-architect,
decision-log-chief, design-system-governor, developer-experience-engineer,
dialectical-examiner, evals-observability-lead, first-principles-analyst,
intuitive-commanding-ux-director, mvp-forge-lead, opus-architecture-intelligence-lead,
performance-engineer, platform-golden-path-engineer, pmbok-advisor, practical-reasoner,
process-mining-analyst, procurement-and-vendor-operator, product-discovery-lead,
roadmap-artist, roadmap-strategist, sales-tax-nexus-analyst, sre-incident-commander,
staff-architecture-partner, supply-chain-provenance-auditor, svelte-file-editor,
task-extractor, task-validator, test-strategy-engineer, ts-troubleshooter, ts-tsnet-developer,
ux-flow-architect

### ALL-USER → `cap://all/asg/everyone` — commands (12)

agentic-sdlc, alias, analyze-cohorts, analyze-feedback, analyze-test, brainstorm, build-agent,
build-mcp, business-model, competitive-analysis, derive-tests, discover

> Note: the supplied ALL-USER list was truncated mid-entry at command `document-app`; that
> entry and anything after it were **not** processed and remain private. See needs-operator.

---

## Needs-operator items

1. **Run promotion gates for real** against the 100 promoted caps (currently override-approved
   over infra-`pending` gates) — tests, retrieval evals, signature, provenance, prompt-injection
   scan, risk-tier policy. Clear the `[OVERRIDE: …]` markers afterward.
2. **Truncated feed tail not processed:** the input ORG list ended mid-entry at `faq-writer`
   and the ALL-USER list ended mid-entry at command `document-app`. Any capabilities at/after
   those cut points were left private (conservative default — incomplete records are not moved).
   Re-supply the complete lists to promote the remainder.
3. **Grant the operator a durable role assignment** if routine promotions are expected: the
   acting account is `member`; `approve`/`manage` here required the `platform_admin`
   `--principal-json` override. A persisted `org_admin`/`namespace_admin` role_assignment for
   `admin@example.com` on the operator's stores would remove the need for the override flag.

---

## Stay-private set (207) — summarized by theme

These were classified PRIVATE by the triage and were **not** moved. They remain in
`cap://user/asg/idn_75f310a283e0b72ebde0ee07/private`. By theme:

- **Personal / individual productivity & assistant agents** — single-operator helpers,
  personal scratch agents, and one-off command shims with no team or org reuse value.
- **Highly entity- or deal-specific artifacts** — agents bound to a single named transaction,
  client, or matter where org-wide discovery would leak sensitive context.
- **Sensitive finance / HR / compensation internals** rated above the conservative
  promote threshold (anything flagged higher sensitivity was excluded from both promote lists
  by design).
- **Experimental / unversioned / WIP drafts** not yet production-ready — kept private until
  they pass gates and earn a stable interface.
- **Operator/infra-privileged tooling** (vault, secrets, host-ops adjacent) that must never be
  broadly discoverable.
- **Duplicates / superseded versions** of capabilities whose canonical version is the one
  promoted, kept private to avoid ambiguous resolution.

No secrets, credentials, or vault material are included in this report.

---

## Gates (promotion-gate verification run — 2026-06-28)

**Operator ask:** run the six capmesh promotion gates (`tests`, `retrievalEvals`,
`signature`, `provenance`, `promptInjectionScan`, `riskTierPolicy`) against the promoted
set, clear `overridePendingGates` markers for caps that pass, and honestly document any
gate that lacks a runner.

### Mechanism discovery (what actually exists)

I read `capmesh help`, the CLI (`capmesh/cli.py`), and the governance core
(`capmesh/governance.py`). Findings:

- The six gates are defined in `default_promotion_gates()` (governance.py:1650) and written
  into `promotion_requests.gates_json` **once, at submit time, always as `"pending"`.**
- `approve_request()` (governance.py:1671) only **reads** `gates_json`. If any gate is not
  `"passed"` it refuses unless `overridePendingGates=true`, in which case it stamps an
  audited `[OVERRIDE: …]` note and writes a `promotion.gate_override` audit event.
- **There is no gate-execution harness.** Grep across the whole repo (`*.py`, `*.sh`) finds
  **no** code that updates `gates_json`, sets a gate to `"passed"`, signs an artifact, or
  computes provenance. `signature_status`/`provenance_status` (index.py) only ever transition
  `unchecked → pending` on approval (governance.py:1745-1746); nothing computes a real result.
- Consequently the override markers are **immutable audit-log events** — there is no
  supported operation to "clear" them, and no field a passing check could be written back to.

### Per-gate posture — which gates can run for real

| Gate | Runner exists? | Verdict |
|------|----------------|---------|
| `tests` | **Yes** — `pytest` suite under `tests/` | **RAN: 29 passed** (service-level suite; not a per-capability test) |
| `retrievalEvals` | **Yes** — `capmesh eval` + `evals/retrieval-golden.json` | **RAN: recall@10 = 0.75 (3/4), `passed=false`** |
| `promptInjectionScan` | **Yes** — `scan_prompt_injection()` (governance.py:3119) | **RAN over 507 promoted cap sources: 27 flagged** (see below) |
| `signature` | **No** — no signing code (no cosign/sigstore/keys) | **needs-operator: no infrastructure** |
| `provenance` | **No** — no provenance computation/attestation | **needs-operator: no infrastructure** |
| `riskTierPolicy` | **Partial** — `risk_tier` is validated as a known enum (`validate_capability_payload`), but there is **no policy engine** that decides whether a tier is *allowed* to promote to a given vault | **needs-operator: enum-check only, no policy** |

### Results of the gates that ran

- **tests** — `python -m pytest -q tests/` → **29 passed in ~1.6s**. This is the
  asg-capmesh service test suite (governance/router/soak), i.e. it proves the mesh
  itself is sound, **not** that each promoted capability has its own passing test. A true
  per-capability `tests` gate does not exist.
- **retrievalEvals** — `capmesh eval --file evals/retrieval-golden.json --k 10` →
  **total 4, hits 3, recall@10 0.75, `passed=false`.** The golden set has only 4 cases and
  one misses, so this gate would **fail** if enforced as-is. It also evaluates *mesh search
  recall*, not a per-promoted-capability retrieval quality, so it is not a per-cap gate.
- **promptInjectionScan** — ran `scan_prompt_injection()` over the on-disk source of all
  **507** approved promoted capabilities: **scanned 507, flagged 27, source_missing 0.**
  All 27 hits are the scanner's informational blocklist matching benign authoring language
  in agent/system-prompt definitions — e.g. `act as` (role framing in agent specs),
  `system prompt` (caps literally named `*-system-prompt`), and `bypass auth(entication)`
  (a security-engineering capability that legitimately discusses the term). These are
  **false positives by design** (the function's own docstring states it is "informational,
  not a security boundary"), not injected attacks — but a strict gate would block all 27.

### Override markers — could NOT be cleared (by design, not by omission)

Current live DB state (`~/.capmesh/asg-capmesh.db`), which has **grown since this report's
original 100-move run** to 551 promotion requests:

- **551** promotion requests total — **549 approved**, 1 recalled, 1 pending.
- **34** requests carry all-six-`passed` gates (caps submitted with a non-default gate
  payload — primarily the 14 `system` caps + test fixtures); **517** requests have ≥1
  `pending` gate.
- **515** `promotion.gate_override` audit events recorded — i.e. ~515 caps are live in
  org/all-user vaults over pending gates.
- `signature_status`/`provenance_status` across 521 approved caps: **507 `pending`, 14
  `system`** — confirming no real signing/provenance ever ran. `risk_review_status`: 521
  `approved` (set administratively at approval, not by a policy engine).

**No markers were cleared.** Even for the three gates I *could* run, the codebase exposes no
operation to write a `passed` result back into a request's `gates_json` or to retract a
`gate_override` audit event. Doing so by raw SQL would forge gate state outside the governed,
audited path — explicitly out of scope ("if no harness exists, DO NOT fake it"). The audited
override markers therefore **remain in place, accurately reflecting reality.**

### needs-operator list

1. **Build a real gate-execution + write-back path.** Add a `capmesh gates run <requestId>`
   (or `system.gates`) operation that executes each gate and **updates `gates_json`** to
   `passed`/`failed` through the governed/audited path, so `approve_request()` can pass
   cleanly without `overridePendingGates`. Today gates are write-once-at-submit and read-only
   thereafter.
2. **`signature` — no infrastructure.** Needs a signing toolchain (e.g. cosign/sigstore or a
   keyed manifest hash), a key source (OpenBao), and a `signature_status` computation that
   writes a verifiable result. Nothing exists today.
3. **`provenance` — no infrastructure.** Needs an attestation step (source commit, ingest
   hash, builder identity → SLSA-style record) feeding `provenance_status`. Nothing exists
   today.
4. **`riskTierPolicy` — needs a policy engine.** Today only the tier *string* is validated.
   Needs rules mapping `{risk_tier × target vault/visibility} → allow/deny` (e.g. block
   `high`/`critical` from `cap://all/asg/everyone`).
5. **`retrievalEvals` is failing and too small.** Expand `evals/retrieval-golden.json`
   beyond 4 cases and fix the 1 miss before this gate can be enforced; decide whether it
   should gate *mesh search* or *per-capability* retrieval.
6. **`tests` is service-level, not per-capability.** Decide the gate's contract: if it must
   mean "this capability has its own passing tests," that harness does not exist yet.
7. **`promptInjectionScan` needs an allowlist/severity model** so benign authoring phrases
   (`act as`, `system prompt` in `*-system-prompt` caps) don't block legitimate agent
   definitions — otherwise 27/507 promoted caps would be blocked on false positives.

### Bottom line

- **Gates that ran:** `tests` (29 passed, service-level), `retrievalEvals` (recall@10 0.75,
  **fails**), `promptInjectionScan` (507 scanned, 27 flagged — all benign false positives).
- **Gates with NO infrastructure:** `signature`, `provenance` (and `riskTierPolicy` is
  enum-validation only, no policy engine).
- **Override markers cleared:** **0** — there is no governed write-back to clear them, and
  faking gate state was explicitly out of scope. **~515 caps remain override-pending**, which
  is the truthful state. See the needs-operator list above for what to build.
