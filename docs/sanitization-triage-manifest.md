# Capability-Mesh Productionization — Sanitization Triage Manifest

**Status:** Analysis artifact (controller-authored from verified scan evidence)
**Date:** 2026-07-25
**Source repo:** `the asg-capmesh service` → target sanitized repo `the sanitized capmesh repo` (submodule of `cire-apps`)
**Authority:** `cire-apps/CLAUDE.md` sanitization rule + `docs/security/ai-agent-security.md`; `docs/workstreams/capmesh.md` workstream.

> This manifest is the authoritative A/B/MIXED triage for productionizing asg-capmesh as a
> company-agnostic product. It is derived from direct `rg` scans of the the upstream tree (real token
> counts), not estimates. "Leak" here means **ASG identifiers that must be stripped per the
> cire-apps sanitization contract** — hostnames, domains, Entra tenant, entity names, node names,
> superadmin emails, personal/private paths — not only hardcoded secrets (which are already
> env/vault-sourced and absent).

---

## 1. Service-core per-file ASG-identifier leak inventory

Path `services/asg-capmesh/`. Scanned for: `example.com|the capmesh host|capmesh.the capmesh host|the authoritative node|a replica node|<entra-tenant-id>|the company|a research lab|the state directory|the developer home dir|the operator admin|the operator admin` (excl. `.venv/__pycache__/.pytest_cache/.mypy_cache/.ruff_cache/egg-info`).

### `capmesh/*.py` core (11 files carry ASG identifiers)
| File | Token hits | Sanitization action |
|---|---|---|
| `governance.py` (3945 ln) | 7 | Pluggable identity: drop `@example.com` corporate resolution + Entra tenant `<entra-tenant-id>…` pin → tenant-configured allowlists/IdP. |
| `cli.py` (1099 ln) | 8 | De-brand tenant/org defaults (`the company`) → configurable. |
| `help.py` (363 ln) | 3 | Replace `capmesh.the capmesh host` examples → symbolic `BOLDE_CAPMESH_URL`. |
| `node_role.py` (51 ln) | 3 | De-brand `the authoritative node`/`a replica node` topology → config-driven node roles. |
| `server.py` (2262 ln) | 2 | Symbolic endpoints; remove `the capmesh host` callback/proxy refs. |
| `router.py` (551 ln) | 3 | Remove ASG-named default roots/examples. |
| `index.py` (2090 ln) | 2 | De-brand allowed-origins tailnet FQDNs → tenant config. |
| `models.py` (219 ln) | 1 | Genericize default principal/tenant. |
| `install_policy.py` | 2 | Tenant-configured superadmin actor (drop `the operator admin`/`the operator admin` pin); fail-closed stays. |
| `auth_google.py` | 1 | Genericize corporate-domain mapping. |
| `lifecycle_cli.py` | 1 | De-brand default actor. |
| **clean (0 hits)** | 0 | `signing.py`, `auth.py`, `audit.py`, `manifest.py`(730 ln — verify roots), `scim.py`, `production_config.py`, `lifecycle.py`, `__init__.py`, `__main__.py` — port with spot-check. |

### Non-`capmesh/` surfaces with ASG identifiers
| Path | Action |
|---|---|
| `config/capmesh.example.json`, `.env.example` | Symbolic placeholders; drop `capmesh.the capmesh host`/tenant id/superadmin emails. |
| `install/install.sh`, `install.ps1`, `install/mac/asgcode-capmesh-install.sh` | Rewrite to tenant config (Phase 5); drop `the developer home dir`, `/secure/…` paths. |
| `deploy/launchd/*.plist`, `deploy/systemd/*.{service,timer}` | De-brand unit names/labels; keep structure. |
| `ops/deploy-capmesh.sh`, `ops/*sync*.sh`, `ops/*watchdog*.sh`, `ops/install-safe-sqlite-runtime.sh`, `ops/git-sync.sh`, `ops/backup-db.sh`, `ops/provision-local-service-client.sh`, `ops/parity-check.sh`, `ops/closure-verify.sh`, `ops/check-deploy-drift.sh`, `ops/selfheal-reingest.sh` | De-brand; drop the authoritative node/a replica node host refs; make deploy roots config-driven. |
| `ops/hosts/the authoritative node/*` (HARDWARE-FAILING-DIMM, KDUMP-SSH-TARGET, kdump.conf, RMA) | **EXCLUDE** — ASG-host-specific hardware ops. |
| `README.md`, `SECURITY.md`, `LLM-INTEGRATION.md` | Rewrite sanitized (Phase 1). |
| `tests/{test_capmesh,test_capmesh_soak,test_http_service_auth,test_identity_provisioning,test_ingest_transactional,test_mcp_security_readiness,test_production_config,test_search_concurrency,test_vault_placement}.py`, `tests/ops/test-ops.sh` | Replace ASG fixtures → synthetic tenant fixtures; add leak-negative tests. |
| `docs/` (~20 runbooks) | AUTHORITY-INVARIANT, PRODUCTION-EXIT, STABILIZE-*, POSTMORTEM-*, VAULT-TRIAGE-*, BOLDE-FLEET-AUDIT, google-sso-setup, MAGIC-INSTALL, RESTIC-RECOVERY → **EXCLUDE or redact**; keep only generic design/spec docs sanitized. |

**Leak-negative gate (must pass before any phase done):** scanner asserts 0 hits across shipped repo for: `example.com`, `the capmesh host`, `capmesh.the capmesh host`, `the authoritative node`, `a replica node`, `<entra-tenant-id>`, `the company`, `a research lab`, entity names ASI/MRI/IPSA/Xero/Trace, `the state directory`, `the developer home dir`, `the operator admin`, `the operator admin`.

---

## 2. Plugin corpus triage (real per-plugin ASG-token counts)

Scanned `the upstream repo/plugins/*` for ASG identifiers (excl. node_modules). Buckets per the approved plan + the user's "sanitize-and-include methodology, drop ASG branding" decision.

### Bucket A — EXCLUDE (deeply ASG-internal; sanitizing would gut content)
`asg-entity-strategy`(626), `asg-govcon-capture`(550), `asg-regulatory-radar`(548), `asg-strategic-planning`(358), `asg-financial-consolidation`(301), `asg-visual-intelligence`(282), `asg-intercompany-governance`(184), `asg-board-governance`(186), `asg-chairman-office`(121), `asg-subcontractor-network`(112), `asg-overlay-asi`(114), `asg-overlay-ipsa`(142), `asg-overlay-mri`(148), `asg-overlay-agentic-trace`(78), `asg-overlay-agent-xero`(55), `asg-overlay-aisf`(28), `asg-agent-governance`(198, if it encodes ASG policy), `asg-local-agent-roster`, `asg-training-and-visuals`(120), `jason-persona` **produced data** (`persona.json`, `references/*`, `north-star.md` — private). Keep in the upstream repo only.

### Bucket MIXED — SANITIZE-then-include (generic methodology, strip ASG branding/identifiers)
`asg-people-operations`(565), `asg-communications`(384), `asg-contract-lifecycle`(372), `asg-document-forge`(348), `asg-pricing-strategy`(243), `asg-external-docs`(239), `asg-internal-docs`(182), `asg-client-delivery`(158), `asg-program-management`(155), `asg-operating-model`(154), `asg-delivery-pmo-and-sops`(83), `asg-finance-govcon-controls`(128), `asg-small-business`(12), `overlays/`(423 → genericize per-entity overlays to role overlays).
**Plus non-`asg-` packs the plan had assumed clean — MUST sanitize, not include as-is:** `redteam-ops`(179), `redteam-cloud`(89), `redteam-mobile`(77), `redteam-c2`(77), `redteam-recon`(68), `redteam-webapp`(67), `redteam-ai-llm`(58), `redteam-web3`(58), `redteam-ics-ot`(59), `redteam-ad`(57), `redteam-hardware`(60), `redteam-wireless-rf`(49), `dfir-network-cloud`(88), `dfir-disk-timeline`(64), `dfir-memory`(62), `re-malware`(64), `re-fuzzing`(61), `re-dynamic`(59), `re-exploit-dev`(57), `re-workbench`(45), `re-firmware`(32), `codeforensics-acquisition`(160), `codeforensics-similarity`(72), `codeforensics-license`(69), `codeforensics-expert-report`(67), `codeforensics-provenance`(59), `codeforensics-negative`(57), `purple-detection`(65), `asgcode-mkt`(71), `linear-integration`(80), `cfo-com`(18), `figma-command`(19). Action: strip ASG entity tags/names/branding + private examples, keep methodology, re-validate frontmatter (name≤64, desc≤1024).

### Bucket B — INCLUDE AS-IS (0 ASG tokens, clean)
All `pm-*` (pm-product-strategy, pm-market-research, pm-product-discovery, pm-go-to-market, pm-data-analytics, pm-marketing-growth, pm-execution, pm-toolkit, pm-ai-shipping), `vibe-mandates-2026`, `svelte`, `swiftui-expert`, `typescript-lsp`, `tailscale-specialists-2026`, `m365-intune-management`, `marketingskills`, `musk-audit`, `musk-audit-protocol`, `musk-audit-codex`, `real-estate-investor`, `real-estate-opposition`, `re-deal-workflow`, `re-market-analysis`, `re-underwriting`, `nova-investment-analyst`, `nova-gis-analyst`, `patent-practice`, `org-chart`, `ledger-forge`, `vossian`, `pmp-pmbok-guide`, `operating-qwen-inference-fleet`, `lean-product-specialist`, `summitos`, `site-sentinel`, `pixel-ghost`, `mcp-forge`, `plugin-forge`, `one-pager-forge`, `narrative-architect`, `narrative-experience-researcher`, `roadmap-frameworks`, `phantom-writer`, `sovereign-uiux-architect`, `xero-stripe`, `install-titrate`, `resend-skills`, `general-agile-pm`, `eos-visionary-plugin`, `aristotelian-first-principles`, `bolde-*`(6 each — spot-check), `meta-social`(9), `tax-prep-cpa-grade`(8), `task-intelligence`(5), `task-viz`(0). `trailofbits`(2) — spot-check before include.

---

## 3. Required inclusions (verified)

- **Wargame workflow:** `compass-suite/skills/compass-qa-wargamer/SKILL.md` — `compass-suite` scans **0 ASG tokens** → include as-is. Generic investor Q&A wargaming methodology.
- **Persona-creation ("you") workflow:** `pm-market-research/skills/user-personas/SKILL.md` scans **0 tokens** → safe generic source. Build new sanitized **`persona-author` skill** = `user-personas` methodology + authoring pattern from `jason-persona/skills/jason-draft/SKILL.md` + `commands/jason-draft.md`, **excluding ALL produced Jason data** (`persona.json`, `psych_profile.json`, `references/persona-model.md`, `references/north-star.md`, `agents/jason-*.md`). Lets any cap/workflow author build their own persona capsule.

---

## 4. Anthropic-official refresh plan (REQUIRED — not "no refresh")

Every `plugins/anthropic-official/*/.upstream-source` records:
```
imported-at: 2026-05-13T18:35:XX+00:00
source-remote: (unknown)
source-commit: (unknown)
```
No recorded git pin → **must re-pull all ~24 subplugins from the upstream Anthropic official marketplace to 2026-07-25**, this time recording real `source-remote` (marketplace repo URL) + `source-commit` (SHA) + `imported-at: 2026-07-25` + `source-path`. Subplugins: claude-code-setup, mcp-server-dev, feature-dev, claude-md-management, playground, example-plugin, learning-output-style, cwc-makers, code-review, plugin-dev, math-olympiad, pr-review-toolkit, skill-creator, security-guidance, frontend-design, code-modernization, agent-sdk-dev, explanatory-output-style, commit-commands, ralph-loop, hookify, code-simplifier (+ any umbrella). Land in sanitized corpus; keep LICENSE; re-run frontmatter-length + sanitization scanner. (Earlier delegated lane wrongly concluded "no refresh required" — that conclusion is incorrect per the provenance stubs.)

---

## 5. Verification (per plan)
1. Leak scanner green across shipped repo + corpus. 2. `python -m pytest` (ported tests, synthetic fixtures). 3. Seven-tool smoke (`ingest`→`check`→`search`→`load`→`serve-http`; `cap.*` return sanitized JSON). 4. `GET /health/ready` `catalog.generation` parity across nodes. 5. Every `anthropic-official/*/.upstream-source` has real remote+commit + `2026-07-25`. 6. `cap.search "wargame"` → `compass-qa-wargamer`; `cap.search "persona"` → `persona-author`; neither has ASG/private material. 7. cire-apps submodule pinned, portal reaches via `BOLDE_CAPMESH_URL`. 8. This manifest's buckets match shipped corpus.

## 6. Open / follow-up
- `the sanitized capmesh repo` repo created (empty); needs clone + tree copy (no the upstream repo history) + leak scanner + sanitized service.
- Confirm upstream Anthropic marketplace repo URL for the re-pull (resolve from the `.upstream-source` `source-marketplace: anthropic-official` + Claude plugin marketplace).
- Assign named owner to `cire-apps/docs/workstreams/capmesh.md` (currently "unknown owner").
