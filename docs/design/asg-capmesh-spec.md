# CAPABILITY MESH — Build-Ready Specification for an OS-Agnostic, LLM-Agnostic Capability Management & Orchestration System
**Spec v0.10 (draft for Codex build) · the operator · Prepared June 15, 2026**

> v0.10 adds Section L (Organizational Distribution, Tiered Access & Secured Namespaces): public / internal / protected / secret visibility classes, server-side entitlement enforcement via MCP's OAuth 2.1 Resource Server model, and a two-plane (public mirror + private sovereign) registry.

## TL;DR
- **Build a two-layer system**: (1) a signed **package/authoring format** ("CAP") that is a strict superset of Anthropic Agent Skills (SKILL.md) plus agent and plugin manifests, and (2) a **lazy semantic capability-router** exposed as an MCP server (spec 2025-11-25, forward-compat to the 2026-07-28 RC) with a **fixed 7-tool surface** that serves capability bodies on demand via a detail-level enum — never dumping every skill/agent/plugin into the model's tool array.
- **The custom build is justified** because Anthropic's native Tool Search Tool (GA Feb 2026) is Claude/Anthropic-proprietary and does not port to Codex, Cursor, opencode, or OpenHands; Capability Mesh provides one cross-client semantic router with hybrid retrieval (BM25 + vectors), deterministic fallbacks, signing, and a standing eval harness — and yields to native Tool Search on Claude clients.
- **Retrieval recall is the make-or-break risk** — in Stacklok's own head-to-head test across 2,792 tools, "Stacklok MCP Optimizer achieves 94% accuracy in selecting the right tools, while Anthropic's Tool Search Tool achieves only 34% accuracy" — so the spec mandates hybrid retrieval, exact-name/category/paginated fallbacks, content-hash + Sigstore signing of all loaded bodies (treated as untrusted data), and per-client conformance adapters for all six targets.
- **Org distribution is built in via tiered visibility + secured namespaces** (Section L): every capability carries a `visibility` class — `public` (open) / `internal` (org-wide GA) / `protected` (need-to-know) / `secret` (compartmented) — and the router enforces entitlements **server-side** using MCP's OAuth 2.1 Resource Server model: Protected Resource Metadata (RFC 9728), resource-indicator-bound tokens (RFC 8707), and **step-up authorization** (SEP-835), so protected capabilities are either fully hidden or returned as **locked stubs** that trigger incremental consent. Entitlements sync from the org IdP (reference binding: **IdP → SCIM**); a private self-hosted registry holds internal/protected/secret capabilities on the org **tailnet**, while the public mirror carries only `public` ones. You share GA broadly and gate sensitive skills/agents to groups without changing the 7-tool surface.

## Key Findings

1. **MCP version targeting.** Stable spec is **2025-11-25** (the de facto build target). A **2026-07-28 release candidate** (locked May 21, 2026) introduces a stateless protocol core (no `initialize` handshake, no `Mcp-Session-Id`), response caching via **`ttlMs`/`cacheScope`** (SEP-2549, HTTP Cache-Control style), a formal extensions framework (MCP Apps, redesigned Tasks), auth hardening, and deprecates Roots/Sampling/Logging on a 12-month clock. Build against 2025-11-25; isolate transport/session assumptions behind an interface so the RC is a config flip.

2. **Tool ceilings are real and quantified.** Cursor warns at ~40 active tools and hard-caps near ~80; Claude Code degrades past ~50 visible tools. Anthropic's own testing showed token usage dropping from ~134k to ~5k (an 85% reduction); a modest five-server / 58-tool setup consumed ~55K tokens before the conversation even started. This is the entire reason for lazy loading.

3. **Anthropic native Tool Search** (`tool_search_tool_bm25_20251119` / `tool_search_tool_regex_20251119`, `defer_loading:true`, beta header `advanced-tool-use-2025-11-20`) delivers an ~85% token reduction; Opus 4 MCP-eval accuracy 49%->74%, Opus 4.5 79.5%->88.1% — but is proprietary. Capability Mesh mirrors its mechanics in a portable tool surface.

4. **Anthropic Agent Skills are now an open standard** (agentskills.io, published Dec 18, 2025) with ~40 adopters incl. GitHub Copilot, VS Code, Cursor, OpenAI Codex, Gemini CLI, Goose, OpenCode. Format: a folder with `SKILL.md` (YAML frontmatter: required `name` <=64 chars lowercase-hyphen, `description` <=1024 chars) + optional `scripts/`, `references/`, `assets/`. Three-tier progressive disclosure: metadata (~100 tokens) -> body (<5K tokens) -> reference files on demand.

5. **Code-execution-with-MCP / progressive disclosure** is the top-of-line context technique: present capabilities as files/code APIs read on demand, or a `search_capabilities` tool with a **detail-level parameter** (name only / name+description / full schema). Anthropic reports one workflow dropping from 150,000 tokens to 2,000 tokens (98.7% saving) when reframed this way.

6. **Prior art to fork, not reinvent.** Stacklok ToolHive MCP Optimizer exposes only `find_tool`/`call_tool`, builds a hybrid (BM25 + TEI vector embeddings, default `BAAI/bge-small-en-v1.5`) semantic index, surfaces up to 8 tools by default, and reduces token usage 60-85% per request. Arcade.dev's "4,000 Tools, 60% Success" test loaded 4,027 tools across 25 straightforward tasks; regex search hit 56% (14/25) and BM25 64% (16/25) — confirming retrieval accuracy is the key risk at scale.

## A. System Overview & Architecture

Capability Mesh has five planes:

1. **Authoring plane (CAP packages).** Developers author capabilities (skills, agents, plugins) as signed, versioned directories. A `cap` CLI builds, hashes, signs (Sigstore keyless + in-toto/SLSA provenance), and publishes to a registry.
2. **Registry plane.** A `server.json`-compatible metadata registry (reverse-DNS namespaces, semver, content digests) backed by an artifact store (OCI/npm/git). Two planes: a public mirror and a private sovereign registry (Section L).
3. **Index plane.** An ingest pipeline pulls capability metadata + bodies from the registry, chunks them, and builds a hybrid index in **SQLite + sqlite-vec** (FTS5 for BM25, vec0 virtual table for embeddings). Stores content hashes, signature status, and **visibility/ACL** metadata for server-side filtering.
4. **Router plane (the MCP server).** A small, fixed tool surface that performs hybrid retrieval, serves capability bodies at a requested detail level, executes/delegates capabilities, enforces entitlements, and emits `notifications/*/list_changed`. This is the only thing each client connects to.
5. **Orchestration plane.** Multi-agent delegation (orchestrator-worker, sub-agent context isolation, A2A/ACP bridges) and OpenHands integration via microagents/skills + delegation tool.

**Data flow:** client -> authoritative node's Router MCP server (7 tools) -> hybrid index (SQLite) -> registry/artifact store. additional synchronized non-voting members that may serve their local agents for low-latency reads but cannot accept authoritative writes; all other nodes are clients. Capability bodies flow to the model *only* through `cap.load` at the requested detail level. Bodies are content-hash-verified and signature-checked at load time and treated as data, not authority. Every retrieval and load is **entitlement-filtered server-side** (Section L). The normative topology record is `../AUTHORITY-INVARIANT.md`.

## B. Layer 1 — Package / Authoring Format (CAP)

**B.1 Directory layout** (a CAP package is a superset of an Agent Skill):
```
my-capability/
├── cap.json                 # REQUIRED manifest (metadata, type, version, deps, visibility, signing refs)
├── SKILL.md                 # REQUIRED for type=skill (YAML frontmatter + markdown body)
├── AGENT.md                 # REQUIRED for type=agent (system prompt, tools, model prefs)
├── plugin.json              # REQUIRED for type=plugin (bundles skills/agents/MCP servers)
├── scripts/                 # optional executable code (zero context cost until run)
├── references/              # optional deep docs (tier-3 progressive disclosure)
├── assets/                  # optional templates/data
├── .well-known/             # optional adapter hints per client
└── provenance/
    ├── attestation.intoto.jsonl   # in-toto/SLSA provenance
    └── signature.sig              # Sigstore bundle (Rekor inclusion proof)
```

**B.2 `cap.json` manifest schema** (REQUIRED fields, now including access-control fields from Section L):
```json
{
  "$schema": "https://the operator's schema endpoint/cap/0.10/cap.schema.json",
  "name": "protected.legal/msa-redline",    // reverse-DNS namespace + id (class-tagged)
  "type": "skill",                               // skill | agent | plugin
  "version": "1.4.2",                            // strict semver
  "title": "MSA Redline Assistant",
  "description": "Redline a Master Services Agreement against the ASG playbook. Use for MSA/SOW review.",
  "capabilityUri": "cap://protected.legal/msa-redline@1.4.2",
  "contentHash": "sha256:...",                   // hash of canonicalized package tree
  "entrypoint": "SKILL.md",
  "dependencies": [ { "uri": "cap://internal/contract-core@^2.0.0" } ],
  "mutating": false,                             // declares whether capability mutates state
  "riskTier": "low",                             // low | medium | high (gates HITL approval)
  "clients": ["claude-code","codex","cursor","opencode","openhands","asgcode"],

  "visibility": "protected",                     // public | internal | protected | secret  (Section L)
  "discoveryMode": "locked",                     // hidden | locked  (for protected/secret)
  "compartment": "legal",                        // optional need-to-know tag
  "dataClassification": "confidential",          // public | internal | confidential | cui
  "owner": "grp:legal-team",                      // group ref (IdP/SCIM)
  "maintainers": ["grp:legal-team-maint"],
  "acl": { "allow": ["grp:legal-team","grp:exec"], "deny": [] },
  "requiredScopes": ["cap.load:protected.legal","cap.call:protected.legal"],
  "lifecycle": "published",                      // draft|internal-review|published|deprecated|yanked

  "signing": { "method": "sigstore-keyless", "identity": "ci@asg.dev", "rekorLogIndex": 123456 },
  "icons": [ { "src": "https://.../legal.png", "mimeType": "image/png", "sizes": ["48x48"] } ]
}
```

**B.3 Frontmatter (SKILL.md).** Required `name` (<=64 chars, `^[a-z0-9-]+$`, matches folder), `description` (<=1024 chars, both what + when, trigger keywords). Optional `allowed-tools`, `mcp_tools`/`mcp_location` (OpenHands-style), `trigger` (`always`|`keyword`|`manual` with `keywords`). Body recommended <5K tokens; spill into `references/`.

**B.4 Agent definitions (`AGENT.md`).** Frontmatter: `name`, `description`, `model` (optional preference), `tools`/`permissions` (allow/ask/deny per opencode pattern), `mode` (`primary`|`subagent`|`all`), `maxIterations`, `temperature`. Body = system prompt. Maps directly to opencode `agents/*.md`, Claude Code subagents, OpenHands skills.

**B.5 Plugin bundles (`plugin.json`).** Mirrors Claude Code plugin schema: `name`, `version` (semver), `description`, `author`, `repository`, `license`; bundles `skills/`, `agents/`, `commands/`, `hooks/hooks.json`, `.mcp.json`. Distributed via marketplace (`.claude-plugin/marketplace.json` with `plugins[]`, `pluginRoot`, per-plugin `source` pinned to SHA in production).

**B.6 Signing & provenance (normative).** Each package MUST carry: (a) a `contentHash` over the canonicalized tree; (b) a Sigstore bundle (keyless OIDC, Rekor transparency log inclusion); (c) an in-toto attestation with SLSA provenance (builder identity, source repo, build params). Target **SLSA Level 2** minimum, **Level 3 for `secret`/high-risk** capabilities. Registry verifies namespace ownership (GitHub OAuth or DNS/HTTP challenge) before publish.

## C. Layer 2 — Wire / Runtime Protocol (the Router MCP Server)

**C.1 Fixed tool surface (7 tools).** This is the entire model-visible surface regardless of how many thousands of capabilities exist:

| # | Tool | Purpose | Key inputs | Output |
|---|------|---------|-----------|--------|
| 1 | `cap.search` | Hybrid semantic+keyword retrieval over capabilities | `query`, `k` (<=25, default 8), `type`, `detail`, `clientHints` | ranked `capabilities[]` (entitlement-filtered) |
| 2 | `cap.load` | Fetch a capability body at a detail level | `capabilityUri`, `detail` (`name`/`summary`/`full`), `fileRef` | body + `contentHash` + `signatureVerified` |
| 3 | `cap.call` | Execute/invoke a capability (tool/script) | `capabilityUri`, `arguments`, `task` (optional async) | `CallToolResult` (content[], structuredContent, isError) |
| 4 | `cap.list` | Deterministic paginated browse / category fallback | `category`, `cursor`, `pageSize` | `capabilities[]`, `nextCursor`, `ttlMs`, `cacheScope` |
| 5 | `cap.describe` | Exact-name lookup (deterministic, no ranking) | `capabilityUri` or exact `name` | full definition or not-found |
| 6 | `cap.delegate` | Spawn an isolated sub-agent / hand off a task | `agentUri`, `task`, `contextRefs[]`, `budget` | `taskId` (async) or distilled summary |
| 7 | `cap.report` | Telemetry: "capability existed but wasn't surfaced", feedback | `query`, `expectedUri`, `outcome` | ack |

All schemas use **JSON Schema 2020-12** (the default dialect in MCP 2025-11-25 per SEP-1613). `cap.call` and `cap.delegate` support the experimental Tasks augmentation (`task:{ttl}` -> `taskId`, poll `tasks/get`, fetch `tasks/result`; states `working`/`input_required`/`completed`/`failed`/`cancelled`).

**C.2 Detail-level loading (normative).** `cap.search`/`cap.load` MUST honor a `detail` enum modeled on Anthropic's guidance (name only / name+description / full definition with schemas):
- `name` -> identifier + title only (~20 tokens)
- `summary` -> name + description + arg names (~100 tokens)
- `full` -> complete body/schema (SKILL.md body, full input/outputSchema)

`cap.search` defaults to `summary`. The model escalates to `full` via `cap.load` only for the 1-3 capabilities it commits to. Capability bodies MUST be delivered via this **tool** (with the detail enum), NOT primarily via MCP resources, because client resource-autonomy support is uneven. Resource URIs (`cap://...`) are retained as **stable identifiers only**.

**C.3 URI grammar.** `cap://<reverse-dns-namespace>/<id>[@<semver-or-range>][#<fileRef>]`. Example: `cap://protected.legal/msa-redline@1.4.2#references/playbook.md`. Unversioned URIs resolve to latest stable the caller is entitled to see.

**C.4 Example `cap.search` output (structured, JSON Schema 2020-12):**
```json
{
  "content": [{ "type": "text", "text": "2 capabilities matched (1 locked)." }],
  "structuredContent": {
    "capabilities": [
      { "capabilityUri": "cap://internal/contract-core@2.1.0",
        "name": "contract-core", "title": "Contract Core",
        "type": "skill", "score": 0.88, "detail": "summary",
        "signatureVerified": true, "visibility": "internal", "locked": false },
      { "capabilityUri": "cap://protected.legal/msa-redline@1.4.2",
        "name": "msa-redline", "title": "MSA Redline Assistant",
        "type": "skill", "score": 0.93, "detail": "name",
        "visibility": "protected", "locked": true,
        "requiredScopes": ["cap.load:protected.legal"] }
    ],
    "fallbacksAvailable": ["cap.list","cap.describe"]
  }
}
```
Tool result envelope follows MCP 2025-11-25: `CallToolResult` has `content` (REQUIRED array), optional `structuredContent` (validated against the tool's `outputSchema`), optional `isError`. Input-validation failures return as **Tool Execution Errors** (`isError:true`) per SEP-1303, not protocol errors, so the model can self-correct.

**C.5 list-changed & caching.** The router emits `notifications/tools/list_changed` only if the 7-tool surface itself changes (rare); capability inventory changes are NOT surfaced as tool-list churn. Under 2025-11-25, `cap.list`/`cap.search` attach `ttlMs`/`cacheScope` (forward-compatible with SEP-2549) so clients cache the catalog without re-polling. `cacheScope` MUST be set per-principal for entitlement-filtered results so caches are never shared across principals.

**C.6 Capability negotiation.** Router advertises `capabilities.tools.listChanged:true`; optionally `resources` (subscribe/listChanged) for stable-identifier URIs; `tasks.requests.tools.call:{}` for async. `initialize` returns `protocolVersion:"2025-11-25"`, `serverInfo`, and `instructions` describing the 7-tool workflow.

## D. Semantic Index & Retrieval Subsystem

**D.1 Storage schema (SQLite + sqlite-vec).**
- `capabilities(uri PK, name, type, version, title, description, body_summary, content_hash, signature_verified, risk_tier, mutating, category, visibility, compartment, owner, updated_at)`
- `capability_acl(uri, group_ref, right)` — (right ∈ discover|load|call|delegate|publish)
- `capabilities_fts` (FTS5 over name/title/description/keywords for BM25)
- `capabilities_vec` (vec0; embeddings of name+description+keywords)
- `eval_runs`, `retrieval_telemetry` (query, returned URIs, chosen URI, miss flag), `access_audit` (principal, uri, decision, scope, reason, ts)

Filesystem/registry remain source of truth; the index is a rebuildable acceleration layer.

**D.2 Hybrid retrieval (normative).** MUST run BM25 (FTS5) and vector search in parallel, fuse with Reciprocal Rank Fusion (RRF), then optionally rerank a reduced candidate set (cross-encoder). Embedding default `BAAI/bge-small-en-v1.5` via a local TEI server (matching ToolHive), pluggable. BM25 rescues exact tokens (names, IDs, versions); vectors cover paraphrase. **Entitlement filtering is applied to the candidate set before ranking is returned** (Section L.5).

**D.3 Deterministic fallbacks (normative, all three REQUIRED).**
1. Exact-name lookup (`cap.describe`)
2. Category browse + paginated full list (`cap.list`)
3. Telemetry-logged miss (`cap.report`) for "capability exists but wasn't surfaced"

**D.4 Eval / regression harness (normative).** A standing test set of (query -> expected capabilityUri) pairs measuring **recall@k, MRR, nDCG**, run in CI on every index/embedding/description change, gated. Adopt Arcade-style failure analysis (large tool count, everyday workflows). Track per-model accuracy. Telemetry dashboards for retrieval misses feed description improvements.

## E. Per-Client Conformance Adapters

**Conformance tiers:** Tier 0 (any MCP client: 7-tool surface). Tier 1 (native skill support: also install CAP skills locally). Tier 2 (native tool-search: yield to it).

| Client | Config file | Native capability | Native-vs-custom boundary |
|--------|-------------|-------------------|---------------------------|
| **Claude Code** | `.mcp.json` / `~/.claude/settings.json`; plugins via `.claude-plugin/marketplace.json` | Native Tool Search (GA Feb 2026), Agent Skills, plugins | Yield to native Tool Search when only Claude clients connect; use Mesh router for cross-client portability, shared registry, and entitlements. Install CAP skills as native skills. |
| **OpenAI Codex** | `~/.codex/config.toml` (`[mcp_servers.<id>]`, command/url, `enabled_tools`, `default_tools_approval_mode`, `tool_timeout_sec`); project `.codex/config.toml` (trusted only) | MCP (stdio+HTTP), connectors, approval modes, SKILL.md | Router as one `[mcp_servers.capmesh]`. `default_tools_approval_mode="prompt"` for `cap.call`/`cap.delegate`; `approve` for high-risk. OAuth or bearer header for entitlements. |
| **Cursor** | `.cursor/mcp.json` (project) / `~/.cursor/mcp.json` (global) | MCP; ~40-tool soft cap, ~80 hard cap | Router's 7 tools stay far under the cap — solving Cursor's biggest MCP pain. All capabilities reachable through 7 tools. |
| **opencode** | `opencode.json(c)` `mcp` block; `.well-known/opencode` org defaults; agents in `agents/*.md`; skills in `skills/` | MCP, model-agnostic providers, plugins (25+ hooks), ACP server, per-tool permissions | Router as one `mcp` entry. Permission patterns (`capmesh_call:"ask"`) for gating. Route other heavy servers through Mesh. |
| **OpenHands** | `.openhands/microagents/` (V0) / `.openhands/skills/` (V1); MCP config; `config.toml` | Event-stream agent, microagents/skills (triggers, `mcp_tools`), sub-agent delegation, Docker runtime | Router as MCP server in the sandbox. CAP skills map 1:1 to OpenHands skills. `cap.delegate` bridges to OpenHands sub-agent delegation. Broker injects short-lived workload identity. |
| **the orchestrator** (Claude-based) | Same as Claude Code | Inherits Claude Tool Search + Skills | Claude-Code conformance profile; yield to native Tool Search, plus Mesh for org registry/signing/entitlements. |

**Adapter responsibilities:** translate the 7-tool surface into each client's config; map approval/permission semantics; carry the caller's credential (OAuth token, bearer header, or mTLS) so the router can enforce entitlements; decide native-vs-custom.

## F. Multi-Agent / OpenHands Orchestration

**F.1 Patterns supported.** Orchestrator-worker (lead agent + isolated sub-agents), handoffs, shared scratchpad (filesystem/resources), and bridges to **A2A** (Linux Foundation v1.0, JSON-RPC-over-HTTP + SSE, Agent Cards, task lifecycle) and **ACP/Agent Client Protocol** (opencode ships an ACP server). `cap.delegate` is the unified entry; it can target a local sub-agent or an external A2A/ACP agent. Prefer centralized/hybrid orchestration through the router as agent count grows (avoid N-squared peer connectivity).

**F.2 Context isolation (normative).** Each delegated sub-agent gets its own context window and returns only a **distilled summary** (~1-2K tokens) to the parent (Anthropic's multi-agent researcher pattern). Detailed sub-agent traces stay isolated. This is the core anti-context-eating mechanism for "max multi-agent flow." Pair with compaction (summarize trajectory near window limit) and context offloading to filesystem.

**F.3 OpenHands specifics.** Event-stream core: stateless Agent emits Actions -> Runtime (Docker/sandbox) executes -> Observations flow back through an append-only EventLog; LLM brokered via LiteLLM. Router runs as an MCP server inside the OpenHands Docker runtime; CAP skills drop into `.openhands/skills/` (V1) or `.openhands/microagents/` (V0); `cap.delegate` maps to OpenHands' delegation tool. Budget controls (max iterations, accumulated-cost) and stuck detection are respected. CAP `mcp_tools`/`mcp_location` frontmatter lets a skill spin up the router on activation.

## G. Security, Integrity & Safeguards

**G.1 Loaded bodies are untrusted (normative).** SKILL.md/AGENT.md bodies are instruction content and a prompt-injection / supply-chain surface. The router MUST: verify `contentHash` and Sigstore signature at load time; refuse or flag unsigned/mismatched bodies; treat loaded content as **data, not authority**. Sanitize for hidden-instruction patterns (invisible Unicode, hidden HTML).

**G.2 NSA MCP baseline mapping.** (a) message-level integrity (signed receipts) since TLS secures the channel not the content; (b) per-call permission scoping (least privilege); (c) tamper-evident, signed audit log of every `cap.call`/`cap.delegate`/access decision; (d) trust chains to prevent malicious-gateway substitution.

**G.3 Least privilege & no token passthrough.** Capabilities run with minimal scopes; secrets injected at request time by a broker/sidecar, never read into model context (short-lived workload identity). Use code-execution-with-MCP tokenization so sensitive fields never enter the model. Mutating/high-`riskTier` capabilities require **human-in-the-loop approval** (Codex `approval_mode="approve"`, opencode `"ask"`, Claude prompt).

**G.4 Sandboxing & isolation.** Capability execution and sub-agents run sandboxed (Docker/Bubblewrap/Modal). Network egress allowlisted. Stamp every tool response with build hash, config hash, and execution-environment ID.

**G.5 Supply-chain for multi-contributor ecosystem.** Registry enforces namespace ownership, signature + provenance verification, version-locking, and policy-based allowlists (registry-only mode). Optional malware scanning; tool-poisoning/description-drift detection on every index update.

## H. Registry, Versioning & Distribution

- **Registry model:** `server.json`-compatible (`$schema`, reverse-DNS `name` like `internal/<id>`, `version`, `packages[]` with `registryType`/`identifier`/`transport`, `_meta`). Registry hosts metadata + digests, not code. Namespace ownership proven via GitHub auth or DNS/HTTP challenge.
- **Versioning:** strict **semver**; URIs may pin exact or range; production pins to content digest/SHA. Deprecation policy >=12 months (mirroring MCP SEP-2596).
- **Dependency resolution:** `cap.json.dependencies[]` resolved transitively at install/index time; conflicts surfaced.
- **Update propagation:** registry polling rebuilds the index; capability changes update SQLite silently (no tool-list churn). Marketplace catalogs may reference plugins from multiple repos, each pinned to a SHA in production.
- **Two planes:** public mirror (public only) + private sovereign registry (internal/protected/secret) — see Section L.7.

## I. Audit & Observability

- **Signed audit log** of every capability load/call/delegate AND every access decision (who/what/when, content hash, signature status, scope, approval/deny decision, outcome).
- **W3C Trace Context** in `_meta` (`traceparent`/`tracestate`/`baggage`, forward-compat with SEP-414); OpenTelemetry export (Codex `[otel]` OTLP exporters; ToolHive OTel/Jaeger/Prometheus patterns).
- **Retrieval telemetry**: recall misses, chosen-vs-expected, per-model accuracy, token savings/request.
- **Eval dashboards**: recall@k/MRR/nDCG trends gating releases.

## J. Phased Implementation Roadmap (Codex-followable)

- **Phase 0 — Skeleton (wk 1-2):** MCP server (TS or Python SDK) implementing `initialize` + 7 tools with stub data; conformance test vs MCP Inspector; Cursor/Codex/opencode adapters.
- **Phase 1 — Index & retrieval (wk 3-4):** SQLite + sqlite-vec, FTS5 BM25, TEI embeddings (`bge-small-en-v1.5`), RRF fusion, `cap.search`/`cap.load`/`cap.list`/`cap.describe`; detail-level loading; eval harness.
- **Phase 2 — Packaging, signing & namespaces (wk 5-6):** `cap` CLI (build/hash/sign/publish), all manifest schemas, Sigstore + in-toto/SLSA, registry with namespace ownership, **visibility classes + private registry plane (L.1-L.2, L.7)**.
- **Phase 3 — Execution, orchestration & entitlement filtering (wk 7-9):** `cap.call` (Tasks async), `cap.delegate` (isolated sub-agents), OpenHands mapping, A2A/ACP bridges, HITL gating, **router-side entitlement filtering + step-up auth (L.4-L.5)**.
- **Phase 4 — Security hardening, IdP & native boundaries (wk 10-12):** load-time verification, sandboxing, signed audit log, content sanitization, Claude/the orchestrator yield-to-native path, OTel/trace context, RC (2026-07-28) transport branch, **org IdP wiring (Entra/SCIM), CIMD client gating, broker-injected workload identity, denied-attempt audit (L.3, L.6, L.9)**.

**K. Conformance test checklist:**
- [ ] 7-tool surface and nothing else visible to every client; stays under Cursor's 40-tool cap
- [ ] `detail` enum returns name/summary/full token tiers correctly
- [ ] Hybrid retrieval recall@8 >= target on eval set; all 3 deterministic fallbacks work
- [ ] Every loaded body content-hash + signature verified; unsigned rejected/flagged
- [ ] Tasks async lifecycle (working->completed/failed/cancelled) for `cap.call`/`cap.delegate`
- [ ] Sub-agent delegation returns distilled summaries, isolated context
- [ ] Per-client config adapters validated (Claude Code, Codex, Cursor, opencode, OpenHands, the orchestrator)
- [ ] HITL approval fires for `mutating:true`/`riskTier:high`
- [ ] Audit log signed and tamper-evident; OTel traces correlate end-to-end
- [ ] `notifications/*/list_changed` only on the 7-tool surface, never on capability inventory
- [ ] Forward-compat: transport layer swappable to 2026-07-28 stateless core
- [ ] **Visibility tiers enforced server-side in cap.search/list/describe (hidden omitted; locked stubbed with requiredScopes)**
- [ ] **cap.load/call/delegate re-check entitlement at exec time (never trust prior discovery filtering)**
- [ ] **Step-up (403 + WWW-Authenticate w/ scope) fires for locked protected capabilities; secret/hidden returns empty/404 and never reveals existence**
- [ ] **PRM at /.well-known/oauth-protected-resource, RFC 8707 resource indicators, OIDC discovery wired to org IdP (Entra)**
- [ ] **Private registry holds internal/protected/secret; public mirror carries only public; protected artifacts access-controlled**
- [ ] **`cacheScope` per-principal for entitlement-filtered results; denied/step-up attempts on protected/secret audited**

## L. Organizational Distribution, Tiered Access & Secured Namespaces

This layer lets you publish capabilities to the whole org (general availability) while gating sensitive skills/agents to specific groups in secured namespaces — **without changing the 7-tool surface**. All gating is enforced in the router, so it holds uniformly across all six clients.

**L.1 Visibility tiers (per namespace, inheritable per capability).**
- `public` — anonymous/world or all-org; GA, no entitlement beyond base membership (open-source skills, broadly safe tools).
- `internal` — all authenticated org members; **GA inside the org**. Default for shared internal capabilities.
- `protected` — restricted to entitled principals/groups (need-to-know). `discoveryMode` is `hidden` or `locked`.
- `secret` — high-sensitivity compartment; **hidden by default**, need-to-know, elevated signing (SLSA L3) + audit. Maps to CUI/compartmented work.

**L.2 Namespace grammar & classification.** Namespace carries class + optional compartment: `<reverse-dns>[.<class>][.<compartment>]/<id>`.
- `io.github.asg/pdf-forms` -> public
- `internal/runway-tool` -> internal GA
- `protected.legal/msa-redline` -> protected, legal compartment
- `secret.ic/<id>` -> secret, IC compartment

`visibility` in `cap.json` is authoritative; the namespace prefix is a human-readable convention the registry MUST keep consistent with the manifest.

**L.3 Identity, groups, entitlements (ABAC).**
- Principals: human users, **agent/service identities** (each agent gets its own identity so delegation is attributable), and CI.
- Groups/roles synced from the org IdP. **Reference binding: IdP -> SCIM -> Mesh** (the SCIM-synced group model already in use); Auth0/Keycloak/Okta/other IdPs equally supported via OIDC.
- Entitlement = (principal | group) x (namespace | capabilityUri) x rights {`discover`,`load`,`call`,`delegate`,`publish`}. ABAC attributes (team, clearance, compartment, client, riskTier) compose the policy.

**L.4 Authorization mechanics (MCP-native, normative).** The router is an **OAuth 2.1 Resource Server** (MCP 2025-11-25). It MUST:
- Publish **Protected Resource Metadata** at `/.well-known/oauth-protected-resource` (RFC 9728), advertising the org Authorization Server and supported scopes.
- Require **Resource Indicators (RFC 8707)** so tokens are bound to the router (no token reuse elsewhere).
- Encode access as scopes: `cap.discover:<ns>`, `cap.load:<ns>`, `cap.call:<ns>`, `cap.delegate:<ns>`, `cap.publish:<ns>`. Base membership grants `*:public` and `discover+load+call` on `internal`; protected/secret require explicit grants.
- Use **step-up authorization (SEP-835):** when a caller lacks scope for a `protected` capability in `locked` mode, return **HTTP 403 + `WWW-Authenticate`** (Bearer, with `scope=` listing the required scope and `resource_metadata`); the client runs incremental consent and retries. `secret` (and `protected` in `hidden` mode) return **empty/404 — never reveal existence**.
- Discover the AS via **OIDC Discovery 1.0** or OAuth AS metadata.
- Optionally enforce **Client ID Metadata Documents (SEP-991):** the org AS admits only approved client domains (e.g., allow `*.asg.dev`, deny others) — org-level client gating by URL/domain policy.

**L.5 Server-side enforcement (defense in depth, normative).** Entitlement is enforced **in the router**, never delegated to the client:
- `cap.search`/`cap.list`/`cap.describe` MUST filter by caller entitlements *before* returning. `hidden` capabilities are omitted entirely; `locked` ones may appear as stubs (`name`/`title` + `locked:true` + `requiredScopes`) so the model knows to request access.
- `cap.load`/`cap.call`/`cap.delegate` MUST **re-check entitlement at load/exec time** (never trust that discovery already filtered).
- Decisions are uniform across all six clients regardless of credential path.

**L.6 Cross-client credential paths.**
- **Rich (OAuth/OIDC):** Claude Code, Codex remote MCP, Cursor remote — full PRM -> AS -> step-up loop.
- **Local/CI (sandbox/stdio):** bearer token, mTLS client cert, or signed identity header carrying scopes/claims; injected via `headers`/`env` in each client's MCP config and validated by the router.
- **OpenHands/opencode sandboxes:** a broker injects **short-lived workload identity** (no long-lived secrets in context — consistent with G.3).
- Whatever the path, **the token carries entitlements; the router decides.**

**L.7 Registry & publishing controls (two-plane).**
- Each namespace has an owner + class + maintainer set (groups). Publishing to `protected`/`secret` requires `cap.publish:<ns>` + maintainer role; `secret` additionally requires **SLSA L3** provenance and a designated CI identity.
- **Public mirror** carries only `public` capabilities. **Private sovereign registry** (self-hosted on org infra, reachable only on the org **tailnet**) carries `internal`/`protected`/`secret`. Protected/secret **artifacts** live in an access-controlled store (object store + OpenBao-brokered access) — never the public mirror.
- Network boundary: a public GA endpoint is optional; internal/protected/secret router endpoints bind to the org tailnet (tag-based isolation) so even discovery traffic is network-gated.

**L.8 Sharing & promotion lifecycle.** `draft` (author/maintainer only) -> `internal-review` -> publish at target visibility (`internal`/`public`) **or** `protected`/`secret`. Promotion is an explicit, audited transition that re-evaluates ACLs, bumps version, and **re-signs**. Demotion/recall (`yanked`) propagates via list-changed + cache invalidation.

**L.9 Audit additions.** Log every access **decision** (granted/denied, principal, capabilityUri, scope, reason), every **step-up** event, and every **denied** attempt on `protected`/`secret` (a security signal). Denied/hidden lookups MUST be observable to security without revealing secret contents to the caller.

**L.10 Manifest fields (added to `cap.json`, see B.2).** `visibility`, `discoveryMode`, `acl{allow,deny}`, `requiredScopes`, `compartment`, `dataClassification`, `owner`/`maintainers`, `lifecycle`.

**L.11 Worked example (your setup).**
- A runway/budget skill published to `internal/` -> every authenticated ASG member sees and uses it (GA).
- The MSA-redline skill published to `protected.legal/` with `acl.allow=[grp:legal-team, grp:exec]`, `discoveryMode:locked` -> non-legal members don't see it in `cap.search`; legal/exec see it and can `cap.load`/`cap.call`. A curious engineer who somehow references the URI gets a 403 + step-up prompt, not the body.
- An IC-compartment agent in `secret.ic/` with `discoveryMode:hidden`, SLSA L3 -> invisible to everyone outside `grp:ic-team`; the router returns empty for non-entitled callers and never confirms it exists; bound to the GCC-High/tailnet plane only.

## Recommendations
1. **Fork ToolHive MCP Optimizer's architecture** (find_tool/call_tool + hybrid index + TEI) rather than reinvent; extend it to the 7-tool surface, signing, entitlements, and multi-agent delegation. It already cross-targets Claude Code/Cursor/Copilot and is the documented 94%-accuracy reference point.
2. **Build against MCP 2025-11-25, isolate transport** so the 2026-07-28 stateless RC is a config change. Don't hard-depend on the experimental Tasks shape (it changed in the RC).
3. **Treat retrieval recall as the #1 risk.** Ship the eval harness in Phase 1, gate releases on recall@k, instrument "capability exists but wasn't surfaced" from day one.
4. **On Claude/the orchestrator, yield to native Tool Search** for retrieval but keep Mesh as the registry/signing/entitlements/cross-client body server.
5. **Make signing non-optional.** Every capability body is untrusted instruction content; content-hash + Sigstore + SLSA L2 minimum (L3 for `secret`), verified at load.
6. **Enforce access in the router, not the client.** Filter discovery results and re-check at load/exec. Use `hidden` for `secret` (deny existence) and `locked` + step-up for `protected` (reveal that access can be requested). Default new namespaces to `internal`, not `public`.
7. **Bind to your existing identity + network fabric.** IdP -> SCIM for groups, OpenBao for scope/secret brokering, Tailscale tailnet (tag-based isolation) as the boundary for internal/protected/secret. Keep the spec IdP-agnostic but ship the Entra binding first.

**Thresholds that change the plan:** if recall@8 < ~85% on the eval set, add reranking and improve descriptions before scaling capability count; if a single client community standardizes (e.g. all-Claude), collapse to native Tool Search + Skills and keep Mesh only as registry + entitlements; if the 2026-07-28 RC finalizes, flip the transport branch and migrate Tasks.

## Caveats
- The 2026-07-28 spec is a **release candidate**, not final (target July 28, 2026); all RC details are subject to change — design for it, don't depend on it.
- The Stacklok 94% vs Anthropic 34% comparison is **Stacklok's own benchmark**; treat the absolute gap as vendor-reported, though the directional finding (hybrid retrieval > regex/BM25-only at scale) is corroborated by Arcade.dev's independent 4,027-tool test (regex 56%, BM25 64%) and by RAG research.
- Anthropic native Tool Search accuracy figures and the 134K->5K / 150K->2K token reductions are Anthropic-reported.
- OpenHands V1 SDK ("skills") is mid-migration from V0 ("microagents"); support both directory conventions.
- Tool-ceiling numbers (Cursor ~40/~80, Claude ~50) are community/vendor-observed and may shift with client updates.
- The MCP authorization model used in Section L (OAuth 2.1 Resource Server, PRM/RFC 9728, Resource Indicators/RFC 8707, step-up/SEP-835, OIDC discovery, CIMD/SEP-991) is from the **stable 2025-11-25 spec**; not all clients implement the full OAuth flow yet, which is exactly why the router ALSO supports the bearer/mTLS/identity-header credential path (L.6) and enforces server-side regardless.
- "Secret/hidden" namespaces reduce but do not eliminate inference risk (timing, dependency graphs). For true compartmentation, pair `hidden` with network isolation (separate tailnet/registry instance) rather than relying on router filtering alone.
