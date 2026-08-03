# Capability Mesh — LLM Integration Guide

**For:** Claude Code, ASGCode, Codex, Cursor, and any LLM coding agent
**Last updated:** 2026-07-18

---

## TL;DR

```bash
# Search for capabilities matching a domain
capmesh search "legal litigation expert report" --type agent --k 10

# Search + load top N entrypoints in one JSON output block
capmesh search-load "legal contract counsel" --k 2 --type agent

# Quick roster scan of specific agents
capmesh agent-brief expert-report-drafter intercompany-counsel gc-risk-and-contracts-counsel

# JSON output for agent-brief (machine-parseable)
capmesh agent-brief expert-report-drafter --json

# Load a specific capability's full instructions
capmesh load --detail entrypoint "expert-report-drafter"
```

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────┐
│  Claude Code / ASGCode / Codex / Cursor                  │
│  (the LLM agent)                                          │
│                                                          │
│  1. User prompt contains domain keywords                 │
│  2. LLM calls cap.search through the local MCP gateway   │
│  3. LLM calls cap.load for selected, authorized results  │
│  4. Capmesh verifies the indexed content digest          │
│  5. LLM executes the playbook instructions directly      │
└───────────────────────────┬─────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │ ASG MCP gateway│
                    │  → capmesh     │
                    │                │
                    │  search  → find│
                    │  load    → read│
                    │  search-load → find+read│
                    │  agent-brief → quick scan│
                    │ seven cap.* tools only       │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  Local SQLite  │
                    │  index of all  │
                    │  plugins/agents│
                    │  /skills/        │
                    └────────────────┘
```

---

## Two Execution Models

The primary multi-client path is the unified loopback gateway at
`http://127.0.0.1:17777/mcp`. The direct tailnet endpoint is the stateless MCP
2025-11-25 JSON endpoint at the canonical VIP `https://capmesh.asg.ts.net/mcp`
(`CAPMESH_BASE_URL + /mcp`); it intentionally returns `405` for GET/SSE. For
TAILNET users, verified Tailscale whois authenticates reads and discovery
(initialize, tools/list, cap.search, cap.load, cap.list, cap.describe) with
NO OAuth and NO bearer token. Mutating tools (cap.call/cap.delegate/cap.report)
require a service bearer supplied by the asg-mcp-gateway relay for ASG users,
or a minted session via `capmesh login` for external (non-tailnet) users. That
endpoint is served by the authoritative node. Other Capmesh installations are
clients, except additional synchronized non-voting members. Local agents may
use those members directly for low-latency reads; all authoritative writes
still go to the authoritative node.

### Direct MCP client config (tailnet — URL only, no auth block)

TAILNET users can point an MCP client directly at the canonical VIP with no
auth block — verified Tailscale whois authenticates reads/discovery:

**Claude Code** (`~/.claude.json`):

```json
{
  "mcpServers": {
    "capmesh": { "type": "http", "url": "https://capmesh.asg.ts.net/mcp" }
  }
}
```

Or via the CLI: `claude mcp add --transport http capmesh https://capmesh.asg.ts.net/mcp`

**Cursor** (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "capmesh": { "url": "https://capmesh.asg.ts.net/mcp" }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.capmesh]
url = "https://capmesh.asg.ts.net/mcp"
```

No `Authorization` header, no OAuth flow. Mutating tools still require a
service bearer (supplied by the asg-mcp-gateway relay for ASG users) or a
minted session via `capmesh login` (external users).

### Model A: Load-and-Execute (Primary — works now)

```
capmesh search → capmesh search-load → LLM reads JSON → LLM executes agent playbook
```

The capmesh index stores agent instruction files (`.md` entrypoints). `capmesh search-load` returns the full content of these files as structured JSON. The LLM reads the content and **executes the agent's instructions directly in the session loop**.

**When to use:** Every task. This is the primary and only execution path that works today.

**Example:**

```bash
# Step 1: Find legal agents
capmesh search-load "FRCP expert report litigation" --k 3 --type agent
```

Returns:
```json
{
  "status": "done",
  "query": "FRCP expert report litigation",
  "type": "agent",
  "loaded": 3,
  "results": [
    {
      "name": "expert-report-drafter",
      "title": "Expert Report Drafter",
      "type": "agent",
      "description": "Autonomous expert report drafting agent...",
      "uri": "cap://user/asg/...expert-report-drafter@0.1.0",
      "plugin": "codeforensics-expert-report",
      "entrypoint": "---\nname: expert-report-drafter\n...full .md content..."
    },
    ...
  ]
}
```

The LLM then:
1. Reads the `entrypoint` field (a complete agent instruction file)
2. Applies the agent's playbook to the task
3. Produces work product in the session

### Model B: Delegate-and-Report (Future — no runner available)

```
capmesh delegate → queue envelope → [no runner] → cap.report (telemetry only)
```

`capmesh delegate` creates a task envelope and queues it. **There is no agent runner process** that consumes these envelopes and produces output files. To use this model, you'd need:

1. An agent runner that polls the capmesh server for queued envelopes
2. The runner loads the agent's entrypoint via `capmesh load`
3. The runner executes the playbook and writes output files
4. Results are reported back via `capmesh report`

Until that infrastructure exists, Model A is the only option.

---

## CLI Reference

### `capmesh search [query] [--k N] [--type TYPE]`

Search the local index. Returns ranked matches.

```bash
capmesh search "legal" --k 10 --type agent     # Legal agents only
capmesh search "contract negotiation" --k 5    # All types
capmesh search "pentest" --type skill          # Skills only
```

**Query types:** `agent`, `skill`, `command`, `plugin` (omit for all)

### `capmesh load --detail {metadata,entrypoint,full} [identifier]`

Load a capability's full content by name or URI.

```bash
capmesh load --detail entrypoint "expert-report-drafter"
capmesh load --detail metadata "cap://user/asg/.../intercompany-counsel@0.1.0"
```

**Detail modes:**
- `metadata` — only metadata (name, description, type, URI, plugin)
- `entrypoint` — metadata + content field (the full .md instruction file)
- `full` — everything including all capabilities and tools

### `capmesh search-load [query] [--k N] [--type TYPE]`

**LLM-optimized.** Search for capabilities and load full entrypoints in one command. Returns a single JSON block.

```bash
capmesh search-load "legal compliance audit" --k 3 --type agent
```

**Output format:**
```json
{
  "status": "done",
  "query": "legal compliance audit",
  "type": "agent",
  "loaded": 3,
  "results": [
    {
      "name": "...",
      "title": "...",
      "type": "agent",
      "description": "...",
      "uri": "cap://...",
      "plugin": "...",
      "entrypoint": "---\nname: ...\n...full .md...\n"
    },
    ...
  ]
}
```

### `capmesh agent-brief [name1 [name2 ...]] [--json]`

Quick roster scan of specific capabilities. Returns a compact brief.

```bash
capmesh agent-brief expert-report-drafter intercompany-counsel gc-risk-and-contracts-counsel
capmesh agent-brief expert-report-drafter --json
```

**Markdown output** (default):
```
## expert-report-drafter
- **Title:** Expert Report Drafter
- **Type:** agent
- **URI:** `cap://user/asg/...`
- **Plugin:** codeforensics-expert-report
- **Description:** Autonomous expert report drafting agent...
```

**JSON output** (`--json`):
```json
[
  {
    "name": "expert-report-drafter",
    "title": "Expert Report Drafter",
    "type": "agent",
    "description": "...",
    "uri": "cap://...",
    "plugin": "codeforensics-expert-report",
    ...
  }
]
```

### `capmesh delegate [task] --uri [uri] --name [name]`

Create a task envelope for an agent. Returns queued status.

```bash
capmesh delegate "Draft an expert report" --uri "cap://user/asg/.../expert-report-drafter@0.1.0" --name "expert-report-drafter"
```

**Note:** This queues a task envelope but does not execute it. No agent runner is available.

### `capmesh describe [identifier]`

Get lightweight metadata for one capability.

```bash
capmesh describe "intercompany-counsel"
```

---

## Auto-Discovery Hook

The Claude Code hook at `~/.claude/hooks/capmesh-auto-discovery.py` runs before every prompt and automatically:

1. Scans the prompt for domain keywords (legal, security, devops, finance, product, design)
2. Runs `capmesh search-load` for the matched domain
3. Injects a `<system-reminder>` block into the prompt with suggested agents

**This is registered automatically** via `~/.claude/settings.json`. If it's missing, add:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "~/.capmesh/hooks/capmesh-auto-discovery.py",
            "timeout": 3
          }
        ]
      }
    ]
  }
}
```

The hook is **non-blocking** (fail-open) and runs in ≤3 seconds. It only fires on prompts that match known domain keywords.

---

## Installation

### Step 1: Install the capmesh CLI

```bash
# Install from ASG-OS repo
pip install ./GitHub/asg-os/services/asg-capmesh

# Verify
capmesh --help
capmesh search "test" --k 1
```

### Step 2: Install the hook

```bash
# The hook should already be at:
ls ~/.claude/hooks/capmesh-auto-discovery.py

# If not, create it from the repo:
cp ./GitHub/asg-os/scripts/capmesh-auto-discovery.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/capmesh-auto-discovery.py
```

### Step 3: Restart Claude Code

```
/reload-plugins
```

Or restart the Claude Code process.

---

## LLM Operating Procedure

When a user's task involves any domain where capmesh has registered capabilities:

1. **Identify the domain** from the user's prompt keywords
2. **Run `capmesh search-load`** with domain keywords, `--k 3` to `--k 5`
3. **Read the JSON output** — each `result.entrypoint` is a complete agent instruction file
4. **Execute the agent's playbook** using the loaded instructions
5. **Produce work product** — the agent's methodology guides the output

### Example: Legal Document Drafting

```bash
# User: "Draft a forum non conveniens motion for the Brandon case"

# Agent runs:
capmesh search-load "forum non conveniens motion litigation" --k 3 --type agent

# Agent reads the JSON, extracts entrypoint content for the top match,
# then applies the agent's playbook to draft the document.
```

### Example: Capability Roster Scan

```bash
# User: "What legal agents do we have available?"

# Agent runs:
capmesh agent-brief expert-report-drafter intercompany-counsel gc-risk-and-contracts-counsel litigation-workflow-designer contract-drafter privilege-steward similarity-orchestrator

# Agent presents the roster in Markdown.
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `capmesh: command not found` | Install via `pip install ./GitHub/asg-os/services/asg-capmesh` |
| `capmesh search` returns empty results | Ask the authoritative node to run the governed ingest/resync; never rebuild a non-voting member locally. |
| `capmesh agent-brief` returns "not found" | Check name with `capmesh search "<name>"` first |
| Hook not firing on prompts | Verify hook is registered in `~/.claude/settings.json` |
| Hook timing out (>3s) | Increase timeout in settings.json or reduce `--k` in the hook |
| Remote capmesh returns 401 | Token expired; regenerate via `capmesh auth login` |
| `search-load` loads too many agents | Reduce `--k` from 5 to 2-3 |
| Pyproject.toml build fails | Ensure `[build-system]` and `[tool.setuptools.packages.find]` sections exist |

---

## Plugin Sources

All capabilities are discovered from these roots:

| Root | Path |
|------|------|
| authoring plugins | `<CAPMESH_ROOTS>/` |
| Claude skills | `~/.capmesh/plugins/cache/personal/` |
| Codex skills | `~/.capmesh/skills/` |
| Skill registry | `~/.capmesh/skill-registry/` |
| Codex plugin cache | `~/.capmesh/plugins/cache/` |

**Major legal-domain plugin families:**
- `codeforensics-expert-report` — Expert reports, privilege steward, citation verification
- `codeforensics-similarity` — Code similarity for IP litigation
- `overlays` — Litigation workflow designer, classifying matter intake
- `asg-overlay-ipsa` — Litigation workflow designer (IPSA tenant)
- `asg-intercompany-governance` — Intercompany counsel, IP chain of title
- `asg-external-docs` — Contract drafter, engagement letter writer, investigation report writer
- `asg-local-agent-roster` — GC risk & contracts counsel, compliance license, API contracts
- `asg-chairman-office` — Cross-entity risk reviewer, chief of staff
- `asg-regulatory-radar` — Regulatory watchdog, compliance impact analyzer
- `compass-suite` — Legal compliance (Compass)
- `vossian` — Legal negotiation, vendor contract negotiation
- `executive-gtm-operators-2026` — GC risk & contracts counsel (agent, not yet capmesh-indexed)
- `defamation-defender` — Defamation risk analyzer
- `patent-practice` — Patent drafting/prosecution
- `anthropic-knowledge-work/legal` — Brief, legal-response, triage-nda skills

---

## Notes

- The local capmesh index is a SQLite database at `~/.capmesh/asg-capmesh.db`
- Re-index after adding new plugins: route `cap.call system.capabilities` through the authoritative node; its deployment/ingest path owns activation.
- For TAILNET users the remote capmesh server at `https://capmesh.asg.ts.net/mcp` authenticates via verified Tailscale whois (no OAuth, no bearer) for reads/discovery; mutating tools require a service bearer (asg-mcp-gateway relay for ASG users, or a minted session via `capmesh login` for external users)
- All agents/skills in the local index are available for **load-and-execute** without authentication
- `cap.delegate` and `cap.call` return `status: "queued"` — no runner consumes envelopes yet

## MCP Client Registration Verification

After registering capmesh as an MCP server in any client, verify with:

**Claude Code:**
```bash
claude mcp list | grep capmesh
```

**Codex:**
```bash
codex mcp list | grep capmesh
```

**Cursor:**
```bash
cursor-agent mcp list 2>&1 | grep capmesh
```

If any client reports capmesh as not loaded, the MCP URL may need approval
(Cursor) or the config may need a restart. For direct tailnet access, the
URL is `https://capmesh.asg.ts.net/mcp` (no auth block needed for tailnet
reads/discovery). For the local gateway, use `http://127.0.0.1:17777/mcp`.

## Registry Diff

Compare the current mesh state against a previous JSONL export:

```bash
capmesh export-jsonl --export-jsonl ~/snapshots/prev.jsonl
capmesh diff --previous ~/snapshots/prev.jsonl
```

Reports added, removed, and changed capability URIs with a summary count.
