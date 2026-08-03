# Capmesh external gates registry

**Entity:** ASG · **Scope:** Capability Mesh · **Updated:** 2026-07-21  
**Owner:** the operator (default) unless noted  

Every unchecked ideal-state external/product gate has owner, date, and next action.

| Gate | Owner | Date | Next action | Status |
|------|-------|------|-------------|--------|
| Public OAuth 2.1 + PKCE for non-tailnet clients | the operator | 2026-07-21 | Deferred; see ADR-2026-07-21-remote-oauth-tailnet-only | deferred |
| RFC 9728 PRM / resource indicators for public edge | the operator | 2026-07-21 | Only if Capmesh leaves tailnet | deferred |
| Entra group → mesh allow binding (full) | the operator | 2026-07-21 | Extend SCIM/group sync when multi-tenant org users expand | open |
| SCIM sync for entitlement groups | the operator | 2026-07-21 | Product backlog | open |
| Real embedding model (replace lexical default) | the operator | 2026-07-21 | Wire approved local/model-backed vectors when retrieval SLO demands | open |
| Sigstore / SLSA supply chain | the operator | 2026-07-21 | After internal Ed25519 provenance is universal | open |
| Streamable HTTP MCP / MCP RC adapter | the operator | 2026-07-21 | Track MCP spec finalization | open |
| OTel traces + search/load latency SLO dashboards | the operator | 2026-07-21 | Prometheus metrics exist; add traces when observability sprint opens | open |
| Package lifecycle (draft/active/deprecated/retired) + semver policy | the operator | 2026-07-21 | Spec then implement | open |
| Dependency graph / namespace transfer policy | the operator | 2026-07-21 | Spec then implement | open |
| `claude/codex/cursor-agent mcp list` verification CI | the operator | 2026-07-21 | Add to doctor after gateway smoke | open |
| Cursor approval smoke | the operator | 2026-07-21 | Manual once per major gateway change | open |
| `cap.delegate` agent-runner integration | the operator | 2026-07-21 | Product backlog | open |
| hardware DIMM RMA (host hardware) | the operator / hardware | 2026-07-21 | Complete Supermicro RMA; not Capmesh software | open |
| Proxy token rotation cadence | Capmesh ops | 2026-07-21 | Rotated 2026-07-21 after diagnostic exposure; rotate on leak | done |

## Production exit gates (section 12) — live proof 2026-07-21

| Gate | Evidence | Status |
|------|----------|--------|
| Loopback workers behind authenticated nginx/Serve | Workers `127.0.0.1:17781–17796`; nginx `17778`; Tailscale Serve | **done** |
| Remote HTTP/MCP security/readiness smoke | `ops/closure-verify.sh` all checks passed 2026-07-21 | **done** |
| Immutable deploy/refresh on both nodes | Release `20260721T123721Z-61166d5d9cc7` on the authoritative node + fallback; gen match | **done** |
| Remote OAuth decision | ADR-2026-07-21-remote-oauth-tailnet-only | **done** |
| External gates owner/date/next | This registry | **done** |
