# Capmesh production exit — 2026-07-21

**Entity:** ASG · **Scope:** Capability Mesh  
**Sensitivity:** `[INTERNAL]`  
**Result:** **PASS** for tailnet production operation  

## Closure verify

```
ops/closure-verify.sh → RESULT: all checks passed (twice, after token rotation + TEI durable)
```

| Check | Result |
|-------|--------|
| Authority `/health/ready` | ready, authoritative, **3472** caps, gen `sha256:abf45b9b…` |
| Public `/metrics` bare | **401** |
| Mac non-voting | ready, `non-voting-raft`, **3472** (synced from authority DB) |
| the authoritative node role | `authoritative`, release `20260721T123721Z-61166d5d9cc7` |
| the fallback node role | `non-voting-raft`, same release + gen |
| the fallback node write | `NOT_AUTHORITATIVE` |
| Root disk (the authoritative node) | **~40%** (was 84%) |
| TEI | NanoCpus **16e9**, durable unit `ExecStartPre=ensure-embeddings-capped.sh` |
| Proxy token | rotated 2026-07-21 (env + nginx) |

## Host remediations (the authoritative node)

| Item | Result |
|------|--------|
| Root disk | **84% → ~40%** (cold Capmesh → `/data`, prune, supermemory → `/data`) |
| TEI bge-m3 | **16 CPU cap**; durable `/data/seesuite/ensure-embeddings-capped.sh` + unit `ExecStartPre` |
| Metrics leak | nginx no longer injects proxy auth for `/metrics`; bare public **401** |
| Proxy token | **Rotated** 2026-07-21 (leaked in diagnostics); env + nginx updated together |
| Workers | loopback-only `17781–17796`, LB `17778` |

## Documents closed

- `docs/ADR-2026-07-21-remote-oauth-tailnet-only.md`
- `docs/EXTERNAL-GATES-REGISTRY.md`
- `docs/ideal-state-checklist.md` §12 production exit → all checked

## Remaining ideal-state (product backlog, not production exit)

See EXTERNAL-GATES-REGISTRY.md: real embeddings, OAuth for public edge (deferred),
SCIM, Sigstore/SLSA, Streamable MCP, OTel SLOs, package lifecycle, client MCP list CI.

## Operator commands

```bash
cd services/asg-capmesh && bash ops/closure-verify.sh
curl -fsS https://capmesh.example.local/health/ready | jq '{status,topology,catalog}'
curl -sS -o /dev/null -w '%{http_code}\n' https://capmesh.example.local/metrics  # expect 401
```
