# Bolde Capability Fleet Audit — 2026-07-20

## Decision

The `jw-seesuite-llm-fleet-1.0.0` handoff is accepted only after deterministic
conversion into the Bolde product and organization model. The reviewed output
contains 93 capabilities in six governed Bolde namespaces. It is suitable for
immutable deployment and normal Capmesh promotion; it must not bypass lifecycle
gates.

The source repository remains
`the upstream repository` until that repository is
renamed. That literal is provenance, not product naming. User-facing names,
capability identifiers, instructions, and plugin identifiers are Bolde-native.
Every indexed capability carries the explicit identity rule that `SeeSuite` and
`jw-seesuite` are legacy aliases for Bolde, so either legacy query resolves to
the same fleet while new output uses the canonical Bolde name.

Converted package revision: `1.0.1` (source handoff: `1.0.0`).

## Inventory and placement

| Plugin | Bolde namespace | Plugin | Skills | Agents | Commands | Total |
|---|---|---:|---:|---:|---:|---:|
| `bolde-command` | `command` | 1 | 5 | 3 | 4 | 13 |
| `bolde-foundation` | `foundation` | 1 | 5 | 5 | 8 | 19 |
| `bolde-semantics` | `semantics` | 1 | 3 | 3 | 5 | 12 |
| `bolde-retrieval` | `retrieval` | 1 | 2 | 2 | 6 | 11 |
| `bolde-reliability` | `reliability` | 1 | 6 | 6 | 8 | 21 |
| `bolde-governance` | `governance` | 1 | 4 | 4 | 8 | 17 |
| **Total** |  | **6** | **25** | **23** | **39** | **93** |

Source bundle tree SHA-256:
`846aa24572d3a694c6526e1894e7b1987f475e2619472da82f77a15168bfeccd`.

## Material corrections

1. Consolidated the duplicated workflow-runner capability into
   `bolde-command`. Six equal-authority copies would otherwise collide on the
   canonical capability key.
2. Consolidated identical session hooks into `bolde-command` so one event does
   not execute the same hook six times. Hook roots are quoted and use explicit
   runtime-variable fallbacks.
3. Converted capability-facing `SeeSuite`/`seesuite-*` names and instructions to
   Bolde. Technical source-provenance literals remain, and every capability now
   declares the legacy-name compatibility rule so LLM retrieval does not split
   SeeSuite and Bolde into different systems.
4. Replaced unbounded `xhigh` agent effort with the system's titrated default.
5. Corrected the unsupported OpenLineage Python `1.51.0` claim to the verified
   `1.47.0` package baseline. Numeric dependency versions are explicitly
   treated as install-time baselines that require a current compatibility and
   security check.
6. Added explicit untrusted-input, least-privilege, tenant-isolation, secret
   redaction, idempotency, rollback, and postcondition requirements to every
   skill and agent.
7. Embedded the source knowledge in each plugin so each package remains
   self-contained when installed or upgraded independently.

## Five-pass audit evidence

| Pass | Evidence | Result |
|---|---|---|
| Structure | Exact plugin/type inventory; unique canonical keys; strict collision mode | Pass |
| Content | Frontmatter validator on all 25 skills; JSON parse; Python AST parse; stale-name scan | Pass |
| Activation | Hook execution smoke test; one hook owner; deterministic importer `--check` | Pass |
| Security | Secret/path scan; prompt-injection boundaries; least-privilege and rollback instructions | Pass |
| Integration | Isolated Capmesh ingest, retrieval records, lifecycle verify, signed atomic approval | Pass |

The isolated lifecycle run discovered and indexed 93/93 capabilities. Catalog
verification passed 93/93. Atomic catalog approval approved 93/93, reported zero
failed gates and zero remaining non-compliant capabilities, and created the test
signing key with mode `0600`.

## Standards baseline

The conversion was checked against the current MCP tool contract, OWASP prompt
injection guidance, ODCS 3.1.0, OpenLineage Python 1.47.0, Qdrant server 1.18.2
and client 1.18.0, SLSA 1.2, and OpenTelemetry's stable declarative
configuration. These are audit baselines, not hard-coded claims that suppress
freshness checks during future upgrades.

## Reproduction

```bash
python3 scripts/import-bolde-capability-fleet.py \
  --source "the source handoff directory" \
  --check
python3 scripts/check-skill-frontmatter-lengths.py \
  plugins/bolde-command plugins/bolde-foundation plugins/bolde-semantics \
  plugins/bolde-retrieval plugins/bolde-reliability plugins/bolde-governance
```

Production acceptance additionally requires deployment on the authoritative node,
governed promotion into the six Bolde namespaces, replica synchronization, and
authenticated exact-name search/load canaries.
