# CapGuard Quarantine Runbook

Entity: ASI | Scope: Multi | [INTERNAL] | [DRAFT — REQUIRES HUMAN REVIEW — v2026-08-08]

Operational runbook for the CapGuard quarantine-before-indexing store. CapGuard
is the fail-closed gate between an untrusted capability artifact entering the
system and that artifact becoming indexable/callable. Nothing is indexed
directly: every artifact lands in a per-customer quarantine container, is
scanned in place, and only an artifact with a recorded `passed` scan verdict is
promoted to the immutable post-scan container (`camber-caps` / `cire-caps`)
that the gateway serves from.

This runbook is the contract an on-call operator needs to inspect quarantine,
verify a scan verdict, promote a passed artifact, retain a failed one for
forensics, and confirm the fail-closed guarantee holds. It does not deploy;
provisioning is `services/client-mcp-gateway/infra/capguard-quarantine.bicep`
(wired from `cap-store.subscription.bicep`). See
`docs/capguard-persistent-store.md` for the architecture.

## 1. The flow

```
ingest ──► <account>/camber-quarantine        (alpha / Camber)
        │        artifact locked 7d (immutability)
        │
        ├─► scan (malware_scan.py + prompt_injection.py)
        │        verdict blob written to <account>/camber-scanstate
        │        (<quarantine_id>.json, locked 30d)
        │
        ├─ verdict == passed ──► promote ──► <capStore>/camber-caps   (post-scan, immutable)
        │                                       (promoter identity, fail-closed check)
        └─ verdict == failed ──► stays in quarantine (auto-deletable after 7d)
                                 operator MAY copy to camber-quarantine-failed (90d)
```

The same flow exists for CIRE under the `cire-*` containers, fully isolated by
identity and RBAC (section 4). An alpha Machine can never read or write a CIRE
container, and vice versa.

## 2. The persistent-store layout

Provisioned by `capguard-quarantine.bicep` (a storage account separate from the
post-scan `cap-store` account, on purpose — a compromise of the quarantine write
path never touches the post-scan containers):

| Container                       | Customer | Purpose                                  | Immutability |
|---------------------------------|----------|------------------------------------------|--------------|
| `camber-quarantine`             | alpha    | incoming unscanned artifacts              | 7 days       |
| `camber-scanstate`              | alpha    | immutable scan-verdict ledger (JSON blob) | 30 days      |
| `camber-quarantine-failed`      | alpha    | operator dead-letter for failed scans     | 90 days      |
| `cire-quarantine`               | beta     | incoming unscanned artifacts              | 7 days       |
| `cire-scanstate`                | beta     | immutable scan-verdict ledger (JSON blob) | 30 days      |
| `cire-quarantine-failed`        | beta     | operator dead-letter for failed scans     | 90 days      |

Immutability is per-blob, `allowProtectedAppendWrites=false`: each blob is
write-once then locked for the period. New blobs can still be written (the lock
does not block new writes), so ingest never blocks, but a written artifact or
verdict cannot be modified or deleted until the lock expires. The verdict ledger
is therefore tamper-evident by construction — a `passed` verdict cannot be
forged after the fact, which is what the fail-closed promotion check relies on.

The post-scan containers (`camber-caps` / `cire-caps`) live in the separate
`cap-store` storage account and are themselves immutable with a 30-day policy
and versioning (see `cap-store.bicep`). Promotion is a cross-account copy, not a
same-account move.

## 3. The scan verdict and the fail-closed gate

The scan a verdict records is the composition of the existing fail-closed
scanning surface already on disk in `client-capmesh/capmesh/`:

- `malware_scan.py` — `scan_capability()` runs `MALWARE_SIGNATURES` against the
  artifact body. A `critical` or `high` finding fails the scan
  (`passed = critical == 0 and high == 0`). Capped at `MAX_SCAN_SIZE_BYTES`
  (4 MiB); an oversize or missing body fails the scan rather than being skipped.
  Results are recorded in the local SQLite `malware_scan_results` table
  (`scan_capability` inserts a row with `scan_passed` and `findings_json`).
- `prompt_injection.py` — `scan_prompt_injection` runs the injection blocklist
  (resistant to zero-width/homoglyph obfuscation). `evaluate_prompt_injection_scan`
  wraps it with the `injection_allowlist.py` classifier.
- `injection_allowlist.py` — `classify_scan_result` / `should_block` downgrade
  benign authoring phrases (e.g. `system prompt` inside a `*-system-prompt` cap)
  to `allowed`/`info`, but a genuine injection indicator stays `block` regardless
  of name. The gate reads `should_block` (severity == `block`) as its single
  boolean.
- `install_policy.py` — the fail-closed admission layer. `assert_body_resolvable`
  refuses a capability whose body is outside every configured root or is
  missing; `assert_not_duplicate` refuses a second root for one capability. Both
  raise `InstallPolicyError` (a hard error, not a skip) — the measured 2026-07-31
  defect was exactly the silent variety.

The scan verdict blob in `<account>/<customer>-scanstate/<quarantine_id>.json`
records the composed outcome. A promotion is allowed only when the verdict's
top-level `passed` is `true` AND every gate that ran recorded `passed` (no
`failed`, no missing verdict). `CAPGUARD_FAIL_CLOSED=true` (default) makes an
ingest that cannot reach the scan-state ledger — missing ledger, network error,
expired token — FAIL rather than index. That is the whole guarantee: the
absence of a `passed` verdict is treated the same as a `failed` verdict.

The authoritative client-capmesh server records verdicts in its local SQLite
`malware_scan_results` table by default; setting `CAPGUARD_STORE=azure` mirrors
the immutable verdict ledger to the quarantine account so a non-authoritative
host can verify a `passed` verdict without trusting the remote catalog (see
`client-capmesh/.env.example`).

## 4. Identities and RBAC (Camber/CIRE isolation)

Isolation is enforced at three layers — container, identity, RBAC — mirroring
the model proven in `cap-store.bicep`.

| Identity (user-assigned MI)        | Customer | Granted by                          | Has                                                                                                     |
|-----------------------------------|----------|-------------------------------------|---------------------------------------------------------------------------------------------------------|
| `id-capguard-write-alpha`         | alpha    | capguard-quarantine.bicep           | Blob Data Contributor on `camber-quarantine` + `camber-scanstate`                                       |
| `id-capguard-write-beta`          | beta     | capguard-quarantine.bicep           | Blob Data Contributor on `cire-quarantine` + `cire-scanstate`                                            |
| `id-capguard-promote-alpha`       | alpha    | capguard-quarantine.bicep + cap-store.bicep | Blob Data Reader on `camber-quarantine` (here) + Blob Data Contributor on `camber-caps` (cap-store.bicep)  |
| `id-capguard-promote-beta`        | beta     | capguard-quarantine.bicep + cap-store.bicep | Blob Data Reader on `cire-quarantine` (here) + Blob Data Contributor on `cire-caps` (cap-store.bicep)      |
| operator (human Entra principal)  | both     | capguard-quarantine.bicep + cap-store.bicep | Contributor on each customer's `*-quarantine` + `*-quarantine-failed`; Contributor on `camber-caps`/`cire-caps` (cap-store.bicep) |

Each identity is federated to its own Fly Machine subject via a federated
identity credential (`fly-alpha-write`, `fly-beta-write`, `fly-alpha-promote`,
`fly-beta-promote`), audience `api://AzureADTokenExchange`, issuer
`https://oidc.fly.io/<your-org>`. The writer and promoter use
distinct subjects so the promote path is independently revocable: rotating the
promoter subject stops promotion without affecting ingest/scan, and vice versa.

Secretless: the Fly VM obtains a short-lived, machine-bound OIDC assertion from
its local Unix socket (`/.fly/api`) and exchanges it for a storage data-plane
token via Entra workload identity federation. No storage key, SAS, client
secret, or certificate is stored in the image, environment, database, or
filesystem — the same pattern `capmesh/remote_store.py` uses for the post-scan
mirror (`AzureMirrorConfig.from_env`, `CAPMESH_REMOTE_STORE=azure`).

## 5. Inspecting quarantine

All commands are read-only. Run from a host whose principal has at least Blob
Data Reader on the relevant containers (the operator principal, or any
identity above). Replace `<account>` with the quarantine storage account name
(output `quarantineStorageAccount` from the subscription deployment) and
`<customer>` with `camber` or `cire`.

```bash
# List artifacts currently in quarantine (alpha / Camber).
az storage blob list \
  --account-name <account> \
  --container-name camber-quarantine \
  --auth-mode login \
  --output table

# Read a scan verdict from the immutable ledger.
az storage blob download \
  --account-name <account> \
  --container-name camber-scanstate \
  --name <quarantine_id>.json \
  --auth-mode login \
  --file - | jq .
```

A verdict blob looks like:

```json
{
  "quarantineId": "qg_...",
  "capabilityUri": "cap://...",
  "fileHash": "sha256:...",
  "fileSize": 1234,
  "scannedAt": "2026-08-08T19:00:34Z",
  "passed": true,
  "gates": {
    "malwareScan": { "outcome": "passed", "criticalCount": 0, "highCount": 0 },
    "promptInjectionScan": { "outcome": "passed", "shouldBlock": false },
    "riskTierPolicy": { "outcome": "passed" }
  }
}
```

A `passed: false` or any `gates.*.outcome == "failed"` (or a missing verdict
blob under `CAPGUARD_FAIL_CLOSED=true`) blocks promotion.

## 6. Promoting a passed artifact

Automated promotion runs on the Fly VM using the promoter identity
(`CAPGUARD_PROMOTER_CLIENT_ID`) and the Fly OIDC token. The fail-closed check
verifies the `passed` verdict in scanstate before issuing the copy. This is the
normal path and needs no operator action.

Manual promotion (break-glass or first artifact) uses the operator's Azure CLI
login, which has Contributor on both `camber-quarantine` and `camber-caps`. Run
it ONLY after you have read the verdict blob and confirmed `passed: true` with
no `failed` gate. Replace `<capStoreAccount>` with the post-scan storage account
(output `storageAccount`).

```bash
# 1. CONFIRM the verdict first (do not skip).
az storage blob download \
  --account-name <account> --container-name camber-scanstate \
  --name <quarantine_id>.json --auth-mode login --file - | jq '.passed, .gates'

# 2. Copy the artifact from quarantine to the immutable post-scan container.
#    Same-account-source, cross-account-destination. The destination container's
#    immutability policy will lock the copied blob for 30 days.
az storage blob copy start \
  --source-account-name <account> \
  --source-container camber-quarantine \
  --source-blob <artifact-path> \
  --source-auth-mode login \
  --account-name <capStoreAccount> \
  --container-name camber-caps \
  --auth-mode login

# 3. Verify the copy landed and is locked.
az storage blob show \
  --account-name <capStoreAccount> --container-name camber-caps \
  --name <artifact-path> --auth-mode login \
  --query 'properties.{immutabilityPolicy: immutabilityPolicy.mode, contentMd5: contentMd5}'
```

Never `az storage blob delete` a quarantined artifact to "clean up" — the
immutability policy blocks it for 7 days, and that is the guarantee you are
relying on. Let the lock expire and GC collect it. If an artifact must be
retained past 7 days (e.g. a failed scan under investigation), copy it to the
dead-letter container (section 7) BEFORE its quarantine lock expires.

## 7. Retaining a failed artifact (dead-letter)

A failed-scan artifact stays in quarantine under its 7-day lock; it is never
promoted. To retain it past 7 days for forensics, an operator copies it to the
dead-letter container (`camber-quarantine-failed` / `cire-quarantine-failed`),
which has a 90-day immutability lock. The operator principal has Contributor on
the dead-letter container; the gateway write identity does NOT, so an automated
compromise cannot dead-letter arbitrary content.

```bash
az storage blob copy start \
  --source-account-name <account> \
  --source-container camber-quarantine \
  --source-blob <artifact-path> \
  --source-auth-mode login \
  --account-name <account> \
  --container-name camber-quarantine-failed \
  --auth-mode login
```

The failed verdict is already in `camber-scanstate` under a 30-day lock; the
dead-letter copy preserves the artifact body for the longer window.

## 8. Configuration

Gateway (`services/client-mcp-gateway/.env.example`):

| Variable                               | Meaning                                                              |
|----------------------------------------|----------------------------------------------------------------------|
| `CAPGUARD_STORE`                        | `azure` to enable; empty disables (pre-CapGuard direct ingest).      |
| `CAPGUARD_QUARANTINE_ACCOUNT`           | Quarantine storage account name.                                    |
| `CAPGUARD_QUARANTINE_CONTAINER`         | Per-deployment: `camber-quarantine` or `cire-quarantine`.           |
| `CAPGUARD_SCANSTATE_CONTAINER`          | Per-deployment: `camber-scanstate` or `cire-scanstate`.              |
| `CAPGUARD_FAILED_CONTAINER`            | Per-deployment: `camber-quarantine-failed` or `cire-quarantine-failed`. |
| `CAPGUARD_WRITER_CLIENT_ID`             | Writer identity (ingest + scan) client ID for the token exchange.    |
| `CAPGUARD_PROMOTER_CLIENT_ID`           | Promoter identity client ID for the token exchange.                  |
| `CAPGUARD_FAIL_CLOSED`                  | `true` (default): no `passed` verdict ⇒ no promotion, ingest fails closed. |
| `CAPGUARD_QUARANTINE_IMMUTABILITY_DAYS` | Mirror of the bicep `quarantineImmutabilityDays` (default 7).       |
| `CAPGUARD_SCANSTATE_IMMUTABILITY_DAYS`  | Mirror of `scanstateImmutabilityDays` (default 30).                  |
| `CAPGUARD_FAILED_IMMUTABILITY_DAYS`     | Mirror of `deadLetterImmutabilityDays` (default 90).                |

Authoritative server (`client-capmesh/.env.example`): `CAPGUARD_STORE`,
`CAPGUARD_QUARANTINE_ACCOUNT`, `CAPGUARD_SCANSTATE_CONTAINER`,
`CAPGUARD_WRITER_CLIENT_ID`, `CAPGUARD_FAIL_CLOSED`. The authoritative side
defaults to the local SQLite `malware_scan_results` table; the Azure mirror is
opt-in for cross-host verdict verification.

## 9. Operational checklist

1. **Confirm the quarantine account exists and is isolated.**
   ```bash
   az storage account show --name <account> --query '{allowBlobPublicAccess: allowBlobPublicAccess, allowSharedKeyAccess: allowSharedKeyAccess, minimumTlsVersion: minimumTlsVersion}'
   # Expect: allowBlobPublicAccess=false, allowSharedKeyAccess=false, minimumTlsVersion=TLS1_2
   ```

2. **Confirm the post-scan containers are untouched by the quarantine write identity.**
   The `id-capguard-write-*` identity has NO role assignment on `camber-caps` /
   `cire-caps`. Verify no unexpected role assignments exist:
   ```bash
   az role assignment list \
     --scope "<camber-caps container resource id>" \
     --query "[].{principal:principalName, role:roleDefinitionName}"
   ```

3. **Confirm a failed scan is not promotable.** Inject a test artifact that
   matches a `MALWARE_SIGNATURES` critical pattern (e.g. an `eval(base64...)`
   call) into `camber-quarantine`, run the scan, and verify the scanstate
   verdict has `passed: false`. Then attempt the promotion and confirm it is
   refused by the fail-closed check. (Test-only; do not promote the artifact.)

4. **Confirm fail-closed on a missing ledger.** With `CAPGUARD_FAIL_CLOSED=true`,
   delete (or make unreachable) the scanstate verdict for a quarantined artifact
   and confirm the ingest/promote path refuses rather than indexing. The
   immutability policy will prevent real deletion for 30 days, so simulate this
   in a non-production storage account.

5. **Confirm Camber/CIRE isolation.** From the alpha Machine, attempt to read
   `cire-quarantine` using the alpha writer identity token; expect a 403. From
   the beta Machine, attempt to read `camber-quarantine`; expect a 403. Each
   identity's role assignments are scoped to its own customer's containers.

## 10. Known limits

- **Immutability is per-blob, not per-container.** A new artifact can always be
  written to a quarantine container; the lock only protects already-written
  blobs. Quarantine GC must rely on the per-blob expiry, not on container-level
  emptiness.
- **The verdict ledger is append-only by policy, not by schema.** A second
  verdict blob with the same `<quarantine_id>.json` name would be blocked by the
  container immutability lock (write-once), so the name MUST be the quarantine id
  and MUST be written exactly once. The scan code is responsible for never
  rewriting a verdict.
- **Cross-account promotion is a copy, not a move.** The source artifact remains
  in quarantine under its 7-day lock after promotion. This is intentional (the
  artifact and its verdict stay correlated and tamper-evident) but means
  promotion does not free quarantine space immediately.
- **Operator promotion bypasses the automated fail-closed check.** The manual
  path in section 6 trusts the operator to read the verdict before copying.
  Prefer the automated promoter path; use manual promotion only for break-glass
  or first-artifact bootstrap, and record the reason in the audit log.

## Source references

- `services/client-mcp-gateway/infra/capguard-quarantine.bicep` — quarantine
  account, containers, immutability policies, identities, RBAC.
- `services/client-mcp-gateway/infra/cap-store.bicep` — post-scan
  `camber-caps`/`cire-caps` containers and the optional promotion role
  assignments (`promoteAlphaPrincipalId` / `promoteBetaPrincipalId`).
- `services/client-mcp-gateway/infra/cap-store.subscription.bicep` — wires the
  quarantine module and threads promoter principal IDs into the post-scan store.
- `services/client-mcp-gateway/capmesh/remote_store.py` — secretless Fly
  OIDC → Entra token exchange pattern (`AzureMirrorConfig.from_env`).
- `client-capmesh/capmesh/malware_scan.py` — `scan_capability`,
  `MALWARE_SIGNATURES`, `MAX_SCAN_SIZE_BYTES`, `malware_scan_results` table.
- `client-capmesh/capmesh/prompt_injection.py` — `scan_prompt_injection`,
  `evaluate_prompt_injection_scan`.
- `client-capmesh/capmesh/injection_allowlist.py` — `classify_scan_result`,
  `should_block`, `SEVERITY_BLOCK`/`INFO`/`ALLOWED`.
- `client-capmesh/capmesh/install_policy.py` — `InstallPolicyError`,
  `assert_body_resolvable`, `assert_not_duplicate` (fail-closed admission).
- `client-capmesh/docs/runbooks/observability-scrape.md` — the
  `capmesh_gate_*` gate-counter surface that records per-gate pass/fail/skipped.
