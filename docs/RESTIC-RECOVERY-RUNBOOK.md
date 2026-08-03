Entity: MRI
Scope: MRI
[CONFIDENTIAL]
[DRAFT — REQUIRES HUMAN REVIEW — v2026-07-18]

# Authoritative node Restic Recovery Runbook

## Safety boundary

The live `CAPMESH_STATE_DIR (env)` tree is never a Restic restore target. Preserve the live DB,
WAL/SHM, release pointer, environment, units, audits, and journals before recovery. Code always
comes from a pinned repository release; Restic supplies state for comparison or last-resort DB
recovery.

The helper fixes `PATH` to include `/usr/local/bin/restic`, parses an allowlist from the root-owned
non-symlink `/etc/restic/*.env` file without shell execution, does not print credentials, and
canonicalizes restore targets below `/var/tmp/capmesh-restic-recovery`. Repository checks take the
normal Restic lock; coordinate them with backup timers.

## Quarterly drill

```bash
sudo CAPMESH_STATE_DIR (env)/restic-recovery-drill.sh inventory
sudo CAPMESH_RESTIC_CHECK_SUBSET=5% CAPMESH_STATE_DIR (env)/restic-recovery-drill.sh check
sudo CAPMESH_RESTIC_SNAPSHOT=<short-id> CAPMESH_STATE_DIR (env)/restic-recovery-drill.sh stage-restore
```

Record the short snapshot ID, timestamp, host, captured paths, check output, staged DB counts,
integrity result, elapsed seconds, and operator. The selected snapshot must contain exactly one
Capmesh DB and its captured path must cover the authoritative state tree. Do not run `unlock`,
`forget`, `prune`, `repair`, or `mount` during a drill.

## Recovery decision

1. If live SQLite integrity, catalog readiness, and generation parity pass, retain live state and
   use the staged snapshot only for comparison.
2. If live state is corrupt or below the healthy floor, validate the staged DB with full
   `integrity_check`, schema compatibility, source/capability counts, governance rows, and critical
   retrieval canaries.
3. Take a fresh native `.backup` and preserve incident evidence.
4. Promote only through the shadow-DB atomic-swap procedure in `selfheal-reingest.sh`; never copy
   restored files directly into the live path.
5. Roll back to the pre-swap DB if readiness fails.

Acceptance targets are RPO at most one hour and RTO at most 15 minutes. A drill that exceeds either
target, lacks required paths, or cannot pass full repository integrity is a failed reliability gate.

Current inventory on 2026-07-18 found Restic 0.16.4 at `/usr/local/bin/restic`, dedicated backup and
check timers, and `/etc/restic/backup.env`. Upgrade is a separate reviewed change after a successful
restore drill; never combine a backup-tool upgrade with an incident restore.
