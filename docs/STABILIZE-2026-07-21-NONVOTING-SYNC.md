Entity: ASG
Scope: Capability Mesh non-voting member synchronization
[CONFIDENTIAL]
[DRAFT — REQUIRES HUMAN REVIEW — v2026-07-21]

# Non-Voting Sync Stabilization Note

On 2026-07-21, `ops/sync-nonvoting-member.sh` passed `bash -n`. Review confirmed
that remote SQLite snapshots use an expanded, quoted `.backup` destination. Stale-lock
recovery now requires a verified numeric mtime, removes only an empty stale lock directory,
and is covered by the self-contained `ops/tests/test-sync-nonvoting-lock.sh` regression test.
