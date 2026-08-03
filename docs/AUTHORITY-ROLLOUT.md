# CapMesh receipt-authority rollout

This sequence promotes cpubox as the sole signer for
`capmesh_bundle_receipt.v1` and mutation-authoritative
`capmesh.report.receipt.v1` workflow evidence. Both use the same pinned
authority key with distinct domain separators. The Ed25519 private key is created once under
`/secure/asg-capmesh/authority` and never leaves cpubox.

## Ordered rollout

1. Deploy the accepted asg-os ref with `ops/deploy-capmesh.sh --host primary`.
   Before the first new worker is restarted, the deployer runs
   `ops/bootstrap-authority-trust.sh` as `jason`. It verifies mode `0600` on the
   private key, mode `0644` on public material, and proves that the public
   export contains no private-key filename.
2. Copy only these three files from
   `/secure/asg-capmesh/authority-client-export` through the audited
   configuration channel: `capmesh-authority-ed25519.pub.pem`,
   `capmesh-authority-trust.v1.json`, and `expected-key-id.txt`. Never copy
   `/secure/asg-capmesh/authority`.
3. Install the PEM and pin on each consumer with the accepted ASGCode release
   or `scripts/sync-portable-agent-stack.sh`. Installation checks the exact
   key id and PEM digest and refuses an unceremonied replacement.
4. Refresh the ASGCode orchestrator and MCP gateway through their managed
   release/service controls. Drain existing work before restart; do not kill
   shells or processes by name. A consumer fails closed until both public
   files are present.
5. Run the positive and negative gates below. Do not enable automatic routing
   until every gate passes on both the workstation and cpubox.

## Positive end-to-end gate

On the workstation, run broad `cap.search(k=20)` with no allowlist, load the
selected 2–4-capability bundle, and submit a bounded read-only durable workflow.
Accepted evidence contains, in order: local search/load results; cpubox
`cap.delegate` with a current receipt bound to task, workflow, bundle, and
binding hashes; Worker/Director evidence; cpubox `cap.report` accepting the
canonical outcome once; and GLM review plus deterministic verification.
The report receipt is additionally bound to repository, worktree, base commit,
upstream delegation, exact outcome digest/status, provenance, expiry, and a
unique nonce. SQLite uniqueness on delegated task, report id, and nonce makes
concurrent replay fail closed before a second authoritative audit row commits.

Repeat search/load directly on cpubox against its active immutable release.
Compare capability URIs and digests, not filesystem paths. Delegate/report
audit events must identify cpubox as authority.

## Negative gates

Run ASGCode admission tests that mutate a valid signature, expire an otherwise
valid receipt, substitute an unknown key id, and alter bundle/binding hashes.
Every case must fail before workflow execution. Also run CapMesh authority
tests for a stale rotation ceremony, mismatched PEM/pin, insecure modes,
symlink sources, attempted replay, report/workflow binding substitution, and
attempted key generation on a non-authoritative node. Legacy titration report
receipts are signed and explicitly marked `advisory-audit-only`; their extra
field and missing workflow bindings make them non-canonical for mutation.

Do not send intentionally bad receipts to production; deterministic consumer
tests exercise the same verifier without polluting the authority audit log.

## Rollback

Code, workers, gateway, and consumers roll back independently. The authority
key does not roll back or rotate with software. Restore previous immutable code
while retaining the authority directory and public pin. Rotation requires the
operator-signed ceremony; never generate a replacement as a repair action.
