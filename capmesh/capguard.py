"""CapGuard: tenant quarantine store and signed attestations.

CapGuard holds newly-discovered (or re-scanned) capabilities in a per-tenant
*quarantine store* BEFORE they are indexed into the live catalog, and binds each
release decision to a signed Ed25519 attestation.  Release is **fail-closed**:
a capability is promoted out of quarantine only when a valid ``scan`` attestation
with verdict ``clean`` exists for the quarantine item's exact ``content_hash``,
the signature verifies against the trusted signing anchor, and no later ``scan``
attestation with verdict ``blocked`` supersedes it.  Any missing or invalid
evidence refuses the release and leaves the capability quarantined.

This module is the authoritative-side (client-capmesh) implementation.  It reuses
the existing Ed25519 trust anchor in :mod:`capmesh.signing` (``sign_attestation`` /
``verify_attestation``) and the :func:`capmesh.governance.audit_event` log, so
quarantine decisions are independently auditable alongside other capability
governance events.

Design rules (workflow contract: quarantine-before-indexing, fail-closed
scanning, model-agnostic runtime enforcement):

* Quarantine is a *store*, not a flag on the live ``capabilities`` row.  A
  capability is quarantined before it is ever written to ``capabilities``.
* The signed attestation envelope binds ``quarantineId`` + ``capabilityUri`` +
  ``contentHash`` + ``tenantId`` + verdict, so a release attestation cannot be
  replayed against different content (e.g. after the source file is swapped).
* ``release_from_quarantine`` never silently degrades: it raises
  :class:`QuarantineReleaseBlocked` on every gap, including signature failure,
  key mismatch, content drift, or a superseding blocked scan.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .signing import sign_attestation, trusted_signing_key_id, verify_attestation
from .utils import DEFAULT_TENANT, json_dumps, json_loads, new_id, utc_now

# ---------------------------------------------------------------------------
# Status / verdict vocabulary (kept small and explicit so checks are exact).
# ---------------------------------------------------------------------------

QUARANTINE_STATUSES = ("quarantined", "released", "rejected", "superseded")
QUARANTINE_REASONS = ("pending_scan", "scan_failed", "manual_hold", "resubmitted")
ATTESTATION_TYPES = ("scan", "release", "reject")
SCAN_VERDICTS = ("clean", "blocked", "error")

# Blocking severities — a scan that produced any of these can never yield a
# ``clean`` verdict and therefore can never authorize a release.
BLOCKING_SEVERITIES = {"critical", "high"}


class CapGuardError(Exception):
    """Base class for CapGuard quarantine / attestation failures."""


class QuarantineError(CapGuardError):
    """The quarantine item was not found, is in the wrong tenant, or is in the
    wrong lifecycle state for the requested operation."""


class QuarantineReleaseBlocked(CapGuardError):
    """Fail-closed refusal to release a quarantined capability.

    Raised by :func:`release_from_quarantine` when the attestation chain is
    missing, invalid, mismatched, or superseded.  The capability remains in
    quarantine with ``status='quarantined'``; the caller must remediate and
    re-scan rather than bypass the gate.
    """


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def ensure_quarantine_tables(con: sqlite3.Connection) -> None:
    """Create the CapGuard tables if they do not exist.  Idempotent.

    Called both from :func:`capmesh.index.init_db` (so a fresh DB always has the
    quarantine store) and from migration v3 (so existing DBs upgrade in place).
    """
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS capguard_quarantine (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            capability_uri TEXT NOT NULL,
            capability_type TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            source_path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT 'pending_scan',
            status TEXT NOT NULL DEFAULT 'quarantined'
                CHECK(status IN ('quarantined','released','rejected','superseded')),
            submitted_by TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            released_at TEXT,
            rejected_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_capguard_quarantine_tenant
            ON capguard_quarantine(tenant_id, status);
        CREATE INDEX IF NOT EXISTS idx_capguard_quarantine_uri
            ON capguard_quarantine(tenant_id, capability_uri);
        -- One active quarantine per (tenant, capability, content).  A changed
        -- content_hash (new version / edited source) is allowed to open a fresh
        -- quarantine row; the same content re-quarantined is idempotent.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_capguard_quarantine_active
            ON capguard_quarantine(tenant_id, capability_uri, content_hash)
            WHERE status = 'quarantined';

        CREATE TABLE IF NOT EXISTS capguard_attestations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            quarantine_id TEXT NOT NULL
                REFERENCES capguard_quarantine(id) ON DELETE CASCADE,
            attestation_type TEXT NOT NULL
                CHECK(attestation_type IN ('scan','release','reject')),
            subject_uri TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            verdict TEXT,
            scanner_id TEXT,
            scanner_version TEXT,
            findings_summary_json TEXT NOT NULL DEFAULT '{}',
            algorithm TEXT NOT NULL DEFAULT 'Ed25519',
            key_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            signature TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            verifies INTEGER NOT NULL DEFAULT 0,
            actor TEXT,
            reason TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_capguard_attestations_quarantine
            ON capguard_attestations(tenant_id, quarantine_id, attestation_type, created_at);
        CREATE INDEX IF NOT EXISTS idx_capguard_attestations_key
            ON capguard_attestations(key_id);
        """
    )


# ---------------------------------------------------------------------------
# Record serializers (camelCase API surface, matching stores.py)
# ---------------------------------------------------------------------------

def quarantine_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "capabilityUri": row["capability_uri"],
        "capabilityType": row["capability_type"],
        "name": row["name"],
        "version": row["version"],
        "sourcePath": row["source_path"],
        "contentHash": row["content_hash"],
        "reason": row["reason"],
        "status": row["status"],
        "submittedBy": row["submitted_by"],
        "metadata": json_loads(row["metadata_json"], {}),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "releasedAt": row["released_at"],
        "rejectedAt": row["rejected_at"],
    }


def attestation_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "quarantineId": row["quarantine_id"],
        "attestationType": row["attestation_type"],
        "subjectUri": row["subject_uri"],
        "contentHash": row["content_hash"],
        "verdict": row["verdict"],
        "scannerId": row["scanner_id"],
        "scannerVersion": row["scanner_version"],
        "findingsSummary": json_loads(row["findings_summary_json"], {}),
        "algorithm": row["algorithm"],
        "keyId": row["key_id"],
        "publicKey": row["public_key"],
        "signature": row["signature"],
        "envelope": json_loads(row["envelope_json"], {}),
        "verifies": bool(row["verifies"]),
        "actor": row["actor"],
        "reason": row["reason"],
        "createdAt": row["created_at"],
    }


# ---------------------------------------------------------------------------
# Quarantine store
# ---------------------------------------------------------------------------

def quarantine_capability(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    capability_uri: str,
    capability_type: str,
    name: str,
    version: str,
    source_path: str,
    content_hash: str,
    reason: str = "pending_scan",
    submitted_by: str | None = None,
    metadata: dict[str, Any] | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    """Place a capability into the tenant quarantine store before indexing.

    Idempotent for the same ``(tenant, uri, content_hash)`` while the prior row
    is still ``quarantined``: re-quarantining identical content returns the
    existing row rather than violating the active-quarantine unique index.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    if not capability_uri or not content_hash:
        raise QuarantineError("capabilityUri and contentHash are required.")
    if reason not in QUARANTINE_REASONS:
        raise QuarantineError(f"Unsupported quarantine reason: {reason!r}")

    existing = con.execute(
        """
        SELECT * FROM capguard_quarantine
        WHERE tenant_id = ? AND capability_uri = ? AND content_hash = ? AND status = 'quarantined'
        """,
        (tenant, capability_uri, content_hash),
    ).fetchone()
    if existing is not None:
        return quarantine_record(existing)

    quarantine_id = new_id("qtn")
    con.execute(
        """
        INSERT INTO capguard_quarantine(
            id, tenant_id, capability_uri, capability_type, name, version,
            source_path, content_hash, reason, status, submitted_by, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'quarantined', ?, ?)
        """,
        (
            quarantine_id,
            tenant,
            capability_uri,
            capability_type,
            name,
            version,
            source_path,
            content_hash,
            reason,
            submitted_by,
            json_dumps(metadata or {}),
        ),
    )
    _audit(con, event_type="capguard.quarantined", actor=submitted_by or "system",
           target=quarantine_id, action="quarantine", decision="allow",
           payload={"capabilityUri": capability_uri, "contentHash": content_hash,
                    "reason": reason}, tenant_id=tenant)
    if commit:
        con.commit()
    return quarantine_record(
        con.execute("SELECT * FROM capguard_quarantine WHERE id = ?", (quarantine_id,)).fetchone()
    )


def get_quarantine(
    con: sqlite3.Connection, quarantine_id: str, *, tenant_id: str
) -> dict[str, Any] | None:
    """Fetch a single quarantine row, scoped to *tenant_id*.  Returns ``None``
    if the id does not exist in that tenant (tenant isolation)."""
    ensure_quarantine_tables(con)
    row = con.execute(
        "SELECT * FROM capguard_quarantine WHERE id = ? AND tenant_id = ?",
        (quarantine_id, tenant_id or DEFAULT_TENANT),
    ).fetchone()
    return quarantine_record(row) if row is not None else None


def list_quarantine(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List quarantine rows for a tenant, optionally filtered by status."""
    ensure_quarantine_tables(con)
    if status is not None and status not in QUARANTINE_STATUSES:
        raise QuarantineError(f"Unsupported quarantine status: {status!r}")
    params: list[Any] = [tenant_id or DEFAULT_TENANT]
    where = "tenant_id = ?"
    if status:
        where += " AND status = ?"
        params.append(status)
    params.append(min(max(int(limit), 1), 500))
    rows = con.execute(
        f"SELECT * FROM capguard_quarantine WHERE {where} ORDER BY created_at DESC LIMIT ?",
        tuple(params),
    ).fetchall()
    return [quarantine_record(row) for row in rows]


# ---------------------------------------------------------------------------
# Attestations
# ---------------------------------------------------------------------------

def _verdict_for_scan(scan_result: dict[str, Any]) -> str:
    """Derive a scan verdict from a malware/dependency scan result dict.

    ``error`` -> the scan could not be completed (fail-closed: not clean).
    ``blocked`` -> the scan completed and found blocking severities.
    ``clean`` -> the scan completed with no blocking findings.
    """
    if scan_result.get("error"):
        return "error"
    findings = scan_result.get("findings") or []
    if any(str(f.get("severity", "")).lower() in BLOCKING_SEVERITIES for f in findings if isinstance(f, dict)):
        return "blocked"
    if scan_result.get("criticalCount") or scan_result.get("highCount"):
        return "blocked"
    if scan_result.get("passed") is False:
        return "blocked"
    return "clean"


def _findings_summary(scan_result: dict[str, Any]) -> dict[str, Any]:
    findings = scan_result.get("findings") or []
    return {
        "passed": bool(scan_result.get("passed", False)),
        "criticalCount": int(scan_result.get("criticalCount", 0)),
        "highCount": int(scan_result.get("highCount", 0)),
        "findingCount": len(findings) if isinstance(findings, list) else 0,
        "error": scan_result.get("error"),
    }


def _build_envelope(
    *,
    attestation_type: str,
    quarantine_id: str,
    capability_uri: str,
    content_hash: str,
    tenant_id: str,
    verdict: str | None,
    scanner_id: str | None,
    scanner_version: str | None,
    findings_summary: dict[str, Any],
    actor: str | None,
    reason: str | None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "schema": "capguard.attestation.v1",
        "type": attestation_type,
        "quarantineId": quarantine_id,
        "capabilityUri": capability_uri,
        "contentHash": content_hash,
        "tenantId": tenant_id,
        "issuedAt": utc_now(),
    }
    if attestation_type == "scan":
        envelope["scannerId"] = scanner_id or "capmesh-malware_scan"
        envelope["scannerVersion"] = scanner_version or "unknown"
        envelope["verdict"] = verdict
        envelope["findingsSummary"] = findings_summary
    else:
        envelope["actor"] = actor
        envelope["reason"] = reason
    return envelope


def _store_attestation(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    quarantine_id: str,
    attestation_type: str,
    subject_uri: str,
    content_hash: str,
    signed: dict[str, Any],
    envelope: dict[str, Any],
    verdict: str | None,
    scanner_id: str | None,
    scanner_version: str | None,
    findings_summary: dict[str, Any],
    actor: str | None,
    reason: str | None,
    commit: bool,
) -> dict[str, Any]:
    attestation_id = new_id("att")
    verifies = 1 if verify_attestation(signed) else 0
    con.execute(
        """
        INSERT INTO capguard_attestations(
            id, tenant_id, quarantine_id, attestation_type, subject_uri, content_hash,
            verdict, scanner_id, scanner_version, findings_summary_json,
            algorithm, key_id, public_key, signature, envelope_json, verifies,
            actor, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            attestation_id,
            tenant_id,
            quarantine_id,
            attestation_type,
            subject_uri,
            content_hash,
            verdict,
            scanner_id,
            scanner_version,
            json_dumps(findings_summary),
            signed.get("algorithm", "Ed25519"),
            signed.get("keyId"),
            signed.get("publicKey"),
            signed.get("signature"),
            json_dumps(signed.get("envelope", envelope)),
            verifies,
            actor,
            reason,
        ),
    )
    row = con.execute("SELECT * FROM capguard_attestations WHERE id = ?", (attestation_id,)).fetchone()
    if commit:
        con.commit()
    return attestation_record(row)


def issue_scan_attestation(
    con: sqlite3.Connection,
    quarantine_id: str,
    *,
    tenant_id: str,
    scan_result: dict[str, Any],
    scanner_id: str = "capmesh-malware_scan",
    scanner_version: str | None = None,
    persist: bool = True,
    commit: bool = True,
) -> dict[str, Any]:
    """Sign and store a ``scan`` attestation for a quarantined capability.

    The attestation binds the scan verdict to the quarantine item's exact
    ``content_hash``.  A ``clean`` verdict is the precondition for release; a
    ``blocked`` or ``error`` verdict keeps the capability quarantined and, when
    issued after a prior ``clean`` scan, supersedes it so a re-scan that finds
    new blocking findings cannot be bypassed with stale clean evidence.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    record = get_quarantine(con, quarantine_id, tenant_id=tenant)
    if record is None:
        raise QuarantineError(f"Quarantine item not found: {quarantine_id}")
    if record["status"] != "quarantined":
        raise QuarantineError(
            f"Cannot scan a quarantine item in status {record['status']!r}."
        )
    verdict = _verdict_for_scan(scan_result)
    findings_summary = _findings_summary(scan_result)
    envelope = _build_envelope(
        attestation_type="scan", quarantine_id=quarantine_id,
        capability_uri=record["capabilityUri"], content_hash=record["contentHash"],
        tenant_id=tenant, verdict=verdict, scanner_id=scanner_id,
        scanner_version=scanner_version, findings_summary=findings_summary,
        actor=None, reason=None,
    )
    signed = sign_attestation(envelope, persist=persist)
    stored = _store_attestation(
        con, tenant_id=tenant, quarantine_id=quarantine_id, attestation_type="scan",
        subject_uri=record["capabilityUri"], content_hash=record["contentHash"],
        signed=signed, envelope=envelope, verdict=verdict, scanner_id=scanner_id,
        scanner_version=scanner_version, findings_summary=findings_summary,
        actor=None, reason=None, commit=commit,
    )
    # A blocking verdict supersedes any prior clean scan: mark the quarantine
    # reason so operators see the most recent scan outcome at a glance.
    if verdict == "blocked":
        con.execute(
            "UPDATE capguard_quarantine SET reason = 'scan_failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (quarantine_id,),
        )
        if commit:
            con.commit()
    _audit(con, event_type="capguard.scan.attested", actor=scanner_id,
           target=quarantine_id, action="scan", decision="allow",
           payload={"verdict": verdict, "scannerVersion": scanner_version}, tenant_id=tenant)
    return stored


def verify_attestation_record(
    con: sqlite3.Connection, attestation_id: str, *, trusted_key_id: str | None = None
) -> bool:
    """Re-verify a stored attestation by reconstructing it from its stored
    envelope + signature + public key.  Returns ``True`` only if the embedded
    signature is valid against the embedded public key (and matches
    *trusted_key_id* when provided)."""
    ensure_quarantine_tables(con)
    row = con.execute("SELECT * FROM capguard_attestations WHERE id = ?", (attestation_id,)).fetchone()
    if row is None:
        return False
    signed = {
        "algorithm": row["algorithm"],
        "keyId": row["key_id"],
        "publicKey": row["public_key"],
        "signature": row["signature"],
        "envelope": json_loads(row["envelope_json"], {}),
    }
    return bool(verify_attestation(signed, trusted_key_id=trusted_key_id))


def scan_clean_attestation(
    con: sqlite3.Connection, quarantine_id: str, *, tenant_id: str, trusted_key_id: str | None = None
) -> dict[str, Any] | None:
    """Return the latest valid ``scan`` attestation with verdict ``clean`` for a
    quarantine item, or ``None``.  ``valid`` means: signature verifies against
    the embedded key (and *trusted_key_id* when provided) AND the attestation's
    ``content_hash`` matches the quarantine row's current ``content_hash``.

    This is the core fail-closed primitive: stale clean evidence (signed over
    different content) is rejected.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    record = get_quarantine(con, quarantine_id, tenant_id=tenant)
    if record is None:
        return None
    rows = con.execute(
        """
        SELECT * FROM capguard_attestations
        WHERE tenant_id = ? AND quarantine_id = ? AND attestation_type = 'scan'
        ORDER BY rowid DESC
        """,
        (tenant, quarantine_id),
    ).fetchall()
    for row in rows:
        if row["content_hash"] != record["contentHash"]:
            continue
        if not verify_attestation_record(con, row["id"], trusted_key_id=trusted_key_id):
            continue
        if row["verdict"] == "clean":
            return attestation_record(row)
        # The most recent valid scan is not clean — do not return older clean
        # evidence; a blocking re-scan supersedes it.
        return None
    return None


def attestation_chain_valid(
    con: sqlite3.Connection, quarantine_id: str, *, tenant_id: str, trusted_key_id: str | None = None
) -> bool:
    """Fail-closed gate.  Returns ``True`` iff ALL of:

    * a valid ``scan`` attestation with verdict ``clean`` exists,
    * its signature verifies against the trusted signing anchor,
    * its ``content_hash`` matches the quarantine row's current content,
    * and no later valid ``scan`` attestation with verdict ``blocked``
      supersedes it.
    """
    return scan_clean_attestation(
        con, quarantine_id, tenant_id=tenant_id, trusted_key_id=trusted_key_id
    ) is not None


def evaluate_release_policy(
    capability: Any,
    scan_result: dict[str, Any] | None = None,
    *,
    injection_result: bool | None = None,
    policy: Any | None = None,
) -> Any:
    """Bridge the model-agnostic runtime policy into the release path.

    Returns the :class:`capmesh.cap_guard.CapGuardVerdict` for *capability*.
    The store's release path calls this when a caller supplies a ``Capability``
    so a ``deny``/``quarantine`` verdict blocks the promotion in addition to
    the scan-attestation chain check. The policy import is lazy so the store
    remains importable without the authority's ``Capability`` model on a
    minimal/client install.
    """
    from .cap_guard import CapGuardPolicy, evaluate_cap_guard_policy
    return evaluate_cap_guard_policy(
        capability,
        scan_result,
        policy=policy or CapGuardPolicy(),
        injection_result=injection_result,
    )


def release_from_quarantine(
    con: sqlite3.Connection,
    quarantine_id: str,
    *,
    tenant_id: str,
    actor: str,
    reason: str = "scan_clean",
    trusted_key_id: str | None = None,
    capability: Any | None = None,
    scan_result: dict[str, Any] | None = None,
    injection_result: bool | None = None,
    policy: Any | None = None,
    persist: bool = True,
    commit: bool = True,
) -> dict[str, Any]:
    """Fail-closed release of a quarantined capability.

    Promotes the quarantine item to ``status='released'`` ONLY when
    :func:`attestation_chain_valid` is ``True`` AND, when a ``capability`` is
    supplied, the model-agnostic runtime policy
    (:func:`evaluate_release_policy`) returns an ``allow`` verdict.  On any gap
    the capability remains ``quarantined`` and :class:`QuarantineReleaseBlocked`
    is raised.  A signed ``release`` attestation recording the actor + reason
    is always issued on success.

    The ``capability`` / ``scan_result`` / ``injection_result`` / ``policy``
    arguments are optional so the store can release on attestation evidence
    alone (the client side, which has no authority ``Capability``), while the
    authoritative server can supply them to enforce Camber/CIRE isolation and
    the signature/provenance/injection/risk-tier checks before promotion.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    record = get_quarantine(con, quarantine_id, tenant_id=tenant)
    if record is None:
        raise QuarantineError(f"Quarantine item not found: {quarantine_id}")
    if record["status"] != "quarantined":
        raise QuarantineError(
            f"Cannot release a quarantine item in status {record['status']!r}."
        )

    # Resolve the trusted anchor once: callers may pass an explicit key id
    # (e.g. during key rotation), otherwise use the configured signing key.
    resolved_trust = trusted_key_id
    if resolved_trust is None:
        try:
            resolved_trust = trusted_signing_key_id()
        except Exception:  # noqa: BLE001
            # No usable trust anchor -> fail closed.
            resolved_trust = None

    clean = scan_clean_attestation(
        con, quarantine_id, tenant_id=tenant, trusted_key_id=resolved_trust
    )
    if clean is None:
        raise QuarantineReleaseBlocked(
            "Release refused: no valid clean scan attestation for the current content_hash "
            f"(quarantine={quarantine_id}, tenant={tenant})."
        )

    # Model-agnostic runtime policy gate (Camber/CIRE isolation, signature,
    # provenance, prompt-injection, risk-tier). Only enforced when the caller
    # supplies a Capability — the authoritative server path. The client path
    # (no authority Capability) releases on attestation evidence alone, which
    # is fail-closed by construction via scan_clean_attestation above.
    policy_verdict: dict[str, Any] | None = None
    if capability is not None:
        verdict = evaluate_release_policy(
            capability, scan_result=scan_result, injection_result=injection_result,
            policy=policy,
        )
        policy_verdict = verdict.to_dict()
        if verdict.action != "allow":
            raise QuarantineReleaseBlocked(
                f"Release refused: runtime policy verdict {verdict.action!r} for "
                f"{getattr(capability, 'uri', record['capabilityUri'])!r}: {verdict.reason}"
            )

    envelope = _build_envelope(
        attestation_type="release", quarantine_id=quarantine_id,
        capability_uri=record["capabilityUri"], content_hash=record["contentHash"],
        tenant_id=tenant, verdict=None, scanner_id=None, scanner_version=None,
        findings_summary={}, actor=actor, reason=reason,
    )
    signed = sign_attestation(envelope, persist=persist)
    _store_attestation(
        con, tenant_id=tenant, quarantine_id=quarantine_id, attestation_type="release",
        subject_uri=record["capabilityUri"], content_hash=record["contentHash"],
        signed=signed, envelope=envelope, verdict=None, scanner_id=None,
        scanner_version=None, findings_summary={}, actor=actor, reason=reason,
        commit=False,
    )
    con.execute(
        """
        UPDATE capguard_quarantine
        SET status = 'released', released_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (quarantine_id,),
    )
    con.execute(
        """UPDATE capabilities
           SET lifecycle = 'active', approval_state = 'published', updated_at = CURRENT_TIMESTAMP
           WHERE tenant_id = ? AND uri = ? AND content_hash = ?""",
        (tenant, record["capabilityUri"], record["contentHash"]),
    )
    release_payload: dict[str, Any] = {
        "capabilityUri": record["capabilityUri"], "reason": reason,
        "scanAttestation": clean["id"],
    }
    if policy_verdict is not None:
        release_payload["policyVerdict"] = policy_verdict
    _audit(con, event_type="capguard.released", actor=actor, target=quarantine_id,
           action="release", decision="allow",
           payload=release_payload, tenant_id=tenant)
    if commit:
        con.commit()
    return quarantine_record(
        con.execute("SELECT * FROM capguard_quarantine WHERE id = ?", (quarantine_id,)).fetchone()
    )


def reject_from_quarantine(
    con: sqlite3.Connection,
    quarantine_id: str,
    *,
    tenant_id: str,
    actor: str,
    reason: str,
    persist: bool = True,
    commit: bool = True,
) -> dict[str, Any]:
    """Reject a quarantined capability (the safe path: no clean scan required).

    Issues a signed ``reject`` attestation and sets ``status='rejected'``.  A
    rejected item cannot subsequently be released — it must be re-quarantined
    under a fresh id (new content_hash) and re-scanned.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    record = get_quarantine(con, quarantine_id, tenant_id=tenant)
    if record is None:
        raise QuarantineError(f"Quarantine item not found: {quarantine_id}")
    if record["status"] != "quarantined":
        raise QuarantineError(
            f"Cannot reject a quarantine item in status {record['status']!r}."
        )
    if not reason or not reason.strip():
        raise QuarantineError("A non-empty reject reason is required.")
    envelope = _build_envelope(
        attestation_type="reject", quarantine_id=quarantine_id,
        capability_uri=record["capabilityUri"], content_hash=record["contentHash"],
        tenant_id=tenant, verdict=None, scanner_id=None, scanner_version=None,
        findings_summary={}, actor=actor, reason=reason,
    )
    signed = sign_attestation(envelope, persist=persist)
    _store_attestation(
        con, tenant_id=tenant, quarantine_id=quarantine_id, attestation_type="reject",
        subject_uri=record["capabilityUri"], content_hash=record["contentHash"],
        signed=signed, envelope=envelope, verdict=None, scanner_id=None,
        scanner_version=None, findings_summary={}, actor=actor, reason=reason,
        commit=False,
    )
    con.execute(
        """
        UPDATE capguard_quarantine
        SET status = 'rejected', rejected_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (quarantine_id,),
    )
    con.execute(
        """UPDATE capabilities
           SET lifecycle = 'disabled', approval_state = 'rejected', updated_at = CURRENT_TIMESTAMP
           WHERE tenant_id = ? AND uri = ? AND content_hash = ?""",
        (tenant, record["capabilityUri"], record["contentHash"]),
    )
    _audit(con, event_type="capguard.rejected", actor=actor, target=quarantine_id,
           action="reject", decision="allow",
           payload={"capabilityUri": record["capabilityUri"], "reason": reason}, tenant_id=tenant)
    if commit:
        con.commit()
    return quarantine_record(
        con.execute("SELECT * FROM capguard_quarantine WHERE id = ?", (quarantine_id,)).fetchone()
    )


def list_attestations(
    con: sqlite3.Connection,
    quarantine_id: str,
    *,
    tenant_id: str,
    attestation_type: str | None = None,
) -> list[dict[str, Any]]:
    """List attestations for a quarantine item (tenant-scoped)."""
    ensure_quarantine_tables(con)
    if attestation_type is not None and attestation_type not in ATTESTATION_TYPES:
        raise QuarantineError(f"Unsupported attestation type: {attestation_type!r}")
    params: list[Any] = [tenant_id or DEFAULT_TENANT, quarantine_id]
    where = "tenant_id = ? AND quarantine_id = ?"
    if attestation_type:
        where += " AND attestation_type = ?"
        params.append(attestation_type)
    rows = con.execute(
        f"SELECT * FROM capguard_attestations WHERE {where} ORDER BY rowid ASC",
        tuple(params),
    ).fetchall()
    return [attestation_record(row) for row in rows]


# ---------------------------------------------------------------------------
# Authoritative fail-closed release: compose the real scan + injection scan +
# model-agnostic policy into a signed scan attestation, then release.
# ---------------------------------------------------------------------------

def _scan_quarantined_content(record: dict[str, Any]) -> dict[str, Any]:
    """Run the fail-closed malware scan over the quarantined artifact body.

    Returns a scan-result dict in the shape ``malware_scan.scan_file`` produces
    and ``cap_guard._scan_check`` consumes: ``passed``, ``findings``,
    ``criticalCount``, ``highCount``, and ``error`` on a fail-closed miss.

    Fail-closed by construction: a missing source file, an unreadable body, or an
    oversize file yields ``passed=False`` with ``error`` set, which the policy
    maps to a ``deny`` verdict (never a silent pass). The scan NEVER trusts a
    stored/cache verdict — it re-reads the on-disk source the quarantine row
    points at, so a swapped file is caught as content drift at release time.
    """
    from .malware_scan import scan_file

    source_path = record.get("sourcePath") or ""
    if not source_path:
        return {"passed": False, "error": "quarantine item has no sourcePath", "findings": []}
    return scan_file(source_path)


def _injection_verdict(
    record: dict[str, Any], *, capability: Any | None
) -> tuple[bool | None, list[dict[str, Any]]]:
    """Run the metadata prompt-injection scan over the quarantined capability.

    Returns ``(injection_result, hits)`` where ``injection_result`` is
    ``True`` (clean), ``False`` (blocked), or ``None`` (not evaluated — no
    metadata surface to scan). The hits are wrapped into the
    ``{"phrase": ...}`` shape ``injection_allowlist.should_block`` expects.

    A blocked injection indicator (``should_block`` True) is a critical
    execution-safety finding: the metadata surface is what ``cap.search``
    broadcasts into other agents' context, so an injection here reaches agents
    that never asked for this capability. It fail-closed-denies the release.
    """
    from .injection_allowlist import should_block
    from .prompt_injection import scan_prompt_injection

    # Prefer the live Capability's metadata surface (name/title/description)
    # when the caller supplies it; fall back to the quarantine row's name.
    surface_parts: list[str] = []
    name = record.get("name") or ""
    if capability is not None:
        surface_parts.extend(
            [
                getattr(capability, "name", "") or "",
                getattr(capability, "title", "") or "",
                getattr(capability, "description", "") or "",
            ]
        )
    else:
        surface_parts.append(name)
    surface = "\n".join(p for p in surface_parts if p)
    if not surface.strip():
        return None, []
    phrases = scan_prompt_injection(surface)
    hits = [{"phrase": p} for p in phrases]
    if not hits:
        return True, hits
    cap_name = getattr(capability, "name", name) if capability is not None else name
    cap_kind = getattr(capability, "capability_type", None) if capability is not None else record.get("capabilityType")
    cap_plugin = getattr(capability, "plugin", None) if capability is not None else None
    blocked = should_block(hits, cap_name, capability_kind=cap_kind, capability_plugin=cap_plugin)
    return (not blocked), hits


def release_capability_from_quarantine(
    con: sqlite3.Connection,
    quarantine_id: str,
    *,
    tenant_id: str,
    actor: str,
    reason: str = "scan_clean",
    capability: Any | None = None,
    policy: Any | None = None,
    persist: bool = True,
    commit: bool = True,
) -> dict[str, Any]:
    """Authoritative fail-closed release of a quarantined capability.

    This is the client-capmesh server-side release path. It composes the real
    fail-closed scan surface (malware scan + prompt-injection scan) with the
    model-agnostic CapGuard policy (:func:`evaluate_release_policy`) and binds
    the composed verdict to a signed ``scan`` attestation before calling
    :func:`release_from_quarantine`. The capability is promoted out of
    quarantine ONLY when:

    * the malware scan re-reads the on-disk source and finds no
      ``critical``/``high`` findings (a swapped file is caught as content
      drift — the signed attestation is bound to the quarantine row's
      ``content_hash``, which ``scan_clean_attestation`` re-verifies),
    * the metadata prompt-injection scan does not block,
    * the model-agnostic policy returns ``allow`` (Camber/CIRE isolation,
      signature/provenance/risk-tier checks), and
    * the signed attestation chain verifies against the trusted anchor.

    On ANY gap the capability remains ``quarantined`` and
    :class:`QuarantineReleaseBlocked` is raised — there is no ``allow`` bypass
    and no silent degradation to a weaker path. A scan that errors (unreadable
    body, oversize file) is treated as a failed control, not a skipped one.

    *capability* is the live :class:`capmesh.models.Capability` row for the
    quarantined URI; when ``None`` the helper attempts to load it from the
    ``capabilities`` table so the policy has the full risk-tier/signature/
    provenance metadata. Callers that already hold the Capability pass it
    directly to avoid the extra lookup.
    """
    ensure_quarantine_tables(con)
    tenant = tenant_id or DEFAULT_TENANT
    record = get_quarantine(con, quarantine_id, tenant_id=tenant)
    if record is None:
        raise QuarantineError(f"Quarantine item not found: {quarantine_id}")
    if record["status"] != "quarantined":
        raise QuarantineError(
            f"Cannot release a quarantine item in status {record['status']!r}."
        )

    # Resolve the live Capability for the model-agnostic policy. The quarantine
    # row carries the discovery identity (uri/type/name/version/source/content)
    # but NOT the risk-tier/signature/provenance metadata the policy needs; the
    # authoritative server path indexes that metadata on the capabilities row.
    cap = capability
    if cap is None:
        try:
            from .index import get_capability
            cap = get_capability(con, record["capabilityUri"])
        except Exception:  # noqa: BLE001
            cap = None

    # Gate 1: fail-closed malware scan over the on-disk source body. Re-reads
    # the file the quarantine row points at; an errored scan is a failed
    # control (critical), never a skip.
    scan_result = _scan_quarantined_content(record)

    # Gate 2: metadata prompt-injection scan. None = not evaluated (no surface
    # to scan); True = clean; False = blocked (critical execution-safety risk).
    injection_result, injection_hits = _injection_verdict(record, capability=cap)
    if injection_result is False:
        # Surface the blocked injection in the scan_result so the signed
        # attestation's findings_summary records WHY the release was refused.
        findings = list(scan_result.get("findings") or [])
        findings.append(
            {
                "name": "prompt_injection_blocked",
                "severity": "critical",
                "description": f"metadata injection blocked: {len(injection_hits)} hit(s)",
            }
        )
        scan_result = {**scan_result, "passed": False, "findings": findings,
                       "criticalCount": int(scan_result.get("criticalCount", 0)) + 1}

    # Issue the signed scan attestation binding the composed verdict to the
    # quarantine row's content_hash. This is the fail-closed anchor: a clean
    # verdict is the precondition for release, and it is bound to the exact
    # content so it cannot be replayed after a source swap.
    issue_scan_attestation(
        con, quarantine_id, tenant_id=tenant, scan_result=scan_result,
        scanner_id="capmesh-capguard-release", scanner_version="1",
        persist=persist, commit=False,
    )

    # Gate 3 + release: evaluate the model-agnostic policy and release.
    # release_from_quarantine re-verifies the signed attestation chain against
    # the trusted anchor and refuses on any mismatch, superseding blocked
    # scan, or content drift. The policy gate (Camber/CIRE isolation,
    # signature/provenance/risk-tier) is enforced only when a Capability is
    # available; the attestation-chain gate is always enforced.
    return release_from_quarantine(
        con, quarantine_id, tenant_id=tenant, actor=actor, reason=reason,
        capability=cap, scan_result=scan_result, injection_result=injection_result,
        policy=policy, persist=persist, commit=commit,
    )


# ---------------------------------------------------------------------------
# Internal: audit_event bridged lazily to avoid import cycles with governance.
# ---------------------------------------------------------------------------

def _audit(
    con: sqlite3.Connection,
    *,
    event_type: str,
    actor: str,
    target: str | None,
    action: str | None,
    decision: str | None,
    payload: dict[str, Any],
    tenant_id: str,
) -> None:
    try:
        from .governance import audit_event
        audit_event(
            con,
            event_type=event_type,
            actor=actor,
            target=target,
            action=action,
            decision=decision,
            payload=payload,
            tenant_id=tenant_id,
        )
    except Exception:  # noqa: BLE001, S110
        # The audit log is best-effort: a failure to write an audit row must
        # never release a quarantined capability or roll back the quarantine
        # mutation that already succeeded.
        return
