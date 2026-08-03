"""Signed allowlist for executable call bindings.

Maintains a registry of capabilities that are approved for execution
with Ed25519 signature verification. Only capabilities whose binding
is signed by a trusted key can be invoked via cap.call.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

from .utils import new_id, utc_now


def ensure_allowlist_table(con: sqlite3.Connection) -> None:
    """Create the call_binding_allowlist table if it does not exist."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS call_binding_allowlist (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            capability_uri TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            signing_key_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            approved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            revoked_at TEXT,
            UNIQUE(tenant_id, capability_uri, binding_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_allowlist_cap ON call_binding_allowlist(capability_uri);
        """
    )


def compute_binding_hash(capability_uri: str, entrypoint: str, content_hash: str) -> str:
    """Compute a deterministic hash of a capability binding."""
    data = f"{capability_uri}|{entrypoint}|{content_hash}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def approve_binding(
    con: sqlite3.Connection,
    capability_uri: str,
    binding_hash: str,
    signing_key_id: str,
    signature: str,
    *,
    approved_by: str,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Approve a capability binding for execution with a signed allowlist entry."""
    ensure_allowlist_table(con)
    entry_id = new_id("alw")
    con.execute(
        """INSERT INTO call_binding_allowlist(id, tenant_id, capability_uri, binding_hash, signing_key_id, signature, approved_by, approved_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, capability_uri, binding_hash) DO UPDATE SET
               signing_key_id=excluded.signing_key_id,
               signature=excluded.signature,
               approved_by=excluded.approved_by,
               approved_at=excluded.approved_at,
               revoked_at=NULL""",
        (entry_id, tenant_id, capability_uri, binding_hash, signing_key_id, signature, approved_by, utc_now()),
    )
    if commit:
        con.commit()
    return {
        "capabilityUri": capability_uri,
        "bindingHash": binding_hash,
        "signingKeyId": signing_key_id,
        "approvedBy": approved_by,
        "status": "approved",
    }


def revoke_binding(
    con: sqlite3.Connection,
    capability_uri: str,
    binding_hash: str,
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Revoke a previously approved binding."""
    ensure_allowlist_table(con)
    con.execute(
        "UPDATE call_binding_allowlist SET revoked_at = ? WHERE capability_uri = ? AND binding_hash = ? AND tenant_id = ?",
        (utc_now(), capability_uri, binding_hash, tenant_id),
    )
    if commit:
        con.commit()
    return {"capabilityUri": capability_uri, "bindingHash": binding_hash, "status": "revoked"}


def is_binding_approved(
    con: sqlite3.Connection,
    capability_uri: str,
    binding_hash: str,
    *,
    tenant_id: str = "asg",
) -> bool:
    """Check whether a capability binding is approved and not revoked."""
    ensure_allowlist_table(con)
    row = con.execute(
        "SELECT revoked_at FROM call_binding_allowlist WHERE capability_uri = ? AND binding_hash = ? AND tenant_id = ?",
        (capability_uri, binding_hash, tenant_id),
    ).fetchone()
    return row is not None and row["revoked_at"] is None


def list_approved_bindings(con: sqlite3.Connection, *, tenant_id: str = "asg", active_only: bool = True) -> list[dict[str, Any]]:
    """List all approved bindings in the allowlist."""
    ensure_allowlist_table(con)
    query = "SELECT * FROM call_binding_allowlist WHERE tenant_id = ?"
    if active_only:
        query += " AND revoked_at IS NULL"
    query += " ORDER BY approved_at DESC"
    rows = con.execute(query, (tenant_id,)).fetchall()
    return [
        {
            "capabilityUri": str(row["capability_uri"]),
            "bindingHash": str(row["binding_hash"]),
            "signingKeyId": str(row["signing_key_id"]),
            "approvedBy": str(row["approved_by"]),
            "approvedAt": str(row["approved_at"]),
            "revokedAt": str(row["revoked_at"]) if row["revoked_at"] else None,
            "active": row["revoked_at"] is None,
        }
        for row in rows
    ]
