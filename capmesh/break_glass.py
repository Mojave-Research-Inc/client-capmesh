"""Break-glass admin audit flow for emergency administrative access.

Provides a governed mechanism for granting temporary elevated privileges
with full audit trail. Every break-glass session has a reason, an expiry,
and a revocation path. Break-glass grants are never silent.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import json_dumps, new_id, utc_now

DEFAULT_BREAK_GLASS_TTL_MINUTES = 30
MAX_BREAK_GLASS_TTL_MINUTES = 120


def grant_break_glass(
    con: sqlite3.Connection,
    principal: str,
    reason: str,
    *,
    granted_by: str,
    tenant_id: str = "asg",
    ttl_minutes: int = DEFAULT_BREAK_GLASS_TTL_MINUTES,
    commit: bool = True,
) -> dict[str, Any]:
    """Grant a temporary break-glass admin session.

    The principal receives platform_admin-equivalent rights for the duration.
    Every grant is recorded in break_glass_sessions and audit_events.
    """
    if not reason or not reason.strip():
        raise ValueError("Break-glass requires a non-empty reason")
    if ttl_minutes < 1 or ttl_minutes > MAX_BREAK_GLASS_TTL_MINUTES:
        raise ValueError(f"Break-glass TTL must be between 1 and {MAX_BREAK_GLASS_TTL_MINUTES} minutes")
    session_id = new_id("bg")
    import datetime
    expires_dt = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=ttl_minutes)
    expires_at = expires_dt.isoformat()
    con.execute(
        """INSERT INTO break_glass_sessions(id, tenant_id, principal, reason, granted_by, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (session_id, tenant_id, principal, reason, granted_by, expires_at, utc_now()),
    )
    con.execute(
        """INSERT INTO audit_events(id, tenant_id, event_type, actor, target, action, decision, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("ae"), tenant_id, "break_glass.grant",
            granted_by, principal, "grant", "allow",
            json_dumps({"sessionId": session_id, "reason": reason, "ttlMinutes": ttl_minutes, "expiresAt": expires_at}),
            utc_now(),
        ),
    )
    if commit:
        con.commit()
    return {
        "sessionId": session_id,
        "principal": principal,
        "reason": reason,
        "grantedBy": granted_by,
        "expiresAt": expires_at,
        "ttlMinutes": ttl_minutes,
    }


def revoke_break_glass(
    con: sqlite3.Connection,
    session_id: str,
    *,
    revoked_by: str,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Revoke a break-glass session before its natural expiry."""
    row = con.execute(
        "SELECT * FROM break_glass_sessions WHERE id = ? AND tenant_id = ?",
        (session_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Break-glass session not found: {session_id}")
    if row["revoked_at"] is not None:
        raise ValueError("Break-glass session already revoked")
    con.execute(
        "UPDATE break_glass_sessions SET revoked_at = ? WHERE id = ?",
        (utc_now(), session_id),
    )
    con.execute(
        """INSERT INTO audit_events(id, tenant_id, event_type, actor, target, action, decision, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("ae"), tenant_id, "break_glass.revoke",
            revoked_by, session_id, "revoke", "allow",
            json_dumps({"principal": str(row["principal"]), "reason": str(row["reason"])}),
            utc_now(),
        ),
    )
    if commit:
        con.commit()
    return {
        "sessionId": session_id,
        "principal": str(row["principal"]),
        "revokedBy": revoked_by,
        "revokedAt": utc_now(),
        "status": "revoked",
    }


def list_break_glass_sessions(
    con: sqlite3.Connection,
    *,
    tenant_id: str = "asg",
    active_only: bool = False,
) -> list[dict[str, Any]]:
    """List break-glass sessions, optionally filtering to active only."""
    if active_only:
        rows = con.execute(
            "SELECT * FROM break_glass_sessions WHERE tenant_id = ? AND revoked_at IS NULL ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM break_glass_sessions WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    return [
        {
            "sessionId": str(row["id"]),
            "principal": str(row["principal"]),
            "reason": str(row["reason"]),
            "grantedBy": str(row["granted_by"]),
            "expiresAt": str(row["expires_at"]),
            "revokedAt": str(row["revoked_at"]) if row["revoked_at"] else None,
            "createdAt": str(row["created_at"]),
        }
        for row in rows
    ]


def is_break_glass_active(con: sqlite3.Connection, session_id: str, *, tenant_id: str = "asg") -> bool:
    """Check whether a break-glass session is still active (not revoked, not expired)."""
    row = con.execute(
        "SELECT revoked_at, expires_at FROM break_glass_sessions WHERE id = ? AND tenant_id = ?",
        (session_id, tenant_id),
    ).fetchone()
    if row is None:
        return False
    if row["revoked_at"] is not None:
        return False
    # Check expiry
    import datetime
    now = datetime.datetime.now(datetime.UTC).isoformat()
    return str(row["expires_at"]) > now
