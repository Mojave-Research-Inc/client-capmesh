"""Authenticated CapGuard audit/status/release API surface (client-capmesh server).

Thin, authz-gated wrappers over :mod:`capmesh.capguard` so the authoritative
HTTP server can expose the quarantine store, the signed-attestation ledger,
and the fail-closed release/reject path to authenticated operators. Every
function takes a resolved :class:`capmesh.models.Principal` and enforces
access via :func:`capmesh.access_control.evaluate_access` exactly like the
existing governance surface (``list_audit_events`` / ``list_stores``):

* read surfaces (list/status) require the ``audit`` right on the tenant,
* mutating surfaces (release/reject) require the ``manage`` right on the tenant.

A denied right raises :class:`PermissionError`, which the server maps to HTTP
403 (the same convention ``handle_api_get``/``handle_api_post`` use for every
other governance endpoint). Nothing here is unauthenticated: there is no
public quarantine surface.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .access_control import evaluate_access
from .capguard import (
    list_attestations,
    list_quarantine,
    reject_from_quarantine,
    release_capability_from_quarantine,
)
from .models import Principal
from .utils import DEFAULT_TENANT


def _require_right(con: sqlite3.Connection, principal: Principal, right: str) -> None:
    """Raise PermissionError unless *principal* holds *right* on its tenant."""
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    allowed, reason = evaluate_access(
        con, principal, right=right, resource_uri=f"tenant:{tenant_id}"
    )
    if not allowed:
        raise PermissionError(reason)


def capguard_status(con: sqlite3.Connection, principal: Principal) -> dict[str, Any]:
    """Aggregate quarantine counts for the caller's tenant.

    Read surface; requires the ``audit`` right. Returns the count of items in
    each lifecycle status so an operator can see how many capabilities are
    awaiting scan/release at a glance.
    """
    _require_right(con, principal, "audit")
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    rows = list_quarantine(con, tenant_id=tenant_id, limit=500)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "tenantId": tenant_id,
        "total": len(rows),
        "byStatus": counts,
        "quarantined": counts.get("quarantined", 0),
        "released": counts.get("released", 0),
        "rejected": counts.get("rejected", 0),
    }


def capguard_list_quarantine(
    con: sqlite3.Connection, principal: Principal, *, status: str | None = None
) -> dict[str, Any]:
    """List quarantine rows for the caller's tenant, optionally by status.

    Read surface; requires the ``audit`` right. Tenant-scoped: an operator in
    tenant A never sees tenant B's quarantined capabilities.
    """
    _require_right(con, principal, "audit")
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    rows = list_quarantine(con, tenant_id=tenant_id, status=status, limit=200)
    return {"tenantId": tenant_id, "items": rows}


def capguard_list_attestations(
    con: sqlite3.Connection,
    principal: Principal,
    quarantine_id: str,
    *,
    attestation_type: str | None = None,
) -> dict[str, Any]:
    """List signed attestations for one quarantine item (tenant-scoped).

    Read surface; requires the ``audit`` right. Returns the full signed
    attestation ledger (scan/release/reject) so an operator can audit the
    evidence chain behind a release decision.
    """
    _require_right(con, principal, "audit")
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    rows = list_attestations(
        con,
        quarantine_id,
        tenant_id=tenant_id,
        attestation_type=attestation_type,
    )
    return {"tenantId": tenant_id, "quarantineId": quarantine_id, "items": rows}


def capguard_release(
    con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]
) -> dict[str, Any]:
    """Fail-closed release of a quarantined capability.

    Mutating surface; requires the ``manage`` right. Runs the authoritative
    fail-closed scan + injection scan + model-agnostic policy and promotes the
    quarantine item to ``released`` ONLY on verified evidence. Any gap raises
    :class:`QuarantineReleaseBlocked` (mapped to HTTP 409 by the server) and
    leaves the capability ``quarantined``.

    Payload: ``{"quarantineId": "...", "reason": "scan_clean" (optional)}``.
    """
    _require_right(con, principal, "manage")
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    quarantine_id = str(payload.get("quarantineId") or "").strip()
    if not quarantine_id:
        raise ValueError("quarantineId is required.")
    reason = str(payload.get("reason") or "scan_clean").strip() or "scan_clean"
    actor = principal.subject or principal.email or "capguard-release"
    return release_capability_from_quarantine(
        con,
        quarantine_id,
        tenant_id=tenant_id,
        actor=actor,
        reason=reason,
        commit=True,
    )


def capguard_reject(
    con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]
) -> dict[str, Any]:
    """Reject a quarantined capability (the safe path: no clean scan required).

    Mutating surface; requires the ``manage`` right. Issues a signed ``reject``
    attestation and sets ``status='rejected'``. A rejected item cannot be
    released afterwards. Payload: ``{"quarantineId": "...", "reason": "..."}``;
    a non-empty reason is required.
    """
    _require_right(con, principal, "manage")
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    quarantine_id = str(payload.get("quarantineId") or "").strip()
    if not quarantine_id:
        raise ValueError("quarantineId is required.")
    reason = str(payload.get("reason") or "").strip()
    if not reason:
        raise ValueError("A non-empty reject reason is required.")
    actor = principal.subject or principal.email or "capguard-reject"
    return reject_from_quarantine(
        con,
        quarantine_id,
        tenant_id=tenant_id,
        actor=actor,
        reason=reason,
        commit=True,
    )


__all__ = [
    "capguard_list_attestations",
    "capguard_list_quarantine",
    "capguard_reject",
    "capguard_release",
    "capguard_status",
]
