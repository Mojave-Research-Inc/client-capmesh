from __future__ import annotations

import sqlite3
from typing import Any

from .access_control import ROLE_RIGHTS, evaluate_access
from .models import Principal
from .utils import DEFAULT_TENANT, json_loads, new_id, utc_now


def assign_role(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
    if not allowed:
        raise PermissionError(reason)
    role = str(payload.get("role") or "")
    if role not in ROLE_RIGHTS:
        raise ValueError("Unsupported role.")
    assignment_id = new_id("rol")
    con.execute(
        """
        INSERT INTO role_assignments(id, tenant_id, subject_type, subject_id, role, scope_type, scope_id, source, created_by, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assignment_id,
            tenant_id,
            str(payload.get("subjectType") or "user"),
            str(payload.get("subjectId") or ""),
            role,
            str(payload.get("scopeType") or "tenant"),
            str(payload.get("scopeId") or tenant_id),
            str(payload.get("source") or "manual"),
            principal.subject,
            payload.get("expiresAt"),
        ),
    )
    if payload.get("relationshipObject"):
        con.execute(
            """
            INSERT OR IGNORE INTO relationship_tuples(id, tenant_id, object, relation, user, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("rel"),
                tenant_id,
                str(payload["relationshipObject"]),
                role,
                f"{payload.get('subjectType') or 'user'}:{payload.get('subjectId') or ''}",
                str(payload.get("source") or "manual"),
            ),
        )
    audit_event(con, event_type="role.assigned", actor=principal.subject, target=assignment_id, action="assign", decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return role_record(con.execute("SELECT * FROM role_assignments WHERE id = ?", (assignment_id,)).fetchone())


def revoke_role(con: sqlite3.Connection, principal: Principal, assignment_id: str) -> dict[str, Any]:
    from .governance import audit_event
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"role:{assignment_id}")
    if not allowed:
        raise PermissionError(reason)
    con.execute("UPDATE role_assignments SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND tenant_id = ?", (assignment_id, principal.tenant_id))
    audit_event(con, event_type="role.revoked", actor=principal.subject, target=assignment_id, action="revoke", decision="allow", tenant_id=principal.tenant_id)
    con.commit()
    return {"id": assignment_id, "state": "revoked"}


def require_admin_or_audit(con: sqlite3.Connection, principal: Principal, *, resource_uri: str) -> None:
    """Gate tenant-wide listings (roles, bindings) behind manage OR audit rights.

    Defense-in-depth: the capability-call layer only enforces the 'call' right
    before dispatching system.* capabilities, so without this guard any member
    could enumerate the full role/binding map of the tenant (F-09, F-11).
    """
    for right in ("manage", "audit"):
        allowed, _reason = evaluate_access(con, principal, right=right, resource_uri=resource_uri)
        if allowed:
            return
    raise PermissionError("This listing requires the manage or audit right.")


def list_roles(con: sqlite3.Connection, principal: Principal) -> list[dict[str, Any]]:
    require_admin_or_audit(con, principal, resource_uri=f"tenant:{principal.tenant_id or DEFAULT_TENANT}")
    rows = con.execute("SELECT * FROM role_assignments WHERE tenant_id = ? ORDER BY created_at DESC", (principal.tenant_id,)).fetchall()
    return [role_record(row) for row in rows]


def role_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "subjectType": row["subject_type"],
        "subjectId": row["subject_id"],
        "role": row["role"],
        "scopeType": row["scope_type"],
        "scopeId": row["scope_id"],
        "source": row["source"],
        "createdBy": row["created_by"],
        "expiresAt": row["expires_at"],
        "revokedAt": row["revoked_at"],
        "createdAt": row["created_at"],
    }


_ORG_MEMBER_ROLES = {"member", "namespace_admin", "org_admin"}


def _resolve_org(con: sqlite3.Connection, tenant_id: str, ref: str) -> sqlite3.Row:
    """Resolve an org by id, slug, or its store id within a tenant."""
    if not ref:
        raise ValueError("An org slug, id, or store id is required.")
    row = con.execute(
        """
        SELECT * FROM organizations
        WHERE tenant_id = ? AND (id = ? OR slug = ? OR store_id = ?)
        LIMIT 1
        """,
        (tenant_id, ref, ref, ref),
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown organization: {ref}")
    return row


def list_organizations(con: sqlite3.Connection, principal: Principal) -> list[dict[str, Any]]:
    from .governance import ensure_identity_for_principal
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    ensure_identity_for_principal(con, principal)
    rows = con.execute(
        "SELECT * FROM organizations WHERE tenant_id = ? ORDER BY slug",
        (tenant_id,),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "tenantId": row["tenant_id"],
            "slug": row["slug"],
            "displayName": row["display_name"],
            "storeId": row["store_id"],
            "status": row["status"],
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


def add_org_member(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    """Add a principal to an organization (Design B membership = org-scoped role).

    Gated by manage on the org's store (mirrors create_store org gating); self-add
    is impossible without manage. Writes a role_assignment with scope_type='org'.
    """
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    org = _resolve_org(con, tenant_id, str(payload.get("org") or payload.get("storeId") or payload.get("orgId") or ""))
    org_store_id = org["store_id"]
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"store:{org_store_id}")
    if not allowed:
        # Fall back to tenant-level manage so org_admin/platform_admin can manage.
        allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
    if not allowed:
        raise PermissionError(reason or "Adding an org member requires the manage right on the org store.")
    role = str(payload.get("role") or "member")
    if role not in _ORG_MEMBER_ROLES:
        raise ValueError(f"Unsupported org membership role: {role} (use member, namespace_admin, or org_admin).")
    subject_id = str(payload.get("subjectId") or payload.get("user") or "")
    if not subject_id:
        raise ValueError("A subjectId (user email/identity) is required.")
    assignment_id = new_id("rol")
    con.execute(
        """
        INSERT INTO role_assignments(id, tenant_id, subject_type, subject_id, role, scope_type, scope_id, source, created_by, expires_at)
        VALUES (?, ?, ?, ?, ?, 'org', ?, ?, ?, ?)
        """,
        (
            assignment_id,
            tenant_id,
            str(payload.get("subjectType") or "user"),
            subject_id,
            role,
            org["id"],
            str(payload.get("source") or "manual"),
            principal.subject,
            payload.get("expiresAt"),
        ),
    )
    audit_event(
        con,
        event_type="org.member_added",
        actor=principal.subject,
        target=org["id"],
        action="add_member",
        decision="allow",
        payload={"subjectId": subject_id, "role": role, "assignmentId": assignment_id, "orgSlug": org["slug"]},
        tenant_id=tenant_id,
    )
    con.commit()
    return role_record(con.execute("SELECT * FROM role_assignments WHERE id = ?", (assignment_id,)).fetchone())


def remove_org_member(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    """Revoke a principal's org membership (all matching org-scoped role grants)."""
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    org = _resolve_org(con, tenant_id, str(payload.get("org") or payload.get("storeId") or payload.get("orgId") or ""))
    org_store_id = org["store_id"]
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"store:{org_store_id}")
    if not allowed:
        allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
    if not allowed:
        raise PermissionError(reason or "Removing an org member requires the manage right on the org store.")
    subject_id = str(payload.get("subjectId") or payload.get("user") or "")
    if not subject_id:
        raise ValueError("A subjectId (user email/identity) is required.")
    subject_type = str(payload.get("subjectType") or "user")
    cur = con.execute(
        """
        UPDATE role_assignments
        SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = ? AND scope_type = 'org' AND scope_id = ?
          AND subject_type = ? AND subject_id = ? AND revoked_at IS NULL
        """,
        (tenant_id, org["id"], subject_type, subject_id),
    )
    audit_event(
        con,
        event_type="org.member_removed",
        actor=principal.subject,
        target=org["id"],
        action="remove_member",
        decision="allow",
        payload={"subjectId": subject_id, "subjectType": subject_type, "revoked": cur.rowcount, "orgSlug": org["slug"]},
        tenant_id=tenant_id,
    )
    con.commit()
    return {"orgId": org["id"], "slug": org["slug"], "subjectId": subject_id, "revoked": cur.rowcount, "state": "removed"}


def list_org_members(con: sqlite3.Connection, principal: Principal, org_ref: str) -> list[dict[str, Any]]:
    """List active members of an org. Requires manage OR audit on the org store."""
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    org = _resolve_org(con, tenant_id, org_ref)
    require_admin_or_audit(con, principal, resource_uri=f"store:{org['store_id']}")
    now = utc_now()
    rows = con.execute(
        """
        SELECT * FROM role_assignments
        WHERE tenant_id = ? AND scope_type = 'org' AND scope_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
        """,
        (tenant_id, org["id"]),
    ).fetchall()
    members: list[dict[str, Any]] = []
    for row in rows:
        if row["expires_at"] and row["expires_at"] <= now:
            continue
        members.append(role_record(row))
    return members


def list_audit_events(con: sqlite3.Connection, principal: Principal, limit: int = 50) -> list[dict[str, Any]]:
    allowed, reason = evaluate_access(con, principal, right="audit", resource_uri=f"tenant:{principal.tenant_id}")
    if not allowed:
        raise PermissionError(reason)
    limit = min(max(int(limit), 1), 200)
    rows = con.execute("SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?", (principal.tenant_id, limit)).fetchall()
    return [
        {
            "id": row["id"],
            "eventType": row["event_type"],
            "actor": row["actor"],
            "actorType": row["actor_type"],
            "target": row["target"],
            "action": row["action"],
            "decision": row["decision"],
            "reason": row["reason"],
            "payload": json_loads(row["payload_json"], {}),
            "createdAt": row["created_at"],
        }
        for row in rows
    ]



