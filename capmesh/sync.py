from __future__ import annotations

import secrets
import sqlite3
from typing import Any

from .access_control import evaluate_access
from .models import Principal
from .tokens import hash_secret
from .utils import DEFAULT_TENANT, json_dumps, json_loads, new_id, stable_id


def tag_to_group(ts_name: str) -> str:
    """Map a Tailscale ACL group/tag name to a capmesh group display name.

    Examples:
        ``tag:eng``       -> ``asg:eng``
        ``group:admins``  -> ``asg:admins``
        ``asg:eng``       -> ``asg:eng`` (already namespaced — passthrough)

    The tenant prefix is taken from DEFAULT_TENANT so groups read as
    ``<tenant>:<slug>``. Names that already carry a ``<tenant>:`` prefix are
    returned unchanged so the mapping is idempotent.
    """
    name = (ts_name or "").strip()
    if not name:
        return f"{DEFAULT_TENANT}:tailnet"
    for prefix in ("tag:", "group:"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.strip().strip(":")
    if not name:
        return f"{DEFAULT_TENANT}:tailnet"
    if name.startswith(f"{DEFAULT_TENANT}:"):
        return name
    return f"{DEFAULT_TENANT}:{name}"


def upsert_identity_from_tailnet(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    external_id: str,
    login_name: str,
    display_name: str | None,
    ts_type: str,
    active: bool,
    actor: str = "tailscale-sync",
) -> tuple[str, bool]:
    """Upsert a tailnet user as a capmesh identity (reuses the SCIM identity shape).

    Returns ``(identity_id, was_deactivated)``. ``was_deactivated`` is True only
    when this call flipped a previously-active identity to inactive (so the
    caller can emit ``identity.deactivated`` audit + count it). Suspended/removed
    tailnet users land on the existing ``active = 0`` deactivation path, so
    ``is_disabled()`` denies them. Tailnet identity grants no roles directly.
    """
    from .governance import audit_event

    login = (login_name or "").strip().lower()
    identity_id = stable_id("idn", tenant_id, external_id or login)
    prior = con.execute("SELECT active FROM identities WHERE id = ?", (identity_id,)).fetchone()
    was_active = bool(prior["active"]) if prior is not None else False
    raw_json = json_dumps(
        {
            "source": "tailscale",
            "tsType": ts_type,
            "loginName": login,
            "displayName": display_name or login,
            "externalId": external_id or login,
        }
    )
    con.execute(
        """
        INSERT INTO identities(id, tenant_id, external_id, user_name, display_name, email, identity_type, active, raw_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'human', ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            external_id=excluded.external_id,
            user_name=excluded.user_name,
            display_name=excluded.display_name,
            email=excluded.email,
            active=excluded.active,
            raw_json=excluded.raw_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            identity_id,
            tenant_id,
            external_id or login,
            login,
            display_name or login,
            login if "@" in login else None,
            1 if active else 0,
            raw_json,
        ),
    )
    con.execute(
        """
        INSERT INTO scim_sync_state(id, tenant_id, resource_type, external_id, internal_id, version, raw_json, last_seen_at)
        VALUES (?, ?, 'tailscale_user', ?, ?, NULL, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(tenant_id, resource_type, external_id) DO UPDATE SET
            internal_id=excluded.internal_id,
            raw_json=excluded.raw_json,
            last_seen_at=CURRENT_TIMESTAMP
        """,
        (stable_id("sync", tenant_id, "tailscale_user", external_id or login), tenant_id, external_id or login, identity_id, raw_json),
    )
    was_deactivated = was_active and not active
    if was_deactivated:
        audit_event(
            con,
            tenant_id=tenant_id,
            event_type="identity.deactivated",
            actor=actor,
            actor_type="system",
            target=identity_id,
            action="deactivate",
            decision="allow",
            payload={"source": "tailscale", "loginName": login},
        )
    return identity_id, was_deactivated


def upsert_group_from_tailnet(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    external_id: str,
    display_name: str,
    member_identity_ids: list[str],
    actor: str = "tailscale-sync",
) -> dict[str, int]:
    from .governance import audit_event
    """Upsert a Tailscale ACL group as a capmesh group + diff its membership.

    Membership diff is additive + prune: rows with ``source='tailscale'`` whose
    identity is no longer in the tailnet group are removed. Returns counts of
    members ``added`` and ``pruned``.
    """
    group_id = stable_id("grp", tenant_id, external_id or display_name)
    con.execute(
        """
        INSERT INTO groups(id, tenant_id, external_id, display_name, active, raw_json, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            external_id=excluded.external_id,
            display_name=excluded.display_name,
            active=1,
            raw_json=excluded.raw_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (group_id, tenant_id, external_id or group_id, display_name, json_dumps({"source": "tailscale", "tsGroup": external_id})),
    )
    desired = set(member_identity_ids)
    existing_rows = con.execute(
        "SELECT identity_id FROM group_members WHERE group_id = ? AND source = 'tailscale'",
        (group_id,),
    ).fetchall()
    existing = {row["identity_id"] for row in existing_rows}
    added = 0
    for identity_id in desired - existing:
        con.execute(
            "INSERT OR IGNORE INTO group_members(group_id, identity_id, source) VALUES (?, ?, 'tailscale')",
            (group_id, identity_id),
        )
        added += 1
    pruned = 0
    for identity_id in existing - desired:
        con.execute(
            "DELETE FROM group_members WHERE group_id = ? AND identity_id = ? AND source = 'tailscale'",
            (group_id, identity_id),
        )
        pruned += 1
    con.execute(
        """
        INSERT INTO scim_sync_state(id, tenant_id, resource_type, external_id, internal_id, version, raw_json, last_seen_at)
        VALUES (?, ?, 'tailscale_group', ?, ?, NULL, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(tenant_id, resource_type, external_id) DO UPDATE SET
            internal_id=excluded.internal_id,
            raw_json=excluded.raw_json,
            last_seen_at=CURRENT_TIMESTAMP
        """,
        (
            stable_id("sync", tenant_id, "tailscale_group", external_id or group_id),
            tenant_id,
            external_id or group_id,
            group_id,
            json_dumps({"source": "tailscale", "displayName": display_name, "memberCount": len(desired)}),
        ),
    )
    audit_event(
        con,
        tenant_id=tenant_id,
        event_type="tailscale.group.upsert",
        actor=actor,
        actor_type="system",
        target=group_id,
        action="upsert",
        decision="allow",
        payload={"displayName": display_name, "added": added, "pruned": pruned, "members": len(desired)},
    )
    return {"added": added, "pruned": pruned}


def sync_summary(con: sqlite3.Connection, principal: Principal) -> dict[str, Any]:
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{principal.tenant_id}")
    if not allowed:
        raise PermissionError(reason)
    counts: dict[str, int] = {}
    for table in ("identities", "groups", "apps", "scim_sync_state", "graph_subscriptions", "teams_bindings"):
        counts[table] = int(con.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"])
    tailscale_counts: dict[str, int] = {}
    for resource_type in ("tailscale_user", "tailscale_group"):
        tailscale_counts[resource_type] = int(
            con.execute(
                "SELECT COUNT(*) AS count FROM scim_sync_state WHERE tenant_id = ? AND resource_type = ?",
                (principal.tenant_id, resource_type),
            ).fetchone()["count"]
        )
    return {"tenantId": principal.tenant_id, "counts": counts, "tailscale": tailscale_counts}


def plan_graph_subscription(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
    if not allowed:
        raise PermissionError(reason)
    client_state = str(payload.get("clientState") or secrets.token_urlsafe(24))
    subscription_id = new_id("gsub")
    con.execute(
        """
        INSERT INTO graph_subscriptions(id, tenant_id, resource, change_type, notification_url, client_state_hash, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'planned')
        """,
        (
            subscription_id,
            tenant_id,
            str(payload.get("resource") or "teams/getAllMessages"),
            str(payload.get("changeType") or "created,updated,deleted"),
            str(payload.get("notificationUrl") or ""),
            hash_secret(client_state),
            payload.get("expiresAt"),
        ),
    )
    audit_event(con, event_type="graph.subscription.planned", actor=principal.subject, target=subscription_id, action="plan", decision="allow", payload={"resource": payload.get("resource")}, tenant_id=tenant_id)
    con.commit()
    return {"id": subscription_id, "tenantId": tenant_id, "clientState": client_state, "status": "planned"}


def create_teams_binding(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
    if not allowed:
        raise PermissionError(reason)
    binding_id = new_id("team")
    con.execute(
        """
        INSERT INTO teams_bindings(id, tenant_id, team_id, channel_id, channel_name, approval_url_base, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            binding_id,
            tenant_id,
            str(payload.get("teamId") or ""),
            str(payload.get("channelId") or ""),
            str(payload.get("channelName") or "capmesh-approvals"),
            str(payload.get("approvalUrlBase") or ""),
            json_dumps(payload.get("metadata") or {}),
        ),
    )
    audit_event(con, event_type="teams.binding.created", actor=principal.subject, target=binding_id, action="create", decision="allow", payload={"teamId": payload.get("teamId"), "channelId": payload.get("channelId")}, tenant_id=tenant_id)
    con.commit()
    return teams_binding_record(con.execute("SELECT * FROM teams_bindings WHERE id = ?", (binding_id,)).fetchone())


def list_teams_bindings(con: sqlite3.Connection, principal: Principal) -> list[dict[str, Any]]:
    from .governance import require_admin_or_audit
    require_admin_or_audit(con, principal, resource_uri=f"tenant:{principal.tenant_id or DEFAULT_TENANT}")
    rows = con.execute("SELECT * FROM teams_bindings WHERE tenant_id = ? ORDER BY created_at DESC", (principal.tenant_id,)).fetchall()
    return [teams_binding_record(row) for row in rows]


def teams_binding_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "teamId": row["team_id"],
        "channelId": row["channel_id"],
        "channelName": row["channel_name"],
        "approvalUrlBase": row["approval_url_base"],
        "status": row["status"],
        "metadata": json_loads(row["metadata_json"], {}),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }



