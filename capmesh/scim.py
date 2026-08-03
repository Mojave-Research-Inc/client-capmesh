from __future__ import annotations

import sqlite3
from typing import Any

from .governance import DEFAULT_TENANT, audit_event, json_dumps, json_loads, stable_id

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def service_provider_config(base_url: str) -> dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": f"{base_url.rstrip('/')}/scim/v2/ServiceProviderConfig",
        "patch": {"supported": False},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 100},
        "changePassword": {"supported": False},
        "sort": {"supported": True},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer",
                "description": "Tailnet-scoped capmesh bearer token or OAuth access token.",
                "primary": True,
            }
        ],
    }


def schemas() -> dict[str, Any]:
    return list_response(
        [
            {
                "id": SCIM_USER_SCHEMA,
                "name": "User",
                "description": "Core User",
                "attributes": [
                    {"name": "userName", "type": "string", "required": True, "mutability": "readWrite"},
                    {"name": "displayName", "type": "string", "required": False, "mutability": "readWrite"},
                    {"name": "active", "type": "boolean", "required": False, "mutability": "readWrite"},
                    {"name": "emails", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite"},
                ],
            },
            {
                "id": SCIM_GROUP_SCHEMA,
                "name": "Group",
                "description": "Core Group",
                "attributes": [
                    {"name": "displayName", "type": "string", "required": True, "mutability": "readWrite"},
                    {"name": "members", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite"},
                ],
            },
        ],
        start_index=1,
        count=2,
    )


def resource_types(base_url: str) -> dict[str, Any]:
    return list_response(
        [
            {
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": SCIM_USER_SCHEMA,
                "meta": {"location": f"{base_url.rstrip('/')}/scim/v2/ResourceTypes/User"},
            },
            {
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": SCIM_GROUP_SCHEMA,
                "meta": {"location": f"{base_url.rstrip('/')}/scim/v2/ResourceTypes/Group"},
            },
        ],
        start_index=1,
        count=2,
    )


def list_users(con: sqlite3.Connection, *, tenant_id: str = DEFAULT_TENANT, start_index: int = 1, count: int = 100, filter_query: str | None = None, base_url: str = "") -> dict[str, Any]:
    count = min(max(count, 1), 100)
    offset = max(start_index - 1, 0)
    where = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if filter_query:
        field, value = parse_eq_filter(filter_query)
        if field in {"userName", "externalId"}:
            where.append(("user_name" if field == "userName" else "external_id") + " = ?")
            params.append(value)
    total = con.execute(f"SELECT COUNT(*) AS count FROM identities WHERE {' AND '.join(where)}", params).fetchone()["count"]
    rows = con.execute(
        f"SELECT * FROM identities WHERE {' AND '.join(where)} ORDER BY user_name LIMIT ? OFFSET ?",
        (*params, count, offset),
    ).fetchall()
    return list_response([user_resource(row, base_url=base_url) for row in rows], start_index=start_index, count=len(rows), total=total)


def get_user(con: sqlite3.Connection, user_id: str, *, tenant_id: str = DEFAULT_TENANT, base_url: str = "") -> dict[str, Any] | None:
    row = con.execute("SELECT * FROM identities WHERE id = ? AND tenant_id = ?", (user_id, tenant_id)).fetchone()
    return user_resource(row, base_url=base_url) if row else None


def upsert_user(con: sqlite3.Connection, payload: dict[str, Any], *, tenant_id: str = DEFAULT_TENANT, actor: str = "scim") -> dict[str, Any]:
    external_id = str(payload.get("externalId") or payload.get("id") or "")
    user_name = str(payload.get("userName") or "").strip()
    if not user_name:
        raise ValueError("SCIM User userName is required.")
    identity_id = str(payload.get("id") or stable_id("idn", tenant_id, external_id or user_name))
    existing = con.execute("SELECT tenant_id FROM identities WHERE id = ?", (identity_id,)).fetchone()
    if existing is not None and existing["tenant_id"] != tenant_id:
        raise ValueError("SCIM User id belongs to a different tenant.")
    email = primary_email(payload)
    con.execute(
        """
        INSERT INTO identities(id, tenant_id, external_id, user_name, display_name, email, identity_type, entra_object_id, active, raw_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'human', ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            external_id=excluded.external_id,
            user_name=excluded.user_name,
            display_name=excluded.display_name,
            email=excluded.email,
            entra_object_id=excluded.entra_object_id,
            active=excluded.active,
            raw_json=excluded.raw_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            identity_id,
            tenant_id,
            external_id or identity_id,
            user_name,
            payload.get("displayName") or payload.get("name", {}).get("formatted"),
            email,
            external_id or identity_id,
            1 if payload.get("active", True) else 0,
            json_dumps(payload),
        ),
    )
    con.execute(
        """
        INSERT INTO scim_sync_state(id, tenant_id, resource_type, external_id, internal_id, version, raw_json, last_seen_at)
        VALUES (?, ?, 'User', ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(tenant_id, resource_type, external_id) DO UPDATE SET
            internal_id=excluded.internal_id,
            version=excluded.version,
            raw_json=excluded.raw_json,
            last_seen_at=CURRENT_TIMESTAMP
        """,
        (stable_id("sync", tenant_id, "User", external_id or identity_id), tenant_id, external_id or identity_id, identity_id, payload.get("meta", {}).get("version"), json_dumps(payload)),
    )
    audit_event(con, tenant_id=tenant_id, event_type="scim.user.upsert", actor=actor, actor_type="system", target=identity_id, action="upsert", decision="allow")
    con.commit()
    row = con.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
    return user_resource(row)


def delete_user(con: sqlite3.Connection, user_id: str, *, tenant_id: str = DEFAULT_TENANT, actor: str = "scim") -> bool:
    row = con.execute("SELECT id FROM identities WHERE id = ? AND tenant_id = ?", (user_id, tenant_id)).fetchone()
    if row is None:
        return False
    con.execute("UPDATE identities SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
    audit_event(con, tenant_id=tenant_id, event_type="scim.user.deactivated", actor=actor, actor_type="system", target=user_id, action="delete", decision="allow")
    con.commit()
    return True


def list_groups(con: sqlite3.Connection, *, tenant_id: str = DEFAULT_TENANT, start_index: int = 1, count: int = 100, filter_query: str | None = None, base_url: str = "") -> dict[str, Any]:
    count = min(max(count, 1), 100)
    offset = max(start_index - 1, 0)
    where = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if filter_query:
        field, value = parse_eq_filter(filter_query)
        if field in {"displayName", "externalId"}:
            where.append(("display_name" if field == "displayName" else "external_id") + " = ?")
            params.append(value)
    total = con.execute(f"SELECT COUNT(*) AS count FROM groups WHERE {' AND '.join(where)}", params).fetchone()["count"]
    rows = con.execute(
        f"SELECT * FROM groups WHERE {' AND '.join(where)} ORDER BY display_name LIMIT ? OFFSET ?",
        (*params, count, offset),
    ).fetchall()
    return list_response([group_resource(con, row, base_url=base_url) for row in rows], start_index=start_index, count=len(rows), total=total)


def get_group(con: sqlite3.Connection, group_id: str, *, tenant_id: str = DEFAULT_TENANT, base_url: str = "") -> dict[str, Any] | None:
    row = con.execute("SELECT * FROM groups WHERE id = ? AND tenant_id = ?", (group_id, tenant_id)).fetchone()
    return group_resource(con, row, base_url=base_url) if row else None


def upsert_group(con: sqlite3.Connection, payload: dict[str, Any], *, tenant_id: str = DEFAULT_TENANT, actor: str = "scim") -> dict[str, Any]:
    external_id = str(payload.get("externalId") or payload.get("id") or "")
    display_name = str(payload.get("displayName") or "").strip()
    if not display_name:
        raise ValueError("SCIM Group displayName is required.")
    group_id = str(payload.get("id") or stable_id("grp", tenant_id, external_id or display_name))
    existing = con.execute("SELECT tenant_id FROM groups WHERE id = ?", (group_id,)).fetchone()
    if existing is not None and existing["tenant_id"] != tenant_id:
        raise ValueError("SCIM Group id belongs to a different tenant.")
    member_ids = [str(member.get("value") or "") for member in (payload.get("members") or [])]
    for member_id in (value for value in member_ids if value):
        identity = con.execute("SELECT tenant_id FROM identities WHERE id = ?", (member_id,)).fetchone()
        if identity is None or identity["tenant_id"] != tenant_id:
            raise ValueError("SCIM Group member must exist in the same tenant.")
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
        (group_id, tenant_id, external_id or group_id, display_name, json_dumps(payload)),
    )
    con.execute("DELETE FROM group_members WHERE group_id = ? AND source = 'scim'", (group_id,))
    for member in payload.get("members") or []:
        member_id = str(member.get("value") or "")
        if not member_id:
            continue
        con.execute(
            """
            INSERT OR IGNORE INTO group_members(group_id, identity_id, source)
            VALUES (?, ?, 'scim')
            """,
            (group_id, member_id),
        )
    con.execute(
        """
        INSERT INTO scim_sync_state(id, tenant_id, resource_type, external_id, internal_id, version, raw_json, last_seen_at)
        VALUES (?, ?, 'Group', ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(tenant_id, resource_type, external_id) DO UPDATE SET
            internal_id=excluded.internal_id,
            version=excluded.version,
            raw_json=excluded.raw_json,
            last_seen_at=CURRENT_TIMESTAMP
        """,
        (stable_id("sync", tenant_id, "Group", external_id or group_id), tenant_id, external_id or group_id, group_id, payload.get("meta", {}).get("version"), json_dumps(payload)),
    )
    audit_event(con, tenant_id=tenant_id, event_type="scim.group.upsert", actor=actor, actor_type="system", target=group_id, action="upsert", decision="allow")
    con.commit()
    row = con.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    return group_resource(con, row)


def delete_group(con: sqlite3.Connection, group_id: str, *, tenant_id: str = DEFAULT_TENANT, actor: str = "scim") -> bool:
    row = con.execute("SELECT id FROM groups WHERE id = ? AND tenant_id = ?", (group_id, tenant_id)).fetchone()
    if row is None:
        return False
    con.execute("UPDATE groups SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (group_id,))
    con.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    audit_event(con, tenant_id=tenant_id, event_type="scim.group.deactivated", actor=actor, actor_type="system", target=group_id, action="delete", decision="allow")
    con.commit()
    return True


def user_resource(row: sqlite3.Row, *, base_url: str = "") -> dict[str, Any]:
    raw = json_loads(row["raw_json"], {})
    resource = {
        "schemas": [SCIM_USER_SCHEMA],
        "id": row["id"],
        "externalId": row["external_id"],
        "userName": row["user_name"],
        "displayName": row["display_name"],
        "active": bool(row["active"]),
        "emails": [{"value": row["email"], "primary": True}] if row["email"] else raw.get("emails", []),
        "meta": {"resourceType": "User", "created": row["created_at"], "lastModified": row["updated_at"], "version": f'W/"{row["updated_at"]}"'},
    }
    if base_url:
        resource["meta"]["location"] = f"{base_url.rstrip('/')}/scim/v2/Users/{row['id']}"
    return resource


def group_resource(con: sqlite3.Connection, row: sqlite3.Row, *, base_url: str = "") -> dict[str, Any]:
    members = [
        {
            "value": member["id"],
            "display": member["display_name"] or member["user_name"],
        }
        for member in con.execute(
            """
            SELECT i.id, i.user_name, i.display_name
            FROM group_members gm
            JOIN identities i ON i.id = gm.identity_id
            WHERE gm.group_id = ?
            ORDER BY i.user_name
            """,
            (row["id"],),
        ).fetchall()
    ]
    resource = {
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": row["id"],
        "externalId": row["external_id"],
        "displayName": row["display_name"],
        "members": members,
        "meta": {"resourceType": "Group", "created": row["created_at"], "lastModified": row["updated_at"], "version": f'W/"{row["updated_at"]}"'},
    }
    if base_url:
        resource["meta"]["location"] = f"{base_url.rstrip('/')}/scim/v2/Groups/{row['id']}"
    return resource


def list_response(resources: list[dict[str, Any]], *, start_index: int, count: int, total: int | None = None) -> dict[str, Any]:
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(resources) if total is None else int(total),
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": resources,
    }


def error(status: int, message: str, scim_type: str | None = None) -> dict[str, Any]:
    data = {"schemas": [SCIM_ERROR_SCHEMA], "status": str(status), "detail": message}
    if scim_type:
        data["scimType"] = scim_type
    return data


def primary_email(payload: dict[str, Any]) -> str | None:
    emails = payload.get("emails") or []
    for item in emails:
        if item.get("primary") and item.get("value"):
            return str(item["value"])
    if emails and emails[0].get("value"):
        return str(emails[0]["value"])
    return None


def parse_eq_filter(filter_query: str) -> tuple[str | None, str | None]:
    parts = filter_query.split(" eq ", 1)
    if len(parts) != 2:
        return None, None
    field = parts[0].strip()
    value = parts[1].strip().strip('"')
    return field, value
