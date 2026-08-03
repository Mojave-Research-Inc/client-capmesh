from __future__ import annotations

import sqlite3
from typing import Any

from .access_control import RIGHTS, evaluate_access
from .models import Principal
from .utils import DEFAULT_TENANT, json_dumps, json_loads, new_id, stable_id


def list_stores(
    con: sqlite3.Connection,
    principal: Principal,
    kind: str | None = None,
    ensure: bool = True,
) -> list[dict[str, Any]]:
    # `ensure` defaults True so every other caller keeps the original guarantee — the identity
    # and its stores exist before we list them. Only callers that have just provisioned within
    # the same request (current_user) pass False.
    if ensure:
        from .governance import ensure_identity_for_principal
        ensure_identity_for_principal(con, principal)
    params: list[Any] = [principal.tenant_id]
    where = ["tenant_id = ?", "disabled_at IS NULL"]
    if kind:
        where.append("kind = ?")
        params.append(kind)
    rows = con.execute(
        f"SELECT * FROM stores WHERE {' AND '.join(where)} ORDER BY kind, name",
        params,
    ).fetchall()
    return [store_record(row) for row in rows]


def create_store(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event, ensure_identity_for_principal, slug
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    kind = str(payload.get("kind") or "user_private")
    if kind not in {"user_private", "user_shared", "org", "app", "system", "all_users"}:
        raise ValueError("Unsupported store kind.")
    if kind in {"org", "system", "all_users"}:
        allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"tenant:{tenant_id}")
        if not allowed:
            raise PermissionError(reason)
    identity_id = ensure_identity_for_principal(con, principal)
    owner_app_id = payload.get("ownerAppId")
    store_id = str(payload.get("id") or new_id("store"))
    name = str(payload.get("name") or f"{kind} store")
    prefix = str(payload.get("uriPrefix") or default_store_prefix(tenant_id, kind, store_id, identity_id, owner_app_id))
    if kind == "app" and owner_app_id:
        con.execute(
            """
            INSERT OR IGNORE INTO apps(id, tenant_id, app_id, display_name, active, raw_json)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                owner_app_id,
                tenant_id,
                owner_app_id,
                str(payload.get("appDisplayName") or name),
                json_dumps({"auto": True, "source": "store.create"}),
            ),
        )
    con.execute(
        """
        INSERT INTO stores(id, tenant_id, kind, name, uri_prefix, owner_identity_id, owner_app_id, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (store_id, tenant_id, kind, name, prefix, identity_id if kind.startswith("user_") else payload.get("ownerIdentityId"), owner_app_id, json_dumps(payload.get("metadata") or {})),
    )
    if kind == "org":
        org_slug = str(payload.get("orgSlug") or slug(name))
        con.execute(
            """
            INSERT OR IGNORE INTO organizations(id, tenant_id, slug, display_name, store_id, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("orgId") or stable_id("org", tenant_id, org_slug)),
                tenant_id,
                org_slug,
                name,
                store_id,
                json_dumps(payload.get("metadata") or {}),
            ),
        )
    audit_event(con, event_type="store.created", actor=principal.subject, target=store_id, action="create", decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return store_record(con.execute("SELECT * FROM stores WHERE id = ?", (store_id,)).fetchone())


def default_store_prefix(tenant_id: str, kind: str, store_id: str, identity_id: str, owner_app_id: str | None) -> str:
    from .governance import all_users_store_prefix
    if kind == "org":
        return f"cap://org/{tenant_id}/{store_id}"
    if kind == "app":
        return f"cap://app/{tenant_id}/{owner_app_id or store_id}"
    if kind == "system":
        return f"cap://system/{tenant_id}/{store_id}"
    if kind == "all_users":
        # Deterministic, one-per-tenant prefix (NOT store_id-suffixed) so the
        # stores.uri_prefix UNIQUE constraint enforces a single all_users store
        # per tenant. See all_users_store_prefix().
        return all_users_store_prefix(tenant_id)
    label = "shared" if kind == "user_shared" else "private"
    return f"cap://user/{tenant_id}/{identity_id}/{label}/{store_id}"


def store_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "kind": row["kind"],
        "name": row["name"],
        "uriPrefix": row["uri_prefix"],
        "ownerIdentityId": row["owner_identity_id"],
        "ownerAppId": row["owner_app_id"],
        "metadata": json_loads(row["metadata_json"], {}),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def list_namespaces(con: sqlite3.Connection, principal: Principal, store_id: str | None = None) -> list[dict[str, Any]]:
    from .governance import ensure_identity_for_principal
    ensure_identity_for_principal(con, principal)
    params: list[Any] = [principal.tenant_id]
    where = ["tenant_id = ?"]
    if store_id:
        where.append("store_id = ?")
        params.append(store_id)
    rows = con.execute(
        f"SELECT * FROM namespaces WHERE {' AND '.join(where)} ORDER BY visibility, name",
        params,
    ).fetchall()
    return [namespace_record(row) for row in rows]


def create_namespace(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    store_id = str(payload.get("storeId") or "")
    if not store_id:
        raise ValueError("storeId is required.")
    store = con.execute("SELECT * FROM stores WHERE id = ? AND tenant_id = ?", (store_id, tenant_id)).fetchone()
    if store is None:
        raise ValueError("Store not found.")
    if store["kind"] in {"org", "system"}:
        allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"store:{store_id}")
        if not allowed:
            raise PermissionError(reason)
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("name is required.")
    visibility = str(payload.get("visibility") or "internal")
    if visibility not in {"public", "internal", "protected", "secret"}:
        raise ValueError("Unsupported visibility.")
    namespace_id = str(payload.get("id") or new_id("ns"))
    uri_prefix = str(payload.get("uriPrefix") or f"{store['uri_prefix'].rstrip('/')}/{name.strip('/')}")
    con.execute(
        """
        INSERT INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            namespace_id,
            tenant_id,
            store_id,
            name,
            uri_prefix,
            visibility,
            str(payload.get("owner") or principal.subject),
            str(payload.get("description") or ""),
            json_dumps(payload.get("metadata") or {}),
        ),
    )
    audit_event(con, event_type="namespace.created", actor=principal.subject, target=namespace_id, action="create", decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return namespace_record(con.execute("SELECT * FROM namespaces WHERE id = ?", (namespace_id,)).fetchone())


def namespace_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "storeId": row["store_id"],
        "name": row["name"],
        "uriPrefix": row["uri_prefix"],
        "visibility": row["visibility"],
        "owner": row["owner"],
        "description": row["description"],
        "lifecycle": row["lifecycle"],
        "metadata": json_loads(row["metadata_json"], {}),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def create_share(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event, ensure_identity_for_principal
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    capability_uri = str(payload.get("capabilityUri") or payload.get("uri") or "")
    if not capability_uri:
        raise ValueError("capabilityUri is required.")
    capability_row = con.execute("SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?", (capability_uri, tenant_id)).fetchone()
    if capability_row is None:
        raise ValueError("Capability not found.")
    from .index import capability_from_row

    capability = capability_from_row(capability_row)
    allowed, reason = evaluate_access(con, principal, right="share", capability=capability)
    if not allowed:
        raise PermissionError(reason)
    rights = tuple(str(item) for item in payload.get("rights", ("discover", "load", "call")))
    if not rights or any(right not in RIGHTS for right in rights):
        raise ValueError("rights contains an unsupported right.")
    for right in rights:
        allowed, reason = evaluate_access(con, principal, right=right, capability=capability)
        if not allowed:
            raise PermissionError(f"Cannot share {right!r}: {reason}")
    subject_type = str(payload.get("subjectType") or "user")
    subject_id = str(payload.get("subjectId") or "")
    if not subject_id:
        raise ValueError("subjectId is required.")
    from_identity_id = ensure_identity_for_principal(con, principal)
    share_id = new_id("shr")
    con.execute(
        """
        INSERT INTO shares(id, tenant_id, capability_uri, from_identity_id, subject_type, subject_id, rights_json, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (share_id, tenant_id, capability_uri, from_identity_id, subject_type, subject_id, json_dumps(list(rights)), payload.get("expiresAt")),
    )
    for right in rights:
        con.execute(
            """
            INSERT OR IGNORE INTO relationship_tuples(id, tenant_id, object, relation, user, source)
            VALUES (?, ?, ?, ?, ?, 'share')
            """,
            (new_id("rel"), tenant_id, capability_uri, right, f"{subject_type}:{subject_id}"),
        )
    con.execute("UPDATE capabilities SET share_state = 'shared' WHERE uri = ?", (capability_uri,))
    audit_event(con, event_type="share.created", actor=principal.subject, target=capability_uri, action="share", decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return share_record(con.execute("SELECT * FROM shares WHERE id = ?", (share_id,)).fetchone())


def revoke_share(con: sqlite3.Connection, principal: Principal, share_id: str) -> dict[str, Any]:
    from .governance import audit_event
    row = con.execute("SELECT * FROM shares WHERE id = ? AND tenant_id = ?", (share_id, principal.tenant_id)).fetchone()
    if row is None:
        raise ValueError("Share not found.")
    capability_row = con.execute(
        "SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?",
        (row["capability_uri"], principal.tenant_id),
    ).fetchone()
    if capability_row is None:
        raise ValueError("Capability not found.")
    from .index import capability_from_row

    capability = capability_from_row(capability_row)
    identity_id = principal.identity_id or stable_id("idn", principal.tenant_id or DEFAULT_TENANT, principal.subject)
    allowed, reason = evaluate_access(con, principal, right="share", capability=capability)
    if not allowed and row["from_identity_id"] != identity_id:
        raise PermissionError(reason)
    con.execute("UPDATE shares SET state = 'revoked', revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (share_id,))
    rights = json_loads(row["rights_json"], [])
    for right in rights:
        con.execute(
            "DELETE FROM relationship_tuples WHERE tenant_id = ? AND object = ? AND relation = ? AND user = ? AND source = 'share'",
            (principal.tenant_id, row["capability_uri"], right, f"{row['subject_type']}:{row['subject_id']}"),
        )
    audit_event(con, event_type="share.revoked", actor=principal.subject, target=row["capability_uri"], action="revoke", decision="allow", payload={"shareId": share_id}, tenant_id=principal.tenant_id)
    con.commit()
    return {"id": share_id, "state": "revoked"}


def list_shares(con: sqlite3.Connection, principal: Principal, capability_uri: str | None = None) -> list[dict[str, Any]]:
    params: list[Any] = [principal.tenant_id]
    where = ["tenant_id = ?"]
    if capability_uri:
        capability_row = con.execute(
            "SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?",
            (capability_uri, principal.tenant_id),
        ).fetchone()
        if capability_row is None:
            raise ValueError("Capability not found.")
        from .index import capability_from_row

        capability = capability_from_row(capability_row)
        allowed, reason = evaluate_access(con, principal, right="share", capability=capability)
        if not allowed:
            raise PermissionError(reason)
        where.append("capability_uri = ?")
        params.append(capability_uri)
    else:
        allowed, reason = evaluate_access(con, principal, right="audit", resource_uri=f"tenant:{principal.tenant_id}")
        if not allowed:
            raise PermissionError(reason)
    rows = con.execute(f"SELECT * FROM shares WHERE {' AND '.join(where)} ORDER BY created_at DESC", params).fetchall()
    return [share_record(row) for row in rows]


def share_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "capabilityUri": row["capability_uri"],
        "fromIdentityId": row["from_identity_id"],
        "subjectType": row["subject_type"],
        "subjectId": row["subject_id"],
        "rights": json_loads(row["rights_json"], []),
        "state": row["state"],
        "expiresAt": row["expires_at"],
        "revokedAt": row["revoked_at"],
        "createdAt": row["created_at"],
    }

