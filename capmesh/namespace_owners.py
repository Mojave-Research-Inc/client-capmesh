"""Namespace owner management and transfer policy.

Provides queries for the namespace owner map and a governed transfer
flow that requires admin authorization and records a full audit trail.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import json_dumps, new_id, utc_now


def namespace_owner_map(con: sqlite3.Connection, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """Return a list of namespaces with their owners and capability counts."""
    rows = con.execute(
        """
        SELECT n.id, n.name, n.owner, n.lifecycle, n.visibility,
               s.name as store_name, s.kind as store_kind,
               (SELECT COUNT(*) FROM capabilities c WHERE c.namespace_id = n.id AND c.tenant_id = n.tenant_id) as cap_count
        FROM namespaces n
        LEFT JOIN stores s ON s.id = n.store_id
        WHERE n.tenant_id = ?
        ORDER BY n.name
        """,
        (tenant_id,),
    ).fetchall()
    return [
        {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "owner": str(row["owner"]),
            "lifecycle": str(row["lifecycle"]),
            "visibility": str(row["visibility"]),
            "storeName": str(row["store_name"]) if row["store_name"] else None,
            "storeKind": str(row["store_kind"]) if row["store_kind"] else None,
            "capabilityCount": int(row["cap_count"]),
        }
        for row in rows
    ]


def namespaces_by_owner(con: sqlite3.Connection, owner: str, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """Return all namespaces owned by a specific owner."""
    rows = con.execute(
        """
        SELECT n.id, n.name, n.owner, n.lifecycle, n.visibility, n.description,
               (SELECT COUNT(*) FROM capabilities c WHERE c.namespace_id = n.id) as cap_count
        FROM namespaces n
        WHERE n.tenant_id = ? AND n.owner = ?
        ORDER BY n.name
        """,
        (tenant_id, owner),
    ).fetchall()
    return [
        {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "owner": str(row["owner"]),
            "lifecycle": str(row["lifecycle"]),
            "visibility": str(row["visibility"]),
            "description": str(row["description"]),
            "capabilityCount": int(row["cap_count"]),
        }
        for row in rows
    ]


def transfer_namespace(
    con: sqlite3.Connection,
    namespace_id: str,
    new_owner: str,
    *,
    actor: str,
    tenant_id: str = "asg",
    reason: str = "",
    commit: bool = True,
) -> dict[str, Any]:
    """Transfer namespace ownership to a new owner with audit trail.

    Requires platform_admin or org_admin role (enforced by caller).
    Records an audit event with the full transfer details.
    """
    row = con.execute(
        "SELECT id, name, owner FROM namespaces WHERE id = ? AND tenant_id = ?",
        (namespace_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Namespace not found: {namespace_id}")
    old_owner = str(row["owner"])
    if old_owner == new_owner:
        raise ValueError("New owner is the same as current owner")
    con.execute(
        "UPDATE namespaces SET owner = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_owner, namespace_id),
    )
    # Update capabilities in this namespace to reflect new ownership
    con.execute(
        "UPDATE capabilities SET owner = ?, updated_at = CURRENT_TIMESTAMP WHERE namespace_id = ? AND tenant_id = ?",
        (new_owner, namespace_id, tenant_id),
    )
    con.execute(
        """INSERT INTO audit_events(id, tenant_id, event_type, actor, target, action, decision, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("ae"), tenant_id, "namespace.transfer",
            actor, namespace_id, "transfer", "allow",
            json_dumps({
                "namespaceName": str(row["name"]),
                "fromOwner": old_owner,
                "toOwner": new_owner,
                "reason": reason,
            }),
            utc_now(),
        ),
    )
    if commit:
        con.commit()
    return {
        "namespaceId": namespace_id,
        "namespaceName": str(row["name"]),
        "fromOwner": old_owner,
        "toOwner": new_owner,
        "reason": reason,
        "actor": actor,
    }
