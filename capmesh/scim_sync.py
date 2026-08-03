"""SCIM sync for entitlement groups.

Synchronizes entitlement groups from external identity providers
(Entra ID, Okta, etc.) via the SCIM 2.0 protocol. Maps SCIM groups
to capmesh namespace membership and role assignments.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import new_id, utc_now

SCIM_SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"


def ensure_scim_tables(con: sqlite3.Connection) -> None:
    """Create SCIM sync tracking tables."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS scim_entitlement_sync (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            source TEXT NOT NULL,
            last_sync_at TEXT,
            last_sync_count INTEGER DEFAULT 0,
            last_error TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scim_group_mappings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            scim_group_id TEXT NOT NULL,
            scim_group_display TEXT,
            mesh_namespace_id TEXT,
            mesh_role TEXT NOT NULL DEFAULT 'member',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, scim_group_id)
        );
        """
    )


def upsert_group_mapping(
    con: sqlite3.Connection,
    scim_group_id: str,
    *,
    display_name: str | None = None,
    mesh_namespace_id: str | None = None,
    mesh_role: str = "member",
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Create or update a SCIM group to mesh mapping."""
    ensure_scim_tables(con)
    mapping_id = new_id("scm")
    con.execute(
        """INSERT INTO scim_group_mappings(id, tenant_id, scim_group_id, scim_group_display, mesh_namespace_id, mesh_role)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, scim_group_id) DO UPDATE SET
               scim_group_display=excluded.scim_group_display,
               mesh_namespace_id=excluded.mesh_namespace_id,
               mesh_role=excluded.mesh_role""",
        (mapping_id, tenant_id, scim_group_id, display_name, mesh_namespace_id, mesh_role),
    )
    if commit:
        con.commit()
    return {
        "scimGroupId": scim_group_id,
        "displayName": display_name,
        "meshNamespaceId": mesh_namespace_id,
        "meshRole": mesh_role,
    }


def list_group_mappings(con: sqlite3.Connection, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """List all SCIM group mappings."""
    ensure_scim_tables(con)
    rows = con.execute(
        "SELECT * FROM scim_group_mappings WHERE tenant_id = ? ORDER BY scim_group_display",
        (tenant_id,),
    ).fetchall()
    return [
        {
            "scimGroupId": str(row["scim_group_id"]),
            "displayName": str(row["scim_group_display"]) if row["scim_group_display"] else None,
            "meshNamespaceId": str(row["mesh_namespace_id"]) if row["mesh_namespace_id"] else None,
            "meshRole": str(row["mesh_role"]),
        }
        for row in rows
    ]


def process_scim_group(
    con: sqlite3.Connection,
    scim_group: dict[str, Any],
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Process a SCIM group payload and update mesh mappings."""
    ensure_scim_tables(con)
    group_id = str(scim_group.get("id", ""))
    display_name = str(scim_group.get("displayName", ""))
    members = scim_group.get("members", [])
    if not group_id:
        raise ValueError("SCIM group missing id")
    # Upsert the group mapping
    upsert_group_mapping(con, group_id, display_name=display_name, tenant_id=tenant_id, commit=False)
    # Record sync state
    sync_id = new_id("sync")
    con.execute(
        """INSERT INTO scim_entitlement_sync(id, tenant_id, source, last_sync_at, last_sync_count, last_error)
           VALUES (?, ?, ?, ?, ?, NULL)""",
        (sync_id, tenant_id, "scim", utc_now(), len(members) if isinstance(members, list) else 0),
    )
    if commit:
        con.commit()
    return {
        "groupId": group_id,
        "displayName": display_name,
        "memberCount": len(members) if isinstance(members, list) else 0,
        "synced": True,
    }


def sync_entitlement_groups(
    con: sqlite3.Connection,
    scim_groups: list[dict[str, Any]],
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Sync a batch of SCIM groups to mesh entitlement mappings."""
    ensure_scim_tables(con)
    results: list[dict[str, Any]] = []
    for group in scim_groups:
        try:
            result = process_scim_group(con, group, tenant_id=tenant_id, commit=False)
            results.append(result)
        except Exception as exc:
            results.append({"groupId": str(group.get("id", "?")), "error": str(exc)})
    if commit:
        con.commit()
    return {
        "synced": len(results),
        "errors": sum(1 for r in results if "error" in r),
        "results": results,
    }
