"""Bind Entra ID groups to mesh allow groups.

Maps Microsoft Entra ID (Azure AD) groups to capmesh capability
allow_groups, enabling Entra group membership to gate capability
access without manual user-by-user provisioning.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import new_id, utc_now


def ensure_entra_tables(con: sqlite3.Connection) -> None:
    """Create the entra_group_bindings table."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS entra_group_bindings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            entra_tenant_id TEXT NOT NULL,
            entra_group_id TEXT NOT NULL,
            entra_group_name TEXT,
            mesh_group_name TEXT NOT NULL,
            mesh_role TEXT NOT NULL DEFAULT 'member',
            bound_by TEXT NOT NULL,
            bound_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, entra_tenant_id, entra_group_id)
        );
        CREATE INDEX IF NOT EXISTS idx_entra_binding ON entra_group_bindings(entra_group_id);
        """
    )


def bind_entra_group(
    con: sqlite3.Connection,
    entra_tenant_id: str,
    entra_group_id: str,
    mesh_group_name: str,
    *,
    entra_group_name: str | None = None,
    mesh_role: str = "member",
    bound_by: str = "system",
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Bind an Entra ID group to a mesh allow group."""
    ensure_entra_tables(con)
    binding_id = new_id("egb")
    con.execute(
        """INSERT INTO entra_group_bindings(id, tenant_id, entra_tenant_id, entra_group_id, entra_group_name, mesh_group_name, mesh_role, bound_by, bound_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, entra_tenant_id, entra_group_id) DO UPDATE SET
               entra_group_name=excluded.entra_group_name,
               mesh_group_name=excluded.mesh_group_name,
               mesh_role=excluded.mesh_role""",
        (binding_id, tenant_id, entra_tenant_id, entra_group_id, entra_group_name, mesh_group_name, mesh_role, bound_by, utc_now()),
    )
    if commit:
        con.commit()
    return {
        "entraTenantId": entra_tenant_id,
        "entraGroupId": entra_group_id,
        "entraGroupName": entra_group_name,
        "meshGroupName": mesh_group_name,
        "meshRole": mesh_role,
        "boundBy": bound_by,
    }


def list_entra_bindings(con: sqlite3.Connection, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """List all Entra group bindings."""
    ensure_entra_tables(con)
    rows = con.execute(
        "SELECT * FROM entra_group_bindings WHERE tenant_id = ? ORDER BY bound_at DESC",
        (tenant_id,),
    ).fetchall()
    return [
        {
            "entraTenantId": str(row["entra_tenant_id"]),
            "entraGroupId": str(row["entra_group_id"]),
            "entraGroupName": str(row["entra_group_name"]) if row["entra_group_name"] else None,
            "meshGroupName": str(row["mesh_group_name"]),
            "meshRole": str(row["mesh_role"]),
            "boundBy": str(row["bound_by"]),
            "boundAt": str(row["bound_at"]),
        }
        for row in rows
    ]


def resolve_entra_groups_to_mesh_groups(
    con: sqlite3.Connection,
    entra_group_ids: list[str],
    *,
    tenant_id: str = "asg",
) -> list[str]:
    """Resolve a list of Entra group IDs to their bound mesh group names."""
    ensure_entra_tables(con)
    if not entra_group_ids:
        return []
    placeholders = ",".join("?" for _ in entra_group_ids)
    rows = con.execute(
        f"SELECT mesh_group_name FROM entra_group_bindings WHERE tenant_id = ? AND entra_group_id IN ({placeholders})",
        (tenant_id, *entra_group_ids),
    ).fetchall()
    return [str(row["mesh_group_name"]) for row in rows]


def remove_entra_binding(
    con: sqlite3.Connection,
    entra_tenant_id: str,
    entra_group_id: str,
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Remove an Entra group binding."""
    ensure_entra_tables(con)
    cur = con.execute(
        "DELETE FROM entra_group_bindings WHERE entra_tenant_id = ? AND entra_group_id = ? AND tenant_id = ?",
        (entra_tenant_id, entra_group_id, tenant_id),
    )
    if commit:
        con.commit()
    return {"removed": cur.rowcount > 0, "entraGroupId": entra_group_id}
