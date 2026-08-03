"""Lifecycle transition enforcement for capabilities and namespaces.

Defines valid lifecycle states and the transitions between them.
Enforces that capabilities and namespaces can only move through
valid state transitions, with audit trail for each change.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import json_dumps, new_id, utc_now

# Valid lifecycle states for capabilities
CAPABILITY_LIFECYCLE_STATES = frozenset({"draft", "active", "deprecated", "retired", "published", "disabled", "deleted", "recalled", "yanked"})

# Valid lifecycle states for namespaces
NAMESPACE_LIFECYCLE_STATES = frozenset({"draft", "active", "deprecated", "retired"})

# Valid transitions: {from_state: {to_states}}
CAPABILITY_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"active", "deprecated", "retired", "published"}),
    "active": frozenset({"deprecated", "retired", "draft"}),
    "published": frozenset({"deprecated", "retired", "active"}),
    "deprecated": frozenset({"active", "retired"}),
    "retired": frozenset({"active", "deprecated"}),
    "disabled": frozenset({"active", "deleted"}),
    "deleted": frozenset(),
    "recalled": frozenset({"active", "draft"}),
    "yanked": frozenset({"active"}),
}

NAMESPACE_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"active", "deprecated", "retired"}),
    "active": frozenset({"deprecated", "retired", "draft"}),
    "deprecated": frozenset({"active", "retired"}),
    "retired": frozenset({"active"}),
}


def is_valid_transition(current: str, target: str, transitions: dict[str, frozenset[str]] | None = None) -> bool:
    """Check whether a lifecycle transition is valid."""
    table = transitions or CAPABILITY_TRANSITIONS
    if current == target:
        return True
    allowed = table.get(current, frozenset())
    return target in allowed


def transition_capability(
    con: sqlite3.Connection,
    uri: str,
    target_lifecycle: str,
    *,
    actor: str,
    tenant_id: str = "asg",
    reason: str = "",
    commit: bool = True,
) -> dict[str, Any]:
    """Transition a capability to a new lifecycle state with validation and audit."""
    if target_lifecycle not in CAPABILITY_LIFECYCLE_STATES:
        raise ValueError(f"Invalid lifecycle state: {target_lifecycle}")
    row = con.execute(
        "SELECT lifecycle, name, approval_state FROM capabilities WHERE uri = ? AND tenant_id = ?",
        (uri, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Capability not found: {uri}")
    current = str(row["lifecycle"])
    if not is_valid_transition(current, target_lifecycle):
        raise ValueError(f"Invalid transition: {current} -> {target_lifecycle}")
    con.execute(
        "UPDATE capabilities SET lifecycle = ?, updated_at = CURRENT_TIMESTAMP WHERE uri = ?",
        (target_lifecycle, uri),
    )
    # Record audit event
    con.execute(
        """INSERT INTO audit_events(id, tenant_id, event_type, actor, target, action, decision, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("ae"), tenant_id, "capability.lifecycle.transition",
            actor, uri, "transition", "allow",
            json_dumps({"from": current, "to": target_lifecycle, "reason": reason}),
            utc_now(),
        ),
    )
    if commit:
        con.commit()
    return {
        "uri": uri,
        "from": current,
        "to": target_lifecycle,
        "reason": reason,
        "actor": actor,
    }


def transition_namespace(
    con: sqlite3.Connection,
    namespace_id: str,
    target_lifecycle: str,
    *,
    actor: str,
    tenant_id: str = "asg",
    reason: str = "",
    commit: bool = True,
) -> dict[str, Any]:
    """Transition a namespace to a new lifecycle state with validation and audit."""
    if target_lifecycle not in NAMESPACE_LIFECYCLE_STATES:
        raise ValueError(f"Invalid namespace lifecycle state: {target_lifecycle}")
    row = con.execute(
        "SELECT lifecycle, name FROM namespaces WHERE id = ? AND tenant_id = ?",
        (namespace_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Namespace not found: {namespace_id}")
    current = str(row["lifecycle"])
    if not is_valid_transition(current, target_lifecycle, NAMESPACE_TRANSITIONS):
        raise ValueError(f"Invalid namespace transition: {current} -> {target_lifecycle}")
    con.execute(
        "UPDATE namespaces SET lifecycle = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (target_lifecycle, namespace_id),
    )
    con.execute(
        """INSERT INTO audit_events(id, tenant_id, event_type, actor, target, action, decision, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("ae"), tenant_id, "namespace.lifecycle.transition",
            actor, namespace_id, "transition", "allow",
            json_dumps({"from": current, "to": target_lifecycle, "reason": reason}),
            utc_now(),
        ),
    )
    if commit:
        con.commit()
    return {
        "namespaceId": namespace_id,
        "from": current,
        "to": target_lifecycle,
        "reason": reason,
        "actor": actor,
    }


def list_lifecycle_states(con: sqlite3.Connection, *, tenant_id: str = "asg") -> dict[str, Any]:
    """Return a summary of capability lifecycle state distribution."""
    rows = con.execute(
        "SELECT lifecycle, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY lifecycle ORDER BY count DESC",
        (tenant_id,),
    ).fetchall()
    return {
        "states": {str(row["lifecycle"]): int(row["count"]) for row in rows},
        "validStates": sorted(CAPABILITY_LIFECYCLE_STATES),
        "validTransitions": {k: sorted(v) for k, v in CAPABILITY_TRANSITIONS.items()},
    }
