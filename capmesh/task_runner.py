"""Agent-runner integration for cap.delegate task envelopes.

Provides a stub runner that processes queued task envelopes created
by the cap.delegate tool. Each envelope has a status (queued, running,
completed, failed) and is processed asynchronously.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .utils import json_dumps, json_loads, new_id, utc_now

TASK_STATUSES = frozenset({"queued", "running", "completed", "failed", "cancelled"})


def ensure_task_table(con: sqlite3.Connection) -> None:
    """Create the task_envelopes table if it does not exist."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS task_envelopes (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            capability_uri TEXT NOT NULL,
            principal TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
            task_envelope_json TEXT NOT NULL,
            result_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_task_envelopes_status ON task_envelopes(status, tenant_id);
        CREATE INDEX IF NOT EXISTS idx_task_envelopes_uri ON task_envelopes(capability_uri);
        """
    )


def create_task_envelope(
    con: sqlite3.Connection,
    capability_uri: str,
    principal: str,
    task_envelope: dict[str, Any],
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Create a queued task envelope for later processing."""
    ensure_task_table(con)
    task_id = new_id("task")
    con.execute(
        """INSERT INTO task_envelopes(id, tenant_id, capability_uri, principal, status, task_envelope_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)""",
        (task_id, tenant_id, capability_uri, principal, json_dumps(task_envelope), utc_now(), utc_now()),
    )
    if commit:
        con.commit()
    return {
        "taskId": task_id,
        "capabilityUri": capability_uri,
        "principal": principal,
        "status": "queued",
    }


def list_queued_tasks(con: sqlite3.Connection, *, tenant_id: str = "asg", limit: int = 50) -> list[dict[str, Any]]:
    """List queued task envelopes awaiting processing."""
    ensure_task_table(con)
    rows = con.execute(
        "SELECT * FROM task_envelopes WHERE status = 'queued' AND tenant_id = ? ORDER BY created_at ASC LIMIT ?",
        (tenant_id, min(max(limit, 1), 200)),
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def process_task(
    con: sqlite3.Connection,
    task_id: str,
    handler,
    *,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Process a single task envelope with the provided handler function.

    The handler receives the task envelope dict and returns a result dict.
    On success, the task is marked completed. On failure, it is marked failed.
    """
    ensure_task_table(con)
    row = con.execute(
        "SELECT * FROM task_envelopes WHERE id = ? AND tenant_id = ?",
        (task_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Task not found: {task_id}")
    if str(row["status"]) not in ("queued", "failed"):
        raise ValueError(f"Task is not in a processable state: {row['status']}")
    # Mark as running
    con.execute(
        "UPDATE task_envelopes SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?",
        (utc_now(), utc_now(), task_id),
    )
    if commit:
        con.commit()
    try:
        envelope = json_loads(str(row["task_envelope_json"]), {})
        result = handler(envelope)
        con.execute(
            "UPDATE task_envelopes SET status = 'completed', result_json = ?, completed_at = ?, updated_at = ? WHERE id = ?",
            (json_dumps(result), utc_now(), utc_now(), task_id),
        )
        if commit:
            con.commit()
        return {"taskId": task_id, "status": "completed", "result": result}
    except Exception as exc:
        con.execute(
            "UPDATE task_envelopes SET status = 'failed', error = ?, updated_at = ? WHERE id = ?",
            (str(exc), utc_now(), task_id),
        )
        if commit:
            con.commit()
        return {"taskId": task_id, "status": "failed", "error": str(exc)}


def cancel_task(con: sqlite3.Connection, task_id: str, *, tenant_id: str = "asg", commit: bool = True) -> dict[str, Any]:
    """Cancel a queued or running task."""
    row = con.execute(
        "SELECT status FROM task_envelopes WHERE id = ? AND tenant_id = ?",
        (task_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Task not found: {task_id}")
    if str(row["status"]) not in ("queued", "running"):
        raise ValueError(f"Cannot cancel task in state: {row['status']}")
    con.execute(
        "UPDATE task_envelopes SET status = 'cancelled', updated_at = ? WHERE id = ?",
        (utc_now(), task_id),
    )
    if commit:
        con.commit()
    return {"taskId": task_id, "status": "cancelled"}


def task_status(con: sqlite3.Connection, task_id: str, *, tenant_id: str = "asg") -> dict[str, Any]:
    """Get the status of a task envelope."""
    ensure_task_table(con)
    row = con.execute(
        "SELECT * FROM task_envelopes WHERE id = ? AND tenant_id = ?",
        (task_id, tenant_id),
    ).fetchone()
    if row is None:
        raise ValueError(f"Task not found: {task_id}")
    return _row_to_dict(row)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "taskId": str(row["id"]),
        "tenantId": str(row["tenant_id"]),
        "capabilityUri": str(row["capability_uri"]),
        "principal": str(row["principal"]),
        "status": str(row["status"]),
        "taskEnvelope": json_loads(str(row["task_envelope_json"]), {}) if row["task_envelope_json"] else {},
        "result": json_loads(str(row["result_json"]), {}) if row["result_json"] else None,
        "error": str(row["error"]) if row["error"] else None,
        "createdAt": str(row["created_at"]),
        "startedAt": str(row["started_at"]) if row["started_at"] else None,
        "completedAt": str(row["completed_at"]) if row["completed_at"] else None,
    }
