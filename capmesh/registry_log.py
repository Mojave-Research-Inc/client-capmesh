"""Tamper-evident append-only registry log.

Records capability registry mutations (ingest, update, delete, promotion)
in a hash-chained append-only log. Each entry includes the hash of the
previous entry, making tampering detectable through chain verification.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from .utils import json_dumps, new_id, utc_now


def ensure_registry_log_table(con: sqlite3.Connection) -> None:
    """Create the registry_log table if it does not exist."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS registry_log (
            id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            target_uri TEXT,
            action TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            prev_hash TEXT,
            entry_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_registry_log_seq ON registry_log(sequence);
        CREATE INDEX IF NOT EXISTS idx_registry_log_hash ON registry_log(entry_hash);
        """
    )


def _compute_entry_hash(sequence: int, event_type: str, actor: str, target_uri: str | None, action: str, payload_json: str, prev_hash: str | None) -> str:
    """Compute the SHA-256 hash of a registry log entry."""
    parts = [str(sequence), event_type, actor, target_uri or "", action, payload_json, prev_hash or ""]
    combined = "|".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def append_log_entry(
    con: sqlite3.Connection,
    event_type: str,
    actor: str,
    action: str,
    *,
    target_uri: str | None = None,
    payload: dict[str, Any] | None = None,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Append a new entry to the tamper-evident registry log."""
    ensure_registry_log_table(con)
    # Get the current highest sequence number and its hash
    last = con.execute(
        "SELECT sequence, entry_hash FROM registry_log ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if last is None:
        sequence = 1
        prev_hash = None
    else:
        sequence = int(last["sequence"]) + 1
        prev_hash = str(last["entry_hash"])
    payload_str = json_dumps(payload or {})
    entry_hash = _compute_entry_hash(sequence, event_type, actor, target_uri, action, payload_str, prev_hash)
    entry_id = new_id("rlog")
    con.execute(
        """INSERT INTO registry_log(id, sequence, event_type, actor, target_uri, action, payload_json, prev_hash, entry_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (entry_id, sequence, event_type, actor, target_uri, action, payload_str, prev_hash, entry_hash, utc_now()),
    )
    if commit:
        con.commit()
    return {
        "id": entry_id,
        "sequence": sequence,
        "entryHash": entry_hash,
        "prevHash": prev_hash,
        "eventType": event_type,
        "action": action,
    }


def verify_log_chain(con: sqlite3.Connection) -> dict[str, Any]:
    """Verify the integrity of the registry log hash chain."""
    ensure_registry_log_table(con)
    rows = con.execute(
        "SELECT * FROM registry_log ORDER BY sequence ASC"
    ).fetchall()
    if not rows:
        return {"valid": True, "entries": 0, "brokenAt": None}
    prev_hash: str | None = None
    for row in rows:
        expected_prev = prev_hash
        actual_prev = str(row["prev_hash"]) if row["prev_hash"] else None
        if expected_prev != actual_prev:
            return {"valid": False, "entries": len(rows), "brokenAt": int(row["sequence"]), "reason": "prev_hash mismatch"}
        expected_hash = _compute_entry_hash(
            int(row["sequence"]), str(row["event_type"]), str(row["actor"]),
            str(row["target_uri"]) if row["target_uri"] else None,
            str(row["action"]), str(row["payload_json"]), actual_prev,
        )
        if expected_hash != str(row["entry_hash"]):
            return {"valid": False, "entries": len(rows), "brokenAt": int(row["sequence"]), "reason": "entry_hash mismatch"}
        prev_hash = str(row["entry_hash"])
    return {"valid": True, "entries": len(rows), "brokenAt": None, "lastHash": prev_hash}


def list_log_entries(con: sqlite3.Connection, *, limit: int = 50, offset: int = 0, event_type: str | None = None) -> list[dict[str, Any]]:
    """List registry log entries with optional filtering."""
    ensure_registry_log_table(con)
    query = "SELECT * FROM registry_log"
    params: list[Any] = []
    if event_type:
        query += " WHERE event_type = ?"
        params.append(event_type)
    query += " ORDER BY sequence DESC LIMIT ? OFFSET ?"
    params.extend([min(max(limit, 1), 500), offset])
    rows = con.execute(query, tuple(params)).fetchall()
    return [
        {
            "id": str(row["id"]),
            "sequence": int(row["sequence"]),
            "eventType": str(row["event_type"]),
            "actor": str(row["actor"]),
            "targetUri": str(row["target_uri"]) if row["target_uri"] else None,
            "action": str(row["action"]),
            "payload": json.loads(str(row["payload_json"])) if row["payload_json"] else {},
            "prevHash": str(row["prev_hash"]) if row["prev_hash"] else None,
            "entryHash": str(row["entry_hash"]),
            "createdAt": str(row["created_at"]),
        }
        for row in rows
    ]


def get_log_head(con: sqlite3.Connection) -> dict[str, Any]:
    """Return the latest entry in the registry log."""
    ensure_registry_log_table(con)
    row = con.execute(
        "SELECT sequence, entry_hash, created_at FROM registry_log ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return {"empty": True, "sequence": 0, "hash": None}
    return {
        "empty": False,
        "sequence": int(row["sequence"]),
        "hash": str(row["entry_hash"]),
        "createdAt": str(row["created_at"]),
    }
