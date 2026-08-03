#!/usr/bin/env python3
"""Hash capability and governance state while excluding node-local data.

Non-voting members localize capability source paths and generate their own
audit/policy telemetry, so a raw SQLite file hash cannot express parity. This
digest includes every field that affects discovery, loading, authorization,
promotion, organization membership, or authenticated service identity while
excluding localized source paths and derived indexes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


CAPABILITY_COLUMNS = (
    "uri",
    "canonical_key",
    "tenant_id",
    "store_id",
    "namespace_id",
    "type",
    "name",
    "version",
    "content_hash",
    "visibility",
    "discovery_mode",
    "owner",
    "plugin",
    "required_scopes_json",
    "allow_groups_json",
    "allow_users_json",
    "risk_tier",
    "mutating",
    "lifecycle",
    "created_by",
    "submitted_by",
    "promoted_from_uri",
    "approval_state",
    "share_state",
    "signature_status",
    "provenance_status",
    "risk_review_status",
)

# These tables are copied authoritatively and affect identity, authorization,
# namespace placement, approval state, or supported integrations. Node-local
# audit_events, policy_decisions, router_reports, FTS/vector tables, and
# capability_sources are deliberately excluded.
GOVERNANCE_TABLES = (
    "tenants",
    "identities",
    "groups",
    "group_members",
    "stores",
    "namespaces",
    "organizations",
    "namespace_members",
    "role_assignments",
    "relationship_tuples",
    "shares",
    "apps",
    "capmesh_sessions",
    "oauth_sessions",
    "promotion_requests",
    "approval_steps",
    "promotion_gate_runs",
    "capability_reviews",
    "graph_subscriptions",
    "teams_bindings",
    "scim_sync_state",
)


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    return value


def table_lines(con: sqlite3.Connection, table: str, columns: tuple[str, ...] | None = None) -> list[str]:
    exists = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if exists is None:
        return ["<absent>"]
    selected = columns or tuple(
        str(row[1]) for row in con.execute(f'PRAGMA table_info("{table}")').fetchall()
    )
    if not selected:
        return ["<no-columns>"]
    quoted = ",".join(f'"{column}"' for column in selected)
    rows = con.execute(f'SELECT {quoted} FROM "{table}"').fetchall()
    return sorted(
        json.dumps([json_value(value) for value in row], separators=(",", ":"), ensure_ascii=False)
        for row in rows
    )


def logical_digest(db_path: Path) -> str:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        digest = hashlib.sha256()
        for table, columns in (
            ("capabilities", CAPABILITY_COLUMNS),
            *((table, None) for table in GOVERNANCE_TABLES),
        ):
            digest.update(f"[{table}]\n".encode())
            for line in table_lines(con, table, columns):
                digest.update(line.encode())
                digest.update(b"\n")
        return digest.hexdigest()
    finally:
        con.close()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: logical-catalog-digest.py DB", file=sys.stderr)
        return 2
    db_path = Path(sys.argv[1])
    if not db_path.is_file():
        print(f"database not found: {db_path}", file=sys.stderr)
        return 2
    print(logical_digest(db_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
