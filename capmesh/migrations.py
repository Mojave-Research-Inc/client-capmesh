"""Versioned migration runner for the capmesh SQLite schema."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from typing import Any

_MIGRATIONS_LOGGER = logging.getLogger("capmesh.migrations")

MigrationFn = Callable[[sqlite3.Connection], None]

REGISTRY: list[tuple[int, str, MigrationFn]] = []


def migration(version: int, description: str) -> Callable[[MigrationFn], MigrationFn]:
    """Register a migration with its version number and description."""
    def decorator(fn: MigrationFn) -> MigrationFn:
        REGISTRY.append((version, description, fn))
        REGISTRY.sort(key=lambda m: m[0])
        return fn
    return decorator


def current_version(con: sqlite3.Connection) -> int:
    """Return the recorded schema version, or 0 for a fresh DB."""
    row = con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        return 0
    try:
        return int(row[0])
    except (ValueError, TypeError):
        return 0


def pending_migrations(con: sqlite3.Connection) -> list[tuple[int, str, MigrationFn]]:
    """Return migrations not yet applied to this database."""
    current = current_version(con)
    return [(v, d, fn) for v, d, fn in REGISTRY if v > current]


def run_migrations(con: sqlite3.Connection, *, commit: bool = True) -> dict[str, Any]:
    """Apply all pending migrations in version order.

    Migrations are additive-only and idempotent. A failure stops the chain
    but does not roll back earlier migrations (they are already committed).
    """
    pending = pending_migrations(con)
    if not pending:
        cv = current_version(con)
        return {"applied": 0, "failed": 0, "fromVersion": cv, "toVersion": cv, "migrations": []}

    results: list[dict[str, Any]] = []
    applied = 0
    failed = 0
    last_good_version = current_version(con)

    for version, description, fn in pending:
        try:
            fn(con)
            con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(version),))
            applied += 1
            last_good_version = version
            results.append({"version": version, "description": description, "status": "applied"})
        except Exception as exc:
            failed += 1
            results.append({"version": version, "description": description, "status": "failed", "error": str(exc)})
            break

    if commit:
        con.commit()

    return {
        "applied": applied,
        "failed": failed,
        "fromVersion": pending[0][0],
        "toVersion": last_good_version,
        "migrations": results,
    }


def migration_status(con: sqlite3.Connection) -> dict[str, Any]:
    """Report current schema version and pending migrations."""
    current = current_version(con)
    pending = pending_migrations(con)
    return {
        "currentVersion": current,
        "latestVersion": REGISTRY[-1][0] if REGISTRY else 0,
        "pendingCount": len(pending),
        "pending": [{"version": v, "description": d} for v, d, _ in pending],
        "upToDate": len(pending) == 0,
    }


def register_builtin_migrations() -> None:
    """Register built-in migrations that run on init_db."""
    from .governance import ensure_columns

    @migration(1, "Add source_commit and license columns to capabilities")
    def _v1(con: sqlite3.Connection) -> None:
        ensure_columns(con, "capabilities", {"source_commit": "TEXT", "license": "TEXT"})

    @migration(2, "Add break_glass_sessions table")
    def _v2(con: sqlite3.Connection) -> None:
        con.execute(
            "CREATE TABLE IF NOT EXISTS break_glass_sessions ("
            "id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal TEXT NOT NULL, "
            "reason TEXT NOT NULL, granted_by TEXT NOT NULL, expires_at TEXT NOT NULL, "
            "revoked_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )

    @migration(3, "Add CapGuard quarantine and signed-attestation tables")
    def _v3(con: sqlite3.Connection) -> None:
        from .capguard import ensure_quarantine_tables
        ensure_quarantine_tables(con)
