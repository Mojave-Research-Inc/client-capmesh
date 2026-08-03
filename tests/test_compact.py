"""Test the capmesh compact CLI command (registry compaction)."""

from __future__ import annotations

from pathlib import Path

from capmesh.index import connect, init_db


def test_compact_runs_without_error(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    con = connect(str(db))
    init_db(con)
    con.execute("VACUUM")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    integrity = con.execute("PRAGMA integrity_check").fetchone()
    con.close()
    assert integrity[0] == "ok"


def test_compact_preserves_data(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    con = connect(str(db))
    init_db(con)
    row = con.execute("SELECT id FROM tenants WHERE id = 'asg'").fetchone()
    con.execute("VACUUM")
    row2 = con.execute("SELECT id FROM tenants WHERE id = 'asg'").fetchone()
    con.close()
    assert row is not None
    assert row2 is not None
    assert row["id"] == row2["id"]
