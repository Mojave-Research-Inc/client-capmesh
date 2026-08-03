"""Regression test for the cap.search concurrency deadlock.

Before the fix, cap.search's per-candidate discovery check (can_discover -> can_load ->
evaluate_access) wrote a `policy_decisions` row and never committed it. Under the threaded
HTTP server each thread keeps its own connection, so that uncommitted write held SQLite's
single write lock: the first search was fast, every concurrent/subsequent search blocked on
`busy_timeout`. The fix passes `audit=False` on the bulk discovery path so search performs
no write and never holds the write lock.

This test seeds a tiny mesh, then runs `search()` from many threads on independent
connections (mimicking serve-http) and asserts none blocks. On the pre-fix code the second+
concurrent search would block for the full busy_timeout and this test would time out/fail.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from capmesh.index import connect, init_db, rebuild_index, search
from capmesh.models import Principal


def _member() -> Principal:
    return Principal(subject="test-user@example.com", tenant_id="asg", groups=[], scopes=["cap:*"], authenticated=True)


class SearchConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        # keep any regression FAST-failing rather than hanging the suite
        os.environ["CAPMESH_BUSY_TIMEOUT_MS"] = "3000"
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        plugin = root / "plugins" / "demo-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / "skills" / "write-brief").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "demo-plugin", "version": "1.0.0", "description": "Demo."}), encoding="utf-8"
        )
        (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
            "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n# Write Brief\n",
            encoding="utf-8",
        )
        self.db = root / "mesh.db"
        rebuild_index(self.db, [root / "plugins"], enable_vector=False)

    def tearDown(self) -> None:
        self.tmp.cleanup()
        os.environ.pop("CAPMESH_BUSY_TIMEOUT_MS", None)

    def _one_search(self) -> float:
        """Open an independent connection (per-thread, like serve-http) and time a search."""
        con = connect(self.db)
        init_db(con, enable_vector=False)
        t0 = time.monotonic()
        search(con, "brief", _member(), k=3)
        dt = time.monotonic() - t0
        con.close()
        return dt

    def test_sequential_searches_do_not_block(self) -> None:
        for i in range(10):
            dt = self._one_search()
            self.assertLess(dt, 2.0, f"sequential search #{i} took {dt:.2f}s (write-lock regression?)")

    def test_parallel_searches_do_not_deadlock(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(self._one_search) for _ in range(8)]
            times = [f.result(timeout=15) for f in futures]
        for i, dt in enumerate(times):
            self.assertLess(dt, 5.0, f"parallel search #{i} took {dt:.2f}s (write-lock regression?)")


if __name__ == "__main__":
    unittest.main()
