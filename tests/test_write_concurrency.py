"""Concurrent write/read concurrency test for the SQLite storage layer.

The audit (docs/review/CAPMESH-CONCURRENCY-AUDIT-2026-07-30.md) flagged that
the write path was unguarded by an automated test: cap.search (read) was
exercised concurrently by test_search_concurrency.py, but no test ran
concurrent MUTATING operations to confirm WAL + busy_timeout keeps writers
safe (no SQLITE_BUSY deadlock, no lost updates) under parallel load. Under
100s of concurrent requests bursts of writes hit the single WAL database,
and a missing per-connection busy_timeout would fail fast with SQLITE_BUSY.

This test seeds a tiny mesh, then runs a mix of:
  - concurrent READERS: independent per-thread connections running cap.search
    (the hot read path, mimicking serve-http's ThreadingHTTPServer threads), and
  - concurrent WRITERS: independent per-thread connections each upserting a
    DISTINCT key into the ``meta`` table (the same safe write target
    test_server_shutdown.py uses), so writes are to disjoint keys.

It asserts:
1. No writer raises sqlite3.OperationalError("database is locked") / BUSY —
   the WAL + busy_timeout path must serialize writers cleanly.
2. Every distinct-key write is durable afterwards (no lost updates): the post-
   run meta table contains every key each writer wrote.
3. Concurrent readers do not deadlock or stall past the busy_timeout under
   write pressure — a write-lock regression that held the lock uncommitted
   would make readers block for the full busy_timeout and fail the bound.

Self-contained: temp state dir, loopback-only, no live remote, no network.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from capmesh.index import connect, init_db, rebuild_index, search
from capmesh.models import Principal


def _member() -> Principal:
    return Principal(
        subject="test-user@example.com", tenant_id="asg", groups=[], scopes=["cap:*"], authenticated=True
    )


def _make_plugin(root: Path) -> Path:
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
    return root / "plugins"


class WriteConcurrencyTests(unittest.TestCase):
    READERS = 8
    WRITERS = 8
    WRITES_PER_WRITER = 12

    def setUp(self) -> None:
        # Short busy_timeout so a write-lock regression fails the time bound
        # instead of silently blocking for 60s.
        os.environ["CAPMESH_BUSY_TIMEOUT_MS"] = "3000"
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.plugins_root = _make_plugin(self.root)
        self.db = self.root / "mesh.db"
        rebuild_index(self.db, [self.plugins_root], enable_vector=False)

    def tearDown(self) -> None:
        self.tmp.cleanup()
        os.environ.pop("CAPMESH_BUSY_TIMEOUT_MS", None)

    def _reader_once(self) -> float:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        try:
            t0 = time.monotonic()
            search(con, "brief", _member(), k=3)
            return time.monotonic() - t0
        finally:
            con.close()

    def _writer_once(self, writer_id: int, n: int) -> str:
        """Upsert a distinct meta key/value and return the key written."""
        key = f"wc-{writer_id}-{n}"
        value = f"v-{writer_id}-{n}-{time.monotonic_ns()}"
        con = connect(self.db)
        init_db(con, enable_vector=False)
        try:
            con.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            con.commit()
            return key
        finally:
            con.close()

    def test_concurrent_reads_and_disjoint_writes_are_safe(self) -> None:
        """Concurrent readers + disjoint-key writers: no BUSY, no lost updates, no read stall."""
        expected_keys: set[str] = set()
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.READERS + self.WRITERS
        ) as ex:
            read_futures = [ex.submit(self._reader_once) for _ in range(self.READERS)]
            write_futures = []
            for w in range(self.WRITERS):
                for n in range(self.WRITES_PER_WRITER):
                    write_futures.append(ex.submit(self._writer_once, w, n))
                    expected_keys.add(f"wc-{w}-{n}")

            # Any OperationalError(BUSY) raised by a writer surfaces here and fails.
            read_times = [f.result(timeout=30) for f in read_futures]
            written_keys = [f.result(timeout=30) for f in write_futures]

        # 1. No writer raised a locked-database error (reaching here proves it),
        #    and every writer returned the key it wrote.
        self.assertEqual(len(written_keys), self.WRITERS * self.WRITES_PER_WRITER)
        self.assertEqual(set(written_keys), expected_keys)

        # 2. Durability: every distinct-key write is present in the meta table
        #    afterwards — no lost updates from concurrent WAL writers.
        verify = sqlite3.connect(self.db)
        try:
            present = {row[0] for row in verify.execute("SELECT key FROM meta WHERE key LIKE 'wc-%'")}
        finally:
            verify.close()
        self.assertEqual(present, expected_keys, "a concurrent write was lost (lost-update regression)")

        # 3. Concurrent readers did not stall past the busy_timeout under write
        #    pressure. A write-lock regression that held an uncommitted write
        #    would block readers for the full 3s busy_timeout each.
        max_read = max(read_times)
        self.assertLess(
            max_read,
            3.0,
            f"slowest concurrent reader took {max_read:.2f}s under write pressure — write-lock regression?",
        )

    def test_concurrent_writes_to_disjoint_keys_all_durable(self) -> None:
        """Burst of 48 concurrent disjoint-key writers: all durable, no BUSY."""
        total = 48
        with concurrent.futures.ThreadPoolExecutor(max_workers=total) as ex:
            futures = [
                ex.submit(self._writer_once, i // 12, i % 12)
                for i in range(total)
            ]
            keys = [f.result(timeout=30) for f in futures]
        self.assertEqual(len(set(keys)), total, "distinct-key writes collided")

        verify = sqlite3.connect(self.db)
        try:
            present = {row[0] for row in verify.execute("SELECT key FROM meta WHERE key LIKE 'wc-%'")}
        finally:
            verify.close()
        self.assertEqual(present, set(keys), "a burst write was lost")


if __name__ == "__main__":
    unittest.main()
