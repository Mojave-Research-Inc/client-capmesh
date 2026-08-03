"""CM-13 router observability slice: request-id + structured log per dispatch.

These tests exercise the ``capmesh.router`` request-id resolution and the one
structured log line emitted at the start of each ``cap.<verb>`` dispatch. They
do not assert on dispatch return values (that is covered elsewhere) beyond a
behaviour-preserved sanity check; the focus is the observability contract.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db, rebuild_index
from capmesh.router import CapabilityRouter


class RouterRequestIdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(self.restore_state_dir)
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        plugin = self.root / "plugins" / "demo-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / "skills" / "write-brief").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "demo-plugin", "version": "1.2.3", "description": "Demo plugin."}),
            encoding="utf-8",
        )
        (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
            "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n# Write Brief\nUse for executive summaries.\n",
            encoding="utf-8",
        )
        self.db = self.root / "mesh.db"
        rebuild_index(self.db, [self.root / "plugins"], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        self.router = CapabilityRouter(self.con, roots=(str(self.root / "plugins"),))

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    def test_request_id_from_header(self) -> None:
        """A request-id passed via the ``request_id`` kwarg is carried into the log line."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            self.router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-from-header-123",
            )
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].request_id, "req-from-header-123")

    def test_request_id_generated_when_absent(self) -> None:
        """A dispatch with no ``request_id`` generates a non-empty id."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            self.router.call("cap.search", {"query": "executive brief", "type": "skill"})
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0].request_id)
        self.assertIsInstance(matching[0].request_id, str)
        self.assertGreater(len(matching[0].request_id), 0)

    def test_structured_log_emitted(self) -> None:
        """A ``cap.*`` verb dispatch emits exactly one log record with request_id, subject, verb."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            self.router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-abc",
            )
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1, "exactly one cap.search log record expected")
        record = matching[0]
        self.assertEqual(record.request_id, "req-abc")
        self.assertEqual(record.verb, "search")
        self.assertTrue(record.subject)
        self.assertTrue(hasattr(record, "tenant"))

    def test_dispatch_result_unchanged(self) -> None:
        """The dispatch still returns the same result with logging enabled (no behaviour change)."""
        # Suppress the structured log so it does not pollute test output; the
        # result contract is what we assert here, not the log.
        with self.assertLogs("capMesh.router", level="INFO"):
            result = self.router.call("cap.search", {"query": "executive brief", "type": "skill"})
        self.assertFalse(result["isError"])
        self.assertIn("results", result["structuredContent"])
        self.assertGreaterEqual(len(result["structuredContent"]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
