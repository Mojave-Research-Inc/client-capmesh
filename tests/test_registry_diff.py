"""Tests for the registry diff feature (capmesh diff --previous).

Verifies that registry_diff correctly identifies added capabilities when
comparing the current DB against a previous JSONL export, and raises on
missing previous files.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db, rebuild_index, registry_diff


class RegistryDiffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        plugin = self.root / "plugins" / "demo"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / "skills" / "cap-a").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "description": "Demo."}), encoding="utf-8"
        )
        (plugin / "skills" / "cap-a" / "SKILL.md").write_text(
            "---\nname: cap-a\ndescription: Capability A.\n---\n# Cap A\n", encoding="utf-8"
        )
        self.db = self.root / "mesh.db"
        self.jsonl = self.root / "prev.jsonl"
        rebuild_index(self.db, [self.root / "plugins"], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            registry_diff(self.con, self.root / "nonexistent.jsonl")

    def test_empty_previous_shows_added(self) -> None:
        self.jsonl.write_text("", encoding="utf-8")
        result = registry_diff(self.con, self.jsonl)
        self.assertGreater(result["summary"]["addedCount"], 0)
        self.assertEqual(result["summary"]["removedCount"], 0)
        self.assertIn("summary", result)
        self.assertIn("added", result)
        self.assertIn("removed", result)
        self.assertIn("changed", result)


if __name__ == "__main__":
    unittest.main()
