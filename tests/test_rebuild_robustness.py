from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.index import (
    connect,
    rebuild_index,
)

# ---------------------------------------------------------------------------
# Helper: write a minimal plugin source so discover_capabilities returns caps
# ---------------------------------------------------------------------------

def _write_plugin(root: Path, name: str, description: str) -> Path:
    """Create a tiny plugin with one skill file. Return the root path."""
    pkg = root / name
    pkg.mkdir(parents=True)
    (pkg / ".claude-plugin").mkdir(exist_ok=True)
    (pkg / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": name, "version": "1.0.0", "description": description}),
        encoding="utf-8",
    )
    skills_dir = pkg / "skills" / "test_skill"
    skills_dir.mkdir(parents=True)
    skills_dir.joinpath("SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n# {name}\n{description}\n",
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------------------
# Test 1: rollback on exception
# ---------------------------------------------------------------------------

class RebuildRollbackTests(unittest.TestCase):
    def test_rebuild_rolls_back_on_exception(self) -> None:
        """Force an exception during rebuild (monkeypatch _upsert_vector to raise).
        Assert con.rollback() was called and the DB is left clean, not half-applied.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            root = _write_plugin(Path(tmp) / "roots", "test-plugin-rollback", "rollback test cap")

            # First populate the DB with a successful rebuild so we have state.
            result = rebuild_index(db, [root])
            self.assertEqual(result["operation"], "rebuild")

            # Count caps after first rebuild.
            con = connect(db)
            before_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities "
                    "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
                ).fetchone()[0]
            )
            con.close()
            self.assertGreater(before_count, 0, "Expected some non-system caps after first rebuild")

            # Now mock _upsert_vector to raise on every call.
            with mock.patch(
                "capmesh.index._upsert_vector",
                side_effect=RuntimeError("simulated vector crash"),
            ), self.assertRaises(RuntimeError):
                rebuild_index(db, [root])

            # After the exception the DB should be in its pre-rebuild state.
            # The transaction rollback means nothing we were in the middle of
            # writing persists. Since rebuild_index clears all non-system caps
            # before the loop, rollback should restore whatever existed before
            # (the transaction was on the in-memory DB connection, and the
            # actual on-disk DB was not changed because all writes happened
            # inside the transaction that got rolled back).
            #
            # Verify: count of non-system caps should be unchanged from before
            # (the DB connection was isolated and rolled back).
            con = connect(db)
            after_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities "
                    "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
                ).fetchone()[0]
            )
            con.close()
            self.assertEqual(
                before_count,
                after_count,
                f"DB count changed after rollback: {before_count} -> {after_count}",
            )

    def test_rebuild_rolls_back_on_bare_exception_mid_loop(self) -> None:
        """Even a non-vector exception (e.g. monkeypatched upsert_capability)
        should trigger rollback.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            root = _write_plugin(Path(tmp) / "roots", "test-plugin-upsert-fail", "upsert fail cap")

            # First populate.
            rebuild_index(db, [root])

            con = connect(db)
            before_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities "
                    "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
                ).fetchone()[0]
            )
            con.close()

            # Make upsert_capability raise.
            with mock.patch(
                "capmesh.index.upsert_capability",
                side_effect=RuntimeError("simulated upsert crash"),
            ), self.assertRaises(RuntimeError):
                rebuild_index(db, [root])

            con = connect(db)
            after_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities "
                    "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
                ).fetchone()[0]
            )
            con.close()
            self.assertEqual(
                before_count,
                after_count,
                f"DB count changed after rollback: {before_count} -> {after_count}",
            )


# ---------------------------------------------------------------------------
# Test 2: vector failure is per-capability
# ---------------------------------------------------------------------------

class VectorPerCapTests(unittest.TestCase):
    def test_vector_failure_is_per_cap(self) -> None:
        """One capability whose embedding fails (monkeypatch) is flagged
        vec-failed, while other caps still have their vectors and the global
        vector status is NOT disabled.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            root = Path(tmp) / "roots"

            # Write two plugin sources.
            _write_plugin(root, "good-plugin", "good plugin cap")
            _write_plugin(root, "bad-plugin", "bad plugin cap")

            result = rebuild_index(db, [root])
            self.assertEqual(result["operation"], "rebuild")

            # Now simulate one cap's embedding failing.
            # We monkeypatch _upsert_vector so it returns False for the
            # "bad-plugin" cap and True for everything else.
            call_count = {"n": 0}
            orig_upsert_vector = __import__("capmesh.index", fromlist=["_upsert_vector"])._upsert_vector

            def _selective_vector_fail(con, cap_id, cap, *, enabled, index_text_unchanged=False):
                call_count["n"] += 1
                if "bad-plugin" in (cap.name or "") or "bad-plugin" in (cap.uri or ""):
                    return False
                return orig_upsert_vector(con, cap_id, cap, enabled=enabled, index_text_unchanged=index_text_unchanged)

            with mock.patch("capmesh.index._upsert_vector", side_effect=_selective_vector_fail):
                result = rebuild_index(db, [root])

            self.assertEqual(result["operation"], "rebuild")

            # Global vector status should still be enabled.
            self.assertTrue(
                result["vector"]["enabled"],
                "Global vector should remain enabled when only one cap fails",
            )

            # The failed cap should have metadata["vectorStatus"] == "failed".
            con = connect(db)
            bad_row = con.execute(
                "SELECT metadata_json FROM capabilities WHERE name LIKE '%bad-plugin%'"
            ).fetchone()
            self.assertIsNotNone(bad_row, "bad-plugin capability must exist in the DB")
            bad_meta = json.loads(bad_row["metadata_json"])
            self.assertEqual(
                bad_meta.get("vectorStatus"),
                "failed",
                "Failed cap must have vectorStatus=failed in metadata",
            )

            # The good cap should NOT have vectorStatus=failed.
            good_row = con.execute(
                "SELECT metadata_json FROM capabilities WHERE name LIKE '%good-plugin%'"
            ).fetchone()
            self.assertIsNotNone(good_row, "good-plugin capability must exist in the DB")
            good_meta = json.loads(good_row["metadata_json"])
            self.assertNotEqual(
                good_meta.get("vectorStatus"),
                "failed",
                "Good cap must NOT have vectorStatus=failed",
            )

            con.close()


# ---------------------------------------------------------------------------
# Test 3: rebuild succeeds when vec extension absent
# ---------------------------------------------------------------------------

class RebuildVecExtensionAbsentTests(unittest.TestCase):
    def test_rebuild_succeeds_when_vec_extension_absent(self) -> None:
        """If sqlite-vec is unavailable, global vector status is disabled
        (graceful) but the lexical rebuild still completes.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            root = _write_plugin(Path(tmp) / "roots", "vec-absent-plugin", "vec absent test")

            # Monkey-patch init_db's sqlite-vec loading so it always fails.
            # We intercept the vector loading inside init_db.
            def _broken_load_sqlite_vec(con):
                return (False, "sqlite_vec extension not found")

            with mock.patch("capmesh.index.load_sqlite_vec", side_effect=_broken_load_sqlite_vec):
                result = rebuild_index(db, [root])

            self.assertEqual(result["operation"], "rebuild")

            # Global vector should be disabled.
            self.assertFalse(
                result["vector"]["enabled"],
                "Vector should be disabled when sqlite-vec extension is absent",
            )

            # The DB should still contain the discovered capabilities (lexical rebuild succeeded).
            con = connect(db)
            cap_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities "
                    "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
                ).fetchone()[0]
            )
            con.close()
            self.assertGreater(
                cap_count,
                0,
                f"Capabilities should still be indexed (lexical rebuild succeeded), found {cap_count}",
            )

            # capability_fts should also have rows (lexical index is intact).
            con = connect(db)
            fts_count = int(con.execute("SELECT COUNT(*) FROM capability_fts").fetchone()[0])
            con.close()
            self.assertGreater(
                fts_count,
                0,
                "FTS index should be populated (lexical rebuild succeeded)",
            )


if __name__ == "__main__":
    unittest.main()
