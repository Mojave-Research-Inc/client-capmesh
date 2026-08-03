from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "ops" / "logical-catalog-digest.py"
SPEC = importlib.util.spec_from_file_location("logical_catalog_digest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LogicalCatalogDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mesh.db"
        con = sqlite3.connect(self.db)
        capability_columns = ",".join(f'"{name}" TEXT' for name in MODULE.CAPABILITY_COLUMNS)
        con.execute(f"CREATE TABLE capabilities ({capability_columns}, source_path TEXT)")
        values = ["value"] * len(MODULE.CAPABILITY_COLUMNS)
        con.execute(
            f"INSERT INTO capabilities VALUES ({','.join('?' for _ in range(len(values) + 1))})",
            (*values, "/authority/source"),
        )
        con.execute("CREATE TABLE role_assignments(id TEXT, role TEXT)")
        con.execute("INSERT INTO role_assignments VALUES ('one', 'member')")
        con.execute("CREATE TABLE audit_events(id TEXT, payload TEXT)")
        con.execute("INSERT INTO audit_events VALUES ('one', 'local')")
        con.commit()
        con.close()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_digest_tracks_governance_but_excludes_local_paths_and_audit(self) -> None:
        initial = MODULE.logical_digest(self.db)
        con = sqlite3.connect(self.db)
        con.execute("UPDATE capabilities SET source_path = '/replica/content-addressed'")
        con.execute("INSERT INTO audit_events VALUES ('two', 'replica-local')")
        con.commit()
        con.close()
        self.assertEqual(MODULE.logical_digest(self.db), initial)

        con = sqlite3.connect(self.db)
        con.execute("UPDATE role_assignments SET role = 'org_admin' WHERE id = 'one'")
        con.commit()
        con.close()
        self.assertNotEqual(MODULE.logical_digest(self.db), initial)


if __name__ == "__main__":
    unittest.main()
