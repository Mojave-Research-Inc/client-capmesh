from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.models import Capability, Principal


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class CliGatesRunTests(unittest.TestCase):
    """Tests for the ``capmesh gates run`` subcommand (VAULT-TRIAGE #1)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.key_path = self.root / "signing.pem"
        self.env = mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "test",
                "CAPMESH_SIGNING_KEY_FILE": str(self.key_path),
            },
            clear=False,
        )
        self.env.start()
        self.db = self.root / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        self.admin = Principal(subject="admin@example.com", tenant_id="asg", roles=("org_admin",))

    def tearDown(self) -> None:
        self.con.close()
        self.env.stop()
        self.tmp.cleanup()

    def add_cap(self, name: str) -> Capability:
        """Create and persist a low-risk skill capability with a real source file."""
        source = self.root / name / "SKILL.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            f"---\nname: {name}\ndescription: {name} capability\n---\n# {name}\nOperate safely.\n",
            encoding="utf-8",
        )
        cap = Capability(
            uri=f"cap://user/asg/test/private/skill/test.{name}@0.1.0",
            capability_type="skill",
            name=name,
            version="0.1.0",
            title=name,
            description=f"{name} capability",
            package_path=str(source.parent),
            entrypoint="SKILL.md",
            source_path=str(source),
            source_kind="skill_markdown",
            source_system="test",
            canonical_key=f"skill:test:{name}:0.1.0",
            content_hash=digest(source),
            risk_tier="low",
            mutating=False,
            lifecycle="draft",
            approval_state="draft",
            tenant_id="asg",
        )
        upsert_capability(self.con, cap)
        self.con.commit()
        stored = get_capability(self.con, cap.uri)
        assert stored is not None
        return stored

    def _run_cli(self, argv: list[str]) -> dict:
        """Invoke the CLI main entry, capturing the single JSON print, swallowing SystemExit."""
        from capmesh.cli import main

        output_capture: list[str] = []

        def fake_print(msg: str) -> None:
            output_capture.append(msg)

        import builtins

        original_print_fn = builtins.print
        try:
            builtins.print = fake_print
            main(argv)
            builtins.print = original_print_fn
        except SystemExit:
            builtins.print = original_print_fn
        self.assertEqual(len(output_capture), 1, f"Expected 1 print, got {len(output_capture)}: {output_capture}")
        return json.loads(output_capture[0])

    # ------------------------------------------------------------------ #
    # VAULT-TRIAGE #1: per-gate reporting
    # ------------------------------------------------------------------ #
    def test_gates_run_reports_per_gate(self) -> None:
        """``gates run`` on a sample cap returns one entry per gate with a state."""
        cap = self.add_cap("gate-report")
        result = self._run_cli(["--db", str(self.db), "gates", "run", cap.uri])

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["capability"], cap.uri)
        self.assertIn("gates", result)
        gates = result["gates"]
        self.assertGreater(len(gates), 0, "per-gate result table must not be empty")
        names = {g["gate"] for g in gates}
        # The lifecycle gate set runs at least these gates.
        for expected in ("signature", "provenance", "sourceIntegrity", "riskTierPolicy"):
            self.assertIn(expected, names, f"gate result missing '{expected}'")
        for gate in gates:
            self.assertIn("state", gate)
            self.assertIn(gate["state"], {"passed", "failed", "skipped"})
            self.assertIn("reason", gate)

    def test_gates_run_dry_run_no_write(self) -> None:
        """Without ``--write`` no promotion_gate_runs row is inserted."""
        cap = self.add_cap("dry-run")
        before = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]
        before_requests = self.con.execute("SELECT COUNT(*) FROM promotion_requests").fetchone()[0]

        result = self._run_cli(["--db", str(self.db), "gates", "run", cap.uri])

        self.assertFalse(result["write"], "dry-run must report write=False")
        after = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]
        after_requests = self.con.execute("SELECT COUNT(*) FROM promotion_requests").fetchone()[0]
        self.assertEqual(after, before, "dry-run must not insert promotion_gate_runs rows")
        self.assertEqual(after_requests, before_requests, "dry-run must not insert promotion_requests rows")

    def test_gates_run_write_inserts_row(self) -> None:
        """With ``--write`` a promotion_gate_runs row is inserted for the capability."""
        cap = self.add_cap("write-back")
        before = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]

        result = self._run_cli(["--db", str(self.db), "gates", "run", cap.uri, "--write"])

        self.assertTrue(result["write"], "write run must report write=True")
        self.assertIn("requestId", result)
        self.assertGreater(result.get("rowsWritten", 0), 0)
        after = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]
        self.assertGreater(after, before, "write run must insert promotion_gate_runs rows")
        rows = self.con.execute(
            "SELECT gate_name, state FROM promotion_gate_runs WHERE request_id = ?",
            (result["requestId"],),
        ).fetchall()
        self.assertGreater(len(rows), 0)
        gate_names = {row["gate_name"] for row in rows}
        self.assertIn("signature", gate_names)
        self.assertIn("sourceIntegrity", gate_names)
        # The anchor promotion_requests row must exist (FK parent).
        anchor = self.con.execute(
            "SELECT state, capability_uri FROM promotion_requests WHERE id = ?",
            (result["requestId"],),
        ).fetchone()
        self.assertIsNotNone(anchor)
        self.assertEqual(anchor["state"], "gate_run")
        self.assertEqual(anchor["capability_uri"], cap.uri)

    def test_gates_run_unknown_cap(self) -> None:
        """An unknown capability name produces a clear error, no crash, no writes."""
        before = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]
        result = self._run_cli(["--db", str(self.db), "gates", "run", "does-not-exist-cap"])
        self.assertEqual(result["status"], "error")
        self.assertIn("not found", result["message"])
        after = self.con.execute("SELECT COUNT(*) FROM promotion_gate_runs").fetchone()[0]
        self.assertEqual(after, before, "unknown cap must not insert any rows")

    def test_cli_dispatch_wires_subcommand(self) -> None:
        """The argparse dispatch routes ``gates run`` to the new handler."""
        from capmesh.cli import gates_run_handler

        cap = self.add_cap("dispatch")
        # Invoke the handler directly with an argparse.Namespace mirroring the
        # parser layout, proving the dispatch target is the gates-run handler.
        import argparse

        args = argparse.Namespace(
            identifier=cap.uri,
            tenant="asg",
            write=False,
        )
        result = gates_run_handler(self.con, args)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["capability"], cap.uri)
        self.assertFalse(result["write"])
        self.assertGreater(len(result["gates"]), 0)

        # Also exercise the full main() dispatch path (argparse integration)
        # so the subcommand routing itself is covered.
        full = self._run_cli(["--db", str(self.db), "gates", "run", cap.uri])
        self.assertEqual(full["status"], "ok")


if __name__ == "__main__":
    unittest.main()
