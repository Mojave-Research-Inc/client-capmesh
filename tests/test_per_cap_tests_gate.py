from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase

from capmesh.governance import (
    DEFAULT_USER_SUBJECT,
    default_user_namespace_prefix,
    default_user_private_namespace_id,
    default_user_private_store_id,
)
from capmesh.index import connect, init_db, rebuild_index, upsert_capability
from capmesh.models import Capability
from capmesh.router import CapabilityRouter

# The capmesh package directory — this is where the handler looks for test files
# when resolving relative paths from a capability's metadata.
_CAPMESH_ROOT = str(Path(__file__).resolve().parents[1])


class TestPerCapTestsGate(TestCase):
    """Tests for the per-capability tests presence gate (lanes item #6)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "mesh.db"
        plugin = self.root / "plugins" / "demo-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / "skills" / "write-brief").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "demo-plugin", "version": "1.2.3", "description": "Demo plugin."}),
            encoding="utf-8",
        )
        (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
            "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n# Write Brief\n",
            encoding="utf-8",
        )
        self._previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        self._previous_superadmin_actors = os.environ.get("CAPMESH_SUPERADMIN_ACTORS")
        os.environ["CAPMESH_SUPERADMIN_ACTORS"] = "test-admin@example.com,test-user@example.com"
        rebuild_index(self.db, [self.root / "plugins"], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        self.router = CapabilityRouter(self.con, roots=(str(self.root / "plugins"),))
        self.addCleanup(self._teardown)

    def _teardown(self) -> None:
        self.con.close()
        if self._previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self._previous_state_dir
        # Clean up test artifact files placed in the capmesh tests/ directory
        # by the CLI subcommand tests (they need the file there for the gate).
        _cap_tests_dir = Path(_CAPMESH_ROOT) / "tests"
        for name in list(_cap_tests_dir.iterdir()):
            if name.name.startswith("myplugin."):
                name.unlink(missing_ok=True)
        if self._previous_superadmin_actors is None:
            os.environ.pop("CAPMESH_SUPERADMIN_ACTORS", None)
        else:
            os.environ["CAPMESH_SUPERADMIN_ACTORS"] = self._previous_superadmin_actors
        self.tmp.cleanup()

    def _make_cap(self, name: str, plugin: str, metadata: dict | None = None) -> Capability:
        """Create and persist a Capability for testing."""
        cap = Capability(
            uri=f"{default_user_namespace_prefix()}/skill/{plugin}.{name}@0.1.0",
            capability_type="skill",
            name=name,
            version="0.1.0",
            title=f"{name.title()} skill",
            description=f"A test capability named {name}.",
            package_path=str(self.root),
            entrypoint=f"{name}.py",
            source_path=str(self.root / f"{name}.py"),
            source_kind="cap_manifest",
            source_system="test",
            canonical_key=f"skill:test:{name}:test",
            content_hash="sha256:test",
            visibility="internal",
            discovery_mode="public",
            owner=DEFAULT_USER_SUBJECT,
            plugin=plugin,
            risk_tier="low",
            lifecycle="draft",
            tenant_id="asg",
            store_id=default_user_private_store_id(),
            namespace_id=default_user_private_namespace_id(),
            created_by=DEFAULT_USER_SUBJECT,
            approval_state="draft",
            signature_status="unchecked",
            provenance_status="unchecked",
            risk_review_status="pending",
            metadata=metadata or {},
        )
        Path(self.root / f"{name}.py").write_text("# test source", encoding="utf-8")
        upsert_capability(self.con, cap)
        self.con.commit()
        return cap

    def test_per_cap_test_present_passes(self) -> None:
        """A cap whose testPath metadata points to an existing file => gate passed."""
        from capmesh.cli import run_per_cap_tests_gate

        cap = self._make_cap(
            "test-cap-with-file",
            "myplugin",
            metadata={"testPath": "tests/myplugin.test-cap-with-file_test.py"},
        )
        # Create the declared test file.
        test_file = self.root / "tests" / "myplugin.test-cap-with-file_test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("# test", encoding="utf-8")

        passed, reason = run_per_cap_tests_gate(cap, str(self.root))
        self.assertTrue(passed, f"Expected gate to pass but got: {reason}")
        self.assertIn("per-cap test file present", reason)
        self.assertIn("tests/myplugin.test-cap-with-file_test.py", reason)

    def test_declared_testpath_missing_fails(self) -> None:
        """A cap declaring testPath to a non-existent file => gate failed with 'missing'."""
        from capmesh.cli import run_per_cap_tests_gate

        cap = self._make_cap(
            "test-cap-missing",
            "myplugin",
            metadata={"testPath": "tests/myplugin.test-cap-missing_test.py"},
        )
        # Do NOT create the test file.

        passed, reason = run_per_cap_tests_gate(cap, str(self.root))
        self.assertFalse(passed, "Expected gate to fail but got: passed")
        self.assertIn("declared testPath missing", reason)
        self.assertIn("tests/myplugin.test-cap-missing_test.py", reason)

    def test_no_declared_testpath_passes_optional(self) -> None:
        """A cap with no testPath in metadata => gate passed (optional)."""
        from capmesh.cli import run_per_cap_tests_gate

        cap = self._make_cap(
            "test-cap-no-testpath",
            "myplugin",
            metadata={},
        )

        passed, reason = run_per_cap_tests_gate(cap, str(self.root))
        self.assertTrue(passed, f"Expected gate to pass but got: {reason}")
        self.assertIn("no per-cap test declared (optional)", reason)

    def test_cli_gates_tests_subcommand(self) -> None:
        """The CLI subcommand returns the expected (passed/failed, reason) for a sample cap."""
        from capmesh.cli import main

        cap = self._make_cap(
            "cli-test-cap",
            "myplugin",
            metadata={"testPath": "tests/myplugin.cli-test-cap_test.py"},
        )
        # Create the declared test file in the capmesh package directory,
        # which is where the handler resolves paths from repo_root.
        test_file = Path(_CAPMESH_ROOT) / "tests" / "myplugin.cli-test-cap_test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("# test", encoding="utf-8")

        uri = cap.uri
        output_capture: list[str] = []

        def fake_print(msg: str) -> None:
            output_capture.append(msg)

        try:
            # Patch print to capture the JSON output from the CLI.
            import builtins
            original_print_fn = builtins.print
            builtins.print = fake_print

            main(["--db", str(self.db), "gates", "tests", uri])

            builtins.print = original_print_fn
        except SystemExit:
            builtins.print = original_print_fn

        self.assertEqual(len(output_capture), 1, f"Expected 1 print, got {len(output_capture)}")
        result = json.loads(output_capture[0])
        self.assertEqual(result["gate"], "tests")
        self.assertEqual(result["capability"], uri)
        self.assertTrue(result["passed"], f"Expected gate to pass, got: {result.get('reason')}")
        self.assertIn("per-cap test file present", result["reason"])

    def test_cli_gates_tests_missing_fails(self) -> None:
        """The CLI subcommand returns passed=False when the test file is missing."""
        from capmesh.cli import main

        cap = self._make_cap(
            "cli-test-missing",
            "myplugin",
            metadata={"testPath": "tests/myplugin.cli-test-missing_test.py"},
        )
        # Do NOT create the test file.

        output_capture: list[str] = []

        def fake_print(msg: str) -> None:
            output_capture.append(msg)

        import builtins

        original_print_fn = builtins.print
        try:
            builtins.print = fake_print
            main(["--db", str(self.db), "gates", "tests", cap.uri])
            builtins.print = original_print_fn
        except SystemExit:
            builtins.print = original_print_fn

        self.assertEqual(len(output_capture), 1)
        result = json.loads(output_capture[0])
        self.assertEqual(result["gate"], "tests")
        self.assertFalse(result["passed"])
        self.assertIn("missing", result["reason"])
