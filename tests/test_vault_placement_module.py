"""Module-level tests for the extracted vault-placement subsystem (CM-12).

``capmesh.vault_placement`` holds the self-contained vault-placement helpers
moved out of ``capmesh.governance`` (``_manifest_uri_tail``, ``_vault_match_key``,
``_vault_placement_collision``, ``apply_vault_placement``). ``governance.py``
re-imports those names so its public API is unchanged. These tests pin the
extraction: the new module is importable, ``governance`` still re-exports the
names, the moved code still runs from its new home (including the lazy
governance import inside ``apply_vault_placement``), and there is no circular
import between the two modules.
"""

from __future__ import annotations

import unittest


class VaultPlacementModuleTest(unittest.TestCase):
    """Pin the CM-12 vault-placement extraction from governance.py."""

    def test_vault_placement_module_importable(self) -> None:
        """capmesh.vault_placement is importable and exposes the moved names."""
        import capmesh.vault_placement as vp

        self.assertTrue(hasattr(vp, "apply_vault_placement"))
        self.assertTrue(hasattr(vp, "_vault_match_key"))
        self.assertTrue(hasattr(vp, "_vault_placement_collision"))

    def test_governance_reexports_vault_placement(self) -> None:
        """governance.py re-exports the moved names -- public API preserved."""
        from capmesh.governance import (
            _vault_match_key,
            _vault_placement_collision,
            apply_vault_placement,
        )

        self.assertTrue(callable(apply_vault_placement))
        self.assertTrue(callable(_vault_match_key))
        self.assertTrue(callable(_vault_placement_collision))

    def test_vault_placement_collision_guard_still_works(self) -> None:
        """Smoke test: the moved collision-guard code runs from the new module.

        Mirrors the ``_vault_match_key`` symmetric assertion from
        ``tests/test_vault_match_collision_guard.py`` (VaultMatchKeySymmetricTest)
        plus a minimal no-collision placement (test_no_collision_places_normally)
        to exercise ``apply_vault_placement`` -- and its lazy governance import --
        from the new module.
        """
        import tempfile
        from pathlib import Path

        from capmesh.vault_placement import (
            _manifest_uri_tail,
            _vault_match_key,
            apply_vault_placement,
        )

        # Mirror VaultMatchKeySymmetricTest.test_symmetric_matchkey_unchanged: the
        # symmetric plugin-prefix strip normalizes both sides to the same key.
        self.assertEqual(_vault_match_key("agent/global.foo@0.1.0"), "agent/foo@0.1.0")
        self.assertEqual(
            _vault_match_key("agent/agentic-flow-specialists-2026.foo@0.1.0"),
            "agent/foo@0.1.0",
        )
        self.assertEqual(_vault_match_key("nope"), "nope")

        # Mirror test_no_collision_places_normally: a single cap matching a
        # manifest tail is placed; this exercises the lazy governance import
        # (namespace helpers, audit_event, evaluate_risk_tier_policy) at call
        # time, proving the moved apply_vault_placement runs end-to-end.
        from capmesh.governance import (
            org_shared_namespace_id,
            org_shared_namespace_prefix,
        )
        from capmesh.index import connect, init_db
        from capmesh.models import Capability

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = Path(tmp.name) / "mesh.db"
        con = connect(db_path)
        try:
            init_db(con, enable_vector=False)
            idx = {
                _vault_match_key(
                    _manifest_uri_tail(f"{org_shared_namespace_prefix()}/agent/global.foo@0.1.0")
                ): "org"
            }
            cap = Capability(
                uri="cap://source/global/foo",
                capability_type="agent",
                name="foo",
                version="0.1.0",
                title="global foo",
                description="Source cap for global/foo.",
                package_path="pkg",
                entrypoint="entry",
                source_path="src",
                source_kind="plugin_capability",
                source_system="test",
                canonical_key="agent:global:foo:0.1.0",
                content_hash="sha256:aaa",
                plugin="global",
                tenant_id="asg",
                risk_tier="low",
            )
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed, "non-colliding cap must be placed from the new module")
            self.assertTrue(placed.uri.startswith(org_shared_namespace_prefix()))
            self.assertEqual(placed.namespace_id, org_shared_namespace_id())
            self.assertEqual(placed.approval_state, "approved")
            self.assertIn("global.foo@0.1.0", placed.uri)
        finally:
            con.close()

    def test_no_circular_import(self) -> None:
        """``import capmesh.vault_placement, capmesh.governance`` succeeds.

        Runs in a fresh interpreter so a circular import between the two modules
        (vault_placement importing governance at module top) would surface as a
        non-zero exit / ImportError rather than being masked by already-loaded
        modules in this process.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-c", "import capmesh.vault_placement, capmesh.governance"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"Import failed (rc={result.returncode}):\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
