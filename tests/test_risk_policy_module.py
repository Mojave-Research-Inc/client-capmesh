"""Tests for the extracted risk-tier policy module (CM-12 slice-3).

Verifies that ``capmesh.risk_policy`` is importable, that ``governance.py``
re-exports the moved names (public API preserved), that
``default_promotion_gates`` returns the 7-gate set, that
``evaluate_risk_tier_policy`` runs from the new module, and that there is no
circular import between ``risk_policy`` and ``governance``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


class RiskPolicyModuleTests(unittest.TestCase):
    """CM-12 slice-3: risk-tier policy moved to ``capmesh.risk_policy``."""

    def test_risk_policy_module_importable(self) -> None:
        import capmesh.risk_policy as mod

        self.assertTrue(hasattr(mod, "evaluate_risk_tier_policy"))
        self.assertTrue(hasattr(mod, "default_promotion_gates"))

    def test_governance_reexports_risk_policy(self) -> None:
        from capmesh.governance import (
            default_promotion_gates,
            evaluate_risk_tier_policy,
        )

        # Both names are callable, i.e. real re-exports not lost in the move.
        self.assertTrue(callable(evaluate_risk_tier_policy))
        self.assertTrue(callable(default_promotion_gates))

    def test_default_promotion_gates_seven(self) -> None:
        from capmesh.risk_policy import default_promotion_gates

        gates = default_promotion_gates()
        expected = {
            "sourceIntegrity",
            "tests",
            "retrievalEvals",
            "signature",
            "provenance",
            "promptInjectionScan",
            "riskTierPolicy",
        }
        # Order-agnostic set equality over the gate names.
        self.assertEqual(set(gates.keys()), expected)
        self.assertEqual(len(gates), 7)

    def test_evaluate_risk_tier_policy_smoke(self) -> None:
        from capmesh.risk_policy import evaluate_risk_tier_policy

        # Known-low-risk tier targeting the all-user namespace is allowlisted.
        ok, reason = evaluate_risk_tier_policy("low", "all", "internal")
        self.assertTrue(ok)
        self.assertIn("low", reason.lower())

        # High-risk tier targeting the all-user namespace is blocked.
        ok, reason = evaluate_risk_tier_policy("high", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("high", reason.lower())

        # org/private vaults are allowlisted for all tiers, including high.
        ok, _reason = evaluate_risk_tier_policy("high", "org", "internal")
        self.assertTrue(ok)

    def test_no_circular_import(self) -> None:
        # The subprocess does not inherit pytest's ``pythonpath`` ini setting, so
        # ``import capmesh...`` fails with ModuleNotFoundError when the suite is
        # launched from the repository root (the common case) rather than from
        # ``services/asg-capmesh``. Resolve the package root -- the directory
        # that holds ``capmesh/`` -- from this test file's location and put it
        # on PYTHONPATH with cwd set there, so the import is portable regardless
        # of the pytest invocation directory and without installing the package.
        pkg_root = Path(__file__).resolve().parent.parent  # services/asg-capmesh/
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            part for part in [str(pkg_root), env.get("PYTHONPATH", "")] if part
        )
        result = subprocess.run(
            [sys.executable, "-c", "import capmesh.risk_policy, capmesh.governance"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(pkg_root),
            env=env,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"import failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
