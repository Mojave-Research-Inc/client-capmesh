from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from capmesh.index import connect, init_db
from capmesh.server import readiness_payload


class ReadinessGateRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        # Satisfy the critical catalog readiness checks so the overall status
        # is "ready" and the only variable under test is the gateRunner block.
        self.con.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('last_successful_ingest_at', datetime('now'))"
        )
        self.con.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES"
            "('last_successful_ingest_generation', 'sha256:' || printf('%064d', 1))"
        )
        self.con.commit()

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def _payload(self) -> tuple[dict, object]:
        with patch.dict(
            os.environ,
            {
                "CAPMESH_READY_MIN_CAPABILITIES": "1",
                "CAPMESH_READY_MIN_SOURCES": "0",
                "CAPMESH_READY_MAX_AGE_SECONDS": "3600",
            },
            clear=False,
        ):
            return readiness_payload(self.con, started_at=time.monotonic())

    def _gate_runner_check(self, payload: dict) -> dict:
        matches = [c for c in payload["checks"] if c["name"] == "gateRunner"]
        self.assertEqual(len(matches), 1, payload["checks"])
        return matches[0]

    def test_readiness_includes_gate_runner_check(self) -> None:
        payload, _status = self._payload()
        check = self._gate_runner_check(payload)
        self.assertIn("ok", check)

    def test_gate_runner_check_passes_when_wired(self) -> None:
        payload, _status = self._payload()
        check = self._gate_runner_check(payload)
        self.assertTrue(check["ok"], check)
        self.assertIn("gateCount", check)
        self.assertGreater(check["gateCount"], 0)

    def test_gate_runner_check_fails_gracefully_on_import_error(self) -> None:
        # Simulate a broken lifecycle module: the helper's lazy
        # ``from . import lifecycle`` resolves via ``sys.modules`` and the
        # parent package attribute, so patch both to surface an import error.
        import capmesh  # noqa: WPS433 -- local import for patching

        real_lifecycle = sys.modules.get("capmesh.lifecycle")
        real_attr = getattr(capmesh, "lifecycle", None)

        class _BrokenImport:
            def __getattr__(self, _name: str) -> None:
                raise ImportError("simulated lifecycle breakage")

        broken = _BrokenImport()
        with patch.dict(sys.modules, {"capmesh.lifecycle": broken}), patch.object(
            capmesh, "lifecycle", broken, create=True
        ):
            payload, status = self._payload()
        # Restore the real module references for subsequent tests.
        if real_lifecycle is not None:
            sys.modules["capmesh.lifecycle"] = real_lifecycle
        else:
            sys.modules.pop("capmesh.lifecycle", None)
        if real_attr is not None:
            capmesh.lifecycle = real_attr
        elif hasattr(capmesh, "lifecycle"):
            delattr(capmesh, "lifecycle")

        check = self._gate_runner_check(payload)
        self.assertFalse(check["ok"], check)
        self.assertIn("errorType", check)
        # Endpoint still returns a valid payload (did not crash).
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(status, 200)

    def test_gate_runner_failure_does_not_fail_overall_readiness(self) -> None:
        # Force the gate runner status to False by replacing the helper with a
        # stub. Per the documented choice, gateRunner is a WARNING and must not
        # flip the overall ready status to not-ready.
        import capmesh.server as server_mod

        original = server_mod._gate_runner_status
        server_mod._gate_runner_status = lambda: (False, {"errorType": "Stubbed"})
        try:
            payload, status = self._payload()
        finally:
            server_mod._gate_runner_status = original

        check = self._gate_runner_check(payload)
        self.assertFalse(check["ok"], check)
        self.assertEqual(check["errorType"], "Stubbed")
        # Overall readiness is still the success status.
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
