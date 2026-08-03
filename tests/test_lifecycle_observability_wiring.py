"""WAVE5-WIRING-c: lifecycle.py gate runner is wired to capmesh.observability.

These tests confirm that ``capmesh.lifecycle``'s gate runner
(``review_capability``) emits one structured ``gate.eval`` log event and one
``gate.<name>.<outcome>`` counter increment per evaluated gate, via the
standalone ``capmesh.observability`` helpers (``log_event`` /
``MetricsRegistry`` / ``GateDecision`` / ``format_gate_decision``). They do NOT
edit ``capmesh.observability`` or any gate logic -- observability is
best-effort and must never break the gate runner.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import GATE_METRICS, review_capability
from capmesh.models import Capability, Principal
from capmesh.observability import MetricsRegistry


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _make_cap(root: Path, name: str, *, content: str | None = None) -> Capability:
    source = root / name / "SKILL.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        content
        or f"---\nname: {name}\ndescription: {name} capability\n---\n# {name}\nOperate safely.\n",
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
        content_hash=_digest(source),
        risk_tier="low",
        mutating=False,
        lifecycle="draft",
        approval_state="draft",
        tenant_id="asg",
    )
    return cap


class LifecycleObservabilityWiringTests(unittest.TestCase):
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
        self.con = connect(self.root / "mesh.db")
        init_db(self.con, enable_vector=False)
        self.admin = Principal(subject="admin@example.com", tenant_id="asg", roles=("org_admin",))

    def tearDown(self) -> None:
        self.con.close()
        self.env.stop()
        self.tmp.cleanup()

    def _store(self, cap: Capability) -> Capability:
        upsert_capability(self.con, cap)
        self.con.commit()
        stored = get_capability(self.con, cap.uri)
        assert stored is not None
        return stored

    def test_gate_metrics_registry_exposed(self) -> None:
        """The module exposes a singleton MetricsRegistry for test/ops import."""
        self.assertIsInstance(GATE_METRICS, MetricsRegistry)
        # The imported name is the same object referenced from the lifecycle
        # module namespace (a singleton, not a per-import copy).
        self.assertIs(lifecycle_mod.GATE_METRICS, GATE_METRICS)

    def test_review_capability_increments_metrics(self) -> None:
        """Driving review_capability grows at least one ``gate.*`` counter."""
        cap = self._store(_make_cap(self.root, "metrics"))
        before = GATE_METRICS.snapshot()
        review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        after = GATE_METRICS.snapshot()
        grew = [
            key
            for key, count in after.items()
            if key.startswith("gate.") and count > before.get(key, 0)
        ]
        self.assertTrue(
            grew,
            f"review_capability did not grow any gate.* metric: before={before} after={after}",
        )

    def test_log_event_called_on_gate_eval(self) -> None:
        """review_capability calls log_event with event_type 'gate.eval'."""
        cap = self._store(_make_cap(self.root, "logcall"))
        with mock.patch.object(lifecycle_mod, "log_event") as spy:
            review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        self.assertTrue(spy.called, "log_event was never invoked by the gate runner")
        found_gate_eval = any(
            len(call.args) >= 2 and call.args[1] == "gate.eval"
            for call in spy.call_args_list
        )
        self.assertTrue(
            found_gate_eval,
            "no log_event call used event_type 'gate.eval'",
        )

    def test_observability_failure_does_not_break_gate(self) -> None:
        """A log_event raise is swallowed; review_capability still returns."""
        cap = self._store(_make_cap(self.root, "noisy"))
        with mock.patch.object(lifecycle_mod, "log_event", side_effect=RuntimeError("boom")):
            result = review_capability(
                self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
            )
        self.assertIsInstance(result, dict)
        self.assertIn("gates", result)


if __name__ == "__main__":
    unittest.main()
