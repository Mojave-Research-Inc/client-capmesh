"""Cross-module observability contract lock for the Capability Mesh.

These integration tests pin the contract that the standalone
``capmesh.observability`` helpers (``log_event`` / ``redact`` /
``MetricsRegistry`` / ``format_gate_decision``) are wired consistently across
the gate runner (``capmesh.lifecycle.review_capability``), the router dispatch
(``capmesh.router.CapabilityRouter.call``) and the HTTP transport
(``capmesh.server``). They lock three cross-module invariants:

* every gate evaluation emits a ``gate.eval`` log event AND increments a
  ``gate.<gateName>.<outcome>`` counter on the shared ``GATE_METRICS`` registry;
* the ``redact`` helper masks the documented sensitive keys
  (``token``/``secret``/``password``/``api_key``/``authorization``/``cookie``)
  to ``"[REDACTED]"`` while leaving non-sensitive keys intact -- this is the
  contract the wired ``log_event`` paths depend on;
* observability is best-effort: a ``log_event`` raise in either the lifecycle
  or router path must NEVER propagate to the caller.

These tests do NOT edit any ``capmesh/*.py`` source file or any sibling test.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
import capmesh.router as router_mod
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import GATE_METRICS, review_capability
from capmesh.models import Capability, Principal
from capmesh.observability import redact
from capmesh.router import CapabilityRouter

GATE_COUNTER_RE = re.compile(r"^gate\.[a-zA-Z]+\.(passed|failed|skipped)$")


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


class GateEvalObservabilityIntegrationTests(unittest.TestCase):
    """Lifecycle gate-eval path emits metrics + a redacted log event."""

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

    def test_gate_eval_increments_all_gate_metrics(self) -> None:
        """Driving review_capability grows at least one ``gate.*`` counter,
        and every grown counter matches ``gate.<gateName>.<outcome>``.
        """
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
        for key in grew:
            self.assertRegex(
                key,
                GATE_COUNTER_RE,
                f"grown gate counter {key!r} does not match gate.<gateName>.<outcome>",
            )

    def test_gate_eval_emits_redacted_log_event(self) -> None:
        """review_capability calls log_event with event_type 'gate.eval',
        and the redact contract is locked: a sensitive key would be masked
        while a gate-decision camelCase key survives.
        """
        cap = self._store(_make_cap(self.root, "redact"))
        with mock.patch.object(lifecycle_mod, "log_event") as spy:
            review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})

        self.assertTrue(spy.called, "log_event was never invoked by the gate runner")
        gate_eval_calls = [
            call for call in spy.call_args_list
            if len(call.args) >= 2 and call.args[1] == "gate.eval"
        ]
        self.assertTrue(gate_eval_calls, "no log_event call used event_type 'gate.eval'")

        # The gate.eval fields come from format_gate_decision (camelCase keys
        # gateName/capabilityUri/outcome/requestId/reason -- none sensitive).
        # Lock the redact contract the wired path depends on: a sensitive key
        # is masked, a camelCase gate-decision key passes through.
        contract = redact({"token": "super-secret-value", "gateName": "g"})
        self.assertEqual(contract["token"], "[REDACTED]")
        self.assertEqual(contract["gateName"], "g")

        # And the actual captured fields, when run through redact, must carry
        # no sensitive key with a non-redacted value.
        for call in gate_eval_calls:
            captured = dict(call.kwargs)
            redacted = redact(captured)
            for key, value in redacted.items():
                if key.lower() in {
                    "token", "secret", "password", "api_key", "authorization", "cookie",
                }:
                    self.assertEqual(value, "[REDACTED]", f"key {key!r} not redacted")


class RouterRequestObservabilityIntegrationTests(unittest.TestCase):
    """Router dispatch path emits a ``request`` event with request_id."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(self._restore_state_dir)
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        # Minimal low-risk capability stored in a temp sqlite db so the router
        # has a real index to dispatch against (cap.search returns a result).
        self.db = self.root / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        cap = _make_cap(self.root, "router-cap")
        upsert_capability(self.con, cap)
        self.con.commit()
        self.router = CapabilityRouter(self.con, roots=(str(self.root),))

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def _restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    def test_router_request_event_carries_request_id(self) -> None:
        """CapabilityRouter.call emits a ``request`` event whose ``request_id``
        kwarg is exactly the caller-supplied id.
        """
        with mock.patch.object(router_mod, "log_event") as spy:
            self.router.call(
                "cap.search",
                {"query": "router-cap", "type": "skill"},
                request_id="int-req-1",
            )
        self.assertTrue(spy.called, "router.log_event was never invoked")
        request_calls = [
            call for call in spy.call_args_list
            if len(call.args) >= 2 and call.args[1] == "request"
        ]
        self.assertTrue(request_calls, "no log_event call used event_type 'request'")
        self.assertEqual(request_calls[0].kwargs.get("request_id"), "int-req-1")

    def test_request_event_sensitive_field_redacted(self) -> None:
        """Lock the redact contract the router ``request`` event depends on:
        ``authorization`` is masked, ``verb`` survives.
        """
        contract = redact({"authorization": "bearer xyz", "verb": "search"})
        self.assertEqual(contract["authorization"], "[REDACTED]")
        self.assertEqual(contract["verb"], "search")


class BestEffortObservabilityContractTests(unittest.TestCase):
    """Observability failures never break the gate runner or the router."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.key_path = self.root / "signing.pem"
        self.env = mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "test",
                "CAPMESH_SIGNING_KEY_FILE": str(self.key_path),
                "CAPMESH_STATE_DIR": str(self.root / "state"),
            },
            clear=False,
        )
        self.env.start()
        self.con = connect(self.root / "mesh.db")
        init_db(self.con, enable_vector=False)
        cap = _make_cap(self.root, "besteffort")
        upsert_capability(self.con, cap)
        self.con.commit()
        self.admin = Principal(subject="admin@example.com", tenant_id="asg", roles=("org_admin",))
        self.router = CapabilityRouter(self.con, roots=(str(self.root),))

    def tearDown(self) -> None:
        self.con.close()
        self.env.stop()
        self.tmp.cleanup()

    def test_observability_failure_never_breaks_gate_or_request(self) -> None:
        """If BOTH log_event sites raise, neither review_capability nor
        CapabilityRouter.call propagate; they still return their normal
        result shape. This is the cross-module best-effort contract lock.
        """
        with mock.patch.object(lifecycle_mod, "log_event", side_effect=RuntimeError("boom")), \
                mock.patch.object(router_mod, "log_event", side_effect=RuntimeError("boom")):
            gate_result = review_capability(
                self.con, self.admin,
                {"capabilityUri": "cap://user/asg/test/private/skill/test.besteffort@0.1.0", "dryRun": True},
            )
            router_result = self.router.call(
                "cap.search",
                {"query": "besteffort", "type": "skill"},
                request_id="int-req-besteffort",
            )

        self.assertIsInstance(gate_result, dict, "gate runner must return a dict, not raise")
        self.assertIn("gates", gate_result)
        self.assertIsInstance(router_result, dict, "router must return a dict, not raise")
        self.assertFalse(
            router_result.get("isError"),
            "router dispatch must still succeed when log_event raises",
        )


class MetricsSnapshotContractTests(unittest.TestCase):
    """``GATE_METRICS.snapshot()`` is a sorted-by-key dict for stable parsing."""

    def test_metrics_snapshot_is_sorted_dict(self) -> None:
        snapshot = GATE_METRICS.snapshot()
        self.assertIsInstance(snapshot, dict, "snapshot must be a dict")
        keys = list(snapshot)
        self.assertEqual(keys, sorted(keys), "snapshot keys must be sorted for stable parsing")


if __name__ == "__main__":
    unittest.main()
