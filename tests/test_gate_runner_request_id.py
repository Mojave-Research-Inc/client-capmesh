"""Lock the request_id propagation contract through the gate runner.

This test locks the CURRENT contract for how ``request_id`` flows (or does
not) into the ``gate.eval`` structured log events emitted by
``capmesh.lifecycle``'s gate runner, and documents the desired contract.

Findings from ``capmesh/lifecycle.py`` (read at test-author time):

* ``review_capability`` is the per-gate loop that also covers
  ``review_batch`` and ``approve_catalog``. It emits one ``gate.eval`` log
  event per evaluated gate via ``log_event`` + ``format_gate_decision``.
  ``review_capability`` has no ``request_id`` parameter, so it constructs
  ``GateDecision(..., request_id=None, ...)``. TODAY every ``gate.eval``
  event emitted from ``review_capability`` therefore carries
  ``requestId: None``.

* ``run_promotion_gates`` DOES have a promotion request id (it reads
  ``payload["requestId"]`` and validates it), and it IS instrumented with
  ``log_event`` / ``GateDecision`` / ``format_gate_decision`` (CM-13
  observability wiring). Each ``gate.eval`` event it emits carries
  ``requestId`` equal to the promotion request id, closing the end-to-end
  request-correlation gap. (It also persists gate rows into
  ``promotion_gate_runs`` and writes an ``audit_event``.)

* ``format_gate_decision`` is a stable wire-shape mapper: it carries
  ``request_id`` through unchanged as ``requestId`` (including ``None``).

These tests are TEST-ONLY: they do not edit any ``capmesh/*.py`` source
file. They replicate the temp-sqlite harness from
``tests/test_lifecycle_observability_wiring.py`` inline rather than
importing from the sibling.
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
from capmesh.lifecycle import review_capability, run_promotion_gates
from capmesh.models import Capability, Principal
from capmesh.observability import GateDecision, format_gate_decision


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


class GateRunnerRequestIdContractTests(unittest.TestCase):
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

    def test_review_capability_emits_none_request_id(self) -> None:
        """review_capability has no request_id param, so gate.eval carries requestId=None.

        Today's wiring: ``review_capability`` constructs
        ``GateDecision(..., request_id=None, ...)`` for every evaluated gate
        because it has no correlation id parameter. Every captured
        ``gate.eval`` log_event call therefore carries ``requestId: None``.
        """
        cap = self._store(_make_cap(self.root, "reqid_none"))
        with mock.patch.object(lifecycle_mod, "log_event") as spy:
            review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate_eval_calls = [
            call
            for call in spy.call_args_list
            if len(call.args) >= 2 and call.args[1] == "gate.eval"
        ]
        self.assertTrue(
            gate_eval_calls,
            "review_capability did not emit any gate.eval log_event calls",
        )
        # Every gate.eval event from review_capability carries requestId=None.
        for call in gate_eval_calls:
            self.assertIn(
                "requestId",
                call.kwargs,
                f"gate.eval call missing requestId kwarg: {call}",
            )
            self.assertIsNone(
                call.kwargs["requestId"],
                f"review_capability emitted a non-None requestId: {call}",
            )

    def test_gate_decision_request_id_field_present(self) -> None:
        """A GateDecision with request_id flows through format_gate_decision unchanged.

        Locks the data shape so that when a caller (e.g. a future wiring of
        run_promotion_gates) supplies a real request_id, format_gate_decision
        surfaces it verbatim as ``requestId``.
        """
        decision = GateDecision(
            gate_name="sourceIntegrity",
            capability_uri="cap://user/asg/test/private/skill/test.x@0.1.0",
            outcome="passed",
            request_id="req-xyz",
            reason="source_hash_verified",
        )
        wire = format_gate_decision(decision)
        self.assertEqual(
            wire,
            {
                "gateName": "sourceIntegrity",
                "capabilityUri": "cap://user/asg/test/private/skill/test.x@0.1.0",
                "outcome": "passed",
                "requestId": "req-xyz",
                "reason": "source_hash_verified",
            },
        )

    def test_format_gate_decision_none_request_id(self) -> None:
        """GateDecision(request_id=None) -> format_gate_decision yields requestId=None."""
        decision = GateDecision(
            gate_name="g",
            capability_uri="u",
            outcome="passed",
            request_id=None,
            reason="r",
        )
        self.assertEqual(
            format_gate_decision(decision),
            {"gateName": "g", "capabilityUri": "u", "outcome": "passed", "requestId": None, "reason": "r"},
        )

    def test_run_promotion_gates_request_id_contract(self) -> None:
        """run_promotion_gates is wired to gate.eval and carries its request_id.

        ``run_promotion_gates`` reads ``payload["requestId"]`` (the promotion
        request id), validates it, and emits one ``gate.eval`` log event per
        evaluated gate via ``log_event`` / ``GateDecision`` /
        ``format_gate_decision`` (CM-13 observability wiring). Each event carries
        ``requestId`` equal to the promotion request id it was called with,
        closing the end-to-end request-correlation gap (``review_capability``
        alone hardcodes ``requestId: None`` because it has no request_id param).
        """
        cap = self._store(_make_cap(self.root, "promreq"))
        # Seed a pending promotion request row so run_promotion_gates can load it.
        request_id = "prom-req-1"
        self.con.execute(
            """INSERT INTO promotion_requests(
                   id, tenant_id, capability_uri, state, title, rationale, version, gates_json
               ) VALUES (?, ?, ?, 'pending', '', '', '', '{}')""",
            (request_id, "asg", cap.uri),
        )
        self.con.commit()

        with mock.patch.object(lifecycle_mod, "log_event") as spy:
            result = run_promotion_gates(self.con, self.admin, {"requestId": request_id})

        # run_promotion_gates returns the requestId it was called with.
        self.assertEqual(result["requestId"], request_id)

        gate_eval_calls = [
            call
            for call in spy.call_args_list
            if len(call.args) >= 2 and call.args[1] == "gate.eval"
        ]
        # WIRED contract: run_promotion_gates is now instrumented with
        # log_event + format_gate_decision, so it emits one gate.eval event per
        # evaluated gate and each carries requestId == the promotion request id
        # it was called with (closing the request_id correlation gap).
        self.assertTrue(
            gate_eval_calls,
            "run_promotion_gates should emit gate.eval events once instrumented",
        )
        for call in gate_eval_calls:
            self.assertEqual(
                call.kwargs.get("requestId"),
                request_id,
                "run_promotion_gates gate.eval event missing/wrong requestId: "
                f"{call}",
            )


if __name__ == "__main__":
    unittest.main()
