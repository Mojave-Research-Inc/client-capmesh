"""WAVE5-WIRING-c: approve_request runs the full lifecycle gate set.

The main promotion-approval path (``governance.approve_request``) must call
the lifecycle gate runner so every promotion evaluates the full gate set
(sourceIntegrity, tests, retrievalEvals, signature, provenance,
promptInjectionScan, riskTierPolicy) -- not just the ad-hoc riskTierPolicy +
promptInjectionScan re-evaluations. The gate runner's per-gate states are the
authoritative source for the ``gates_json`` written to ``promotion_requests``;
a failed required gate blocks approval unless ``overridePendingGates`` forces
it through.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh import lifecycle
from capmesh.governance import (
    DEFAULT_USER_SUBJECT,
    approve_request,
    default_promotion_gates,
    ensure_org_shared_namespace,
    submit_promotion,
)
from capmesh.index import connect, init_db, upsert_capability
from capmesh.models import Capability, Principal


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _make_cap(root: Path, name: str, *, risk_tier: str = "low") -> tuple[Capability, Path]:
    source = root / f"{name}.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        f"---\nname: {name}\ndescription: {name} capability\n---\n# {name}\nOperate safely.\n",
        encoding="utf-8",
    )
    cap = Capability(
        uri=f"cap://user/asg/test/private/skill/{name}@0.1.0",
        capability_type="skill",
        name=name,
        version="0.1.0",
        title=name,
        description=f"{name} capability",
        package_path=str(source.parent),
        entrypoint=source.name,
        source_path=str(source),
        source_kind="skill_markdown",
        source_system="test",
        canonical_key=f"skill:test:{name}:0.1.0",
        content_hash=_file_digest(source),
        visibility="protected",
        discovery_mode="hidden",
        owner=DEFAULT_USER_SUBJECT,
        keywords=(),
        risk_tier=risk_tier,
        lifecycle="draft",
        tenant_id="asg",
        created_by=DEFAULT_USER_SUBJECT,
        approval_state="draft",
    )
    return cap, source


class ApproveRequestUsesGateRunnerTests(unittest.TestCase):
    """WAVE5-WIRING-c: approve_request delegates to the lifecycle gate runner."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "test",
                "CAPMESH_STATE_DIR": str(self.root / "state"),
            },
            clear=False,
        )
        self._env.start()
        self.con = connect(self.root / "mesh.db")
        init_db(self.con, enable_vector=False)
        self.admin = Principal(
            subject="admin@example.com",
            tenant_id="asg",
            roles=("org_admin",),
            scopes=("cap:*",),
        )
        self.requester = Principal(
            subject=DEFAULT_USER_SUBJECT,
            tenant_id="asg",
            roles=(),
            scopes=("cap:search", "cap:load", "cap:call", "cap:delegate"),
        )

    def tearDown(self) -> None:
        self.con.close()
        self._env.stop()
        self.tmp.cleanup()

    def add_cap(self, name: str, *, risk_tier: str = "low") -> Capability:
        cap, _source = _make_cap(self.root, name, risk_tier=risk_tier)
        upsert_capability(self.con, cap)
        self.con.commit()
        return cap

    def _gates_json(self, request_id: str) -> dict[str, str]:
        row = self.con.execute(
            "SELECT gates_json FROM promotion_requests WHERE id = ?", (request_id,)
        ).fetchone()
        return json.loads(row["gates_json"])

    def _state(self, request_id: str) -> str:
        return self.con.execute(
            "SELECT state FROM promotion_requests WHERE id = ?", (request_id,)
        ).fetchone()["state"]

    def _submit_to_org(self, cap: Capability) -> dict:
        org_ns_id = ensure_org_shared_namespace(self.con)
        return submit_promotion(
            self.con,
            self.requester,
            {"capabilityUri": cap.uri, "targetNamespaceId": org_ns_id, "title": f"Promote {cap.name}"},
        )

    def test_approve_request_runs_full_gate_set(self) -> None:
        """approve_request writes all 7 gate names to gates_json, not just the
        two ad-hoc re-evaluations."""
        cap = self.add_cap("full-gate-set")
        request = self._submit_to_org(cap)

        approve_request(self.con, self.admin, {"requestId": request["id"], "decision": "approve"})

        gates = self._gates_json(request["id"])
        expected = set(default_promotion_gates())
        self.assertEqual(set(gates.keys()), expected)
        # Every gate has a concrete state (not the placeholder "pending" from
        # submit_promotion) -- the gate runner supplied authoritative values.
        for name, state in gates.items():
            self.assertIn(state, {"passed", "skipped"}, f"gate {name}={state!r}")

    def test_approve_request_all_passed_approves(self) -> None:
        """Happy path: all gates passed -> state=approved (no regression)."""
        cap = self.add_cap("happy-path")
        request = self._submit_to_org(cap)

        result = approve_request(self.con, self.admin, {"requestId": request["id"], "decision": "approve"})

        self.assertEqual(result["state"], "approved")
        gates = self._gates_json(request["id"])
        self.assertTrue(all(state in {"passed", "skipped"} for state in gates.values()))

    def test_approve_request_gate_failure_blocks_approval(self) -> None:
        """If the gate runner returns a failed required gate, approve_request
        must NOT set state=approved -- the request stays pending and the
        failing gate is named."""
        cap = self.add_cap("blocked-by-runner")
        request = self._submit_to_org(cap)

        failed_gates = {
            name: {"state": "passed", "evidence": {"code": "ok"}}
            for name in default_promotion_gates()
        }
        failed_gates["signature"] = {
            "state": "failed",
            "evidence": {"code": "signature_unavailable", "error": "monkeypatched failure"},
        }
        gate_runner_result = {
            "capabilityUri": cap.uri,
            "contentHash": cap.content_hash,
            "reviewScope": "org",
            "dryRun": True,
            "passed": False,
            "gates": failed_gates,
        }
        with mock.patch.object(
            lifecycle, "review_capability", return_value=gate_runner_result
        ) as patched_runner:
            with self.assertRaises(PermissionError) as ctx:
                approve_request(
                    self.con, self.admin, {"requestId": request["id"], "decision": "approve"}
                )
            self.assertTrue(patched_runner.called)

        message = str(ctx.exception)
        self.assertIn("signature", message.lower())
        # No partial write: the request remains pending after the refusal.
        self.assertEqual(self._state(request["id"]), "pending")
        # The failing gate state is recorded in gates_json.
        gates = self._gates_json(request["id"])
        self.assertEqual(gates.get("signature"), "failed")

    def test_override_pending_gates_still_works(self) -> None:
        """overridePendingGates=True forces approval past a failed gate
        (existing behavior preserved)."""
        cap = self.add_cap("override-path")
        request = self._submit_to_org(cap)

        failed_gates = {
            name: {"state": "passed", "evidence": {"code": "ok"}}
            for name in default_promotion_gates()
        }
        failed_gates["signature"] = {
            "state": "failed",
            "evidence": {"code": "signature_unavailable"},
        }
        gate_runner_result = {
            "capabilityUri": cap.uri,
            "contentHash": cap.content_hash,
            "reviewScope": "org",
            "dryRun": True,
            "passed": False,
            "gates": failed_gates,
        }
        with mock.patch.object(
            lifecycle, "review_capability", return_value=gate_runner_result
        ):
            result = approve_request(
                self.con,
                self.admin,
                {
                    "requestId": request["id"],
                    "decision": "approve",
                    "overridePendingGates": True,
                },
            )
        self.assertEqual(result["state"], "approved")
        gates = self._gates_json(request["id"])
        self.assertEqual(gates.get("signature"), "failed")

    def test_gate_runner_invoked(self) -> None:
        """approve_request invokes the lifecycle gate runner with the right
        capability and principal."""
        cap = self.add_cap("invoked-cap")
        request = self._submit_to_org(cap)

        captured: dict[str, object] = {}

        def fake_review_capability(con, principal, payload, **kwargs):
            captured["con"] = con
            captured["principal"] = principal
            captured["payload"] = dict(payload)
            return {
                "capabilityUri": cap.uri,
                "contentHash": cap.content_hash,
                "reviewScope": "org",
                "dryRun": True,
                "passed": True,
                "gates": {
                    name: {"state": "passed", "evidence": {"code": "ok"}}
                    for name in default_promotion_gates()
                },
            }

        with mock.patch.object(lifecycle, "review_capability", side_effect=fake_review_capability):
            result = approve_request(
                self.con, self.admin, {"requestId": request["id"], "decision": "approve"}
            )

        self.assertEqual(result["state"], "approved")
        self.assertTrue(captured)
        self.assertIs(captured["con"], self.con)
        self.assertEqual(captured["principal"].subject, self.admin.subject)
        self.assertEqual(captured["payload"].get("capabilityUri"), cap.uri)
        self.assertEqual(captured["payload"].get("dryRun"), True)


if __name__ == "__main__":
    unittest.main()
