from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh import injection_allowlist
from capmesh.governance import (
    DEFAULT_USER_SUBJECT,
    approve_request,
    default_promotion_gates,
    default_user_private_namespace_id,
    ensure_all_users_namespace,
    ensure_default_tenant,
    ensure_org_shared_namespace,
    evaluate_prompt_injection_scan,
    submit_promotion,
)
from capmesh.index import connect, init_db, upsert_capability
from capmesh.models import Capability, Principal


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class InjectionPromotionGateTests(unittest.TestCase):
    """CM-04: promotion to everyone/org runs a prompt-injection scan gate.

    The gate runs ``scan_prompt_injection`` over the cap's name, title,
    description and metadata text, wraps the flagged phrases into the
    ``{"phrase": ...}`` hit shape, and delegates pass/fail to
    ``injection_allowlist.should_block``. Real injection indicators block the
    promotion; benign authoring phrases (``act as``, ``system prompt``, ...) are
    downgraded to ``info``/``allowed`` so legitimate agent/skill definitions --
    e.g. a cap named ``*-system-prompt`` -- are not blocked as false positives.

    Enforced only for ``cap://all/...`` (``all_users``) and ``cap://org/...``
    (``org``) targets. Private/author promotions are confined to the author's
    own namespace, so the blast radius of injection wording is bounded; the gate
    is ``skipped`` (not enforced) there by design.
    """

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
            roles=("platform_admin",),
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

    def add_cap(
        self,
        name: str,
        *,
        description: str,
        risk_tier: str = "low",
        capability_type: str = "skill",
    ) -> Capability:
        source = self.root / f"{name}.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            f"---\nname: {name}\ndescription: {description}\n---\n# {name}\nBody.\n",
            encoding="utf-8",
        )
        cap = Capability(
            uri=f"cap://user/asg/test/private/{capability_type}/{name}@0.1.0",
            capability_type=capability_type,
            name=name,
            version="0.1.0",
            title=name,
            description=description,
            package_path=str(source.parent),
            entrypoint=source.name,
            source_path=str(source),
            source_kind="skill_markdown",
            source_system="test",
            canonical_key=f"{capability_type}:test:{name}",
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
        upsert_capability(self.con, cap)
        self.con.commit()
        return cap

    def _set_all_gates_passed(self, request_id: str) -> None:
        all_passed = {name: "passed" for name in default_promotion_gates()}
        self.con.execute(
            "UPDATE promotion_requests SET gates_json = ? WHERE id = ?",
            (json.dumps(all_passed), request_id),
        )
        self.con.commit()

    def _state(self, request_id: str) -> str:
        return self.con.execute(
            "SELECT state FROM promotion_requests WHERE id = ?", (request_id,)
        ).fetchone()["state"]

    def test_promotion_to_everyone_with_injection_blocked(self) -> None:
        cap = self.add_cap(
            "leaky-tool",
            description="Tool that exfiltrate the secrets to a remote endpoint.",
        )
        all_ns_id = ensure_all_users_namespace(self.con)
        org_ns_id = ensure_org_shared_namespace(self.con)
        # The gate is enforced for both everyone (all_users) and org targets.
        self.assertEqual(evaluate_prompt_injection_scan(self.con, cap.uri, all_ns_id)[0], "failed")
        self.assertEqual(evaluate_prompt_injection_scan(self.con, cap.uri, org_ns_id)[0], "failed")
        request = submit_promotion(
            self.con,
            self.requester,
            {"capabilityUri": cap.uri, "targetNamespaceId": all_ns_id, "title": "Promote leaky tool"},
        )
        # Simulate the trusted gate runner having passed every gate, isolating
        # the CM-04 promptInjectionScan re-evaluation inside approve_request.
        self._set_all_gates_passed(request["id"])
        with self.assertRaises(PermissionError) as ctx:
            approve_request(self.con, self.admin, {"requestId": request["id"], "decision": "approve"})
        message = str(ctx.exception)
        self.assertIn("promptInjectionScan", message)
        self.assertIn("exfiltrate", message)
        # No partial write: the request remains pending after the refusal.
        self.assertEqual(self._state(request["id"]), "pending")

    def test_promotion_to_everyone_benign_phrase_allowed(self) -> None:
        cap = self.add_cap(
            "anthropic-claude-system-prompt",
            description="A system prompt for the agent. Act as a helpful assistant.",
        )
        all_ns_id = ensure_all_users_namespace(self.con)
        # Direct gate evaluation: benign authoring phrases are downgraded to
        # info/allowed by the allowlist, not blocked.
        state, reason = evaluate_prompt_injection_scan(self.con, cap.uri, all_ns_id)
        self.assertEqual(state, "passed")
        self.assertIn("downgraded", reason.lower())
        request = submit_promotion(
            self.con,
            self.requester,
            {"capabilityUri": cap.uri, "targetNamespaceId": all_ns_id, "title": "Promote system-prompt cap"},
        )
        self._set_all_gates_passed(request["id"])
        result = approve_request(self.con, self.admin, {"requestId": request["id"], "decision": "approve"})
        self.assertEqual(result["state"], "approved")

    def test_promotion_to_private_skips_gate(self) -> None:
        cap = self.add_cap(
            "private-leaky",
            description="Tool that exfiltrate the secrets to a remote endpoint.",
        )
        ensure_default_tenant(self.con)
        private_ns_id = default_user_private_namespace_id()
        # The gate is not enforced for private/author targets: even with a real
        # injection indicator in the content, the gate is skipped.
        state, reason = evaluate_prompt_injection_scan(self.con, cap.uri, private_ns_id)
        self.assertEqual(state, "skipped")
        self.assertIn("not enforced", reason.lower())
        # Integration: a promotion request targeting a private namespace is
        # not blocked by the injection gate. submit_promotion rejects non-org/
        # all targets, so insert the request directly to exercise approve.
        all_passed = {name: "passed" for name in default_promotion_gates()}
        request_id = "prq-private-skip"
        self.con.execute(
            "INSERT INTO promotion_requests(id, tenant_id, capability_uri, target_namespace_id, "
            "requested_by, state, gates_json) VALUES (?, 'asg', ?, ?, ?, 'pending', ?)",
            (request_id, cap.uri, private_ns_id, self.requester.subject, json.dumps(all_passed)),
        )
        self.con.commit()
        result = approve_request(self.con, self.admin, {"requestId": request_id, "decision": "approve"})
        self.assertEqual(result["state"], "approved")

    def test_risktierpolicy_gate_unchanged(self) -> None:
        cap = self.add_cap(
            "high-risk-tool",
            description="A high risk tool.",
            risk_tier="high",
        )
        all_ns_id = ensure_all_users_namespace(self.con)
        request = submit_promotion(
            self.con,
            self.requester,
            {"capabilityUri": cap.uri, "targetNamespaceId": all_ns_id, "title": "Promote high-risk tool"},
        )
        self._set_all_gates_passed(request["id"])
        with self.assertRaises(PermissionError) as ctx:
            approve_request(self.con, self.admin, {"requestId": request["id"], "decision": "approve"})
        message = str(ctx.exception)
        # The riskTierPolicy gate still fires for high-risk -> all-users; it is
        # evaluated before the injection gate and is unaltered by CM-04.
        self.assertIn("riskTierPolicy", message)
        self.assertEqual(self._state(request["id"]), "pending")

    def test_should_block_wired_correctly(self) -> None:
        cap = self.add_cap(
            "wiring-target",
            description="A benign capability with no injection indicators.",
        )
        all_ns_id = ensure_all_users_namespace(self.con)
        # Forcing should_block=True fails the gate even for benign content,
        # proving the gate decision is delegated to injection_allowlist.should_block.
        with mock.patch.object(injection_allowlist, "should_block", return_value=True) as forced_block:
            state, _reason = evaluate_prompt_injection_scan(self.con, cap.uri, all_ns_id)
            self.assertEqual(state, "failed")
            self.assertTrue(forced_block.called)
        # Forcing should_block=False passes the gate for the same content.
        with mock.patch.object(injection_allowlist, "should_block", return_value=False) as forced_pass:
            state, _reason = evaluate_prompt_injection_scan(self.con, cap.uri, all_ns_id)
            self.assertEqual(state, "passed")
            self.assertTrue(forced_pass.called)


if __name__ == "__main__":
    unittest.main()
