from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from capmesh.governance import (
    DEFAULT_USER_SUBJECT,
    approve_request,
    ensure_all_users_namespace,
    evaluate_risk_tier_policy,
    submit_promotion,
)
from capmesh.index import connect, init_db, rebuild_index, upsert_capability
from capmesh.models import Capability, Principal


def _unset_production() -> None:
    os.environ.pop("CAPMESH_PRODUCTION", None)


class RiskTierPolicyTests(unittest.TestCase):
    """Tests for the riskTierPolicy gate engine."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(self._restore_state_dir)
        os.environ["CAPMESH_SUPERADMIN_ACTORS"] = "test-admin@example.com"
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        self.db = self.root / "mesh.db"
        rebuild_index(self.db, [self.root / "plugins"], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def _restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    # ---- Unit tests for evaluate_risk_tier_policy ----

    def test_high_blocked_from_everyone(self) -> None:
        ok, reason = evaluate_risk_tier_policy("high", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("high", reason.lower())
        self.assertIn("all-user", reason.lower())

    def test_critical_blocked_from_everyone(self) -> None:
        ok, reason = evaluate_risk_tier_policy("critical", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("critical", reason.lower())

    def test_medium_allowed_with_warning_to_everyone(self) -> None:
        ok, reason = evaluate_risk_tier_policy("medium", "all", "internal")
        self.assertTrue(ok)
        self.assertIn("warning", reason.lower())

    def test_low_allowed_to_everyone(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("low", "all", "internal")
        self.assertTrue(ok)

    def test_none_allowed_to_everyone(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("none", "all", "internal")
        self.assertTrue(ok)

    def test_high_allowed_to_org(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("high", "org", "internal")
        self.assertTrue(ok)

    def test_critical_allowed_to_org(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("critical", "org", "internal")
        self.assertTrue(ok)

    def test_high_allowed_to_private(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("high", "private", "internal")
        self.assertTrue(ok)

    def test_unknown_tier_denied(self) -> None:
        ok, reason = evaluate_risk_tier_policy("unknown_level", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("unknown", reason.lower())

    def test_unknown_tier_to_org_allows_because_org_is_allowlisted(self) -> None:
        # org/private vaults are allowlisted for all tiers including unknown
        ok, _reason = evaluate_risk_tier_policy("unknown_level", "org", "internal")
        self.assertTrue(ok)

    # ---- Integration: approve_request reflects riskTierPolicy gate ----

    def test_high_tier_cap_to_all_user_has_failed_risk_tier_policy_gate(self) -> None:
        """A high-risk capability promoted to the all-user namespace gets a
        failed riskTierPolicy gate, and approve_request refuses without
        overridePendingGates."""
        admin = Principal(subject="admin@example.com", roles=("platform_admin",), scopes=("cap:*",))

        cap = Capability(
            uri="cap://user/asg/jason/private/high-risk-tool@0.1.0",
            capability_type="skill",
            name="high-risk-tool",
            version="0.1.0",
            title="High Risk Tool",
            description="A tool with high risk tier.",
            package_path=str(self.root),
            entrypoint="high.md",
            source_path=str(self.root / "high.md"),
            source_kind="cap_manifest",
            source_system="test",
            canonical_key="tool:test:high-risk-tool",
            content_hash="sha256:high",
            visibility="protected",
            discovery_mode="hidden",
            owner=DEFAULT_USER_SUBJECT,
            keywords=("high", "risk"),
            risk_tier="high",
            lifecycle="draft",
            tenant_id="asg",
            store_id="store_high",
            namespace_id="ns_high",
            created_by=DEFAULT_USER_SUBJECT,
            approval_state="draft",
            signature_status="unchecked",
            provenance_status="unchecked",
            risk_review_status="pending",
            metadata={},
        )
        (self.root / "high.md").write_text("high risk content", encoding="utf-8")
        upsert_capability(self.con, cap)
        self.con.commit()

        all_ns_id = ensure_all_users_namespace(self.con)

        requester = Principal(
            subject=DEFAULT_USER_SUBJECT,
            roles=(),
            scopes=("cap:search", "cap:load", "cap:call", "cap:delegate"),
        )
        request = submit_promotion(
            self.con,
            requester,
            {
                "capabilityUri": cap.uri,
                "targetNamespaceId": all_ns_id,
                "title": "Promote high-risk tool to all",
            },
        )
        self.assertEqual(request["state"], "pending")

        # Check that the gates_json contains riskTierPolicy
        gates_row = self.con.execute(
            "SELECT gates_json FROM promotion_requests WHERE id = ?", (request["id"],)
        ).fetchone()
        gates = json.loads(gates_row["gates_json"])
        self.assertIn("riskTierPolicy", gates)

        # approve_request without override should refuse because riskTierPolicy
        # evaluates to "failed"
        with self.assertRaises(PermissionError) as ctx:
            approve_request(self.con, admin, {"requestId": request["id"], "decision": "approve"})

        self.assertIn("riskTierPolicy", str(ctx.exception))
        self.assertIn("pending", str(ctx.exception).lower())

        # Request state must still be pending (no partial write)
        state = self.con.execute(
            "SELECT state FROM promotion_requests WHERE id = ?", (request["id"],)
        ).fetchone()["state"]
        self.assertEqual(state, "pending")

    def test_low_tier_cap_to_all_user_passes_risk_tier_policy(self) -> None:
        """A low-risk capability promoted to the all-user namespace has
        riskTierPolicy passing."""
        admin = Principal(subject="admin@example.com", roles=("platform_admin",), scopes=("cap:*",))
        os.environ.pop("CAPMESH_PRODUCTION", None)
        self.addCleanup(_unset_production)

        cap = Capability(
            uri="cap://user/asg/jason/private/low-risk-tool@0.1.0",
            capability_type="skill",
            name="low-risk-tool",
            version="0.1.0",
            title="Low Risk Tool",
            description="A tool with low risk tier.",
            package_path=str(self.root),
            entrypoint="low.md",
            source_path=str(self.root / "low.md"),
            source_kind="cap_manifest",
            source_system="test",
            canonical_key="tool:test:low-risk-tool",
            content_hash="sha256:low",
            visibility="protected",
            discovery_mode="hidden",
            owner=DEFAULT_USER_SUBJECT,
            keywords=("low", "risk"),
            risk_tier="low",
            lifecycle="draft",
            tenant_id="asg",
            store_id="store_low",
            namespace_id="ns_low",
            created_by=DEFAULT_USER_SUBJECT,
            approval_state="draft",
            signature_status="unchecked",
            provenance_status="unchecked",
            risk_review_status="pending",
            metadata={},
        )
        (self.root / "low.md").write_text("low risk content", encoding="utf-8")
        upsert_capability(self.con, cap)
        self.con.commit()

        all_ns_id = ensure_all_users_namespace(self.con)

        requester = Principal(
            subject=DEFAULT_USER_SUBJECT,
            roles=(),
            scopes=("cap:search", "cap:load", "cap:call", "cap:delegate"),
        )
        request = submit_promotion(
            self.con,
            requester,
            {
                "capabilityUri": cap.uri,
                "targetNamespaceId": all_ns_id,
                "title": "Promote low-risk tool to all",
            },
        )
        self.assertEqual(request["state"], "pending")

        # Approve with override: should succeed; low passes riskTierPolicy
        result = approve_request(
            self.con,
            admin,
            {"requestId": request["id"], "decision": "approve", "overridePendingGates": True},
        )
        self.assertEqual(result["state"], "approved")

    def test_medium_tier_to_all_user_passes_risk_tier_policy(self) -> None:
        """Medium-risk capability promoted to all-user passes riskTierPolicy."""
        admin = Principal(subject="admin@example.com", roles=("platform_admin",), scopes=("cap:*",))
        os.environ.pop("CAPMESH_PRODUCTION", None)
        self.addCleanup(_unset_production)

        cap = Capability(
            uri="cap://user/asg/jason/private/med-risk-tool@0.1.0",
            capability_type="skill",
            name="med-risk-tool",
            version="0.1.0",
            title="Medium Risk Tool",
            description="A tool with medium risk tier.",
            package_path=str(self.root),
            entrypoint="med.md",
            source_path=str(self.root / "med.md"),
            source_kind="cap_manifest",
            source_system="test",
            canonical_key="tool:test:med-risk-tool",
            content_hash="sha256:med",
            visibility="protected",
            discovery_mode="hidden",
            owner=DEFAULT_USER_SUBJECT,
            keywords=("medium", "risk"),
            risk_tier="medium",
            lifecycle="draft",
            tenant_id="asg",
            store_id="store_med",
            namespace_id="ns_med",
            created_by=DEFAULT_USER_SUBJECT,
            approval_state="draft",
            signature_status="unchecked",
            provenance_status="unchecked",
            risk_review_status="pending",
            metadata={},
        )
        (self.root / "med.md").write_text("medium risk content", encoding="utf-8")
        upsert_capability(self.con, cap)
        self.con.commit()

        all_ns_id = ensure_all_users_namespace(self.con)

        requester = Principal(
            subject=DEFAULT_USER_SUBJECT,
            roles=(),
            scopes=("cap:search", "cap:load", "cap:call", "cap:delegate"),
        )
        request = submit_promotion(
            self.con,
            requester,
            {
                "capabilityUri": cap.uri,
                "targetNamespaceId": all_ns_id,
                "title": "Promote medium-risk tool to all",
            },
        )

        result = approve_request(
            self.con,
            admin,
            {"requestId": request["id"], "decision": "approve", "overridePendingGates": True},
        )
        self.assertEqual(result["state"], "approved")


if __name__ == "__main__":
    unittest.main()
