"""Tests for CM-07: draft capabilities in vault placement.

Drafts matching a manifest tail ARE placed at the manifest target, retaining
their draft lifecycle/approval_state. High/critical risk drafts targeting
all-user vault are gated by riskTierPolicy. Published caps are unaffected.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capmesh.governance import (
    all_users_namespace_id,
    all_users_namespace_prefix,
    all_users_store_id,
    apply_vault_placement,
    evaluate_risk_tier_policy,
    org_shared_namespace_id,
    org_shared_namespace_prefix,
    org_store_id,
)
from capmesh.index import connect, init_db
from capmesh.models import Capability


def _write_plugin(root: Path, name: str, version: str, skill: str, desc: str) -> None:
    plugin = root / "plugins" / name
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / "skills" / skill).mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": name, "version": version, "description": desc}),
        encoding="utf-8",
    )
    (plugin / "skills" / skill / "SKILL.md").write_text(
        f"---\nname: {skill}\ndescription: {desc}\n---\n# {skill}\n{desc}\n",
        encoding="utf-8",
    )


class DraftVaultPlacementTest(unittest.TestCase):
    """CM-07: Draft capabilities participate in vault placement via direct
    apply_vault_placement calls (unit-level). The full integration path through
    rebuild_index re-creates Capability objects from SKILL.md metadata which
    default to published/active, making it impractical for draft testing."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "mesh.db"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_con(self) -> None:
        con = connect(self.db_path)
        init_db(con, enable_vector=False)
        con.close()

    def _cap(
        self,
        approval_state: str = "published",
        lifecycle: str = "active",
        risk_tier: str = "low",
        tenant_id: str = "asg",
        uri: str | None = None,
        owner: str | None = None,
    ) -> Capability:
        if uri is None:
            from capmesh.governance import default_user_namespace_prefix
            uri = f"{default_user_namespace_prefix(tenant_id)}/skill/test.test-skill@0.1.0"
        return Capability(
            uri=uri,
            capability_type="skill",
            name="test-skill",
            version="0.1.0",
            title="Test skill",
            description="Test description",
            package_path="pkg",
            entrypoint="entry",
            source_path="src",
            source_kind="plugin_capability",
            source_system="test",
            canonical_key="skill:test:test-skill:0.1.0",
            content_hash="deadbeef",
            plugin="test",
            tenant_id=tenant_id,
            risk_tier=risk_tier,
            lifecycle=lifecycle,
            approval_state=approval_state,
            owner=owner,
        )

    def test_draft_matching_manifest_tail_is_placed(self) -> None:
        """A draft whose canonical tail matches a manifest entry is placed at
        the manifest target, retaining its draft lifecycle and approval_state."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{org_shared_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "org",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="draft", lifecycle="draft")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertTrue(placed.uri.startswith(org_shared_namespace_prefix()))
            self.assertEqual(placed.approval_state, "draft")
            self.assertEqual(placed.lifecycle, "draft")
            self.assertEqual(placed.store_id, org_store_id())
            self.assertEqual(placed.namespace_id, org_shared_namespace_id())
            self.assertEqual(placed.share_state, "not_shared")
        finally:
            con.close()

    def test_draft_without_manifest_entry_stays_in_source(self) -> None:
        """A draft with no manifest match is NOT moved (returns None from
        apply_vault_placement)."""
        self._make_con()
        con = connect(self.db_path)
        try:
            # Empty manifest means no matches.
            idx: dict[str, str] = {}
            cap = self._cap(approval_state="draft", lifecycle="draft")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNone(placed)
            # The caller will then apply_default_user_namespace which keeps it
            # in the source private namespace.
            self.assertTrue(cap.uri.startswith("cap://user/"))
            self.assertEqual(cap.approval_state, "draft")
            self.assertEqual(cap.lifecycle, "draft")
        finally:
            con.close()

    def test_high_risk_draft_not_placed_to_all_user(self) -> None:
        """A high-risk draft targeting an all-user vault is NOT placed to all-user.
        riskTierPolicy is honored for drafts."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{all_users_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "all",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="draft", lifecycle="draft", risk_tier="high")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNone(placed, "high-risk draft should NOT be placed to all-user")
        finally:
            con.close()

    def test_critical_risk_draft_not_placed_to_all_user(self) -> None:
        """A critical-risk draft targeting an all-user vault is NOT placed."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{all_users_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "all",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="draft", lifecycle="draft", risk_tier="critical")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNone(placed, "critical-risk draft should NOT be placed to all-user")
        finally:
            con.close()

    def test_low_risk_draft_placed_to_all_user(self) -> None:
        """A low-risk draft targeting an all-user vault IS placed (riskTierPolicy
        allows low-tier)."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{all_users_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "all",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="draft", lifecycle="draft", risk_tier="low")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertTrue(placed.uri.startswith(all_users_namespace_prefix()))
            self.assertEqual(placed.approval_state, "draft")
            self.assertEqual(placed.lifecycle, "draft")
        finally:
            con.close()

    def test_medium_risk_draft_placed_to_all_user(self) -> None:
        """A medium-risk draft targeting an all-user vault IS placed (riskTierPolicy
        allows medium-tier with warning)."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{all_users_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "all",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="draft", lifecycle="draft", risk_tier="medium")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertTrue(placed.uri.startswith(all_users_namespace_prefix()))
            self.assertEqual(placed.approval_state, "draft")
            self.assertEqual(placed.lifecycle, "draft")
        finally:
            con.close()

    def test_published_cap_placement_unchanged_org(self) -> None:
        """A published cap matching the manifest is placed to org namespace with
        approved state (no regression)."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{org_shared_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "org",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="published", lifecycle="active")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertTrue(placed.uri.startswith(org_shared_namespace_prefix()))
            self.assertEqual(placed.approval_state, "approved")
            self.assertEqual(placed.lifecycle, "published")
            self.assertEqual(placed.share_state, "shared")
            self.assertEqual(placed.store_id, org_store_id())
            self.assertEqual(placed.namespace_id, org_shared_namespace_id())
        finally:
            con.close()

    def test_published_cap_placement_unchanged_all(self) -> None:
        """A published cap targeting all-user vault is placed to all with
        approved state (no regression)."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{all_users_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "all",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(approval_state="published", lifecycle="active")
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertTrue(placed.uri.startswith(all_users_namespace_prefix()))
            self.assertEqual(placed.approval_state, "approved")
            self.assertEqual(placed.lifecycle, "published")
            self.assertEqual(placed.share_state, "shared")
            self.assertEqual(placed.store_id, all_users_store_id())
            self.assertEqual(placed.namespace_id, all_users_namespace_id())
        finally:
            con.close()

    def test_draft_state_preserves_original_owner(self) -> None:
        """When a draft is placed, the original owner is preserved in metadata."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{org_shared_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "org",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            cap = self._cap(
                approval_state="draft",
                lifecycle="draft",
                owner="jason@example.com",
            )
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed)
            self.assertEqual(placed.metadata.get("originalOwner"), "jason@example.com")
            self.assertEqual(placed.approval_state, "draft")
        finally:
            con.close()

    def test_system_capability_not_placed(self) -> None:
        """System capabilities are never placed, even if in the manifest."""
        self._make_con()
        con = connect(self.db_path)
        try:
            manifest = {
                "version": 1,
                "placements": [
                    {
                        "uri": f"{org_shared_namespace_prefix()}/skill/test.test-skill@0.1.0",
                        "vault": "org",
                    },
                ],
            }
            from capmesh.governance import _manifest_uri_tail, _vault_match_key
            idx: dict[str, str] = {}
            for entry in manifest.get("placements", []):
                idx[_vault_match_key(_manifest_uri_tail(entry["uri"]))] = entry["vault"]

            from capmesh.models import Capability as _Cap
            cap = _Cap(
                uri="cap://system/test-skill",
                capability_type="skill",
                name="test-skill",
                version="0.1.0",
                title="Test",
                description="Test",
                package_path="pkg",
                entrypoint="entry",
                source_path="src",
                source_kind="system_capability",
                source_system="capmesh.system",
                canonical_key="skill:system:test-skill:0.1.0",
                content_hash="deadbeef",
                plugin="test",
                lifecycle="draft",
                approval_state="draft",
                visibility="internal",
            )
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNone(placed)
        finally:
            con.close()


class RiskTierPolicyGateTest(unittest.TestCase):
    """Verify evaluate_risk_tier_policy is correctly applied to draft placement."""

    def test_high_risk_denied_all_user(self) -> None:
        ok, reason = evaluate_risk_tier_policy("high", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("all-user", reason.lower())

    def test_critical_risk_denied_all_user(self) -> None:
        ok, reason = evaluate_risk_tier_policy("critical", "all", "internal")
        self.assertFalse(ok)
        self.assertIn("all-user", reason.lower())

    def test_low_risk_allowed_all_user(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("low", "all", "internal")
        self.assertTrue(ok)

    def test_medium_risk_allowed_all_user(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("medium", "all", "internal")
        self.assertTrue(ok)

    def test_org_vault_allows_all_risk_tiers(self) -> None:
        ok, _reason = evaluate_risk_tier_policy("high", "org", "internal")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
