"""Tests for CM-01: vault placement collision guard.

When two DISTINCT capabilities (different source_uri / different content_hash)
normalize to the SAME canonical_key after the symmetric ``_vault_match_key``
plugin-prefix strip (CM-05), placement must NOT silently collapse them onto one
target namespace. The guard in ``apply_vault_placement`` REFUSES the second
placement (rather than suffix-disambiguating the key), leaving the second cap in
its source namespace and recording a ``vault_placement.collision`` audit event
that names both caps and the colliding key. The symmetric ``_vault_match_key``
normalization itself is unchanged (CM-05 is DONE).
"""

from __future__ import annotations

import unittest

from capmesh.governance import (
    _vault_match_key,
    apply_vault_placement,
    org_shared_namespace_id,
    org_shared_namespace_prefix,
)
from capmesh.index import connect, init_db, upsert_capability
from capmesh.models import Capability


def _cap(
    plugin: str,
    name: str = "foo",
    content_hash: str = "sha256:aaa",
    source_uri: str | None = None,
    capability_type: str = "agent",
    version: str = "0.1.0",
    tenant_id: str = "asg",
) -> Capability:
    """Build a source capability with an explicit, distinct content hash."""
    if source_uri is None:
        source_uri = f"cap://source/{plugin}/{name}"
    return Capability(
        uri=source_uri,
        capability_type=capability_type,
        name=name,
        version=version,
        title=f"{plugin} {name}",
        description=f"Source cap for {plugin}/{name}.",
        package_path="pkg",
        entrypoint="entry",
        source_path="src",
        source_kind="plugin_capability",
        source_system="test",
        canonical_key=f"{capability_type}:{plugin}:{name}:{version}",
        content_hash=content_hash,
        plugin=plugin,
        tenant_id=tenant_id,
        risk_tier="low",
    )


def _org_index(plugin_tail: str = "global.foo@0.1.0", vault: str = "org") -> dict[str, str]:
    """Build a placement index with one org entry for ``agent/<plugin_tail>``."""
    from capmesh.governance import _manifest_uri_tail

    return {_vault_match_key(_manifest_uri_tail(f"{org_shared_namespace_prefix()}/agent/{plugin_tail}")): vault}


class VaultMatchCollisionGuardTest(unittest.TestCase):
    """CM-01: refuse (not suffix) when a distinct cap would collapse onto a
    canonical_key already held at the same target namespace."""

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "mesh.db"
        con = connect(self.db_path)
        try:
            init_db(con, enable_vector=False)
        finally:
            con.close()

    def _connect(self):
        return connect(self.db_path)

    def test_no_collision_places_normally(self) -> None:
        """A single cap matching a manifest tail is placed as before; the guard
        does not regress the no-collision path."""
        idx = _org_index("global.foo@0.1.0")
        cap = _cap(plugin="global", content_hash="sha256:aaa")
        con = self._connect()
        try:
            placed = apply_vault_placement(con, cap, idx)
            self.assertIsNotNone(placed, "non-colliding cap must be placed")
            self.assertTrue(placed.uri.startswith(org_shared_namespace_prefix()))
            self.assertEqual(placed.namespace_id, org_shared_namespace_id())
            self.assertEqual(placed.approval_state, "approved")
            self.assertIn("global.foo@0.1.0", placed.uri)
        finally:
            con.close()

    def test_collision_refused(self) -> None:
        """Two distinct caps (different source_uri / different content_hash)
        that normalize to the same canonical_key at the same target: the second
        is NOT placed to the target (refused) and stays in its source namespace."""
        idx = _org_index("global.foo@0.1.0")
        cap_a = _cap(plugin="global", content_hash="sha256:aaa")
        cap_b = _cap(
            plugin="agentic-flow-specialists-2026",
            content_hash="sha256:bbb",
            source_uri="cap://source/agentic-flow-specialists-2026/foo",
        )
        # Both normalize to agent/foo@0.1.0 under the symmetric strip.
        self.assertEqual(
            _vault_match_key("agent/global.foo@0.1.0"),
            _vault_match_key("agent/agentic-flow-specialists-2026.foo@0.1.0"),
        )

        con = self._connect()
        try:
            # Place and persist cap A so it occupies the org namespace.
            placed_a = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(placed_a)
            upsert_capability(con, placed_a)

            # Cap B is distinct (different source_uri AND different content_hash)
            # but collapses to the same canonical_key: must be REFUSED.
            placed_b = apply_vault_placement(con, cap_b, idx)
            self.assertIsNone(placed_b, "distinct cap collapsing onto an occupied key must be refused")

            # Refusal leaves cap B in its source namespace (unchanged).
            self.assertEqual(cap_b.uri, "cap://source/agentic-flow-specialists-2026/foo")
            self.assertEqual(cap_b.content_hash, "sha256:bbb")

            # And cap A remains the sole placed cap in the org namespace.
            rows = con.execute(
                "SELECT uri FROM capabilities WHERE namespace_id = ?",
                (org_shared_namespace_id(),),
            ).fetchall()
            placed_uris = [r["uri"] for r in rows]
            self.assertEqual(len(placed_uris), 1)
            self.assertTrue(placed_uris[0].startswith(org_shared_namespace_prefix()))
            self.assertIn("global.foo@0.1.0", placed_uris[0])
        finally:
            con.close()

    def test_same_content_reingest_is_not_a_collision(self) -> None:
        """Re-ingest of the SAME cap (same content_hash) is idempotent and not a
        collision: the guard's content_hash check skips it and re-places
        normally. This protects test_placement_survives_reingest behavior."""
        idx = _org_index("global.foo@0.1.0")
        cap_a = _cap(plugin="global", content_hash="sha256:aaa")
        con = self._connect()
        try:
            placed_a = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(placed_a)
            upsert_capability(con, placed_a)

            # Re-ingest the same source cap (same content_hash): must re-place.
            re_placed = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(re_placed, "re-ingest of the same cap must not be refused")
            self.assertEqual(re_placed.uri, placed_a.uri)
        finally:
            con.close()

    def test_collision_reason_recorded(self) -> None:
        """The refusal records a placement-collision reason (audit event) naming
        both caps and the colliding canonical_key."""
        idx = _org_index("global.foo@0.1.0")
        cap_a = _cap(plugin="global", content_hash="sha256:aaa")
        cap_b = _cap(
            plugin="agentic-flow-specialists-2026",
            content_hash="sha256:bbb",
            source_uri="cap://source/agentic-flow-specialists-2026/foo",
        )
        con = self._connect()
        try:
            placed_a = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(placed_a)
            upsert_capability(con, placed_a)

            placed_b = apply_vault_placement(con, cap_b, idx)
            self.assertIsNone(placed_b)

            import json

            rows = con.execute(
                "SELECT target, action, decision, reason, payload_json "
                "FROM audit_events WHERE event_type = ? ORDER BY created_at DESC",
                ("vault_placement.collision",),
            ).fetchall()
            self.assertEqual(len(rows), 1, "exactly one placement-collision audit event must be recorded")
            row = rows[0]
            self.assertEqual(row["action"], "place")
            self.assertEqual(row["decision"], "deny")
            self.assertIn("canonical_key already held", row["reason"])

            payload = json.loads(row["payload_json"])
            # Names both caps (incoming + existing) and the colliding key.
            self.assertEqual(payload["incomingUri"], cap_b.uri)
            self.assertEqual(payload["incomingContentHash"], "sha256:bbb")
            self.assertEqual(payload["existingUri"], placed_a.uri)
            self.assertEqual(payload["existingContentHash"], "sha256:aaa")
            self.assertEqual(payload["canonicalKey"], "agent/foo@0.1.0")
            self.assertEqual(payload["vault"], "org")
            self.assertEqual(payload["targetNamespace"], org_shared_namespace_id())
            # The audit target is the refused (incoming) cap uri.
            self.assertEqual(row["target"], cap_b.uri)
        finally:
            con.close()

    def test_collision_refused_all_user_target(self) -> None:
        """The guard fires for the all-user vault too, not only org."""
        from capmesh.governance import (
            _manifest_uri_tail,
            all_users_namespace_id,
            all_users_namespace_prefix,
        )

        idx = {
            _vault_match_key(
                _manifest_uri_tail(f"{all_users_namespace_prefix()}/agent/global.foo@0.1.0")
            ): "all"
        }
        cap_a = _cap(plugin="global", content_hash="sha256:aaa")
        cap_b = _cap(
            plugin="anthropic-code-feature-dev",
            content_hash="sha256:bbb",
            source_uri="cap://source/anthropic-code-feature-dev/foo",
        )
        con = self._connect()
        try:
            placed_a = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(placed_a)
            upsert_capability(con, placed_a)

            placed_b = apply_vault_placement(con, cap_b, idx)
            self.assertIsNone(placed_b, "distinct cap collapsing onto all-user key must be refused")

            rows = con.execute(
                "SELECT uri FROM capabilities WHERE namespace_id = ?",
                (all_users_namespace_id(),),
            ).fetchall()
            placed_uris = [r["uri"] for r in rows]
            self.assertEqual(len(placed_uris), 1)
            self.assertTrue(placed_uris[0].startswith(all_users_namespace_prefix()))
        finally:
            con.close()

    def test_collision_refused_for_drafts(self) -> None:
        """The guard fires for draft placement too (drafts are placed but retain
        draft state); a distinct draft collapsing onto an occupied key is refused."""
        idx = _org_index("global.foo@0.1.0")
        cap_a = _cap(plugin="global", content_hash="sha256:aaa")
        cap_a_draft = _cap(
            plugin="agentic-flow-specialists-2026",
            content_hash="sha256:bbb",
            source_uri="cap://source/agentic-flow-specialists-2026/foo",
        )
        # Make B a draft.
        from dataclasses import replace

        cap_b_draft = replace(cap_a_draft, approval_state="draft", lifecycle="draft")
        con = self._connect()
        try:
            placed_a = apply_vault_placement(con, cap_a, idx)
            self.assertIsNotNone(placed_a)
            upsert_capability(con, placed_a)

            placed_b = apply_vault_placement(con, cap_b_draft, idx)
            self.assertIsNone(placed_b, "distinct draft collapsing onto an occupied key must be refused")
        finally:
            con.close()

    def test_distinct_caps_different_names_do_not_collide(self) -> None:
        """Two caps with different canonical names (different match keys) at the
        same target are both placed -- the guard only fires on a real key collision."""
        from capmesh.governance import _manifest_uri_tail

        idx = {
            _vault_match_key(_manifest_uri_tail(f"{org_shared_namespace_prefix()}/agent/global.foo@0.1.0")): "org",
            _vault_match_key(_manifest_uri_tail(f"{org_shared_namespace_prefix()}/agent/global.bar@0.1.0")): "org",
        }
        cap_foo = _cap(plugin="global", name="foo", content_hash="sha256:aaa")
        cap_bar = _cap(plugin="global", name="bar", content_hash="sha256:bbb")
        con = self._connect()
        try:
            placed_foo = apply_vault_placement(con, cap_foo, idx)
            self.assertIsNotNone(placed_foo)
            upsert_capability(con, placed_foo)

            placed_bar = apply_vault_placement(con, cap_bar, idx)
            self.assertIsNotNone(placed_bar, "different-name caps must NOT be refused")
            self.assertNotEqual(placed_foo.uri, placed_bar.uri)
        finally:
            con.close()


class VaultMatchKeySymmetricTest(unittest.TestCase):
    """CM-05 no-regression: _vault_match_key normalizes both sides identically."""

    def test_symmetric_matchkey_unchanged(self) -> None:
        # Strips the single plugin prefix on both manifest URIs and live caps.
        self.assertEqual(_vault_match_key("agent/global.foo@0.1.0"), "agent/foo@0.1.0")
        self.assertEqual(_vault_match_key("agent/agentic-flow-specialists-2026.foo@0.1.0"), "agent/foo@0.1.0")
        self.assertEqual(
            _vault_match_key("agent/anthropic-code-feature-dev.foo@0.1.0"),
            "agent/foo@0.1.0",
        )
        # No slash -> returned as-is (symmetric for both sides).
        self.assertEqual(_vault_match_key("nope"), "nope")
        # The two sides of a real collision normalize to the SAME key.
        self.assertEqual(
            _vault_match_key("agent/global.foo@0.1.0"),
            _vault_match_key("agent/agentic-flow-specialists-2026.foo@0.1.0"),
        )
        # Multi-dot capability names retain their own dots (no over-strip).
        self.assertEqual(_vault_match_key("skill/plugin.foo.bar@2.0.0"), "skill/foo.bar@2.0.0")


if __name__ == "__main__":
    unittest.main()
