from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh import index as index_module
from capmesh.capguard import list_quarantine, release_capability_from_quarantine
from capmesh.governance import (
    all_users_namespace_id,
    all_users_namespace_prefix,
    all_users_store_id,
    apply_vault_placement,
    evaluate_access,
    load_vault_placement_index,
    org_shared_namespace_id,
    org_shared_namespace_prefix,
    org_store_id,
)
from capmesh.index import connect, get_capability, init_db, list_capabilities, rebuild_index, search
from capmesh.models import Capability, Principal


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


class VaultPlacementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # Two plugins: one will be promoted to org, one to all, one stays private.
        _write_plugin(self.root, "org-plugin", "0.1.0", "org-skill", "Org shared skill.")
        _write_plugin(self.root, "all-plugin", "0.1.0", "all-skill", "All-user skill.")
        _write_plugin(self.root, "private-plugin", "0.1.0", "priv-skill", "Stays private.")
        # Manifest keyed by the placement TARGET uri (org/all namespaces), matching
        # by canonical {type}/{plugin}.{name}@{version} tail.
        manifest = {
            "version": 1,
            "placements": [
                {
                    "uri": f"{org_shared_namespace_prefix()}/skill/org-plugin.org-skill@0.1.0",
                    "vault": "org",
                },
                {
                    "uri": f"{all_users_namespace_prefix()}/skill/all-plugin.all-skill@0.1.0",
                    "vault": "all",
                },
            ],
        }
        self.manifest_path = self.root / "vault-placement.json"
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.db = self.root / "mesh.db"
        # The CapGuard release path signs scan/release attestations and verifies
        # the chain against the trusted anchor. Pin the signing key to a temp
        # path so the release-path assertions below are hermetic and do not
        # touch the shared state-dir key. CAPMESH_ENVIRONMENT is left unset so
        # the per-test production override below still toggles integrity checks.
        self._env = mock.patch.dict(
            os.environ,
            {"CAPMESH_SIGNING_KEY_FILE": str(self.root / "signing.pem")},
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self.tmp.cleanup()

    def _rebuild(self) -> None:
        with mock.patch.object(index_module, "vault_placement_path", return_value=self.manifest_path):
            rebuild_index(self.db, [self.root / "plugins"], enable_vector=False)

    def _quarantine_id_for(self, con, uri: str) -> str:
        """Find the active CapGuard quarantine id for a placed capability URI.

        Placement still resolves the org/all-user namespace, but a new or
        changed capability is held in the quarantine store before it is
        indexed, so it is NOT servable until a clean signed release. This
        helper locates the quarantine row the ingest gate created for *uri*.
        """
        row = con.execute(
            "SELECT id FROM capguard_quarantine "
            "WHERE tenant_id = 'asg' AND capability_uri = ? AND status = 'quarantined' "
            "ORDER BY created_at DESC LIMIT 1",
            (uri,),
        ).fetchone()
        self.assertIsNotNone(row, f"expected an active quarantine row for {uri!r}")
        return row["id"]

    def _release_placed(self, con, uri: str) -> str:
        """Promote a held placed capability via the authoritative fail-closed
        CapGuard release path (clean signed scan attestation). Returns the
        quarantine id that was released."""
        qid = self._quarantine_id_for(con, uri)
        released = release_capability_from_quarantine(con, qid, tenant_id="asg", actor="op@asg")
        self.assertEqual(released["status"], "released")
        return qid

    def test_manifest_entry_lands_in_org_namespace_approved(self) -> None:
        # New CapGuard security contract: a placed capability is filed into the
        # org/all-user namespace but held ``pending`` in quarantine before it is
        # indexed, so it is NOT servable until a clean signed release. Placement
        # still resolves the namespace/store; the release path promotes it.
        self._rebuild()
        con = connect(self.db)
        try:
            row = con.execute(
                "SELECT * FROM capabilities WHERE type='skill' AND name='org-skill'"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertTrue(row["uri"].startswith(org_shared_namespace_prefix()))
            self.assertEqual(row["store_id"], org_store_id())
            self.assertEqual(row["namespace_id"], org_shared_namespace_id())
            # Held pending quarantine: NOT approved until released.
            self.assertEqual(row["approval_state"], "pending")
            self.assertEqual(row["promoted_from_uri"][:11], "cap://user/")
            # Held -> get_capability returns None (serving hold), and the
            # capabilities row is filtered out of discover/list/search.
            self.assertIsNone(get_capability(con, row["uri"]))

            all_row = con.execute(
                "SELECT * FROM capabilities WHERE type='skill' AND name='all-skill'"
            ).fetchone()
            self.assertTrue(all_row["uri"].startswith(all_users_namespace_prefix()))
            self.assertEqual(all_row["store_id"], all_users_store_id())
            self.assertEqual(all_row["namespace_id"], all_users_namespace_id())
            self.assertEqual(all_row["approval_state"], "pending")
            self.assertIsNone(get_capability(con, all_row["uri"]))

            priv_row = con.execute(
                "SELECT * FROM capabilities WHERE type='skill' AND name='priv-skill'"
            ).fetchone()
            self.assertTrue(priv_row["uri"].startswith("cap://user/"))
            self.assertEqual(priv_row["approval_state"], "pending")
            self.assertIsNone(get_capability(con, priv_row["uri"]))

            # Release-path assertion: a clean signed CapGuard release promotes
            # the held org-skill to published/approved and makes it servable.
            # This does NOT bypass quarantine -- it is the only authoritative
            # path through the fail-closed scan/release attestation chain.
            self._release_placed(con, row["uri"])
            released_row = con.execute(
                "SELECT approval_state, lifecycle FROM capabilities WHERE uri = ?", (row["uri"],)
            ).fetchone()
            self.assertEqual(released_row["approval_state"], "published")
            self.assertEqual(released_row["lifecycle"], "active")
            self.assertIsNotNone(get_capability(con, row["uri"]))
        finally:
            con.close()

    def test_placement_survives_reingest(self) -> None:
        # Regression proof for the nested-transaction bug: the second ingest
        # re-runs vault placement (which mutates governance state via
        # ensure_*_namespace INSERT OR IGNORE) on the idempotent skip path
        # where no new quarantine row is committed. Placement must own that
        # transaction and leave the connection clean before BEGIN IMMEDIATE,
        # otherwise the second ingest raises "cannot start a transaction
        # within a transaction". Both rebuilds must succeed and the placed cap
        # must NOT be demoted out of its target namespace.
        self._rebuild()
        self._rebuild()  # second ingest must NOT demote the placed cap
        con = connect(self.db)
        try:
            row = con.execute(
                "SELECT * FROM capabilities WHERE type='skill' AND name='org-skill'"
            ).fetchone()
            self.assertTrue(row["uri"].startswith(org_shared_namespace_prefix()))
            # Still placed, still held pending release -- re-ingest did not
            # promote it and did not drop it back to the private namespace.
            self.assertEqual(row["approval_state"], "pending")
            self.assertIsNone(get_capability(con, row["uri"]))
            # Only one active quarantine row for the unchanged placed cap:
            # re-ingest of identical content is idempotent (no re-hold).
            active = con.execute(
                "SELECT COUNT(*) FROM capguard_quarantine "
                "WHERE tenant_id = 'asg' AND capability_uri = ? AND status = 'quarantined'",
                (row["uri"],),
            ).fetchone()[0]
            self.assertEqual(active, 1)
            # The held cap stays pending until released -- release still works
            # after re-ingest, proving the quarantine record is intact.
            self._release_placed(con, row["uri"])
            self.assertIsNotNone(get_capability(con, row["uri"]))
        finally:
            con.close()

    def test_static_all_users_placement_remains_available_in_production(self) -> None:
        # New security contract: a statically-placed all-user capability is held
        # pending a clean signed CapGuard release. It is NOT discoverable or
        # loadable in production while held, even though placement resolved the
        # all-user namespace. Only the release path makes it available.
        self._rebuild()
        con = connect(self.db)
        try:
            row = con.execute(
                "SELECT uri FROM capabilities WHERE type='skill' AND name='all-skill'"
            ).fetchone()
            # Held -> get_capability returns None and the cap is filtered out
            # of list/search surfaces, so it cannot be served in production.
            self.assertIsNone(get_capability(con, row["uri"]))
            principal = Principal(subject="test-member@example.com", tenant_id="asg")
            listed_uris = {item["uri"] for item in list_capabilities(con, principal)["items"]}
            self.assertNotIn(row["uri"], listed_uris)
            self.assertEqual([s.capability.uri for s in search(con, "all-skill", principal)], [])
            # Release-path assertion: the clean signed release is the only way
            # the placed cap becomes servable. Bypassing quarantine is not an
            # option the test takes.
            self._release_placed(con, row["uri"])
            cap = get_capability(con, row["uri"])
            self.assertIsNotNone(cap)
            self.assertEqual(cap.signature_status, "unchecked")
            self.assertEqual(cap.provenance_status, "unchecked")
            # Placement is a manifest filing, not a promotion request, so the
            # release does not synthesize a promotion_requests row.
            self.assertIsNone(
                con.execute(
                    "SELECT 1 FROM promotion_requests WHERE capability_uri=?",
                    (cap.uri,),
                ).fetchone()
            )
            with mock.patch.dict("os.environ", {"CAPMESH_ENVIRONMENT": "production"}, clear=False):
                for right in ("discover", "load"):
                    allowed, reason = evaluate_access(
                        con,
                        principal,
                        right=right,
                        capability=cap,
                        audit=False,
                    )
                    self.assertTrue(allowed, reason)
        finally:
            con.close()


class VaultMatchKeyCrossPrefixTest(unittest.TestCase):
    """The manifest may carry a stale plugin prefix (e.g. ``global.``) while the
    live cap carries the real owning plugin prefix. Placement must still match on
    the stable ``{type}/{basename}@{version}`` key."""

    def _cap(self, plugin: str, name: str = "accessibility-qa-lead", version: str = "0.1.0") -> Capability:
        return Capability(
            uri=f"cap://source/{plugin}/{name}",
            capability_type="agent",
            name=name,
            version=version,
            title=name,
            description="Cross-prefix placement cap.",
            package_path="pkg",
            entrypoint="entry",
            source_path="src",
            source_kind="plugin_capability",
            source_system="test",
            canonical_key=f"agent:{plugin}:{name}:{version}",
            content_hash="deadbeef",
            plugin=plugin,
            tenant_id="asg",
        )

    def test_org_placement_matches_across_plugin_prefix(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        # Manifest entry uses the STALE 'global.' plugin prefix.
        manifest = {
            "version": 1,
            "placements": [
                {
                    "uri": f"{org_shared_namespace_prefix()}/agent/global.accessibility-qa-lead@0.1.0",
                    "vault": "org",
                }
            ],
        }
        manifest_path = root / "vault-placement.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        index = load_vault_placement_index(manifest_path)
        self.assertTrue(index, "expected a non-empty placement index")

        con = connect(root / "mesh.db")
        try:
            init_db(con, enable_vector=False)
            # Live cap carries the REAL owning plugin prefix, not 'global.'.
            cap = self._cap("agentic-flow-specialists-2026")
            placed = apply_vault_placement(con, cap, index)
            self.assertIsNotNone(placed, "cross-prefix cap should be placed")
            self.assertTrue(placed.uri.startswith(org_shared_namespace_prefix()))
            self.assertEqual(placed.store_id, org_store_id())
            self.assertEqual(placed.namespace_id, org_shared_namespace_id())
            self.assertEqual(placed.approval_state, "approved")
            # target_uri must preserve the cap's REAL name + prefix, not the manifest's.
            self.assertIn("agentic-flow-specialists-2026.accessibility-qa-lead@0.1.0", placed.uri)
            self.assertNotIn("global.", placed.uri)
        finally:
            con.close()


class VaultMatchKeyUnitTest(unittest.TestCase):
    def test_normalization_edge_cases(self) -> None:
        from capmesh.governance import _vault_match_key

        # Strips the single plugin prefix; scoped plugin names use hyphens.
        self.assertEqual(
            _vault_match_key("agent/global.foo@0.1.0"), "agent/foo@0.1.0"
        )
        self.assertEqual(
            _vault_match_key("agent/anthropic-code-feature-dev.foo@0.1.0"),
            "agent/foo@0.1.0",
        )
        self.assertEqual(
            _vault_match_key("agent/agentic-flow-specialists-2026.foo@0.1.0"),
            "agent/foo@0.1.0",
        )
        # No plugin prefix (no dot before @) stays unchanged.
        self.assertEqual(_vault_match_key("agent/foo@0.1.0"), "agent/foo@0.1.0")
        # Multi-dot capability names retain their own dots.
        self.assertEqual(
            _vault_match_key("skill/plugin.foo.bar@2.0.0"), "skill/foo.bar@2.0.0"
        )
        # The type segment is preserved.
        self.assertEqual(
            _vault_match_key("workflow/p.w@1"), "workflow/w@1"
        )
        # No slash -> returned as-is.
        self.assertEqual(_vault_match_key("nope"), "nope")


if __name__ == "__main__":
    unittest.main()
