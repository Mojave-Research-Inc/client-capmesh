from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.index import connect, coverage_report, init_db, rebuild_index

# ---------------------------------------------------------------------------
# Fixture helpers: write a minimal plugin source tree so discover_capabilities
# returns deterministic capabilities with distinct canonical_keys (no effective
# URI collisions, so legitimate same-key merges never drop a key).
# ---------------------------------------------------------------------------

def _write_plugin(root: Path, plugin_name: str, skill_name: str) -> Path:
    """Create a tiny plugin with one skill file. Return the plugin root path."""
    pkg = root / plugin_name
    (pkg / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (pkg / "skills" / skill_name).mkdir(parents=True, exist_ok=True)
    (pkg / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": plugin_name, "version": "1.0.0", "description": f"{plugin_name} plugin."}),
        encoding="utf-8",
    )
    (pkg / "skills" / skill_name / "SKILL.md").write_text(
        f"---\nname: {skill_name}\ndescription: {skill_name} skill.\n---\n# {skill_name}\n",
        encoding="utf-8",
    )
    return pkg


def _canonical_key(cap_type: str, plugin: str, name: str, version: str) -> str:
    """Mirror manifest.capability_uri's canonical_key derivation for assertions."""
    return f"{cap_type}:{plugin}:{name}:{version}"


class CoverageDropInvariantTests(unittest.TestCase):
    """CM-10: coverage_report must surface placement-induced capability drops."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.roots = [self.root / "plugins"]
        self.db = self.root / "mesh.db"
        # Disable vectors: the invariant is about canonical_key coverage, not
        # embeddings, and lexical FTS is the deterministic test path.
        self._env = mock.patch.dict("os.environ", {"CAPMESH_EMBEDDING_PROVIDER": "lexical"})
        self._env.__enter__()
        self.addCleanup(self._env.__exit__, None, None, None)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _rebuild(self) -> None:
        rebuild_index(self.db, self.roots, enable_vector=False)

    def _connect(self):
        con = connect(self.db)
        init_db(con, enable_vector=False)
        return con

    def test_coverage_ok_when_no_drops(self) -> None:
        """A populated DB with every discovered key present is fully covered."""
        _write_plugin(self.root / "plugins", "alpha-plugin", "alpha-skill")
        self._rebuild()
        con = self._connect()
        try:
            report = coverage_report(con, self.roots)
        finally:
            con.close()
        self.assertTrue(report["coverageOk"], report)
        self.assertTrue(report["placementOk"], report)
        self.assertEqual(report["placementDroppedKeys"], [])
        self.assertTrue(
            report["placementExtraKeys"] == []
            or set(report["placementExtraKeys"]).isdisjoint(
                {_canonical_key("skill", "alpha-plugin", "alpha-skill", "0.1.0")}
            )
        )

    def test_coverage_detects_dropped_cap(self) -> None:
        """Removing a capability row after rebuild surfaces its canonical_key
        as a placement drop and fails coverageOk."""
        _write_plugin(self.root / "plugins", "alpha-plugin", "alpha-skill")
        self._rebuild()
        con = self._connect()
        try:
            # The source file is still on disk, so the existing missing-source
            # check stays empty; only the placement invariant can see the drop.
            dropped_key = _canonical_key("skill", "alpha-plugin", "alpha-skill", "0.1.0")
            # Sanity: the row exists and is a non-system/non-draft cap.
            row = con.execute(
                "SELECT id FROM capabilities WHERE canonical_key = ?", (dropped_key,)
            ).fetchone()
            self.assertIsNotNone(row, "fixture did not ingest the expected capability")
            # Simulate a placement drop: delete the row AND its source rows so
            # the discovered source is no longer indexed either way, then re-run
            # discovery (source still on disk). The canonical_key disappears
            # from the live rows -> placementDroppedKeys names it.
            con.execute("DELETE FROM capability_fts WHERE rowid = ?", (row["id"],))
            con.execute("DELETE FROM capability_sources WHERE uri IN (SELECT uri FROM capabilities WHERE id = ?)", (row["id"],))
            con.execute("DELETE FROM capabilities WHERE id = ?", (row["id"],))
            con.commit()
            report = coverage_report(con, self.roots)
        finally:
            con.close()
        self.assertIn(dropped_key, report["placementDroppedKeys"])
        self.assertFalse(report["placementOk"], report)
        self.assertFalse(report["coverageOk"], report)

    def test_coverage_extras_warn_not_fail(self) -> None:
        """An extra canonical_key in the DB (not in discovered) is reported as a
        warning but does not by itself flip coverageOk or placementOk."""
        _write_plugin(self.root / "plugins", "alpha-plugin", "alpha-skill")
        self._rebuild()
        con = self._connect()
        try:
            # Inject a foreign, non-system/non-draft capability row whose
            # canonical_key is not produced by any discovered source.
            extra_key = "skill:ghost-plugin:ghost-skill:9.9.9"
            con.execute(
                """
                INSERT INTO capabilities (
                    uri, canonical_key, tenant_id, type, name, version, title,
                    description, package_path, entrypoint, source_path, source_kind,
                    source_system, content_hash, visibility, discovery_mode, owner,
                    lifecycle, approval_state, keywords_json, required_scopes_json,
                    allow_groups_json, allow_users_json, risk_tier, metadata_json
                ) VALUES (?, ?, 'asg', 'skill', 'ghost-skill', '9.9.9', 'Ghost',
                          'ghost', '/', 'SKILL.md', '/ghost/SKILL.md', 'skill',
                          'local', 'deadbeef', 'internal', 'public', 'asg',
                          'active', 'published', '[]', '[]', '[]', '[]', 'low', '{}')
                """,
                ("cap://asg.local/skill/ghost-plugin.ghost-skill@9.9.9", extra_key),
            )
            con.commit()
            report = coverage_report(con, self.roots)
        finally:
            con.close()
        self.assertIn(extra_key, report["placementExtraKeys"])
        self.assertTrue(report["placementOk"], report)
        # Extras alone do not fail coverage; the discovered cap is still present.
        self.assertTrue(report["coverageOk"], report)

    def test_system_and_draft_caps_excluded(self) -> None:
        """System and draft caps do not count toward live_keys or
        discovered_keys; they are excluded from the placement invariant."""
        _write_plugin(self.root / "plugins", "alpha-plugin", "alpha-skill")
        self._rebuild()
        con = self._connect()
        try:
            # A system cap (source_kind='system_capability') and a draft cap
            # (source_kind='capmesh_draft') that are NOT in the discovered set.
            system_key = "workflow:system:builtin-tool:0.1.0"
            draft_key = "skill:capmesh-draft:asg:admin@example.com:draft-skill:0.1.0"
            con.execute(
                """
                INSERT INTO capabilities (
                    uri, canonical_key, tenant_id, type, name, version, title,
                    description, package_path, entrypoint, source_path, source_kind,
                    source_system, content_hash, visibility, discovery_mode, owner,
                    lifecycle, approval_state, keywords_json, required_scopes_json,
                    allow_groups_json, allow_users_json, risk_tier, metadata_json
                ) VALUES (?, ?, 'asg', 'workflow', 'builtin-tool', '0.1.0', 'Builtin',
                          'builtin', '/', 'tool.md', '/', 'system_capability',
                          'capmesh.system', 'sys', 'internal', 'public', 'asg',
                          'published', 'approved', '[]', '[]', '[]', '[]', 'low', '{}')
                """,
                ("cap://system/builtin-tool@0.1.0", system_key),
            )
            con.execute(
                """
                INSERT INTO capabilities (
                    uri, canonical_key, tenant_id, type, name, version, title,
                    description, package_path, entrypoint, source_path, source_kind,
                    source_system, content_hash, visibility, discovery_mode, owner,
                    lifecycle, approval_state, keywords_json, required_scopes_json,
                    allow_groups_json, allow_users_json, risk_tier, metadata_json
                ) VALUES (?, ?, 'asg', 'skill', 'draft-skill', '0.1.0', 'Draft',
                          'draft', '/', 'SKILL.md', '/', 'capmesh_draft',
                          'local', 'draft', 'internal', 'hidden', 'admin@example.com',
                          'draft', 'draft', '[]', '[]', '[]', '[]', 'low', '{}')
                """,
                ("cap://user/asg/admin@example.com/draft-skill@0.1.0", draft_key),
            )
            con.commit()
            report = coverage_report(con, self.roots)
        finally:
            con.close()
        # Neither the system key nor the draft key appears as an extra (they are
        # excluded from live_keys), so they cannot warn or fail the invariant.
        self.assertNotIn(system_key, report["placementExtraKeys"])
        self.assertNotIn(draft_key, report["placementExtraKeys"])
        self.assertNotIn(system_key, report["placementDroppedKeys"])
        self.assertNotIn(draft_key, report["placementDroppedKeys"])
        self.assertTrue(report["placementOk"], report)
        self.assertTrue(report["coverageOk"], report)

    def test_intentional_merge_not_dropped(self) -> None:
        """A canonical_key intentionally merged into another row must NOT appear
        in placementDroppedKeys.

        Exercises the cross-key merge-subtraction path in coverage_report.
        merge_duplicate_capabilities (manifest.py) only performs same-key
        merges, so a cross-key consolidation is constructed directly: two
        discovered caps (distinct canonical_keys, distinct source files) are
        folded into one survivor by deleting the loser's capabilities row and
        re-pointing its source_path to the survivor's uri in
        capability_sources. The survivor ends up owning two source files under
        one canonical_key (same key, different source). The merged-away key must
        be subtracted from placementDroppedKeys so a legitimate merge is not
        false-flagged as a placement drop.
        """
        # Two distinct plugins -> two distinct canonical_keys, two source files.
        _write_plugin(self.root / "plugins", "alpha-plugin", "alpha-skill")
        _write_plugin(self.root / "plugins", "beta-plugin", "beta-skill")
        self._rebuild()
        survivor_key = _canonical_key("skill", "alpha-plugin", "alpha-skill", "0.1.0")
        merged_away_key = _canonical_key("skill", "beta-plugin", "beta-skill", "0.1.0")
        con = self._connect()
        try:
            loser = con.execute(
                "SELECT id, uri, source_path, source_kind, source_system, content_hash "
                "FROM capabilities WHERE canonical_key = ?",
                (merged_away_key,),
            ).fetchone()
            self.assertIsNotNone(loser, "fixture did not ingest the loser capability")
            survivor = con.execute(
                "SELECT uri FROM capabilities WHERE canonical_key = ?", (survivor_key,)
            ).fetchone()
            self.assertIsNotNone(survivor, "fixture did not ingest the survivor")
            # Fold the loser into the survivor: drop the loser's row (cascades to
            # its capability_sources row), then re-point the loser's source file
            # to the survivor's uri. The survivor now owns both source files.
            con.execute("DELETE FROM capability_fts WHERE rowid = ?", (loser["id"],))
            con.execute("DELETE FROM capabilities WHERE id = ?", (loser["id"],))
            con.execute(
                "INSERT INTO capability_sources "
                "(source_path, uri, source_kind, source_system, content_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    loser["source_path"],
                    survivor["uri"],
                    loser["source_kind"],
                    loser["source_system"],
                    loser["content_hash"],
                ),
            )
            con.commit()
            report = coverage_report(con, self.roots)
        finally:
            con.close()
        # The merged-away key is subtracted, not reported as a placement drop.
        self.assertNotIn(merged_away_key, report["placementDroppedKeys"], report)
        self.assertEqual(report["placementDroppedKeys"], [], report)
        # The survivor stays live, so it is not dropped either.
        self.assertNotIn(survivor_key, report["placementDroppedKeys"], report)
        self.assertTrue(report["placementOk"], report)
        # The loser's source file was re-pointed, not orphaned, so source
        # coverage stays green and coverageOk holds.
        self.assertTrue(report["coverageOk"], report)


if __name__ == "__main__":
    unittest.main()


def test_superseded_mirrors_do_not_count_as_placement_drops(tmp_path):
    """The coverage invariant must apply the same admission filter as ingest.

    discover_capabilities() is unfiltered, so it still returns the lower-authority
    mirror copies that _enforce_install_guards drops. Counting their canonical_keys
    as "discovered" made placementDroppedKeys non-empty and failed coverageOk,
    which blocked the release even though nothing was lost.

    Measured 2026-07-31: 8 keys (anti-slop-voice-discipline, caviaar-prep, six
    voss-*), each a byte-identical ~/.codex copy of a ~/.agents original that
    survives in the catalog.
    """
    import sqlite3

    from capmesh.index import _admitted_after_install_guards
    from capmesh.models import Capability

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        "CREATE TABLE capabilities (plugin TEXT, name TEXT, package_path TEXT, "
        "uri TEXT, lifecycle TEXT)"
    )
    con.execute(
        "INSERT INTO capabilities VALUES (?,?,?,?,?)",
        (
            None,
            "voss-red-team",
            "/home/jason/.agents/skill-registry/meta/voss-red-team",
            "cap://all/asg/everyone/skill/global.voss-red-team@0.1.0",
            "active",
        ),
    )
    con.commit()

    def _cap(package_path: str, canonical_key: str) -> Capability:
        return Capability(
            uri="cap://asg.local/skill/global.voss-red-team@0.1.0",
            capability_type="skill",
            name="voss-red-team",
            version="0.1.0",
            title="Voss Red Team",
            description="d",
            package_path=package_path,
            entrypoint="SKILL.md",
            source_path=f"{package_path}/SKILL.md",
            source_kind="skill",
            source_system="test",
            canonical_key=canonical_key,
            content_hash="h",
        )

    mirror = _cap("/home/jason/.codex/skills/meta/voss-red-team", "skill:global:voss-red-team:0.1.0:aaa")
    original = _cap(
        "/home/jason/.agents/skill-registry/meta/voss-red-team",
        "skill:global:voss-red-team:0.1.0:bbb",
    )

    admitted = _admitted_after_install_guards(con, [original, mirror])
    keys = {c.canonical_key for c in admitted}
    assert "skill:global:voss-red-team:0.1.0:bbb" in keys, "the surviving original must be admitted"
    assert "skill:global:voss-red-team:0.1.0:aaa" not in keys, "the superseded mirror must be filtered"


def test_superseded_source_files_are_not_reported_missing():
    """A superseded capability's file is on disk but deliberately unindexed.

    source_files() still enumerates it, so subtracting only the placement keys
    was not enough -- the parallel source-file check still failed. Measured
    2026-07-31: the 8 ~/.codex/skills/meta SKILL.md files, each byte-identical to
    an indexed ~/.agents/skill-registry original (md5 verified on all eight).

    Uses the real path shapes because the ranking is driven by path markers:
    ~/.agents/skill-registry -> 400, ~/.codex/skills -> 300.
    """
    import sqlite3

    from capmesh import index as index_mod
    from capmesh.models import Capability

    ORIG_DIR = "/home/jason/.agents/skill-registry/meta/voss-red-team"
    MIRROR_DIR = "/home/jason/.codex/skills/meta/voss-red-team"

    def _cap(pkg: str, key: str) -> Capability:
        return Capability(
            uri="cap://asg.local/skill/global.voss-red-team@0.1.0",
            capability_type="skill",
            name="voss-red-team",
            version="0.1.0",
            title="t",
            description="d",
            package_path=pkg,
            entrypoint="SKILL.md",
            source_path=f"{pkg}/SKILL.md",
            source_kind="skill",
            source_system="test",
            canonical_key=key,
            content_hash="h",
        )

    orig = _cap(ORIG_DIR, "skill:global:voss-red-team:0.1.0:bbb")
    mirror = _cap(MIRROR_DIR, "skill:global:voss-red-team:0.1.0:aaa")

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        "CREATE TABLE capabilities (plugin TEXT, name TEXT, package_path TEXT, uri TEXT, "
        "lifecycle TEXT)"
    )
    con.commit()

    admitted = index_mod._admitted_after_install_guards(con, [orig, mirror])
    admitted_sources = {index_mod.normalize_path(c.source_path) for c in admitted}
    all_sources = {index_mod.normalize_path(c.source_path) for c in (orig, mirror)}
    superseded = all_sources - admitted_sources

    assert index_mod.normalize_path(mirror.source_path) in superseded, (
        "the lower-authority ~/.codex mirror must be superseded"
    )
    assert index_mod.normalize_path(orig.source_path) not in superseded, (
        "the surviving ~/.agents original must stay indexed"
    )
    # And the ranking that drives it is the real one, not an accident of ordering.
    from capmesh.install_policy import _authority_rank

    assert _authority_rank(ORIG_DIR) > _authority_rank(MIRROR_DIR)
