from __future__ import annotations

import dataclasses
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from capmesh.cli import main as cli_main
from capmesh.cli import offline_replica_rehearsal_allowed
from capmesh.index import (
    CandidateValidationError,
    EffectiveUriCollisionError,
    UnexpectedRemovalError,
    _migrate_canonical_uri,
    _upsert_discovered,
    connect,
    ingest_index,
    init_db,
    promote_shadow_database,
    sqlite_wal_safety,
    stage_rebuild_index,
    upsert_capability,
)
from capmesh.manifest import (
    discover_capabilities,
    merge_duplicate_capabilities,
    package_name_for,
    parse_frontmatter,
    source_files,
)
from capmesh.models import Capability, normalize_path


def write_plugin(root: Path, plugin: str, skill: str) -> None:
    package = root / plugin
    (package / ".claude-plugin").mkdir(parents=True)
    (package / "skills" / skill).mkdir(parents=True)
    (package / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": plugin, "version": "1.0.0", "description": f"{plugin} plugin"}),
        encoding="utf-8",
    )
    (package / "skills" / skill / "SKILL.md").write_text(
        f"---\nname: {skill}\ndescription: {skill} capability\n---\n# {skill}\n",
        encoding="utf-8",
    )


class TransactionalIngestTests(unittest.TestCase):
    def test_replica_rehearsal_exception_is_explicit_and_shadow_path_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            live = state / "asg-capmesh.db"
            shadow = state / "rehearsal" / "candidate.db"
            sibling = state / "candidate.db"
            shadow.parent.mkdir()
            with mock.patch.dict(
                os.environ,
                {"CAPMESH_DB": str(live), "CAPMESH_OFFLINE_REHEARSAL": "1"},
                clear=False,
            ):
                self.assertTrue(offline_replica_rehearsal_allowed("ingest", str(shadow)))
                self.assertFalse(offline_replica_rehearsal_allowed("ingest", str(live)))
                self.assertFalse(offline_replica_rehearsal_allowed("ingest", str(sibling)))
                self.assertFalse(offline_replica_rehearsal_allowed("rebuild", str(shadow)))
            with mock.patch.dict(os.environ, {"CAPMESH_DB": str(live)}, clear=False):
                os.environ.pop("CAPMESH_OFFLINE_REHEARSAL", None)
                self.assertFalse(offline_replica_rehearsal_allowed("ingest", str(shadow)))

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.full = self.root / "plugins"
        for index in range(5):
            write_plugin(self.full, f"plugin-{index}", f"skill-{index}")
        self.db = self.root / "mesh.db"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def live_count(self) -> int:
        con = connect(self.db)
        try:
            return int(
                con.execute(
                    "SELECT COUNT(*) FROM capabilities WHERE source_kind NOT IN ('system_capability','capmesh_draft')"
                ).fetchone()[0]
            )
        finally:
            con.close()

    def test_multiline_quoted_frontmatter_is_preserved(self) -> None:
        frontmatter, body = parse_frontmatter(
            '---\nname: wrapped\ndescription:\n  "A description that\n  continues safely"\n---\n# Body\n'
        )
        self.assertEqual(frontmatter["name"], "wrapped")
        self.assertEqual(frontmatter["description"], "A description that continues safely")
        self.assertEqual(body, "# Body")

    def alias_capability(
        self,
        *,
        alias: str,
        content_hash: str = "sha256:same",
        name: str = "effective-uri-alias",
    ) -> Capability:
        source = self.root / alias / "SKILL.md"
        return Capability(
            uri=f"cap://asg.local/skill/{name}@1.0.0",
            capability_type="skill",
            name=name,
            version="1.0.0",
            title="Effective URI Alias",
            description="Same logical capability exposed by multiple discovery roots.",
            package_path=str(source.parent),
            entrypoint="SKILL.md",
            source_path=str(source),
            source_kind="skill_markdown",
            source_system=alias,
            canonical_key=f"skill:path:{alias}",
            content_hash=content_hash,
            plugin="effective-uri-test",
        )

    def test_effective_uri_aliases_merge_deterministically_with_all_provenance(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        first = self.alias_capability(alias="z-agents-registry")
        second = self.alias_capability(alias="a-codex-skills")

        con.execute("BEGIN IMMEDIATE")
        with mock.patch("capmesh.index.upsert_capability", wraps=upsert_capability) as upsert:
            changes = _upsert_discovered(con, [first, second], vector_enabled=False)
        con.commit()

        row = con.execute(
            "SELECT uri, canonical_key, metadata_json FROM capabilities WHERE name=?",
            (first.name,),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(changes["added"], 1)
        self.assertEqual(upsert.call_count, 1)
        self.assertEqual(row["canonical_key"], "skill:path:a-codex-skills")
        metadata = json.loads(row["metadata_json"])
        expected_paths = sorted([normalize_path(first.source_path), normalize_path(second.source_path)])
        self.assertEqual(metadata["sourcePaths"], expected_paths)
        self.assertEqual(len(metadata["sourceProvenance"]), 2)
        sources = con.execute(
            """
            SELECT source_path, source_system, content_hash
            FROM capability_sources WHERE uri=? ORDER BY source_path
            """,
            (row["uri"],),
        ).fetchall()
        self.assertEqual(
            [tuple(item) for item in sources],
            [
                (normalize_path(second.source_path), second.source_system, second.content_hash),
                (normalize_path(first.source_path), first.source_system, first.content_hash),
            ],
        )

        writes_before = con.total_changes
        con.execute("BEGIN IMMEDIATE")
        with mock.patch("capmesh.index.upsert_capability", wraps=upsert_capability) as upsert:
            second_pass = _upsert_discovered(con, [second, first], vector_enabled=False)
        con.commit()
        self.assertEqual(upsert.call_count, 1)
        self.assertEqual(second_pass["updated"], 0)
        self.assertEqual(second_pass["unchanged"], 1)
        self.assertEqual(con.total_changes, writes_before)
        con.close()

    def test_source_reattribution_retires_only_the_ungoverned_ghost(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        old = self.alias_capability(alias="same-source", name="reattributed")
        new = dataclasses.replace(
            old,
            uri="cap://asg.local/skill/reattributed@2.0.0",
            version="2.0.0",
            canonical_key="skill:path:same-source:2.0.0",
        )

        con.execute("BEGIN IMMEDIATE")
        _upsert_discovered(con, [old], vector_enabled=False)
        con.commit()
        old_uri = con.execute(
            "SELECT uri FROM capabilities WHERE name = 'reattributed' AND version = '1.0.0'"
        ).fetchone()[0]

        con.execute("BEGIN IMMEDIATE")
        changes = _upsert_discovered(con, [new], vector_enabled=False)
        con.commit()

        rows = con.execute(
            "SELECT uri, version FROM capabilities WHERE name = 'reattributed' ORDER BY version"
        ).fetchall()
        self.assertEqual(changes["added"], 1)
        self.assertEqual(changes["removed"], 1)
        self.assertEqual([row["version"] for row in rows], ["2.0.0"])
        self.assertIsNone(con.execute("SELECT 1 FROM capabilities WHERE uri = ?", (old_uri,)).fetchone())
        self.assertEqual(
            con.execute(
                "SELECT COUNT(*) FROM capability_sources WHERE source_path = ?",
                (normalize_path(new.source_path),),
            ).fetchone()[0],
            1,
        )
        con.close()

    def test_source_reattribution_fails_closed_for_governed_ghost(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        old = self.alias_capability(alias="governed-source", name="governed-reattribution")
        new = dataclasses.replace(
            old,
            uri="cap://asg.local/skill/governed-reattribution@2.0.0",
            version="2.0.0",
            canonical_key="skill:path:governed-source:2.0.0",
        )

        con.execute("BEGIN IMMEDIATE")
        _upsert_discovered(con, [old], vector_enabled=False)
        con.commit()
        old_uri = con.execute(
            "SELECT uri FROM capabilities WHERE name = 'governed-reattribution'"
        ).fetchone()[0]
        con.execute(
            """
            INSERT INTO shares(id, tenant_id, capability_uri, subject_type, subject_id, rights_json)
            VALUES('share-reattribution', 'asg', ?, 'user', 'reviewer', '[]')
            """,
            (old_uri,),
        )
        con.commit()

        con.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(CandidateValidationError, "stranded governed capability"):
            _upsert_discovered(con, [new], vector_enabled=False)
        con.rollback()

        self.assertIsNotNone(con.execute("SELECT 1 FROM capabilities WHERE uri = ?", (old_uri,)).fetchone())
        self.assertEqual(
            con.execute("SELECT uri FROM capability_sources WHERE source_path = ?", (normalize_path(old.source_path),)).fetchone()[0],
            old_uri,
        )
        con.close()

    def test_source_files_ignore_nested_runtime_mirrors_but_scan_runtime_root(self) -> None:
        authored = self.root / "authored"
        canonical = authored / "skills" / "canonical" / "SKILL.md"
        nested_mirror = authored / ".codex" / "skills" / "canonical" / "SKILL.md"
        runtime_root = self.root / ".codex" / "skills"
        runtime_skill = runtime_root / "runtime" / "SKILL.md"
        for path in (canonical, nested_mirror, runtime_skill):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("---\nname: test\ndescription: test\n---\n", encoding="utf-8")

        authored_files = source_files([authored])
        runtime_files = source_files([runtime_root])

        self.assertIn(canonical, authored_files)
        self.assertNotIn(nested_mirror, authored_files)
        self.assertIn(runtime_skill, runtime_files)

    def test_plugin_cache_uses_real_plugin_name_and_prefers_current_channel(self) -> None:
        cache_root = self.root / ".codex" / "plugins" / "cache"
        current_path = cache_root / "openai-curated-remote" / "github" / "0.1.8-build" / "skills" / "review" / "SKILL.md"
        legacy_path = cache_root / "openai-curated" / "github" / "legacy-sha" / "skills" / "review" / "SKILL.md"
        self.assertEqual(package_name_for(current_path, cache_root), "github")
        self.assertEqual(package_name_for(legacy_path, cache_root), "github")

        current = dataclasses.replace(
            self.alias_capability(alias="codex.plugin-cache", content_hash="sha256:current", name="review"),
            source_system="codex.plugin-cache",
            source_path=str(current_path),
            canonical_key="skill:github:review:0.1.0",
        )
        legacy = dataclasses.replace(
            current,
            content_hash="sha256:legacy",
            source_path=str(legacy_path),
        )

        merged = merge_duplicate_capabilities([legacy, current])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].content_hash, "sha256:current")

    def test_authored_nested_plugin_is_attributed_to_immediate_owner(self) -> None:
        plugins_root = self.root / "asg-os" / "plugins"
        nested_agent = plugins_root / "anthropic-code" / "feature-dev" / "agents" / "code-reviewer.md"
        nested_manifest = plugins_root / "anthropic-code" / "feature-dev" / ".claude-plugin" / "plugin.json"
        ordinary_skill = plugins_root / "ordinary" / "skills" / "review" / "SKILL.md"
        nested_mcp = plugins_root / "anthropic-knowledge-work" / "finance" / ".mcp.json"

        self.assertEqual(package_name_for(nested_agent, plugins_root), "anthropic-code-feature-dev")
        self.assertEqual(package_name_for(nested_manifest, plugins_root), "anthropic-code-feature-dev")
        self.assertEqual(package_name_for(ordinary_skill, plugins_root), "ordinary")
        self.assertEqual(
            package_name_for(nested_mcp, plugins_root),
            "anthropic-knowledge-work-finance",
        )

    def test_immutable_release_root_preserves_authored_authority_and_plugin_identity(self) -> None:
        release_root = self.root / "state" / "releases" / "candidate" / "capability-roots" / "asg-os-plugins"
        skill = release_root / "jason-persona" / "skills" / "jason-draft" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(
            "---\nname: jason-draft\ndescription: Draft in Jason's voice.\n---\n# Jason draft\n",
            encoding="utf-8",
        )

        capabilities = discover_capabilities([release_root])

        self.assertEqual(len(capabilities), 1)
        capability = capabilities[0]
        self.assertEqual(capability.source_system, "asg-os.plugins")
        self.assertEqual(capability.plugin, "jason-persona")
        self.assertEqual(capability.canonical_key, "skill:jason-persona:jason-draft:0.1.0")
        self.assertEqual(capability.uri, "cap://asg.local/skill/jason-persona.jason-draft@0.1.0")

    def test_effective_uri_collision_degrades_deterministically_and_is_queryable(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        first = self.alias_capability(alias="first", content_hash="sha256:first", name="collision")
        second = self.alias_capability(alias="second", content_hash="sha256:second", name="collision")

        con.execute("BEGIN IMMEDIATE")
        changes = _upsert_discovered(con, [first, second], vector_enabled=False)
        con.commit()

        self.assertEqual(changes["added"], 1)
        row = con.execute("SELECT metadata_json FROM capabilities WHERE name='collision'").fetchone()
        metadata = json.loads(row["metadata_json"])
        self.assertTrue(metadata["ambiguousEffectiveUriCollision"])
        self.assertEqual(metadata["sourceAuthority"]["resolvedBy"], "deterministic-tiebreak")
        self.assertEqual(len(metadata["ambiguousSources"]), 2)
        con.close()

    def test_effective_uri_collision_strict_mode_fails_closed_and_rolls_back(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        first = self.alias_capability(alias="first", content_hash="sha256:first", name="collision")
        second = self.alias_capability(alias="second", content_hash="sha256:second", name="collision")

        con.execute("BEGIN IMMEDIATE")
        with mock.patch.dict("os.environ", {"CAPMESH_STRICT_COLLISIONS": "1"}, clear=False):
            with self.assertRaisesRegex(EffectiveUriCollisionError, "effective URI collision"):
                _upsert_discovered(con, [first, second], vector_enabled=False)
        con.rollback()
        self.assertIsNone(con.execute("SELECT 1 FROM capabilities WHERE name='collision'").fetchone())
        con.close()

    def test_effective_uri_stale_mirror_uses_explicit_source_authority(self) -> None:
        con = connect(self.db)
        init_db(con, enable_vector=False)
        registry = dataclasses.replace(
            self.alias_capability(alias="agents.skill-registry", content_hash="sha256:registry", name="imagegen"),
            source_path="/home/jason/.agents/skill-registry/.system/imagegen/SKILL.md",
        )
        codex = dataclasses.replace(
            self.alias_capability(alias="codex.skills", content_hash="sha256:codex", name="imagegen"),
            source_path="/home/jason/.codex/skills/.system/imagegen/SKILL.md",
        )

        con.execute("BEGIN IMMEDIATE")
        changes = _upsert_discovered(con, [registry, codex], vector_enabled=False)
        con.commit()

        row = con.execute(
            "SELECT uri, source_system, content_hash, metadata_json FROM capabilities WHERE name='imagegen'"
        ).fetchone()
        metadata = json.loads(row["metadata_json"])
        self.assertEqual(changes["added"], 1)
        self.assertEqual((row["source_system"], row["content_hash"]), ("codex.skills", "sha256:codex"))
        self.assertTrue(metadata["staleMirrorDetected"])
        self.assertEqual(metadata["sourceAuthority"]["rank"], 450)
        self.assertEqual(len(metadata["sourceConflicts"]), 1)
        sources = {
            item["source_system"]: item["content_hash"]
            for item in con.execute(
                "SELECT source_system, content_hash FROM capability_sources WHERE uri=?",
                (row["uri"],),
            ).fetchall()
        }
        self.assertEqual(
            sources,
            {"agents.skill-registry": "sha256:registry", "codex.skills": "sha256:codex"},
        )
        con.close()

    def test_canonical_merge_keeps_authoritative_source_hash(self) -> None:
        registry = dataclasses.replace(
            self.alias_capability(alias="agents.skill-registry", content_hash="sha256:registry"),
            canonical_key="skill:plugin:shared:1.0.0",
        )
        authored = dataclasses.replace(
            self.alias_capability(alias="asg-os.plugins", content_hash="sha256:authored"),
            canonical_key="skill:plugin:shared:1.0.0",
            source_path="/opt/asg-os/plugins/effective-uri-test/skills/shared/SKILL.md",
        )

        merged = merge_duplicate_capabilities([registry, authored])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source_system, "asg-os.plugins")
        self.assertEqual(merged[0].content_hash, "sha256:authored")
        self.assertTrue(merged[0].metadata["staleMirrorDetected"])

    def test_equal_authority_collision_degrades_deterministically(self) -> None:
        # Paths must be true equal-authority peers (no nested mirror demotion).
        first = dataclasses.replace(
            self.alias_capability(alias="asg-os.plugins", content_hash="sha256:first"),
            canonical_key="agent:anthropic-code:code-reviewer:0.1.0",
            source_path="/opt/asg-os/plugins/anthropic-code/a/agents/code-reviewer.md",
        )
        second = dataclasses.replace(
            self.alias_capability(alias="asg-os.plugins", content_hash="sha256:second"),
            canonical_key=first.canonical_key,
            source_path="/opt/asg-os/plugins/anthropic-code/z/agents/code-reviewer.md",
        )

        with mock.patch("capmesh.manifest.print") as warning:
            forward = merge_duplicate_capabilities([second, first])
            reverse = merge_duplicate_capabilities([first, second])

        # Deterministic winner is sorted by source_path among equal-authority peers.
        self.assertEqual(forward[0].source_path, first.source_path)
        self.assertEqual(reverse[0].source_path, first.source_path)
        self.assertTrue(forward[0].metadata["ambiguousAuthorityCollision"])
        self.assertEqual(
            forward[0].metadata["sourceAuthority"]["resolvedBy"],
            "deterministic-tiebreak",
        )
        self.assertEqual(len(forward[0].metadata["ambiguousSources"]), 2)
        self.assertGreaterEqual(warning.call_count, 2)

    def test_equal_authority_collision_can_fail_strict_ci(self) -> None:
        first = dataclasses.replace(
            self.alias_capability(alias="asg-os.plugins", content_hash="sha256:first"),
            canonical_key="agent:anthropic-code:code-reviewer:0.1.0",
            source_path="/opt/asg-os/plugins/anthropic-code/a/agents/code-reviewer.md",
        )
        second = dataclasses.replace(
            self.alias_capability(alias="asg-os.plugins", content_hash="sha256:second"),
            canonical_key=first.canonical_key,
            source_path="/opt/asg-os/plugins/anthropic-code/z/agents/code-reviewer.md",
        )

        with mock.patch.dict(
            "capmesh.manifest.os.environ",
            {"CAPMESH_STRICT_COLLISIONS": "1"},
        ), self.assertRaisesRegex(ValueError, "ambiguous canonical-key collision"):
            merge_duplicate_capabilities([first, second])

    def test_narrow_ingest_cannot_repeat_2110_to_16_incident(self) -> None:
        first = ingest_index(self.db, [self.full], enable_vector=False)
        before = self.live_count()
        self.assertGreaterEqual(before, 10)

        narrow = ingest_index(self.db, [self.full / "plugin-0"], enable_vector=False)

        self.assertEqual(self.live_count(), before)
        self.assertEqual(narrow["removed"], 0)
        self.assertEqual(narrow["countBefore"], before)
        self.assertEqual(narrow["countAfter"], before)
        self.assertEqual(first["operation"], "merge")

    def test_ingest_is_idempotent_and_audit_counts_are_live_counts(self) -> None:
        first = ingest_index(self.db, [self.full], enable_vector=False)
        second = ingest_index(self.db, [self.full], enable_vector=False)
        self.assertEqual(first["countAfter"], second["countAfter"])
        self.assertEqual(second["added"], 0)
        self.assertEqual(second["updated"], 0)
        self.assertEqual(second["discoveredCapabilities"], second["unchanged"])
        audit = [json.loads(line) for line in (self.root / "ingest-audit.jsonl").read_text().splitlines()]
        self.assertEqual(audit[-1]["count_after"], self.live_count())
        self.assertEqual(audit[-1]["removed"], 0)

    def test_post_ingest_policy_failure_rolls_back_discovery(self) -> None:
        def reject(_con: object) -> dict[str, object]:
            raise RuntimeError("approval gate rejected catalog")

        with self.assertRaisesRegex(RuntimeError, "approval gate rejected"):
            ingest_index(self.db, [self.full], enable_vector=False, post_ingest=reject)

        self.assertEqual(self.live_count(), 0)

    def test_cli_superadmin_install_approves_immediately_with_audit_identity(self) -> None:
        output = io.StringIO()
        export_path = self.root / "catalog.jsonl"
        with mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "test",
                "CAPMESH_SIGNING_KEY_FILE": str(self.root / "signing.pem"),
                "CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE": "1",
                "CAPMESH_SUPERADMIN_ACTOR": "test-user@example.com",
            },
            clear=False,
        ), redirect_stdout(output):
            cli_main(
                [
                    "--db",
                    str(self.db),
                    "ingest",
                    "--root",
                    str(self.full),
                    "--no-vector",
                    "--export-jsonl",
                    str(export_path),
                ]
            )

        result = json.loads(output.getvalue())
        self.assertTrue(result["postIngest"]["catalogApproved"])
        self.assertEqual(result["postIngest"]["actor"], "test-user@example.com")
        con = connect(self.db)
        try:
            pending = con.execute(
                """SELECT COUNT(*) FROM capabilities
                   WHERE source_kind != 'system_capability'
                     AND (approval_state != 'approved' OR lifecycle != 'published'
                          OR signature_status != 'verified' OR provenance_status != 'verified'
                          OR risk_review_status != 'approved')"""
            ).fetchone()[0]
            actors = {
                row[0]
                for row in con.execute(
                    "SELECT DISTINCT actor FROM audit_events WHERE event_type='capability.review.approved'"
                ).fetchall()
            }
        finally:
            con.close()
        self.assertEqual(pending, 0)
        self.assertEqual(actors, {"test-user@example.com"})

    def test_cli_ingest_is_refused_on_nonvoting_member_with_authoritative_node_target(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "production",
                "CAPMESH_NODE_ROLE": "non-voting-raft",
                "CAPMESH_AUTHORITY_URL": "https://capmesh.example.com",
            },
            clear=False,
        ), redirect_stdout(output), self.assertRaisesRegex(SystemExit, "3"):
            cli_main(["--db", str(self.db), "ingest", "--root", str(self.full), "--no-vector"])
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["error"]["code"], "NOT_AUTHORITATIVE")
        self.assertEqual(payload["error"]["details"]["authorityMcpUrl"], "https://capmesh.example.com/mcp")
        self.assertFalse(self.db.exists())

    def test_unchanged_ingest_repairs_missing_vector_row(self) -> None:
        first = ingest_index(self.db, [self.full], enable_vector=True)
        if not first["vector"]["enabled"]:
            self.skipTest(first["vector"]["reason"])
        con = connect(self.db)
        try:
            cap_id = con.execute("SELECT id FROM capabilities WHERE name = 'skill-0'").fetchone()[0]
            count_before = con.execute("SELECT COUNT(*) FROM capability_vec").fetchone()[0]
            con.execute("DELETE FROM capability_vec WHERE rowid = ?", (cap_id,))
            con.commit()
            self.assertEqual(con.execute("SELECT COUNT(*) FROM capability_vec").fetchone()[0], count_before - 1)
        finally:
            con.close()

        second = ingest_index(self.db, [self.full], enable_vector=True)

        self.assertEqual(second["unchanged"], second["discoveredCapabilities"])
        con = connect(self.db)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM capability_vec").fetchone()[0], count_before)
        finally:
            con.close()

    def test_staged_rebuild_rejects_every_unapproved_removal_without_touching_live(self) -> None:
        ingest_index(self.db, [self.full], enable_vector=False)
        before = self.live_count()
        with self.assertRaises(UnexpectedRemovalError):
            stage_rebuild_index(self.db, [self.full / "plugin-0"], enable_vector=False)
        self.assertEqual(self.live_count(), before)

    def test_staged_rebuild_preserves_governance_references(self) -> None:
        ingest_index(self.db, [self.full], enable_vector=False)
        con = connect(self.db)
        uri = con.execute("SELECT uri FROM capabilities WHERE name='skill-0'").fetchone()[0]
        con.execute(
            "INSERT INTO shares(id,tenant_id,capability_uri,subject_type,subject_id,rights_json) VALUES('share-test','asg',?,'user','u','[]')",
            (uri,),
        )
        con.execute(
            "INSERT INTO promotion_requests(id,tenant_id,capability_uri,state) VALUES('promotion-test','asg',?,'pending')",
            (uri,),
        )
        con.execute(
            "INSERT INTO relationship_tuples(id,tenant_id,object,relation,user) VALUES('relation-test','asg',?,'viewer','user:u')",
            (uri,),
        )
        con.commit()
        con.close()

        staged = stage_rebuild_index(self.db, [self.full], enable_vector=False)
        candidate = connect(staged["candidatePath"])
        try:
            self.assertEqual(staged["validation"]["governanceOrphans"], {"shares": 0, "promotionRequests": 0, "relationships": 0})
            self.assertEqual(candidate.execute("SELECT capability_uri FROM shares WHERE id='share-test'").fetchone()[0], uri)
            self.assertEqual(candidate.execute("SELECT capability_uri FROM promotion_requests WHERE id='promotion-test'").fetchone()[0], uri)
            self.assertEqual(candidate.execute("SELECT object FROM relationship_tuples WHERE id='relation-test'").fetchone()[0], uri)
        finally:
            candidate.close()
            Path(staged["candidatePath"]).unlink(missing_ok=True)

    def test_terminal_promotion_history_may_reference_retired_source_but_pending_may_not(self) -> None:
        ingest_index(self.db, [self.full], enable_vector=False)
        con = connect(self.db)
        con.execute(
            "INSERT INTO promotion_requests(id,tenant_id,capability_uri,state) VALUES('history','asg','cap://retired/source','approved')"
        )
        con.commit()
        con.close()
        staged = stage_rebuild_index(self.db, [self.full], enable_vector=False)
        Path(staged["candidatePath"]).unlink(missing_ok=True)

        con = connect(self.db)
        con.execute(
            "INSERT INTO promotion_requests(id,tenant_id,capability_uri,state) VALUES('pending-orphan','asg','cap://missing/source','pending')"
        )
        con.commit()
        con.close()
        with self.assertRaises(CandidateValidationError):
            stage_rebuild_index(self.db, [self.full], enable_vector=False)

    def test_uri_migration_updates_all_governance_references(self) -> None:
        ingest_index(self.db, [self.full / "plugin-0"], enable_vector=False)
        con = connect(self.db)
        old_uri = con.execute("SELECT uri FROM capabilities WHERE name='skill-0'").fetchone()[0]
        new_uri = old_uri.replace("/private/", "/shared/")
        con.execute("INSERT INTO shares(id,tenant_id,capability_uri,subject_type,subject_id,rights_json) VALUES('s','asg',?,'user','u','[]')", (old_uri,))
        con.execute("INSERT INTO promotion_requests(id,tenant_id,capability_uri,state) VALUES('p','asg',?,'pending')", (old_uri,))
        con.execute("INSERT INTO relationship_tuples(id,tenant_id,object,relation,user) VALUES('r','asg',?,'viewer','user:u')", (old_uri,))
        con.execute("INSERT INTO policy_decisions(id,tenant_id,principal,action,resource_uri,decision,reason) VALUES('d','asg','u','load',?,'allow','test')", (old_uri,))
        _migrate_canonical_uri(con, old_uri, new_uri)
        con.commit()
        self.assertIsNotNone(con.execute("SELECT 1 FROM capabilities WHERE uri=?", (new_uri,)).fetchone())
        self.assertEqual(con.execute("SELECT capability_uri FROM shares WHERE id='s'").fetchone()[0], new_uri)
        self.assertEqual(con.execute("SELECT capability_uri FROM promotion_requests WHERE id='p'").fetchone()[0], new_uri)
        self.assertEqual(con.execute("SELECT object FROM relationship_tuples WHERE id='r'").fetchone()[0], new_uri)
        self.assertEqual(con.execute("SELECT resource_uri FROM policy_decisions WHERE id='d'").fetchone()[0], new_uri)
        con.close()

    def test_sqlite_wal_safety_backports(self) -> None:
        self.assertFalse(sqlite_wal_safety("3.51.2")["walResetSafe"])
        self.assertTrue(sqlite_wal_safety("3.51.3")["walResetSafe"])
        self.assertTrue(sqlite_wal_safety("3.50.7")["walResetSafe"])
        self.assertTrue(sqlite_wal_safety("3.44.6")["walResetSafe"])
        self.assertFalse(sqlite_wal_safety("3.50.6")["walResetSafe"])

    def test_ingest_preserves_attestations_only_for_identical_content(self) -> None:
        ingest_index(self.db, [self.full / "plugin-0"], enable_vector=False)
        con = connect(self.db)
        uri = con.execute("SELECT uri FROM capabilities WHERE name='skill-0'").fetchone()[0]
        con.execute(
            """
            UPDATE capabilities
            SET approval_state='approved', lifecycle='published', share_state='shared',
                signature_status='verified', provenance_status='verified',
                risk_review_status='approved'
            WHERE uri=?
            """,
            (uri,),
        )
        con.commit()
        con.close()

        ingest_index(self.db, [self.full / "plugin-0"], enable_vector=False)
        con = connect(self.db)
        unchanged = con.execute(
            "SELECT approval_state,lifecycle,share_state,signature_status,provenance_status,risk_review_status "
            "FROM capabilities WHERE uri=?",
            (uri,),
        ).fetchone()
        self.assertEqual(tuple(unchanged), ("approved", "published", "shared", "verified", "verified", "approved"))
        con.close()

        skill = self.full / "plugin-0" / "skills" / "skill-0" / "SKILL.md"
        skill.write_text(skill.read_text(encoding="utf-8") + "\nChanged implementation.\n", encoding="utf-8")
        ingest_index(self.db, [self.full / "plugin-0"], enable_vector=False)
        con = connect(self.db)
        changed = con.execute(
            "SELECT approval_state,lifecycle,share_state,signature_status,provenance_status,risk_review_status "
            "FROM capabilities WHERE uri=?",
            (uri,),
        ).fetchone()
        self.assertEqual(tuple(changed), ("pending", "draft", "not_shared", "pending", "pending", "pending"))
        con.close()

    def test_shadow_promotion_rejects_candidate_changed_after_validation(self) -> None:
        ingest_index(self.db, [self.full], enable_vector=False)
        staged = stage_rebuild_index(self.db, [self.full], enable_vector=False)
        candidate = Path(staged["candidatePath"])
        with candidate.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(CandidateValidationError):
            promote_shadow_database(
                self.db,
                candidate,
                workers_drained=True,
                expected_sha256=staged["candidateSha256"],
            )
        self.assertTrue(self.db.exists())
        candidate.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
