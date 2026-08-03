"""Tests for dependency graph, query expansion, SLO tracking, registry log,
dependency audit, dashboard, and plugin hook features."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db


class TestDependencyGraph(unittest.TestCase):
    def _setup_db(self):
        tmp = tempfile.mkdtemp()
        db = Path(tmp) / "test.db"
        con = connect(db)
        init_db(con)
        return con, tmp

    def _insert_cap(self, con, uri, name="test-cap", version="1.0.0", cap_type="skill"):
        con.execute(
            """INSERT INTO capabilities (uri, canonical_key, tenant_id, type, name, version, title,
               description, package_path, entrypoint, source_path, source_kind, source_system,
               content_hash, visibility, discovery_mode, owner, keywords_json, required_scopes_json,
               allow_groups_json, allow_users_json, risk_tier, mutating, lifecycle, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uri, uri, "asg", cap_type, name, version, name,
             "Test", ".", ".", ".", "system", "test", "sha256:" + uri,
             "internal", "public", "test", "[]", "[]", "[]", "[]",
             "low", 0, "active", "{}"),
        )
        con.commit()

    def test_add_and_list_dependencies(self) -> None:
        from capmesh.dependency_graph import add_dependency, list_dependencies
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b")
        add_dependency(con, "test:cap-a", "test:cap-b")
        deps = list_dependencies(con, "test:cap-a")
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["dependsOnUri"], "test:cap-b")
        self.assertTrue(deps[0]["resolved"])
        con.close()

    def test_remove_dependency(self) -> None:
        from capmesh.dependency_graph import add_dependency, list_dependencies, remove_dependency
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b")
        add_dependency(con, "test:cap-a", "test:cap-b")
        result = remove_dependency(con, "test:cap-a", "test:cap-b")
        self.assertTrue(result["removed"])
        deps = list_dependencies(con, "test:cap-a")
        self.assertEqual(len(deps), 0)
        con.close()

    def test_self_dependency_rejected(self) -> None:
        from capmesh.dependency_graph import add_dependency
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        with self.assertRaises(ValueError):
            add_dependency(con, "test:cap-a", "test:cap-a")
        con.close()

    def test_detect_cycles(self) -> None:
        from capmesh.dependency_graph import add_dependency, detect_cycles
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b")
        self._insert_cap(con, "test:cap-c", "cap-c")
        add_dependency(con, "test:cap-a", "test:cap-b")
        add_dependency(con, "test:cap-b", "test:cap-c")
        add_dependency(con, "test:cap-c", "test:cap-a")
        cycles = detect_cycles(con)
        self.assertGreater(len(cycles), 0)
        con.close()

    def test_topological_sort(self) -> None:
        from capmesh.dependency_graph import add_dependency, topological_sort
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b")
        self._insert_cap(con, "test:cap-c", "cap-c")
        # c depends on b depends on a
        add_dependency(con, "test:cap-b", "test:cap-a")
        add_dependency(con, "test:cap-c", "test:cap-b")
        order = topological_sort(con)
        a_idx = order.index("test:cap-a")
        b_idx = order.index("test:cap-b")
        c_idx = order.index("test:cap-c")
        self.assertLess(a_idx, b_idx)
        self.assertLess(b_idx, c_idx)
        con.close()

    def test_check_compatibility(self) -> None:
        from capmesh.dependency_graph import add_dependency, check_compatibility
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a", "2.0.0")
        self._insert_cap(con, "test:cap-b", "cap-b")
        add_dependency(con, "test:cap-a", "test:cap-b", version_constraint=">=1.0.0")
        result = check_compatibility(con, "test:cap-a")
        self.assertTrue(result["compatible"])
        con.close()

    def test_check_compatibility_version_mismatch(self) -> None:
        from capmesh.dependency_graph import add_dependency, check_compatibility
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b", "0.5.0")
        add_dependency(con, "test:cap-a", "test:cap-b", version_constraint=">=1.0.0")
        result = check_compatibility(con, "test:cap-a")
        self.assertFalse(result["compatible"])
        self.assertEqual(len(result["issues"]), 1)
        self.assertEqual(result["issues"][0]["issue"], "version_mismatch")
        con.close()

    def test_list_dependents(self) -> None:
        from capmesh.dependency_graph import add_dependency, list_dependents
        con, _tmp = self._setup_db()
        self._insert_cap(con, "test:cap-a", "cap-a")
        self._insert_cap(con, "test:cap-b", "cap-b")
        self._insert_cap(con, "test:cap-c", "cap-c")
        add_dependency(con, "test:cap-a", "test:cap-c")
        add_dependency(con, "test:cap-b", "test:cap-c")
        deps = list_dependents(con, "test:cap-c")
        self.assertEqual(len(deps), 2)
        con.close()


class TestQueryExpansion(unittest.TestCase):
    def test_expand_query_synonyms(self) -> None:
        from capmesh.query_expansion import expand_query
        result = expand_query("how to search for skills")
        self.assertIn("search", result["originalQuery"].lower())
        self.assertGreater(len(result["expandedTerms"]), 0)
        self.assertIn("find", result["expandedTerms"])

    def test_expand_query_type_inference(self) -> None:
        from capmesh.query_expansion import expand_query
        result = expand_query("find me a playbook")
        self.assertIn("skill", result["inferredTypes"])

    def test_expand_query_mcp(self) -> None:
        from capmesh.query_expansion import expand_query
        result = expand_query("show me mcp servers")
        self.assertIn("mcp_server", result["inferredTypes"])

    def test_expand_search_terms(self) -> None:
        from capmesh.query_expansion import expand_search_terms
        result = expand_search_terms("search for auth config")
        self.assertIn("OR", result) or self.assertIn("auth", result.lower())


class TestSLOTracking(unittest.TestCase):
    def test_record_and_percentiles(self) -> None:
        from capmesh.slo_tracking import SLOTracker
        tracker = SLOTracker()
        for i in range(100):
            tracker.record("search", float(i + 1))
        pcts = tracker.percentiles("search")
        self.assertEqual(pcts["count"], 100)
        self.assertGreater(pcts["p50"], 0)
        self.assertGreaterEqual(pcts["p99"], pcts["p50"])

    def test_slo_status(self) -> None:
        from capmesh.slo_tracking import SLOTracker
        tracker = SLOTracker()
        tracker.record("search", 10.0)
        status = tracker.slo_status("search")
        self.assertTrue(status["search"]["sloMet"])

    def test_slo_violation(self) -> None:
        from capmesh.slo_tracking import SLOTracker
        tracker = SLOTracker(slo_targets={"search": {"p50": 5}})
        tracker.record("search", 100.0)
        status = tracker.slo_status("search")
        self.assertFalse(status["search"]["sloMet"])
        self.assertGreater(len(status["search"]["violations"]), 0)

    def test_summary(self) -> None:
        from capmesh.slo_tracking import SLOTracker
        tracker = SLOTracker()
        tracker.record("search", 10.0)
        tracker.record("load", 20.0)
        summary = tracker.summary()
        self.assertEqual(summary["totalOperations"], 2)
        self.assertTrue(summary["allSloMet"])

    def test_persist_slo_snapshot(self) -> None:
        from capmesh.slo_tracking import get_tracker, persist_slo_snapshot, record_latency
        get_tracker().reset()
        record_latency("search", 10.0)
        record_latency("load", 20.0)
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            summary = persist_slo_snapshot(con)
            self.assertIn("details", summary)
            # Verify it was persisted
            count = con.execute("SELECT COUNT(*) FROM slo_snapshots").fetchone()[0]
            self.assertGreater(count, 0)
            con.close()


class TestRegistryLog(unittest.TestCase):
    def test_append_and_verify(self) -> None:
        from capmesh.registry_log import append_log_entry, verify_log_chain
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            append_log_entry(con, "ingest", "system", "ingest", target_uri="test:cap-1")
            append_log_entry(con, "update", "system", "update", target_uri="test:cap-1")
            verification = verify_log_chain(con)
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["entries"], 2)
            con.close()

    def test_tamper_detection(self) -> None:
        from capmesh.registry_log import append_log_entry, verify_log_chain
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            append_log_entry(con, "ingest", "system", "ingest")
            append_log_entry(con, "update", "system", "update")
            # Tamper with the second entry
            con.execute("UPDATE registry_log SET entry_hash = ? WHERE sequence = 2", ("bogus",))
            con.commit()
            verification = verify_log_chain(con)
            self.assertFalse(verification["valid"])
            self.assertEqual(verification["brokenAt"], 2)
            con.close()

    def test_list_entries(self) -> None:
        from capmesh.registry_log import append_log_entry, list_log_entries
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            for i in range(5):
                append_log_entry(con, "ingest", "system", "ingest")
            entries = list_log_entries(con)
            self.assertEqual(len(entries), 5)
            self.assertEqual(entries[0]["sequence"], 5)  # most recent first
            con.close()

    def test_get_log_head(self) -> None:
        from capmesh.registry_log import append_log_entry, get_log_head
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            head = get_log_head(con)
            self.assertTrue(head["empty"])
            append_log_entry(con, "ingest", "system", "ingest")
            head = get_log_head(con)
            self.assertFalse(head["empty"])
            self.assertEqual(head["sequence"], 1)
            con.close()


class TestDependencyAudit(unittest.TestCase):
    def test_run_audit_no_findings(self) -> None:
        from capmesh.dependency_audit import run_dependency_audit
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # No non-system capabilities -> no findings
            result = run_dependency_audit(con)
            self.assertEqual(result["totalFindings"], 0)
            con.close()

    def test_run_audit_with_findings(self) -> None:
        from capmesh.dependency_audit import run_dependency_audit
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Insert a capability with eval() in metadata
            con.execute(
                """INSERT INTO capabilities (uri, canonical_key, tenant_id, type, name, version, title,
                   description, package_path, entrypoint, source_path, source_kind, source_system,
                   content_hash, visibility, discovery_mode, owner, keywords_json, required_scopes_json,
                   allow_groups_json, allow_users_json, risk_tier, mutating, lifecycle, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("test:vuln", "test:vuln", "asg", "skill", "vuln-cap", "1.0.0", "Vuln",
                 "Vulnerable cap", ".", ".", ".", "local", "test", "sha256:vuln",
                 "internal", "public", "test", "[]", "[]", "[]", "[]",
                 "low", 0, "active", '{"code": "eval(user_input)"}'),
            )
            con.commit()
            result = run_dependency_audit(con)
            self.assertGreater(result["totalFindings"], 0)
            self.assertIn("critical", result["severityBreakdown"])
            self.assertGreater(result["severityBreakdown"]["critical"], 0)
            con.close()


class TestDashboard(unittest.TestCase):
    def test_dashboard_returns_data(self) -> None:
        from capmesh.dashboard import capability_volume_dashboard
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = capability_volume_dashboard(con)
            self.assertIn("totals", result)
            self.assertIn("distributions", result)
            self.assertIn("lifecycle", result["distributions"])
            self.assertIn("type", result["distributions"])
            self.assertGreater(result["totals"]["capabilities"], 0)  # builtin caps
            con.close()

    def test_capability_detail(self) -> None:
        from capmesh.dashboard import capability_detail
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = capability_detail(con, "nonexistent:cap")
            self.assertFalse(result["found"])
            con.close()


class TestPluginHook(unittest.TestCase):
    def test_detect_skill_type(self) -> None:
        from capmesh.plugin_hook import detect_capability_type
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "test-skill"
            (pkg / "skills" / "test-skill").mkdir(parents=True)
            (pkg / "skills" / "test-skill" / "SKILL.md").write_text("---\nname: test\n---\n# Test\n")
            cap_type = detect_capability_type(pkg)
            self.assertEqual(cap_type, "skill")

    def test_detect_plugin_type(self) -> None:
        from capmesh.plugin_hook import detect_capability_type
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "test-plugin"
            (pkg / ".claude-plugin").mkdir(parents=True)
            (pkg / ".claude-plugin" / "plugin.json").write_text('{"name": "test"}')
            cap_type = detect_capability_type(pkg)
            self.assertEqual(cap_type, "plugin")

    def test_generate_cap_json(self) -> None:
        from capmesh.plugin_hook import generate_cap_json
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "test-skill"
            (pkg / "skills" / "test-skill").mkdir(parents=True)
            (pkg / "skills" / "test-skill" / "SKILL.md").write_text("---\nname: test\n---\n# Test\n")
            manifest = generate_cap_json(pkg, write=False)
            self.assertEqual(manifest["type"], "skill")
            self.assertEqual(manifest["schema"], "capmesh.capability.v1")
            self.assertEqual(manifest["lifecycle"], "draft")

    def test_generate_cap_json_write(self) -> None:
        from capmesh.plugin_hook import generate_cap_json
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "test-skill"
            (pkg / "skills" / "test-skill").mkdir(parents=True)
            (pkg / "skills" / "test-skill" / "SKILL.md").write_text("---\nname: test\n---\n# Test\n")
            generate_cap_json(pkg, write=True)
            cap_json = pkg / "cap.json"
            self.assertTrue(cap_json.exists())
            data = json.loads(cap_json.read_text())
            self.assertEqual(data["type"], "skill")


if __name__ == "__main__":
    unittest.main()
