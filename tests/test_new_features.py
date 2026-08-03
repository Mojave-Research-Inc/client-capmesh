"""Tests for the new capability mesh features: migrations, lifecycle transitions,
namespace owners, semver policy, break-glass, task runner, and step-up auth."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db
from capmesh.models import Capability, Principal


class TestMigrations(unittest.TestCase):
    def test_migration_runner_registers_and_applies(self) -> None:
        """Migrations register and apply on a fresh database."""
        from capmesh.migrations import migration_status
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)  # Creates all tables and runs migrations
            status = migration_status(con)
            self.assertTrue(status["upToDate"])
            self.assertEqual(status["currentVersion"], 2)
            status = migration_status(con)
            self.assertTrue(status["upToDate"])
            self.assertEqual(status["currentVersion"], 2)
            con.close()

    def test_migration_runner_idempotent(self) -> None:
        """Running migrations on an already-migrated DB is a no-op."""
        from capmesh.migrations import register_builtin_migrations, run_migrations
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            register_builtin_migrations()
            run_migrations(con)
            result2 = run_migrations(con)
            self.assertEqual(result2["applied"], 0)
            con.close()


class TestLifecycleTransitions(unittest.TestCase):
    def test_valid_transitions(self) -> None:
        from capmesh.lifecycle_transitions import is_valid_transition
        self.assertTrue(is_valid_transition("active", "deprecated"))
        self.assertTrue(is_valid_transition("deprecated", "retired"))
        self.assertTrue(is_valid_transition("draft", "active"))
        self.assertTrue(is_valid_transition("active", "active"))  # same state is valid

    def test_invalid_transitions(self) -> None:
        from capmesh.lifecycle_transitions import is_valid_transition
        self.assertFalse(is_valid_transition("active", "deleted"))
        self.assertFalse(is_valid_transition("deleted", "active"))
        self.assertFalse(is_valid_transition("yanked", "published"))

    def test_transition_capability(self) -> None:
        from capmesh.lifecycle_transitions import transition_capability
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Insert a test capability
            con.execute(
                """INSERT INTO capabilities (uri, canonical_key, tenant_id, type, name, version, title,
                   description, package_path, entrypoint, source_path, source_kind, source_system,
                   content_hash, visibility, discovery_mode, owner, keywords_json, required_scopes_json,
                   allow_groups_json, allow_users_json, risk_tier, mutating, lifecycle, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("test:cap1", "test:cap1", "asg", "skill", "test-cap", "1.0.0", "Test",
                 "Test cap", ".", ".", ".", "system", "test", "sha256:test",
                 "internal", "public", "test", "[]", "[]", "[]", "[]",
                 "low", 0, "active", "{}"),
            )
            con.commit()
            result = transition_capability(con, "test:cap1", "deprecated", actor="admin", reason="end of life")
            self.assertEqual(result["from"], "active")
            self.assertEqual(result["to"], "deprecated")
            # Verify the DB was updated
            row = con.execute("SELECT lifecycle FROM capabilities WHERE uri = ?", ("test:cap1",)).fetchone()
            self.assertEqual(str(row["lifecycle"]), "deprecated")
            con.close()

    def test_invalid_transition_raises(self) -> None:
        from capmesh.lifecycle_transitions import transition_capability
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            con.execute(
                """INSERT INTO capabilities (uri, canonical_key, tenant_id, type, name, version, title,
                   description, package_path, entrypoint, source_path, source_kind, source_system,
                   content_hash, visibility, discovery_mode, owner, keywords_json, required_scopes_json,
                   allow_groups_json, allow_users_json, risk_tier, mutating, lifecycle, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("test:cap2", "test:cap2", "asg", "skill", "test-cap2", "1.0.0", "Test2",
                 "Test cap2", ".", ".", ".", "system", "test", "sha256:test2",
                 "internal", "public", "test", "[]", "[]", "[]", "[]",
                 "low", 0, "active", "{}"),
            )
            con.commit()
            with self.assertRaises(ValueError):
                transition_capability(con, "test:cap2", "deleted", actor="admin")
            con.close()

    def test_list_lifecycle_states(self) -> None:
        from capmesh.lifecycle_transitions import list_lifecycle_states
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = list_lifecycle_states(con)
            self.assertIn("states", result)
            self.assertIn("validStates", result)
            self.assertIn("validTransitions", result)
            con.close()


class TestNamespaceOwners(unittest.TestCase):
    def test_namespace_owner_map(self) -> None:
        from capmesh.namespace_owners import namespace_owner_map
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = namespace_owner_map(con)
            self.assertIsInstance(result, list)
            con.close()

    def test_namespaces_by_owner(self) -> None:
        from capmesh.namespace_owners import namespaces_by_owner
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = namespaces_by_owner(con, "nonexistent")
            self.assertEqual(result, [])
            con.close()

    def test_transfer_namespace_not_found(self) -> None:
        from capmesh.namespace_owners import transfer_namespace
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            with self.assertRaises(ValueError):
                transfer_namespace(con, "nonexistent", "new_owner", actor="admin")
            con.close()


class TestSemverPolicy(unittest.TestCase):
    def test_parse_semver(self) -> None:
        from capmesh.semver_policy import parse_semver
        self.assertEqual(parse_semver("1.2.3"), (1, 2, 3, None, None))
        self.assertEqual(parse_semver("v1.2.3"), (1, 2, 3, None, None))
        self.assertEqual(parse_semver("1.2.3-rc.1"), (1, 2, 3, "rc.1", None))
        self.assertEqual(parse_semver("1.2.3+build.1"), (1, 2, 3, None, "build.1"))
        self.assertIsNone(parse_semver("not-a-version"))

    def test_compare_semver(self) -> None:
        from capmesh.semver_policy import compare_semver
        self.assertEqual(compare_semver("1.0.0", "1.0.0"), 0)
        self.assertEqual(compare_semver("1.0.0", "2.0.0"), -1)
        self.assertEqual(compare_semver("2.0.0", "1.0.0"), 1)
        self.assertEqual(compare_semver("1.0.0", "1.0.1"), -1)
        self.assertEqual(compare_semver("1.0.0", "1.1.0"), -1)
        # Prerelease has lower precedence
        self.assertEqual(compare_semver("1.0.0-rc.1", "1.0.0"), -1)
        self.assertEqual(compare_semver("1.0.0", "1.0.0-rc.1"), 1)

    def test_resolve_version_conflict(self) -> None:
        from capmesh.semver_policy import resolve_version_conflict
        result = resolve_version_conflict(["1.0.0", "1.2.0", "1.1.0"])
        self.assertEqual(result["winner"], "1.2.0")
        self.assertTrue(result["conflict"])
        self.assertTrue(result["allValid"])

    def test_resolve_no_conflict(self) -> None:
        from capmesh.semver_policy import resolve_version_conflict
        result = resolve_version_conflict(["1.0.0"])
        self.assertEqual(result["winner"], "1.0.0")
        self.assertFalse(result["conflict"])

    def test_resolve_empty(self) -> None:
        from capmesh.semver_policy import resolve_version_conflict
        result = resolve_version_conflict([])
        self.assertIsNone(result["winner"])

    def test_check_version_conflicts(self) -> None:
        from capmesh.semver_policy import check_version_conflicts
        caps = [
            {"canonicalKey": "test:cap", "version": "1.0.0"},
            {"canonicalKey": "test:cap", "version": "1.1.0"},
            {"canonicalKey": "test:other", "version": "2.0.0"},
        ]
        conflicts = check_version_conflicts(caps)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["canonicalKey"], "test:cap")
        self.assertEqual(conflicts[0]["winner"], "1.1.0")


class TestBreakGlass(unittest.TestCase):
    def test_grant_and_revoke(self) -> None:
        from capmesh.break_glass import (
            grant_break_glass,
            is_break_glass_active,
            list_break_glass_sessions,
            revoke_break_glass,
        )
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Grant
            result = grant_break_glass(con, "user@example.com", "emergency fix", granted_by="admin")
            self.assertEqual(result["principal"], "user@example.com")
            self.assertEqual(result["reason"], "emergency fix")
            self.assertTrue(result["sessionId"].startswith("bg"))
            # Check active
            self.assertTrue(is_break_glass_active(con, result["sessionId"]))
            # List
            sessions = list_break_glass_sessions(con, active_only=True)
            self.assertEqual(len(sessions), 1)
            # Revoke
            revoke_result = revoke_break_glass(con, result["sessionId"], revoked_by="admin")
            self.assertEqual(revoke_result["status"], "revoked")
            # Check no longer active
            self.assertFalse(is_break_glass_active(con, result["sessionId"]))
            # List active should be empty
            active = list_break_glass_sessions(con, active_only=True)
            self.assertEqual(len(active), 0)
            con.close()

    def test_grant_requires_reason(self) -> None:
        from capmesh.break_glass import grant_break_glass
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            with self.assertRaises(ValueError):
                grant_break_glass(con, "user@example.com", "", granted_by="admin")
            con.close()

    def test_grant_ttl_limits(self) -> None:
        from capmesh.break_glass import grant_break_glass
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            with self.assertRaises(ValueError):
                grant_break_glass(con, "user@example.com", "reason", granted_by="admin", ttl_minutes=0)
            with self.assertRaises(ValueError):
                grant_break_glass(con, "user@example.com", "reason", granted_by="admin", ttl_minutes=999)
            con.close()


class TestTaskRunner(unittest.TestCase):
    def test_create_and_process_task(self) -> None:
        from capmesh.task_runner import create_task_envelope, list_queued_tasks, process_task, task_status
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Create a task
            envelope = {"objective": "test task", "capability": "test:cap"}
            result = create_task_envelope(con, "test:cap", "user@example.com", envelope)
            self.assertEqual(result["status"], "queued")
            task_id = result["taskId"]
            # Check status
            status = task_status(con, task_id)
            self.assertEqual(status["status"], "queued")
            # List queued
            queued = list_queued_tasks(con)
            self.assertEqual(len(queued), 1)
            # Process with a handler
            def handler(env):
                return {"output": "task completed", "objective": env["objective"]}
            proc_result = process_task(con, task_id, handler)
            self.assertEqual(proc_result["status"], "completed")
            # Check final status
            final = task_status(con, task_id)
            self.assertEqual(final["status"], "completed")
            self.assertIsNotNone(final["result"])
            con.close()

    def test_task_failure(self) -> None:
        from capmesh.task_runner import create_task_envelope, process_task
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            envelope = {"objective": "failing task"}
            result = create_task_envelope(con, "test:cap", "user@example.com", envelope)
            task_id = result["taskId"]
            def failing_handler(env):
                raise RuntimeError("task failed")
            proc_result = process_task(con, task_id, failing_handler)
            self.assertEqual(proc_result["status"], "failed")
            self.assertIn("task failed", proc_result["error"])
            con.close()

    def test_cancel_task(self) -> None:
        from capmesh.task_runner import cancel_task, create_task_envelope, task_status
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            envelope = {"objective": "cancel me"}
            result = create_task_envelope(con, "test:cap", "user@example.com", envelope)
            task_id = result["taskId"]
            cancel_result = cancel_task(con, task_id)
            self.assertEqual(cancel_result["status"], "cancelled")
            status = task_status(con, task_id)
            self.assertEqual(status["status"], "cancelled")
            con.close()


class TestStepUpAuth(unittest.TestCase):
    def test_requires_step_up_high_risk(self) -> None:
        from capmesh.access_control import requires_step_up
        cap = Capability(
            uri="test:high", capability_type="skill", name="high", version="1.0.0",
            title="High", description="High risk", package_path=".", entrypoint=".",
            source_path=".", source_kind="system", source_system="test",
            canonical_key="test:high", content_hash="sha256:high", risk_tier="high", mutating=True,
        )
        self.assertTrue(requires_step_up("manage", cap))
        self.assertTrue(requires_step_up("approve", cap))
        self.assertTrue(requires_step_up("publish", cap))
        self.assertFalse(requires_step_up("load", cap))
        self.assertFalse(requires_step_up("call", cap))

    def test_requires_step_up_low_risk(self) -> None:
        from capmesh.access_control import requires_step_up
        cap = Capability(
            uri="test:low", capability_type="skill", name="low", version="1.0.0",
            title="Low", description="Low risk", package_path=".", entrypoint=".",
            source_path=".", source_kind="system", source_system="test",
            canonical_key="test:low", content_hash="sha256:low", risk_tier="low",
        )
        self.assertFalse(requires_step_up("manage", cap))
        self.assertFalse(requires_step_up("approve", cap))

    def test_step_up_blocks_evaluate(self) -> None:
        """evaluate_access returns deny when step-up is required but not authenticated."""
        from capmesh.access_control import evaluate_access
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Insert a high-risk capability
            con.execute(
                """INSERT INTO capabilities (uri, canonical_key, tenant_id, type, name, version, title,
                   description, package_path, entrypoint, source_path, source_kind, source_system,
                   content_hash, visibility, discovery_mode, owner, keywords_json, required_scopes_json,
                   allow_groups_json, allow_users_json, risk_tier, mutating, lifecycle, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("test:high", "test:high", "asg", "skill", "high-cap", "1.0.0", "High Cap",
                 "High risk cap", ".", ".", ".", "system", "test", "sha256:high",
                 "internal", "public", "test", "[]", "[]", "[]", "[]",
                 "high", 1, "active", "{}"),
            )
            con.commit()
            # Principal WITHOUT step-up auth
            principal = Principal(subject="admin", roles=("platform_admin",))
            from capmesh.index import get_capability
            cap = get_capability(con, "test:high")
            allowed, reason = evaluate_access(con, principal, right="manage", capability=cap)
            self.assertFalse(allowed)
            self.assertIn("Step-up", reason)
            # Principal WITH step-up auth
            principal_stepped = Principal(subject="admin", roles=("platform_admin",), step_up_authenticated=True)
            allowed2, _reason2 = evaluate_access(con, principal_stepped, right="manage", capability=cap)
            self.assertTrue(allowed2)
            con.close()


class TestSourceCommitAndLicense(unittest.TestCase):
    def test_capability_has_source_commit_and_license(self) -> None:
        cap = Capability(
            uri="test:cap", capability_type="skill", name="test", version="1.0.0",
            title="Test", description="Test", package_path=".", entrypoint=".",
            source_path=".", source_kind="system", source_system="test",
            canonical_key="test:cap", content_hash="sha256:test",
            source_commit="abc123", license="MIT",
        )
        self.assertEqual(cap.source_commit, "abc123")
        self.assertEqual(cap.license, "MIT")
        record = cap.to_record()
        self.assertEqual(record["sourceCommit"], "abc123")
        self.assertEqual(record["license"], "MIT")

    def test_schema_has_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            columns = [r[1] for r in con.execute("PRAGMA table_info(capabilities)").fetchall()]
            self.assertIn("source_commit", columns)
            self.assertIn("license", columns)
            con.close()


class TestLoadTest(unittest.TestCase):
    """Synthetic load test for large registry."""

    def test_large_registry_search(self) -> None:
        """Search and list work correctly with a large number of capabilities."""
        from capmesh.index import list_capabilities, search
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            # Insert 500 capabilities
            for i in range(500):
                cap = Capability(
                    uri=f"test:cap-{i}",
                    capability_type="skill",
                    name=f"capability-{i}",
                    version="1.0.0",
                    title=f"Capability {i}",
                    description=f"Test capability number {i}",
                    package_path=".",
                    entrypoint=".",
                    source_path=".",
                    source_kind="system",
                    source_system="test",
                    canonical_key=f"test:cap-{i}",
                    content_hash=f"sha256:cap-{i}",
                )
                from capmesh.index import upsert_capability
                upsert_capability(con, cap)
            con.commit()
            # Verify count
            count = con.execute("SELECT COUNT(*) FROM capabilities WHERE name LIKE ?", ("capability-%",)).fetchone()[0]
            self.assertEqual(count, 500)
            # Test search by name
            principal = Principal(subject="local", roles=("platform_admin",))
            results = search(con, "capability-250", principal, k=5)
            self.assertGreater(len(results), 0)
            # Test list with pagination
            page1 = list_capabilities(con, principal, page_size=50)
            self.assertEqual(len(page1["items"]), 50)
            self.assertIsNotNone(page1["nextCursor"])
            # Test page 2
            page2 = list_capabilities(con, principal, page_size=50, cursor=page1["nextCursor"])
            self.assertEqual(len(page2["items"]), 50)
            con.close()


if __name__ == "__main__":
    unittest.main()
