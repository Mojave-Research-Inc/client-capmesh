"""Tests for capmesh/auth.py — discovery/load scoping and scope enforcement.

These tests exercise the ``can_discover``, ``can_load``, and ``require_scope``
functions that gate every cap.search and cap.load call.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest

from capmesh.auth import can_discover, can_load, require_scope
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.models import Capability, Principal


def _make_capability(
    *,
    visibility: str = "public",
    discovery_mode: str = "public",
    allow_users: list[str] | None = None,
    allow_groups: list[str] | None = None,
    required_scopes: list[str] | None = None,
) -> Capability:
    return Capability(
        uri="cap://user/asg/test/private/skill/test-scope@0.1.0",
        capability_type="skill",
        name="test-scope",
        version="0.1.0",
        title="Test Scope",
        description="Tests auth scoping",
        package_path="/tmp",
        entrypoint="SKILL.md",
        source_path="/tmp/SKILL.md",
        source_kind="skill_markdown",
        source_system="test",
        canonical_key="skill:test:scope:0.1.0",
        content_hash="sha256:abc123",
        risk_tier="low",
        mutating=False,
        lifecycle="draft",
        approval_state="draft",
        visibility=visibility,
        discovery_mode=discovery_mode,
        allow_users=allow_users or [],
        allow_groups=allow_groups or [],
        required_scopes=required_scopes,
        tenant_id="asg",
    )


def _make_db_and_cap(**cap_kwargs) -> tuple[sqlite3.Connection, Capability]:
    from pathlib import Path as _Path
    tmp = tempfile.TemporaryDirectory()
    db_path = str(_Path(tmp.name) / "test.db")
    con = connect(db_path)
    init_db(con, enable_vector=False)
    cap = _make_capability(**cap_kwargs)
    upsert_capability(con, cap)
    con.commit()
    stored = get_capability(con, cap.uri)
    assert stored is not None
    object.__setattr__(stored, "_tmpdir", tmp)  # type: ignore[attr-defined]
    return con, stored


class CanLoadTests(unittest.TestCase):
    """Test the can_load access control function."""

    def test_public_capability_always_allowed(self) -> None:
        cap = _make_capability(visibility="public")
        anonymous = Principal(subject="anon", tenant_id="asg", roles=())
        allowed, _ = can_load(cap, anonymous)
        self.assertTrue(allowed)

    def test_internal_capability_denies_unauthenticated(self) -> None:
        cap = _make_capability(visibility="internal")
        anonymous = Principal(subject="anon", tenant_id="asg", roles=(), authenticated=False)
        allowed, reason = can_load(cap, anonymous)
        self.assertFalse(allowed)
        self.assertEqual(reason, "Authentication required.")

    def test_internal_capability_allows_authenticated(self) -> None:
        cap = _make_capability(visibility="internal")
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        allowed, _ = can_load(cap, user)
        self.assertTrue(allowed)

    def test_secret_denies_without_explicit_entitlement(self) -> None:
        cap = _make_capability(visibility="secret")
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        allowed, reason = can_load(cap, user)
        self.assertFalse(allowed)
        self.assertEqual(reason, "Capability is secret and hidden without explicit entitlement.")

    def test_secret_allows_when_user_in_allow_users(self) -> None:
        cap = _make_capability(visibility="secret", allow_users=["user@example.com"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        allowed, _ = can_load(cap, user)
        self.assertTrue(allowed)

    def test_secret_denies_when_user_not_in_allow_users(self) -> None:
        cap = _make_capability(visibility="secret", allow_users=["other@example.com"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        allowed, _ = can_load(cap, user)
        self.assertFalse(allowed)

    def test_secret_allows_when_group_intersection_matches(self) -> None:
        cap = _make_capability(visibility="secret", allow_groups=["admins", "reviewers"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",), groups=["reviewers"])
        allowed, _ = can_load(cap, user)
        self.assertTrue(allowed)

    def test_secret_denies_when_no_group_intersection(self) -> None:
        cap = _make_capability(visibility="secret", allow_groups=["admins"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",), groups=["reviewers"])
        allowed, _ = can_load(cap, user)
        self.assertFalse(allowed)

    def test_secret_allows_when_required_scopes_subset_of_principal(self) -> None:
        cap = _make_capability(visibility="secret", required_scopes=["cap:load", "cap:search"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",), scopes=["cap:load", "cap:search", "cap:delegate"])
        allowed, _ = can_load(cap, user)
        self.assertTrue(allowed)

    def test_secret_denies_when_missing_required_scope(self) -> None:
        cap = _make_capability(visibility="secret", required_scopes=["cap:load", "cap:search", "cap:delegate"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",), scopes=["cap:load", "cap:search"])
        allowed, _ = can_load(cap, user)
        self.assertFalse(allowed)

    def test_empty_groups_and_scopes_do_not_match_allowlists(self) -> None:
        cap = _make_capability(visibility="secret", allow_groups=["admins"], required_scopes=["cap:load"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",), groups=[], scopes=[])
        allowed, _ = can_load(cap, user)
        self.assertFalse(allowed)

    def test_can_load_with_database_delegate_calls_governance(self) -> None:
        con, cap = _make_db_and_cap(visibility="secret", allow_users=["user@example.com"], required_scopes=[])
        try:
            user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
            # When con is provided, governance.evaluate_access is called
            # This tests the DB path through governance
            allowed, _reason = can_load(cap, user, con=con)
            # governance grants access when user matches allow_users
            self.assertTrue(allowed)
        finally:
            con.close()
            cap._tmpdir.cleanup()  # type: ignore


class CanDiscoverTests(unittest.TestCase):
    """Test the can_discover visibility filtering function."""

    def test_public_capability_discoverable(self) -> None:
        cap = _make_capability(visibility="public")
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        visible, locked = can_discover(cap, user)
        self.assertTrue(visible)
        self.assertFalse(locked)

    def test_hidden_capability_denies_discovery(self) -> None:
        cap = _make_capability(visibility="secret", discovery_mode="hidden")
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        visible, locked = can_discover(cap, user)
        self.assertFalse(visible)
        self.assertFalse(locked)

    def test_hidden_capability_discoverable_when_entitled(self) -> None:
        cap = _make_capability(visibility="secret", discovery_mode="hidden", allow_users=["user@example.com"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        visible, locked = can_discover(cap, user)
        self.assertTrue(visible)
        self.assertFalse(locked)

    def test_locked_capability_shows_stub_without_load_access(self) -> None:
        cap = _make_capability(visibility="secret", discovery_mode="locked")
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        visible, locked = can_discover(cap, user)
        self.assertTrue(visible)
        self.assertTrue(locked)

    def test_locked_capability_full_when_entitled(self) -> None:
        cap = _make_capability(visibility="secret", discovery_mode="locked", allow_users=["user@example.com"])
        user = Principal(subject="user@example.com", tenant_id="asg", roles=("member",))
        visible, locked = can_discover(cap, user)
        self.assertTrue(visible)
        self.assertFalse(locked)


class RequireScopeTests(unittest.TestCase):
    """Test the require_scope scope enforcement function."""

    def test_exact_scope_match(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap:load"])
        ok, _ = require_scope(user, "cap:load")
        self.assertTrue(ok)

    def test_wildcard_grants_all_scopes(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap:*"])
        for scope in ("cap:load", "cap:search", "cap:delegate", "cap:call"):
            ok, _ = require_scope(user, scope)
            self.assertTrue(ok, f"cap:* should grant {scope}")

    def test_scope_equivalence_cap_search(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap.discover"])
        ok, _ = require_scope(user, "cap:search")
        self.assertTrue(ok)
        user2 = Principal(subject="user", tenant_id="asg", scopes=["cap.discover:*"])
        ok2, _ = require_scope(user2, "cap:search")
        self.assertTrue(ok2)

    def test_scope_equivalence_cap_load(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap.load"])
        ok, _ = require_scope(user, "cap:load")
        self.assertTrue(ok)
        user2 = Principal(subject="user", tenant_id="asg", scopes=["cap.load:*"])
        ok2, _ = require_scope(user2, "cap:load")
        self.assertTrue(ok2)

    def test_scope_equivalence_cap_delegate(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap.delegate"])
        ok, _ = require_scope(user, "cap:delegate")
        self.assertTrue(ok)

    def test_scope_equivalence_cap_report(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap.audit"])
        ok, _ = require_scope(user, "cap:report")
        self.assertTrue(ok)

    def test_scope_equivalence_cap_call(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap.call"])
        ok, _ = require_scope(user, "cap:call")
        self.assertTrue(ok)

    def test_missing_scope_denied(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=["cap:load"])
        ok, reason = require_scope(user, "cap:search")
        self.assertFalse(ok)
        self.assertIn("Missing required scope", reason)

    def test_empty_scopes_denied(self) -> None:
        user = Principal(subject="user", tenant_id="asg", scopes=[])
        ok, reason = require_scope(user, "cap:load")
        self.assertFalse(ok)
        self.assertIn("Missing required scope", reason)


if __name__ == "__main__":
    unittest.main()
