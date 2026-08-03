"""Identity provisioning must not write on every request.

WHY THIS FILE EXISTS
--------------------
On 2026-07-19 /api/v1/whoami wedged the single SQLite write lock in production. Under 24
concurrent requests through the nginx LB, 144 of 144 failed, every one exceeding a 20s client
timeout, and the write lock stayed wedged afterwards. New-client onboarding was broken for
hours and nothing alerted, because /health never writes and stayed green throughout.

The cause was ensure_identity_for_principal() running an unconditional
``INSERT ... ON CONFLICT DO UPDATE`` on every call. current_user() calls it, commits, then
calls list_stores() which called it AGAIN — two writes plus a commit per request, serialised
across 16 worker processes sharing one write lock.

`rg ensure_identity_for_principal tests/` returned NOTHING before this file. The code path
that took production down had zero test coverage, which is the actual reason it shipped.

These tests assert on ``con.total_changes`` — the number of rows actually written — not on
return values or counters. That distinction matters: the sibling defect in ingest survived a
green idempotency test precisely because that test asserted counters while 13.6 MB of WAL
churned per run. A test that cannot see writes cannot catch a write regression.

Every test here FAILS against the pre-fix implementation (which always wrote) and PASSES
against the read-first one.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capmesh.governance import (
    current_user,
    ensure_identity_for_principal,
    init_governance_schema,
    list_stores,
)
from capmesh.index import connect, init_db
from capmesh.models import Principal


def principal(subject: str = "test-steady@example.com", **overrides: object) -> Principal:
    base: dict[str, object] = {
        "subject": subject,
        "tenant_id": "asg",
        "groups": ("asg:tailnet",),
        "roles": ("member",),
        "scopes": ("cap:search", "cap:load"),
        "authenticated": True,
    }
    base.update(overrides)
    return Principal(**base)  # type: ignore[arg-type]


class IdentityProvisioningWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con)
        init_governance_schema(self.con)
        self.con.commit()

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def writes_during(self, fn) -> int:
        """Rows written by fn(), measured at the connection rather than inferred."""
        before = self.con.total_changes
        fn()
        return self.con.total_changes - before

    # ---- the regression that took production down -------------------------------------

    def test_repeat_provisioning_writes_nothing(self) -> None:
        """The steady state — same principal, unchanged attributes — must not write.

        This is the assertion that would have caught the incident. Pre-fix this is ~5.
        """
        p = principal()
        ensure_identity_for_principal(self.con, p)
        self.con.commit()

        self.assertEqual(
            self.writes_during(lambda: ensure_identity_for_principal(self.con, p)),
            0,
            "repeat provisioning wrote rows; every whoami will contend for the write lock",
        )

    def test_current_user_repeat_writes_nothing_and_leaves_no_open_transaction(self) -> None:
        """current_user() is what /api/v1/whoami calls. It must be read-only when settled.

        Also asserts it does not leave a transaction open: an unconditional commit of nothing
        still costs a round trip on the hottest endpoint, and an open transaction would hold
        the write lock across the response.
        """
        p = principal()
        current_user(self.con, p)
        self.con.commit()

        self.assertEqual(
            self.writes_during(lambda: current_user(self.con, p)),
            0,
            "current_user wrote on a settled identity",
        )
        self.assertFalse(
            self.con.in_transaction,
            "current_user left a transaction open, holding the write lock",
        )

    def test_concurrent_shape_many_repeats_write_nothing(self) -> None:
        """N sequential whoami calls must cost zero writes in total.

        Production ran 24 concurrent against one write lock. Serial repetition is the
        single-threaded proxy: if 25 calls write nothing, they cannot serialise on the lock.
        """
        p = principal()
        current_user(self.con, p)
        self.con.commit()

        total = self.writes_during(lambda: [current_user(self.con, p) for _ in range(25)])
        self.assertEqual(total, 0, f"25 repeat whoami calls wrote {total} rows")

    # ---- the fast path must not skip work that is genuinely needed ---------------------

    def test_first_contact_provisions_identity_and_two_stores(self) -> None:
        """Suppressing repeat writes must not suppress first-contact provisioning."""
        p = principal("newcomer@example.com")
        writes = self.writes_during(lambda: ensure_identity_for_principal(self.con, p))
        self.con.commit()

        self.assertGreater(writes, 0, "first contact did not provision")
        identity_id = ensure_identity_for_principal(self.con, p)
        owned = self.con.execute(
            "SELECT COUNT(*) FROM stores WHERE tenant_id = ? AND owner_identity_id = ? "
            "AND kind IN ('user_private','user_shared')",
            ("asg", identity_id),
        ).fetchone()[0]
        self.assertEqual(owned, 2, "private+shared stores were not both created")

    def test_changed_attribute_still_writes(self) -> None:
        """A real change must still reach the database."""
        p = principal()
        ensure_identity_for_principal(self.con, p)
        self.con.commit()

        changed = principal(display_name="Changed Name")
        self.assertGreater(
            self.writes_during(lambda: ensure_identity_for_principal(self.con, changed)),
            0,
            "an attribute change was silently dropped by the fast path",
        )

    def test_identity_id_is_stable_across_calls(self) -> None:
        """The fast path must return the same identity, not mint a new one."""
        p = principal()
        first = ensure_identity_for_principal(self.con, p)
        self.con.commit()
        self.assertEqual(first, ensure_identity_for_principal(self.con, p))

    # ---- list_stores(ensure=False) is an optimisation, not a behaviour change ----------

    def test_list_stores_ensure_false_matches_ensure_true(self) -> None:
        """current_user passes ensure=False because it just provisioned. Prove equivalence."""
        p = principal()
        ensure_identity_for_principal(self.con, p)
        self.con.commit()

        with_ensure = [s["id"] for s in list_stores(self.con, p, ensure=True)]
        without = [s["id"] for s in list_stores(self.con, p, ensure=False)]
        self.assertEqual(with_ensure, without)
        self.assertTrue(with_ensure, "no stores visible to a provisioned principal")

    def test_list_stores_default_still_provisions_unseen_principal(self) -> None:
        """Callers other than current_user rely on ensure=True to provision. Keep that."""
        stores = list_stores(self.con, principal("test-never-seen@example.com"))
        self.assertTrue(stores, "ensure=True did not provision an unseen principal")


if __name__ == "__main__":
    unittest.main()
