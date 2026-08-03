from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from capmesh.index import connect, init_db
from capmesh.server import _validate_scim_members_same_tenant

# ---------------------------------------------------------------------------
# Direct unit tests for the CM-05b validation helper.
# ---------------------------------------------------------------------------


class ScimMemberValidationHelperTests(unittest.TestCase):
    """Direct unit tests for _validate_scim_members_same_tenant (CM-05b).

    The helper is the single choke point that decides whether a SCIM group
    member ``value`` may be inserted: every member value must resolve to an
    existing identity in the SAME tenant. These tests cover the pure logic
    against an in-memory SQLite catalog; the HTTP class below covers the
    end-to-end 400/403 responses and the "not inserted" guarantee.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def _insert_identity(self, identity_id: str, tenant_id: str, user_name: str) -> None:
        self.con.execute(
            "INSERT OR IGNORE INTO tenants(id, slug, display_name, status) "
            "VALUES (?, ?, ?, 'active')",
            (tenant_id, tenant_id, tenant_id.title()),
        )
        self.con.execute(
            "INSERT INTO identities(id, tenant_id, external_id, user_name, "
            "display_name, identity_type, active, raw_json) "
            "VALUES (?, ?, ?, ?, ?, 'human', 1, '{}')",
            (identity_id, tenant_id, identity_id, user_name, user_name),
        )
        self.con.commit()

    def test_member_value_resolves_to_existing_identity(self) -> None:
        """A member whose value is an existing same-tenant identity is accepted."""
        self._insert_identity("idn-asg-1", "asg", "alice@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": "idn-asg-1", "display": "Alice"}], "asg"
        )
        self.assertTrue(ok, reason)
        self.assertEqual(reason, "")

    def test_member_value_resolves_by_login(self) -> None:
        """A member value matching the identity's user_name (login) also resolves."""
        self._insert_identity("idn-asg-2", "asg", "bob@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": "bob@example.com"}], "asg"
        )
        self.assertTrue(ok, reason)

    def test_member_value_missing_identity_rejected(self) -> None:
        """A member whose value is no known identity is rejected with the value named."""
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": "ghost@example.com"}], "asg"
        )
        self.assertFalse(ok)
        self.assertIn("ghost@example.com", reason)

    def test_member_value_cross_tenant_rejected(self) -> None:
        """A member whose identity exists in a DIFFERENT tenant is rejected."""
        self._insert_identity("idn-other-1", "other", "carol@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": "idn-other-1"}], "asg"
        )
        self.assertFalse(ok)
        self.assertIn("idn-other-1", reason)
        self.assertIn("same tenant", reason)

    def test_member_value_cross_tenant_by_login_rejected(self) -> None:
        """A cross-tenant identity referenced by login (user_name) is also rejected."""
        self._insert_identity("idn-other-2", "other", "dave@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": "dave@example.com"}], "asg"
        )
        self.assertFalse(ok)
        self.assertIn("dave@example.com", reason)

    def test_multiple_offending_members_listed(self) -> None:
        """Every offending member value is named in the reason when several fail."""
        self._insert_identity("idn-asg-3", "asg", "erin@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con,
            [
                {"value": "idn-asg-3"},  # valid
                {"value": "missing-1"},  # missing
                {"value": "missing-2"},  # missing
            ],
            "asg",
        )
        self.assertFalse(ok)
        self.assertIn("missing-1", reason)
        self.assertIn("missing-2", reason)

    def test_empty_or_non_list_members_accepted(self) -> None:
        """Empty or absent member lists are accepted (members is optional)."""
        self.assertTrue(_validate_scim_members_same_tenant(self.con, [], "asg")[0])
        self.assertTrue(_validate_scim_members_same_tenant(self.con, None, "asg")[0])
        # A non-dict entry with no usable value is skipped, not a hard failure.
        self.assertTrue(_validate_scim_members_same_tenant(self.con, [{"display": "NoValue"}], "asg")[0])

    def test_blank_member_value_skipped(self) -> None:
        """A member with a blank value is skipped rather than treated as missing."""
        self._insert_identity("idn-asg-4", "asg", "frank@example.com")
        ok, reason = _validate_scim_members_same_tenant(
            self.con, [{"value": ""}, {"value": "idn-asg-4"}], "asg"
        )
        self.assertTrue(ok, reason)


# ---------------------------------------------------------------------------
# End-to-end HTTP tests for CM-05b through the real handler.
# ---------------------------------------------------------------------------


class ScimMemberValidationHttpTests(unittest.TestCase):
    """End-to-end SCIM CM-05b behaviour through the real HTTP handler.

    These tests boot the capmesh HTTP server in a subprocess with a
    platform_admin provisioning principal, then exercise the SCIM group
    create path to assert the observable contract:

      * a member value that resolves to an existing same-tenant identity is
        accepted (201, member present in the response);
      * a member value with no known identity is rejected with 400 and the
        group is NOT inserted;
      * a member value whose identity exists in a different tenant is
        rejected with 400 and the group is NOT inserted;
      * a SCIM POST carrying a body tenant that differs from the principal's
        tenant is rejected with 403 (principal.tenant_id wins);
      * the read-only SCIM GET path is unaffected.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "mesh.db"
        cls.service_token = "cm05b-test-service-bearer"
        cls.proxy_token = "cm05b-test-proxy-bearer"
        cls.admin_login = "scim-admin@example.com"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = int(sock.getsockname()[1])
        env = {
            **os.environ,
            "CAPMESH_BEARER_TOKEN": cls.service_token,
            "CAPMESH_PROXY_TOKEN": cls.proxy_token,
            "CAPMESH_ENVIRONMENT": "production",
            "CAPMESH_NODE_ROLE": "authoritative",
            "CAPMESH_AUTHORITY_URL": "https://capmesh.example.com",
            # Grant the provisioning principal platform_admin so it has the
            # `manage` right required by require_scim_access(write=True). The
            # principal's tenant is DEFAULT_TENANT ("asg"); CM-05b binds the
            # SCIM write tenant to that, not to any body tenant.
            "CAPMESH_SUPERADMIN_ACTORS": cls.admin_login,
        }
        cls.server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "capmesh",
                "--db",
                str(cls.db),
                "serve-http",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{cls.port}/health/live", timeout=0.5
                ):
                    break
            except (OSError, urllib.error.URLError):
                if cls.server.poll() is not None:
                    stderr = cls.server.stderr.read() if cls.server.stderr else ""
                    raise RuntimeError(f"test Capmesh server exited early: {stderr}")
                time.sleep(0.05)
        else:
            cls.server.terminate()
            raise RuntimeError("test Capmesh server did not become ready")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)
        if cls.server.stderr:
            cls.server.stderr.close()
        cls.tmp.cleanup()

    # -- helpers -----------------------------------------------------------

    @classmethod
    def _request(
        cls,
        method: str,
        path: str,
        headers: dict[str, str],
        body: dict | None = None,
    ) -> tuple[int, dict[str, object]]:
        data = json.dumps(body or {}).encode() if body else b"{}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}{path}",
            data=data,
            headers={"Content-Type": "application/json", **headers},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def _admin_headers(self) -> dict[str, str]:
        """Provisioning principal: proxy hop + service bearer + tailnet identity.

        The tailnet login is in CAPMESH_SUPERADMIN_ACTORS, so the resolved
        principal carries a platform_admin role_assignment granting the
        `manage` right on tenant "asg". principal.tenant_id is "asg".
        """
        return {
            "X-Capmesh-Proxy-Token": self.proxy_token,
            "Authorization": f"Bearer {self.service_token}",
            "Tailscale-User-Login": self.admin_login,
            "Tailscale-User-Name": "SCIM Admin",
        }

    def _group_exists(self, display_name: str) -> bool:
        """Query the live DB (WAL allows concurrent reads) for a group row."""
        con = connect(self.db)
        try:
            row = con.execute(
                "SELECT 1 FROM groups WHERE tenant_id = 'asg' AND display_name = ?",
                (display_name,),
            ).fetchone()
            return row is not None
        finally:
            con.close()

    def _insert_cross_tenant_identity(self, tenant_id: str, identity_id: str, user_name: str) -> None:
        """Insert a tenant + identity in a DIFFERENT tenant via a second connection.

        WAL + busy_timeout let this brief write commit alongside the running
        server process. The cross-tenant identity is then referenced by a SCIM
        group member value to assert the validator rejects cross-tenant refs.
        """
        con = connect(self.db)
        try:
            con.execute(
                "INSERT OR IGNORE INTO tenants(id, slug, display_name, status) "
                "VALUES (?, ?, ?, 'active')",
                (tenant_id, tenant_id, tenant_id.title()),
            )
            con.execute(
                "INSERT INTO identities(id, tenant_id, external_id, user_name, "
                "display_name, identity_type, active, raw_json) "
                "VALUES (?, ?, ?, ?, ?, 'human', 1, '{}')",
                (identity_id, tenant_id, identity_id, user_name, user_name),
            )
            con.commit()
        finally:
            con.close()

    # -- required tests ----------------------------------------------------

    def test_member_value_resolves_to_existing_identity(self) -> None:
        """A member whose value is an existing same-tenant identity -> accepted.

        Create a user via SCIM, then a group referencing that user's id. The
        group is created (201) and the member is present in the response,
        proving the validator allowed the insert.
        """
        status, user = self._request(
            "POST",
            "/scim/v2/Users",
            self._admin_headers(),
            body={
                "userName": "alice@example.com",
                "displayName": "Alice Example",
                "emails": [{"value": "alice@example.com", "primary": True}],
            },
        )
        self.assertEqual(status, 201)
        user_id = user["id"]
        status, group = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-legal-accepted",
                "members": [{"value": user_id, "display": "Alice Example"}],
            },
        )
        self.assertEqual(status, 201)
        members = group.get("members", [])
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]["value"], user_id)

    def test_member_value_missing_identity_rejected(self) -> None:
        """A member whose value is no known identity -> 400, not inserted."""
        status, payload = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-ghost-group",
                "members": [{"value": "nonexistent-id-123", "display": "Ghost"}],
            },
        )
        self.assertEqual(status, 400)
        # SCIM error envelope naming the offending member value.
        self.assertIn("detail", payload)
        self.assertIn("nonexistent-id-123", payload["detail"])
        # The group must NOT have been inserted.
        self.assertFalse(self._group_exists("asg-ghost-group"))

    def test_member_value_cross_tenant_rejected(self) -> None:
        """A member whose identity exists in a DIFFERENT tenant -> 400, not inserted."""
        self._insert_cross_tenant_identity(
            tenant_id="other",
            identity_id="idn-other-carol",
            user_name="carol@example.com",
        )
        status, payload = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-cross-tenant-group",
                "members": [{"value": "idn-other-carol", "display": "Carol"}],
            },
        )
        self.assertIn(status, (400, 403))
        self.assertIn("detail", payload)
        self.assertIn("idn-other-carol", payload["detail"])
        self.assertFalse(self._group_exists("asg-cross-tenant-group"))

    def test_tenant_bound_to_principal_not_body(self) -> None:
        """A SCIM POST with body tenant != principal.tenant_id -> 403.

        CM-05b: the SCIM provisioning tenant is bound to the provisioning
        principal's tenant (principal.tenant_id == "asg"), NOT the client-
        supplied body tenant. A client cannot self-assign a different tenant;
        a body tenant that differs from principal.tenant_id is rejected 403.
        """
        status, payload = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-body-tenant-group",
                "tenant": "other",
                "members": [],
            },
        )
        self.assertEqual(status, 403)
        self.assertIn("detail", payload)
        # The 403 reason names the principal's bound tenant and the rejected body tenant.
        self.assertIn("asg", payload["detail"])
        self.assertIn("other", payload["detail"])
        self.assertFalse(self._group_exists("asg-body-tenant-group"))

    def test_scim_get_unaffected(self) -> None:
        """The read-only SCIM GET path is unaffected by CM-05b write validation."""
        status, payload = self._request(
            "GET",
            "/scim/v2/Groups",
            self._admin_headers(),
        )
        self.assertEqual(status, 200)
        # SCIM ListResponse envelope is still served.
        self.assertIn("Resources", payload)
        self.assertIn("totalResults", payload)

    # -- additional end-to-end coverage ------------------------------------

    def test_absent_body_tenant_uses_principal_tenant(self) -> None:
        """No body tenant -> principal.tenant_id is used (pre-CM-05b behaviour).

        A SCIM POST with no `tenant` field proceeds under the principal's
        tenant, so a valid same-tenant member is accepted. This locks in that
        CM-05b only rejects a MISMATCHED body tenant, not the absence of one.
        """
        status, user = self._request(
            "POST",
            "/scim/v2/Users",
            self._admin_headers(),
            body={"userName": "dave@example.com", "displayName": "Dave"},
        )
        self.assertEqual(status, 201)
        status, group = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-no-body-tenant-group",
                "members": [{"value": user["id"], "display": "Dave"}],
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(group["members"][0]["value"], user["id"])

    def test_body_tenant_matching_principal_allowed(self) -> None:
        """A body tenant EQUAL to principal.tenant_id is accepted (no mismatch)."""
        status, user = self._request(
            "POST",
            "/scim/v2/Users",
            self._admin_headers(),
            body={"userName": "erin@example.com", "displayName": "Erin"},
        )
        self.assertEqual(status, 201)
        status, group = self._request(
            "POST",
            "/scim/v2/Groups",
            self._admin_headers(),
            body={
                "displayName": "asg-matching-body-tenant-group",
                "tenant": "asg",
                "members": [{"value": user["id"], "display": "Erin"}],
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(group["members"][0]["value"], user["id"])


if __name__ == "__main__":
    unittest.main()
