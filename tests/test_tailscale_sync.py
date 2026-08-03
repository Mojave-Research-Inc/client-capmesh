"""Tests for capmesh/tailscale_sync.py — tailnet user/group sync engine.

These tests exercise the internal helpers and orchestration paths (API and
fallback) without requiring actual Tailscale infrastructure.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.index import connect, init_db
from capmesh.tailscale_sync import (
    TailscaleSyncError,
    _acquire_token,
    _api_get,
    _bao_get,
    _fallback_status_users,
    _fetch_acl_groups,
    _fetch_users,
    _oauth_credentials,
    _resolve_tailnet,
)
from capmesh.tailscale_sync import (
    run as run_sync,
)

# ---------------------------------------------------------------------------
# Secret + token acquisition helpers
# ---------------------------------------------------------------------------


class BaoCredentialsTests(unittest.TestCase):
    """Test _oauth_credentials resolution."""

    def test_env_override_returns_credentials(self) -> None:
        with mock.patch.dict(os.environ, {
            "CAPMESH_TAILSCALE_CLIENT_ID": "env-id",
            "CAPMESH_TAILSCALE_CLIENT_SECRET": "env-secret",
        }):
            result = _oauth_credentials()
            self.assertEqual(result, ("env-id", "env-secret"))

    def test_env_id_only_without_secret_returns_none(self) -> None:
        with mock.patch("capmesh.tailscale_sync._bao_get", return_value=None), \
             mock.patch.dict(os.environ, {
                 "CAPMESH_TAILSCALE_CLIENT_ID": "env-id",
             }, clear=False):
            result = _oauth_credentials()
            self.assertIsNone(result)

    def test_bao_fallback_when_env_missing(self) -> None:
        with mock.patch("capmesh.tailscale_sync._bao_get", return_value="bao-secret"), \
             mock.patch.dict(os.environ, {
                 "CAPMESH_TAILSCALE_CLIENT_ID": "env-id",
             }, clear=False):
            result = _oauth_credentials()
            # env ID + bao secret => credentials resolved via fallback
            self.assertEqual(result, ("env-id", "bao-secret"))

    def test_bao_failure_returns_none(self) -> None:
        with mock.patch("capmesh.tailscale_sync._bao_get", return_value=None):
            with mock.patch.dict(os.environ, {}, clear=True):
                result = _oauth_credentials()
                self.assertIsNone(result)


class BaoGetTests(unittest.TestCase):
    """Test the internal _bao_get vault read helper."""

    def test_success_returns_value(self) -> None:
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "my-secret-value\n"
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            result = _bao_get("some/path", "key")
            self.assertEqual(result, "my-secret-value")

    def test_nonzero_returncode_returns_none(self) -> None:
        mock_result = mock.MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            result = _bao_get("some/path", "key")
            self.assertIsNone(result)

    def test_file_not_found_returns_none(self) -> None:
        with mock.patch("capmesh.tailscale_sync.subprocess.run", side_effect=FileNotFoundError("bao-client not found")):
            result = _bao_get("some/path", "key")
            self.assertIsNone(result)

    def test_empty_stdout_returns_none(self) -> None:
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\n"
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            result = _bao_get("some/path", "key")
            self.assertIsNone(result)


class AcquireTokenTests(unittest.TestCase):
    """Test _acquire_token OAuth flow."""

    def test_extracts_access_token_from_response(self) -> None:
        response = json.dumps({"access_token": "ts-token-xyz", "expires_in": 3600})
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = response.encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            token = _acquire_token("client-id", "client-secret")
            self.assertEqual(token, "ts-token-xyz")

    def test_raises_when_no_access_token_in_response(self) -> None:
        response = json.dumps({"error": "invalid_grant"})
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = response.encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            with self.assertRaisesRegex(TailscaleSyncError, "did not include an access_token"):
                _acquire_token("client-id", "client-secret")

    def test_raises_on_http_error(self) -> None:
        from urllib.error import HTTPError
        with mock.patch("capmesh.tailscale_sync.urlopen", side_effect=HTTPError("url", 401, "Unauthorized", {}, None)):
            with self.assertRaisesRegex(TailscaleSyncError, "OAuth token request failed"):
                _acquire_token("client-id", "client-secret")


class ApiGetTests(unittest.TestCase):
    """Test _api_get."""

    def test_fetches_and_parses_json(self) -> None:
        payload = {"key": "value", "list": [1, 2]}
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            result = _api_get("bearer-token", "/api/v2/test")
            self.assertEqual(result, payload)

    def test_raises_on_api_error(self) -> None:
        from urllib.error import URLError
        with mock.patch("capmesh.tailscale_sync.urlopen", side_effect=URLError("no network")):
            with self.assertRaisesRegex(TailscaleSyncError, "GET /api/v2/test failed"):
                _api_get("bearer-token", "/api/v2/test")


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------


class ResolveTailnetTests(unittest.TestCase):
    """Test _resolve_tailnet."""

    def test_explicit_tailnet_takes_precedence(self) -> None:
        result = _resolve_tailnet("token", "my-tailnet")
        self.assertEqual(result, "my-tailnet")

    def test_env_tailnet_when_no_explicit(self) -> None:
        with mock.patch.dict(os.environ, {"CAPMESH_TAILSCALE_TAILNET": "env-tailnet"}):
            result = _resolve_tailnet("token", None)
            self.assertEqual(result, "env-tailnet")

    def test_default_dash_when_nothing_set(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            result = _resolve_tailnet("token", None)
            self.assertEqual(result, "-")


class FetchUsersTests(unittest.TestCase):
    """Test _fetch_users."""

    def test_parses_users_list(self) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "users": [
                {"loginName": "alice@example.com", "id": "alice1"},
                {"loginName": "bob@example.com", "id": "bob2"},
            ]
        }).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            users = _fetch_users("token", "my-tailnet")
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["loginName"], "alice@example.com")

    def test_filters_non_dict_entries(self) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "users": [
                {"loginName": "valid"},
                "invalid-string",
                None,
                42,
            ]
        }).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            users = _fetch_users("token", "my-tailnet")
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]["loginName"], "valid")


class FetchAclGroupsTests(unittest.TestCase):
    """Test _fetch_acl_groups."""

    def test_parses_groups_from_acl(self) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "groups": {
                "group:ts:admins": ["alice@example.com", "bob@example.com"],
                "group:ts:developers": ["bob@example.com"],
            }
        }).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            groups = _fetch_acl_groups("token", "my-tailnet")
            self.assertEqual(len(groups), 2)
            self.assertEqual(groups["group:ts:admins"], ["alice@example.com", "bob@example.com"])

    def test_returns_empty_on_api_error(self) -> None:
        from urllib.error import URLError
        with mock.patch("capmesh.tailscale_sync.urlopen", side_effect=URLError("no network")):
            groups = _fetch_acl_groups("token", "my-tailnet")
            self.assertEqual(groups, {})

    def test_returns_empty_when_no_groups_block(self) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            groups = _fetch_acl_groups("token", "my-tailnet")
            self.assertEqual(groups, {})

    def test_skips_non_list_group_members(self) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({
            "groups": {
                "group:ts:bad": "not-a-list",
                "group:ts:good": ["user@example.com"],
            }
        }).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("capmesh.tailscale_sync.urlopen", return_value=mock_resp):
            groups = _fetch_acl_groups("token", "my-tailnet")
            self.assertEqual(len(groups), 1)
            self.assertIn("group:ts:good", groups)


class FallbackStatusUsersTests(unittest.TestCase):
    """Test _fallback_status_users (tailscale CLI fallback)."""

    def test_parses_self_and_peers(self) -> None:
        status = {
            "Self": {"LoginName": "self@example.com", "UserID": "self123", "DisplayName": "Self User"},
            "Peer": {
                "peer1": {"LoginName": "peer@example.com", "UserID": "peer1", "DisplayName": "Peer"},
            },
            "User": {
                "self123": {"LoginName": "self@example.com", "ID": "self123", "DisplayName": "Self User"},
                "peer1": {"LoginName": "peer@example.com", "ID": "peer1", "DisplayName": "Peer"},
            },
        }
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(status)
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            users = _fallback_status_users()
            self.assertEqual(len(users), 2)
            logins = {u["loginName"] for u in users}
            self.assertIn("self@example.com", logins)
            self.assertIn("peer@example.com", logins)

    def test_returns_empty_on_command_not_found(self) -> None:
        with mock.patch("capmesh.tailscale_sync.subprocess.run", side_effect=FileNotFoundError("tailscale not found")):
            users = _fallback_status_users()
            self.assertEqual(users, [])

    def test_returns_empty_on_nonzero_exit(self) -> None:
        mock_result = mock.MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            users = _fallback_status_users()
            self.assertEqual(users, [])

    def test_returns_empty_on_parse_error(self) -> None:
        mock_result = mock.MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not-json"
        with mock.patch("capmesh.tailscale_sync.subprocess.run", return_value=mock_result):
            users = _fallback_status_users()
            self.assertEqual(users, [])


# ---------------------------------------------------------------------------
# Orchestration: run()
# ---------------------------------------------------------------------------


class RunSyncTests(unittest.TestCase):
    """Test the main sync orchestration function."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.con = connect(self.db_path)
        init_db(self.con, enable_vector=False)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def test_dry_run_with_mocked_apis(self) -> None:
        mock_users = [
            {"loginName": "alice@example.com", "id": "alice1", "type": "member", "status": "active"},
            {"loginName": "bob@example.com", "id": "bob2", "type": "admin", "status": "active"},
        ]
        mock_acl = {
            "groups": {
                "group:ts:admins": ["alice@example.com"],
                "group:ts:devs": ["alice@example.com", "bob@example.com"],
            }
        }

        mock_resp_users = mock.MagicMock()
        mock_resp_users.read.return_value = json.dumps({"users": mock_users}).encode("utf-8")
        mock_resp_users.__enter__ = mock.MagicMock(return_value=mock_resp_users)
        mock_resp_users.__exit__ = mock.MagicMock(return_value=False)

        mock_resp_acl = mock.MagicMock()
        mock_resp_acl.read.return_value = json.dumps(mock_acl).encode("utf-8")
        mock_resp_acl.__enter__ = mock.MagicMock(return_value=mock_resp_acl)
        mock_resp_acl.__exit__ = mock.MagicMock(return_value=False)

        mock_token_resp = mock.MagicMock()
        mock_token_resp.read.return_value = json.dumps({"access_token": "token123"}).encode("utf-8")
        mock_token_resp.__enter__ = mock.MagicMock(return_value=mock_token_resp)
        mock_token_resp.__exit__ = mock.MagicMock(return_value=False)

        side_effects = [mock_token_resp, mock_resp_users, mock_resp_acl]

        def urlopen_side_effect(url, **kwargs):
            return side_effects.pop(0)

        with mock.patch("capmesh.tailscale_sync.urlopen", side_effect=urlopen_side_effect):
            with mock.patch.dict(os.environ, {
                "CAPMESH_TAILSCALE_CLIENT_ID": "test-id",
                "CAPMESH_TAILSCALE_CLIENT_SECRET": "test-secret",
            }):
                result = run_sync(self.con, tenant_id="asg", dry_run=True)
                self.assertTrue(result["dryRun"])
                self.assertEqual(result["usersSeen"], 2)
                self.assertEqual(result["usersUpserted"], 2)
                self.assertEqual(result["groupsSeen"], 2)
                self.assertEqual(result["groupsUpserted"], 2)

    def test_no_credentials_uses_fallback(self) -> None:
        # No env credentials and _bao_get returns None — falls back to
        # _fallback_status_users. We mock that to return a user.
        with mock.patch("capmesh.tailscale_sync._oauth_credentials", return_value=None):
            with mock.patch("capmesh.tailscale_sync._fallback_status_users", return_value=[
                {"loginName": "fallback@example.com", "id": "fb1", "type": "member", "status": "active"},
            ]):
                result = run_sync(self.con, tenant_id="asg", dry_run=True)
                self.assertEqual(result["source"], "tailscale-status")
                self.assertEqual(result["usersSeen"], 1)

    def test_no_credentials_no_fallback_raises(self) -> None:
        with mock.patch("capmesh.tailscale_sync._oauth_credentials", return_value=None):
            with mock.patch("capmesh.tailscale_sync._fallback_status_users", return_value=[]):
                with self.assertRaisesRegex(TailscaleSyncError, "No tailnet source available"):
                    run_sync(self.con, tenant_id="asg")

    def test_dry_run_summary_has_all_fields(self) -> None:
        with mock.patch("capmesh.tailscale_sync._oauth_credentials", return_value=("id", "secret")):
            with mock.patch("capmesh.tailscale_sync._acquire_token", return_value="fake-token"):
                with mock.patch("capmesh.tailscale_sync._fetch_users", return_value=[]):
                    with mock.patch("capmesh.tailscale_sync._fetch_acl_groups", return_value={}):
                        result = run_sync(self.con, tenant_id="asg", dry_run=True)
        self.assertIn("usersSeen", result)
        self.assertIn("usersUpserted", result)
        self.assertIn("usersDeactivated", result)
        self.assertIn("groupsSeen", result)
        self.assertIn("groupsUpserted", result)
        self.assertIn("groupMembersAdded", result)
        self.assertIn("groupMembersPruned", result)


if __name__ == "__main__":
    unittest.main()
