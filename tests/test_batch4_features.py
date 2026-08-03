"""Tests for streamable HTTP, OAuth PKCE, SCIM sync, Entra groups, Sigstore, local embedding, MCP SDK wrapper."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db


class TestStreamableHTTP(unittest.TestCase):
    def test_initialize(self) -> None:
        from capmesh.streamable_http import handle_initialize
        resp = handle_initialize({})
        self.assertEqual(resp.status, 200)
        self.assertIn("protocolVersion", resp.body)
        self.assertIn("serverInfo", resp.body)

    def test_ping(self) -> None:
        from capmesh.streamable_http import handle_request
        resp = handle_request("ping", {})
        self.assertTrue(resp.body["pong"])

    def test_tools_list(self) -> None:
        from capmesh.streamable_http import handle_request
        resp = handle_request("tools/list", {})
        self.assertIn("tools", resp.body)
        self.assertGreater(len(resp.body["tools"]), 0)

    def test_check_protocol_version(self) -> None:
        from capmesh.streamable_http import check_protocol_version
        v = check_protocol_version({"MCP-Protocol-Version": "2026-01-25"})
        self.assertEqual(v, "2026-01-25")
        v = check_protocol_version({})
        self.assertIsNotNone(v)
        v = check_protocol_version({"MCP-Protocol-Version": "invalid"})
        self.assertIsNone(v)

    def test_sse_format(self) -> None:
        from capmesh.streamable_http import StreamableHTTPResponse
        resp = StreamableHTTPResponse(body={"test": True})
        sse = resp.to_sse()
        self.assertIn("event: message", sse)
        self.assertIn("data:", sse)


class TestOAuthPKCE(unittest.TestCase):
    def test_code_verifier_and_challenge(self) -> None:
        from capmesh.oauth_pkce import compute_code_challenge, generate_code_verifier, validate_pkce
        verifier = generate_code_verifier()
        challenge = compute_code_challenge(verifier)
        self.assertTrue(validate_pkce(verifier, challenge))
        self.assertFalse(validate_pkce("wrong", challenge))

    def test_authorization_url(self) -> None:
        from capmesh.oauth_pkce import build_authorization_url, generate_code_verifier
        verifier = generate_code_verifier()
        url = build_authorization_url(
            authorization_endpoint="https://auth.test.com/authorize",
            client_id="test-client",
            redirect_uri="https://capmesh.test.com/callback",
            code_verifier=verifier,
            scopes=["capmesh:read"],
        )
        self.assertIn("https://auth.test.com/authorize", url)
        self.assertIn("code_challenge", url)
        self.assertIn("S256", url)

    def test_pkce_session(self) -> None:
        from capmesh.oauth_pkce import PKCESession
        session = PKCESession(client_id="test", redirect_uri="https://capmesh.test.com/callback")
        url = session.authorization_url("https://auth.test.com/authorize")
        self.assertIn("code_challenge", url)
        token_req = session.token_request("https://auth.test.com/token", "auth_code")
        self.assertEqual(token_req["body"]["grant_type"], "authorization_code")
        self.assertEqual(token_req["body"]["code"], "auth_code")


class TestSCIMSync(unittest.TestCase):
    def test_process_scim_group(self) -> None:
        from capmesh.scim_sync import process_scim_group
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            group = {"id": "group-1", "displayName": "Test Group", "members": [{"value": "user1"}, {"value": "user2"}]}
            result = process_scim_group(con, group)
            self.assertTrue(result["synced"])
            self.assertEqual(result["memberCount"], 2)
            con.close()

    def test_sync_entitlement_groups(self) -> None:
        from capmesh.scim_sync import sync_entitlement_groups
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            groups = [{"id": "g1", "displayName": "Group 1"}, {"id": "g2", "displayName": "Group 2"}]
            result = sync_entitlement_groups(con, groups)
            self.assertEqual(result["synced"], 2)
            self.assertEqual(result["errors"], 0)
            con.close()

    def test_list_group_mappings(self) -> None:
        from capmesh.scim_sync import list_group_mappings, upsert_group_mapping
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            upsert_group_mapping(con, "g1", display_name="Test", mesh_role="member")
            mappings = list_group_mappings(con)
            self.assertEqual(len(mappings), 1)
            self.assertEqual(mappings[0]["scimGroupId"], "g1")
            con.close()


class TestEntraGroups(unittest.TestCase):
    def test_bind_and_list(self) -> None:
        from capmesh.entra_groups import bind_entra_group, list_entra_bindings
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            bind_entra_group(con, "entra-tenant-1", "group-1", "mesh-group-1", entra_group_name="Engineers")
            bindings = list_entra_bindings(con)
            self.assertEqual(len(bindings), 1)
            self.assertEqual(bindings[0]["entraGroupId"], "group-1")
            self.assertEqual(bindings[0]["meshGroupName"], "mesh-group-1")
            con.close()

    def test_resolve_entra_groups(self) -> None:
        from capmesh.entra_groups import bind_entra_group, resolve_entra_groups_to_mesh_groups
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            bind_entra_group(con, "t1", "g1", "mesh-g1")
            bind_entra_group(con, "t1", "g2", "mesh-g2")
            mesh_groups = resolve_entra_groups_to_mesh_groups(con, ["g1", "g2", "g3"])
            self.assertIn("mesh-g1", mesh_groups)
            self.assertIn("mesh-g2", mesh_groups)
            con.close()

    def test_remove_entra_binding(self) -> None:
        from capmesh.entra_groups import bind_entra_group, list_entra_bindings, remove_entra_binding
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "test.db")
            init_db(con)
            bind_entra_group(con, "t1", "g1", "mesh-g1")
            result = remove_entra_binding(con, "t1", "g1")
            self.assertTrue(result["removed"])
            self.assertEqual(len(list_entra_bindings(con)), 0)
            con.close()


class TestSigstoreSigning(unittest.TestCase):
    def test_build_and_sign_export_bundle(self) -> None:
        from capmesh.sigstore_signing import build_export_bundle, sign_export_bundle, verify_export_bundle
        bundle = build_export_bundle(export_data={"caps": []}, export_id="exp-1", exporter="system")
        self.assertIsNone(bundle["signature"])
        bundle = sign_export_bundle(bundle, signature="sig123", certificate="cert123")
        self.assertEqual(bundle["signature"], "sig123")
        valid, _ = verify_export_bundle(bundle)
        self.assertTrue(valid)

    def test_verify_unsigned_bundle(self) -> None:
        from capmesh.sigstore_signing import build_export_bundle, verify_export_bundle
        bundle = build_export_bundle(export_data={}, export_id="exp-1", exporter="system")
        valid, err = verify_export_bundle(bundle)
        self.assertFalse(valid)
        self.assertIn("not signed", err.lower())

    def test_signing_policy(self) -> None:
        from capmesh.sigstore_signing import build_sigstore_signing_policy
        policy = build_sigstore_signing_policy()
        self.assertTrue(policy["requireCertificate"])
        self.assertTrue(policy["requireRekorLog"])


class TestLocalEmbedding(unittest.TestCase):
    def test_get_embedding_config(self) -> None:
        from capmesh.local_embedding import get_embedding_config
        config = get_embedding_config("bge-m3")
        self.assertEqual(config["model"], "BAAI/bge-m3")
        self.assertEqual(config["dims"], 1024)
        config = get_embedding_config()
        self.assertEqual(config["model"], "all-MiniLM-L6-v2")

    def test_is_model_available(self) -> None:
        from capmesh.local_embedding import is_model_available
        # Should return False when sentence-transformers is not installed
        result = is_model_available("all-MiniLM-L6-v2")
        self.assertIsInstance(result, bool)

    def test_build_embedding_config_for_environment(self) -> None:
        from capmesh.local_embedding import build_embedding_config_for_environment
        config = build_embedding_config_for_environment()
        self.assertIn("provider", config)
        self.assertIn("model", config)


class TestMCPSDKWrapper(unittest.TestCase):
    def test_to_sdk_name(self) -> None:
        from capmesh.mcp_sdk_wrapper import to_sdk_name
        self.assertEqual(to_sdk_name("cap.search"), "cap_search")
        self.assertEqual(to_sdk_name("cap.load"), "cap_load")

    def test_to_dotted_name(self) -> None:
        from capmesh.mcp_sdk_wrapper import to_dotted_name
        self.assertEqual(to_dotted_name("cap_search"), "cap.search")
        self.assertEqual(to_dotted_name("cap_load"), "cap.load")

    def test_initialize_response(self) -> None:
        from capmesh.mcp_sdk_wrapper import build_initialize_response
        resp = build_initialize_response()
        self.assertIn("protocolVersion", resp)
        self.assertIn("serverInfo", resp)
        self.assertEqual(resp["serverInfo"]["name"], "capmesh")

    def test_tools_list(self) -> None:
        from capmesh.mcp_sdk_wrapper import build_tools_list
        tools = build_tools_list()
        self.assertGreater(len(tools), 0)
        # All tool names should be SDK-compatible (no dots)
        for tool in tools:
            self.assertNotIn(".", tool["name"])

    def test_is_sdk_available(self) -> None:
        from capmesh.mcp_sdk_wrapper import is_sdk_available
        result = is_sdk_available()
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
