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

# ``system.roles`` is a high-risk, mutating system capability (governance.py:1091
# lists it among the mutating system capabilities). Its ``list`` action routes to
# ``list_roles`` -> ``require_admin_or_audit`` which raises ``PermissionError`` for
# any non-admin principal (governance.py:2607-2604). A bare tailnet identity is a
# least-privilege ``member`` (server.py principal_from_tailscale_identity), so a
# real mutation can never complete via this capability for that caller. We use it
# as the canonical "mutating system capability" for the regression below.
SYSTEM_ROLES_URI = "cap://system/asg/roles@0.1.0"


class McpMutationBlockedTests(unittest.TestCase):
    """R4-06: a bare tailnet identity cannot mutate via POST /mcp tools/call.

    R1-03 (R3) routed POST /mcp through the read-only ``authorized()`` gate
    instead of the mutating gate, so read-only tools/call (cap.search/load/
    list/describe) succeed for a tailnet caller in production. The safety
    property under test is that a bare tailnet identity (no service token)
    CANNOT execute a mutation through ``/mcp tools/call cap.call`` — the
    enforcement lives inside ``CapabilityRouter.cap_call`` (router.py:1284-1337
    require_scope + dryRun + dispatch guards), NOT at the transport gate.

    This regression asserts the invariant as enforced: a mutating ``cap.call``
    from a bare tailnet identity NEVER produces an executed mutation — the
    result is either a transport-level rejection (401/403) or an
    application-level ``isError`` result whose code is a scope/forbidden/
    confirmation/authoritative denial, or a dryRun-only safe result. The same
    caller's read-only ``cap.search`` must succeed (200), proving the magic
    install read path still works for a tailnet identity.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "mesh.db"
        cls.service_token = "r406-test-service-bearer"
        cls.proxy_token = "r406-test-proxy-bearer"
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    def _mcp_post(
        cls,
        body: dict[str, object],
        headers: dict[str, str],
    ) -> tuple[int, dict[str, object] | bytes]:
        """POST a JSON-RPC envelope to /mcp and return (status, parsed_body).

        On a non-JSON transport rejection (e.g. 401 with a JSON error body) the
        body is still parsed; an unparseable body is returned raw so the caller
        can inspect it. Defaults to the headers a native MCP client sends.
        """
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}/mcp",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-11-25",
                **headers,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                try:
                    return resp.status, json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return exc.code, raw

    def _tailnet_identity_headers(self) -> dict[str, str]:
        """Proxy-authenticated tailnet identity with NO service bearer.

        Mirrors the test_http_service_auth.py / test_mutating_route_service_token.py
        pattern: X-Capmesh-Proxy-Token authenticates the loopback proxy hop and
        Tailscale-User-Login resolves (server.py principal_from_tailscale_identity)
        to a least-privilege ``member`` principal with
        (cap:search, cap:load, cap:call, cap:delegate, cap:report). Crucially no
        ``Authorization: Bearer <service_token>`` is included, so the dual-auth
        mutating-route gate (if reached) would reject the mutation.
        """
        return {
            "X-Capmesh-Proxy-Token": self.proxy_token,
            "Tailscale-User-Login": "tailnet-member@example.com",
            "Tailscale-User-Name": "Tailnet Member",
        }

    @staticmethod
    def _envelope(msg_id: int, name: str, arguments: dict[str, object]) -> dict[str, object]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_bare_tailnet_identity_cannot_mutate_via_mcp_cap_call(self) -> None:
        """A bare tailnet identity POSTing a mutating cap.call is never executed.

        ``system.roles`` is a mutating system capability. Calling it with
        ``dryRun=False`` and ``confirm=True`` from a bare tailnet identity must
        NEVER produce an executed mutation. The result is either:

          * a transport-level rejection (401 UNAUTHORIZED / 403 FORBIDDEN), or
          * an application-level JSON-RPC ``result`` with ``isError=True`` and
            an error code in {INSUFFICIENT_SCOPE, FORBIDDEN, CONFIRMATION_REQUIRED,
            NOT_AUTHORITATIVE}, or
          * a dryRun-only safe result (``isError=False`` but ``dryRun=True``).

        This accepts all three so the regression pins the safety invariant
        rather than the specific gate that enforces it (R1-03 keeps the
        enforcement inside cap_call, not at the transport gate).
        """
        headers = self._tailnet_identity_headers()
        body = self._envelope(
            1,
            "cap.call",
            {
                "uri": SYSTEM_ROLES_URI,
                "dryRun": False,
                "confirm": True,
                "args": {"action": "list"},
            },
        )
        status, payload = self._mcp_post(body, headers)

        # The mutation must NEVER execute. Capture every observable outcome and
        # assert against the union of safe results, so a future source change
        # that moves the gate (transport -> cap_call or vice versa) cannot
        # silently let a mutation through.
        self.assertIsInstance(payload, dict, f"unexpected non-JSON body: {payload!r}")

        transport_rejected = status in {401, 403} and "error" in payload
        if transport_rejected:
            # Transport gate (mutating_route_authorized or authorized) rejected
            # before cap_call ran. No mutation could execute.
            self.assertIn(payload["error"].get("code"), {"UNAUTHORIZED", "FORBIDDEN"})
            return

        # Application-level response: handle_jsonrpc returns {"jsonrpc", "id",
        # "result": <router.call result>} with HTTP 200. The result itself is an
        # ok_result/error dict carrying isError + structuredContent.
        self.assertEqual(status, 200, f"unexpected status {status}: {payload!r}")
        self.assertIn("result", payload, f"expected JSON-RPC result envelope: {payload!r}")
        result = payload["result"]
        self.assertIsInstance(result, dict)

        if result.get("isError"):
            structured = result.get("structuredContent")
            error_payload = structured.get("error") if isinstance(structured, dict) else None
            self.assertIsInstance(
                error_payload, dict, f"isError result without structured error: {result!r}"
            )
            code = str(error_payload.get("code") or "")
            self.assertIn(
                code,
                {"INSUFFICIENT_SCOPE", "FORBIDDEN", "CONFIRMATION_REQUIRED", "NOT_AUTHORITATIVE"},
                f"mutating cap.call returned an unexpected error code: {code} ({result!r})",
            )
            return

        # A non-error result must be a dryRun-only safe result ("execution
        # skipped"), never an executed mutation. The structuredContent must
        # announce dryRun=True and must NOT carry the live role assignments.
        structured = result.get("structuredContent")
        self.assertIsInstance(structured, dict, f"unexpected ok result shape: {result!r}")
        self.assertTrue(
            structured.get("dryRun") is True,
            f"non-error cap.call result was not dryRun-only: {structured!r}",
        )
        # Executed mutations return role assignment rows under structuredContent
        # data; a dryRun-only safe result must not surface them.
        serialized = json.dumps(structured)
        self.assertNotIn(
            "subjectId", serialized, f"dryRun result leaked executed role data: {structured!r}"
        )

    def test_same_caller_cap_search_succeeds_read_only(self) -> None:
        """The same bare tailnet identity POSTing cap.search succeeds (200, read-only).

        This proves the magic install read path still works for a tailnet
        identity: R1-03 routed /mcp read-only tools (cap.search/load/list/
        describe) through the read-only ``authorized()`` gate, so a bare
        tailnet identity can discover capabilities even though it cannot mutate.
        """
        headers = self._tailnet_identity_headers()
        body = self._envelope(2, "cap.search", {"query": "roles"})
        status, payload = self._mcp_post(body, headers)

        self.assertIsInstance(payload, dict, f"unexpected non-JSON body: {payload!r}")
        self.assertEqual(status, 200, f"cap.search must succeed, got {status}: {payload!r}")
        self.assertIn("result", payload, f"expected JSON-RPC result envelope: {payload!r}")
        result = payload["result"]
        self.assertIsInstance(result, dict)
        self.assertFalse(
            result.get("isError", True),
            f"read-only cap.search must not be an error for a tailnet identity: {result!r}",
        )
        structured = result.get("structuredContent")
        self.assertIsInstance(structured, dict)
        # cap.search returns the query it ran plus a (possibly empty) results
        # array; the key invariant is that the read path returned structured
        # discovery data, not a denial.
        self.assertIn("query", structured, f"cap.search missing query echo: {structured!r}")


if __name__ == "__main__":
    unittest.main()
