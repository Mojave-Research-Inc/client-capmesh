"""CM-13 server-half slice: thread the HTTP X-Request-Id header into router.call.

The router.py slice (CM-13) already landed: ``CapabilityRouter.call`` accepts a
keyword-only ``request_id: str | None`` and emits one structured log line
carrying it. server.py reads ``X-Request-Id`` (falling back to
``X-Correlation-Id``) but the three ``router.call`` sites did not pass it, so
the router log got a generated uuid instead of the real HTTP request-id.

This slice threads the header value into those call sites via a tiny
``_http_request_id`` helper on the Handler and a new keyword-only
``http_request_id`` param on ``handle_jsonrpc`` (named to avoid collision with
the JSON-RPC message id local ``request_id``).

These tests assert the threading contract (header -> router.call request_id ->
structured log) and that dispatch results are unchanged. They do NOT touch
router.py, governance.py, index.py, lifecycle.py, or cli.py.
"""

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

from capmesh.index import connect, init_db, rebuild_index
from capmesh.router import CapabilityRouter
from capmesh.server import handle_jsonrpc


def _make_plugin(root: Path) -> Path:
    """Create a minimal plugin with one skill so cap.search returns a result."""
    plugin = root / "plugins" / "demo-plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / "skills" / "write-brief").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo-plugin", "version": "1.2.3", "description": "Demo plugin."}),
        encoding="utf-8",
    )
    (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
        "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n"
        "# Write Brief\nUse for executive summaries.\n",
        encoding="utf-8",
    )
    return root / "plugins"


class HandleJsonrpcRequestIdThreadTests(unittest.TestCase):
    """The ``http_request_id`` kwarg on ``handle_jsonrpc`` flows into router.call.

    These cover the JSON-RPC / /mcp POST call site (handle_jsonrpc -> router.call).
    The /cap/search and /tools/call sites use the same ``request_id=`` kwarg on
    router.call and the same ``_http_request_id`` helper; the
    ``RequestIdHttpHeaderTests`` class below exercises the real HTTP transport
    header read that feeds all three sites.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(self.restore_state_dir)
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        self.plugins_root = _make_plugin(self.root)
        self.db = self.root / "mesh.db"
        rebuild_index(self.db, [self.plugins_root], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        self.router = CapabilityRouter(self.con, roots=(str(self.plugins_root),))
        self.search_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "cap.search", "arguments": {"query": "executive brief", "type": "skill"}},
        }

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    def test_router_call_receives_header_request_id(self) -> None:
        """handle_jsonrpc(http_request_id=...) threads the value into the router log."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            handle_jsonrpc(self.router, self.search_request, http_request_id="req-from-header-123")
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].request_id, "req-from-header-123")

    def test_router_call_generates_id_when_no_header(self) -> None:
        """No http_request_id -> router.call gets None -> log carries a generated uuid."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            handle_jsonrpc(self.router, self.search_request)
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1)
        rid = matching[0].request_id
        self.assertIsInstance(rid, str)
        self.assertGreater(len(rid), 0, "router must generate a non-empty id when no header is supplied")
        self.assertNotEqual(rid, "req-from-header-123")

    def test_empty_string_header_treated_as_generated(self) -> None:
        """Empty-string http_request_id is falsy; the router generates a fresh uuid."""
        with self.assertLogs("capMesh.router", level="INFO") as caplog:
            handle_jsonrpc(self.router, self.search_request, http_request_id="")
        matching = [r for r in caplog.records if r.message == "cap.search"]
        self.assertEqual(len(matching), 1)
        self.assertGreater(len(matching[0].request_id), 0)
        self.assertNotEqual(matching[0].request_id, "")

    def test_dispatch_result_unchanged(self) -> None:
        """Threading the request-id is additive: dispatch results are identical."""
        with self.assertLogs("capMesh.router", level="INFO"):
            result_with = handle_jsonrpc(self.router, self.search_request, http_request_id="req-xyz")
            result_without = handle_jsonrpc(self.router, self.search_request)
        # The router result (structuredContent) is identical regardless of
        # request_id; only the log observability changes.
        self.assertEqual(result_with, result_without)
        self.assertFalse(result_with["result"]["isError"])
        self.assertIn("results", result_with["result"]["structuredContent"])

    def test_jsonrpc_id_not_affected_by_request_id_threading(self) -> None:
        """The JSON-RPC message id (request["id"]) is distinct from the HTTP request-id."""
        req = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "cap.search", "arguments": {"query": "executive brief", "type": "skill"}},
        }
        with self.assertLogs("capMesh.router", level="INFO"):
            response = handle_jsonrpc(self.router, req, http_request_id="req-http-99")
        self.assertEqual(response["id"], 42, "JSON-RPC message id must be preserved")


class RequestIdHttpHeaderTests(unittest.TestCase):
    """The HTTP transport reads X-Request-Id (then X-Correlation-Id) into the
    ``_http_request_id`` helper that feeds all three router.call sites.

    Because ``serve_http`` installs signal handlers (main-thread only), the
    server is run as a subprocess. The subprocess cannot be introspected with
    ``assertLogs``; instead we assert the observable contract: the response
    echoes the request-id via the same ``_http_request_id`` helper (the response
    ``X-Request-Id`` header is emitted by ``_send_common_headers`` using
    ``self.request_id()``, which now delegates to ``_http_request_id``). This
    proves the header-read order and the X-Correlation-Id fallback at the
    transport boundary that feeds the router.call kwarg.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins_root = _make_plugin(cls.root)
        cls.db = Path(cls.tmp.name) / "mesh.db"
        rebuild_index(cls.db, [cls.plugins_root], enable_vector=False)
        cls.service_token = "test-service-bearer-cm13"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = int(sock.getsockname()[1])
        env = {
            **os.environ,
            "CAPMESH_BEARER_TOKEN": cls.service_token,
            "CAPMESH_ENVIRONMENT": "production",
            "CAPMESH_NODE_ROLE": "authoritative",
            "CAPMESH_AUTHORITY_URL": "https://capmesh.example.com",
            "CAPMESH_ROOTS": str(cls.plugins_root),
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
            if cls.server.poll() is not None:
                stderr = cls.server.stderr.read() if cls.server.stderr else ""
                raise RuntimeError(f"test Capmesh server exited early: {stderr}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/health/live", timeout=0.5):
                    break
            except (OSError, urllib.error.URLError):
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

    @classmethod
    def _cap_search(cls, headers: dict[str, str]) -> tuple[int, dict[str, str], dict[str, object]]:
        url = f"http://127.0.0.1:{cls.port}/cap/search?q=brief&type=skill"
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {cls.service_token}", **headers})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = json.load(response)
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), json.load(exc)

    def test_x_request_id_header_echoed_in_response(self) -> None:
        """X-Request-Id header is read by _http_request_id and echoed on the response."""
        status, headers, _body = self._cap_search({"X-Request-Id": "req-header-abc123"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Request-Id"), "req-header-abc123")

    def test_x_correlation_id_fallback(self) -> None:
        """No X-Request-Id -> _http_request_id falls back to X-Correlation-Id."""
        status, headers, _body = self._cap_search({"X-Correlation-Id": "corr-987654"})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Request-Id"), "corr-987654")

    def test_no_header_yields_synthesized_nonempty_response_id(self) -> None:
        """No request-id headers -> the response still carries a non-empty synthesized id.

        The response-header id (request_id()) is distinct from the router's
        generated uuid, but both are non-empty when no header is supplied; this
        asserts the transport boundary does not produce an empty id.
        """
        status, headers, _body = self._cap_search({})
        self.assertEqual(status, 200)
        rid = headers.get("X-Request-Id")
        self.assertIsNotNone(rid)
        self.assertGreater(len(rid or ""), 0)


if __name__ == "__main__":
    unittest.main()
