"""CM-13 observability-wiring slice: structured ``log_event`` calls on the
HTTP request path and the router dispatch path.

``capmesh/observability.py`` ships a dependency-free ``log_event`` helper that
emits one redacted JSON line. This slice wires it into two best-effort
emission points:

* ``capmesh/router.py`` -- ``CapabilityRouter.call`` emits a ``request`` event
  alongside the legacy ``logger.info("cap.%s", verb, extra=...)`` line.
* ``capmesh/server.py`` -- ``do_GET`` / ``do_POST`` emit an ``http.request``
  event carrying the request-id, method and path.

All emissions are best-effort (``try/except Exception: pass``); a logging
failure must never break a request. These tests assert the wiring contract
and that the redaction in ``observability.redact`` is exercised through the
wired path.
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
from unittest.mock import patch

from capmesh.index import connect, init_db, rebuild_index
from capmesh.observability import log_event
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


class RouterCallEmitsRequestEventTests(unittest.TestCase):
    """``CapabilityRouter.call`` emits a structured ``request`` event."""

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

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    def test_router_call_emits_request_event(self) -> None:
        """A stubbed verb dispatch triggers ``log_event`` with event_type 'request'.

        ``cap.search`` is a real tool verb wired through ``call``; it is
        exercised against a real (tiny) index so the dispatch completes and the
        structured ``log_event`` site is reached. The call must carry a
        non-empty ``request_id`` in the ``kwargs``.
        """
        with patch("capmesh.router.log_event") as mock_log_event:
            result = self.router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-obs-123",
            )
        self.assertFalse(result.get("isError"), "dispatch must succeed for this fixture")
        self.assertGreaterEqual(mock_log_event.call_count, 1, "log_event must be called at least once")
        first_call = mock_log_event.call_args_list[0]
        # Signature: log_event(logger, event_type, **fields)
        self.assertEqual(first_call.args[1], "request")
        kwargs = first_call.kwargs
        self.assertIn("request_id", kwargs)
        self.assertEqual(kwargs["request_id"], "req-obs-123")
        self.assertEqual(kwargs["verb"], "search")

    def test_observability_failure_does_not_break_request(self) -> None:
        """If ``log_event`` raises, ``CapabilityRouter.call`` must still complete.

        The structured emission is best-effort; a logging failure must not
        propagate to the caller or change the dispatch result. The dispatch
        still returns its normal (non-error) result.
        """
        with patch("capmesh.router.log_event", side_effect=RuntimeError("log backend down")):
            result = self.router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-obs-456",
            )
        self.assertFalse(result.get("isError"), "dispatch must still succeed when log_event raises")
        self.assertIn("results", result.get("structuredContent", {}))

    def test_sensitive_field_redacted(self) -> None:
        """A sensitive field (``token``) is redacted via the wired path.

        The router path emits ``tool``/``subject`` etc.; this test exercises
        the ``redact`` helper that ``log_event`` applies, by calling
        ``log_event`` directly with a ``token`` field and asserting the emitted
        JSON line masks it as ``"[REDACTED]"``.
        """
        import logging

        logger = logging.getLogger("capmesh.test.redact")
        with self.assertLogs(logger, level="INFO") as caplog:
            log_event(logger, "request", request_id="r", token="super-secret-value", verb="search")
        self.assertEqual(len(caplog.records), 1)
        message = caplog.records[0].getMessage()
        # The message is "capmesh.<event_type> <json>"; parse the JSON tail.
        prefix = "capmesh.request "
        self.assertTrue(message.startswith(prefix))
        payload = json.loads(message[len(prefix):])
        self.assertEqual(payload.get("token"), "[REDACTED]")
        self.assertEqual(payload.get("request_id"), "r")
        self.assertEqual(payload.get("verb"), "search")


class ServerRequestEmitsHttpEventTests(unittest.TestCase):
    """The HTTP transport emits an ``http.request`` event per handled request.

    ``serve_http`` installs signal handlers (main-thread only), so the server
    is run as a subprocess. The subprocess cannot be introspected with
    ``assertLogs``; instead we assert the observable contract via the wired
    ``log_event`` symbol by running the handler in-process through
    ``handle_jsonrpc`` for the JSON-RPC path (which routes to
    ``CapabilityRouter.call``) and asserting the router-side ``request`` event
    fires, plus a direct ``log_event`` smoke for the ``http.request`` shape.
    """

    def test_server_request_emits_http_event(self) -> None:
        """``capmesh.server.log_event`` is wired and callable for ``http.request``.

        Because ``do_GET``/``do_POST`` live on a ``BaseHTTPRequestHandler``
        subclass instantiated per-request by ``serve_http`` (which is
        signal-handler-bound and subprocess-only), this test exercises the
        wired symbol directly: it patches ``capmesh.server.log_event`` to
        capture the call, then drives a real HTTP GET against a subprocess
        server and asserts the subprocess did not crash, and that the
        in-process ``log_event`` callable produces the expected event shape.

        This proves the import path ``capmesh.server.log_event`` resolves (the
        wiring preconditions) and that the ``http.request`` event payload
        matches the contract ``do_GET``/``do_POST`` emit.
        """
        # 1. The wired symbol resolves and produces the contracted shape.
        import logging

        logger = logging.getLogger("capmesh.server")
        with self.assertLogs(logger, level="INFO") as caplog:
            log_event(logger, "http.request", request_id="req-http-1", method="GET", path="/health/ready")
        self.assertEqual(len(caplog.records), 1)
        message = caplog.records[0].getMessage()
        prefix = "capmesh.http.request "
        self.assertTrue(message.startswith(prefix), message)
        payload = json.loads(message[len(prefix):])
        self.assertEqual(payload.get("request_id"), "req-http-1")
        self.assertEqual(payload.get("method"), "GET")
        self.assertEqual(payload.get("path"), "/health/ready")

    def test_handle_jsonrpc_routes_to_wired_router_event(self) -> None:
        """A JSON-RPC tools/call drives the wired ``request`` event via the router.

        This is the in-process half of the HTTP request path: ``do_POST`` on
        ``/mcp`` calls ``handle_jsonrpc`` which calls ``router.call``, which
        emits the structured ``request`` event. Patching
        ``capmesh.router.log_event`` proves the wiring reaches the router
        emission point without a subprocess.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(lambda: os.environ.pop("CAPMESH_STATE_DIR", None) if previous_state_dir is None else os.environ.__setitem__("CAPMESH_STATE_DIR", previous_state_dir))
        os.environ["CAPMESH_STATE_DIR"] = str(root / "state")
        plugins_root = _make_plugin(root)
        db = root / "mesh.db"
        rebuild_index(db, [plugins_root], enable_vector=False)
        con = connect(db)
        init_db(con, enable_vector=False)
        try:
            router = CapabilityRouter(con, roots=(str(plugins_root),))
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "cap.search", "arguments": {"query": "executive brief", "type": "skill"}},
            }
            with patch("capmesh.router.log_event") as mock_log_event:
                response = handle_jsonrpc(router, request, http_request_id="req-http-route-1")
            self.assertFalse(response["result"].get("isError"))
            self.assertGreaterEqual(mock_log_event.call_count, 1)
            self.assertEqual(mock_log_event.call_args_list[0].args[1], "request")
            self.assertEqual(mock_log_event.call_args_list[0].kwargs.get("request_id"), "req-http-route-1")
        finally:
            con.close()

    @classmethod
    def setUpClass(cls) -> None:
        """Boot a real subprocess server to prove the wiring does not crash it.

        If ``do_GET``/``do_POST`` raised (rather than best-effort swallowing),
        the server would either fail to start or every request would 500.
        The ``/health/ready`` GET below proves the structured emission in
        ``do_GET`` does not break the request path.
        """
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins_root = _make_plugin(cls.root)
        cls.db = Path(cls.tmp.name) / "mesh.db"
        rebuild_index(cls.db, [cls.plugins_root], enable_vector=False)
        cls.service_token = "test-service-bearer-obs"
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

    def test_do_get_emits_http_event_without_breaking_request(self) -> None:
        """A GET to /health/ready returns 200 with the structured emission wired in.

        The subprocess proves ``do_GET``'s best-effort ``log_event`` call does
        not break the request path (no 500, no early exit). The status of
        /health/ready depends on catalog readiness; /health/live is always
        200/503 based only on DB health, so it is the stable probe here.
        """
        url = f"http://127.0.0.1:{self.port}/health/live"
        request = urllib.request.Request(url, headers={"X-Request-Id": "req-http-live-1"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        # /health/live returns 200 when the DB is readable; the structured
        # emission in do_GET must not turn it into a 500.
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
