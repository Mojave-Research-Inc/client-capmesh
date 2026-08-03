"""CM-13-full request-span slice: one OTel "request" span per HTTP dispatch.

``capmesh/tracing.py`` (already landed + green) exports ``Tracer``, ``Span``,
``SpanContext``, ``format_traceparent`` and ``parse_traceparent``.
``capmesh/lifecycle.py`` has a module-level ``TRACER`` for gate.eval spans; this
slice does NOT touch lifecycle.py.

This slice wires the HTTP request path:

* ``capmesh/router.py`` -- a module-level ``REQUEST_TRACER`` mints one
  ``request`` span per ``CapabilityRouter.call`` dispatch. An inbound W3C
  traceparent (threaded from ``server.py``) is parsed and used as the parent
  context so the request span is a child of the inbound trace; otherwise the
  Tracer synthesizes a fresh trace_id. The span carries ``verb``/``subject``/
  ``tenant``/``tool``/``request_id`` attributes and is ended when the dispatch
  returns. Best-effort only: a tracing failure never breaks the dispatch.
* ``capmesh/server.py`` -- ``do_GET``/``do_POST`` read the inbound
  ``traceparent`` header, thread it into ``router.call``, and echo a
  ``traceparent`` header on the response so downstream callers continue the
  trace.

These tests pin the wiring contract: a span is emitted per dispatch, the
inbound traceparent is used as the parent (trace_id reused, span_id fresh),
a fresh trace is synthesized when none is supplied, the server echoes a
traceparent, and a tracing failure never breaks a request. They exercise the
router in-process (deterministic span introspection) and the server over a
subprocess (real HTTP transport header read/echo).
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


def _valid_traceparent(trace_id: str, span_id: str) -> str:
    """Build a well-formed W3C traceparent string from hex ids."""
    return f"00-{trace_id}-{span_id}-01"


class RouterRequestSpanTests(unittest.TestCase):
    """In-process assertions on ``REQUEST_TRACER`` span emission per dispatch.

    These drive ``CapabilityRouter.call`` directly against a tiny real index so
    the dispatch completes and the span is recorded. The module-level
    ``REQUEST_TRACER`` is patched onto ``capmesh.router`` for isolation so the
    shared tracer does not accumulate spans across tests.
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
        # Patch the module-level REQUEST_TRACER with a fresh Tracer so each test
        # observes only its own spans (the real one is shared and would leak).
        from capmesh.tracing import Tracer

        self.tracer = Tracer()
        self._patch = patch("capmesh.router.REQUEST_TRACER", self.tracer)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def restore_state_dir(self) -> None:
        if self.previous_state_dir is None:
            os.environ.pop("CAPMESH_STATE_DIR", None)
        else:
            os.environ["CAPMESH_STATE_DIR"] = self.previous_state_dir

    def test_router_call_emits_request_span(self) -> None:
        """A ``cap.search`` dispatch records one ended span named ``request``.

        The span carries the ``verb``/``subject``/``tenant``/``tool``/
        ``request_id`` attributes set on the dispatch path, and the dispatch
        result is unchanged.
        """
        result = self.router.call(
            "cap.search",
            {"query": "executive brief", "type": "skill"},
            request_id="req-span-123",
        )
        self.assertFalse(result.get("isError"), "dispatch must succeed for this fixture")
        spans = self.tracer.ended_spans()
        self.assertGreaterEqual(len(spans), 1, "at least one request span must be ended")
        request_spans = [s for s in spans if s.name == "request"]
        self.assertEqual(len(request_spans), 1, "exactly one 'request' span expected")
        span = request_spans[0]
        attrs = span.attributes
        self.assertEqual(attrs.get("verb"), "search")
        self.assertEqual(attrs.get("tool"), "cap.search")
        self.assertEqual(attrs.get("request_id"), "req-span-123")
        self.assertIn("subject", attrs)
        self.assertTrue(attrs.get("subject"))
        self.assertIn("tenant", attrs)
        self.assertTrue(attrs.get("tenant"))

    def test_inbound_traceparent_used_as_parent(self) -> None:
        """An inbound traceparent is reused as the parent: trace_id matches, span_id is fresh."""
        inbound_trace_id = "a" * 32
        inbound_span_id = "b" * 16
        tp = _valid_traceparent(inbound_trace_id, inbound_span_id)
        result = self.router.call(
            "cap.search",
            {"query": "executive brief", "type": "skill"},
            request_id="req-parent-1",
            traceparent=tp,
        )
        self.assertFalse(result.get("isError"))
        spans = [s for s in self.tracer.ended_spans() if s.name == "request"]
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.context.trace_id, inbound_trace_id, "trace_id must be reused from the inbound parent")
        self.assertEqual(span.parent_span_id, inbound_span_id, "parent_span_id must be the inbound span_id")
        self.assertNotEqual(span.context.span_id, inbound_span_id, "span_id must be fresh, not the inbound one")
        self.assertEqual(span.context.trace_flags, "01")

    def test_no_inbound_traceparent_synthesizes_trace(self) -> None:
        """No inbound traceparent -> the request span has a fresh non-zero 32-hex trace_id."""
        result = self.router.call(
            "cap.search",
            {"query": "executive brief", "type": "skill"},
            request_id="req-synth-1",
        )
        self.assertFalse(result.get("isError"))
        spans = [s for s in self.tracer.ended_spans() if s.name == "request"]
        self.assertEqual(len(spans), 1)
        span = spans[0]
        trace_id = span.context.trace_id
        self.assertTrue(trace_id, "trace_id must be non-empty")
        self.assertNotEqual(trace_id, "0" * 32, "trace_id must not be all zeros")
        self.assertEqual(len(trace_id), 32, "trace_id must be 32 hex chars")
        self.assertTrue(all(c in "0123456789abcdef" for c in trace_id), "trace_id must be lowercase hex")
        self.assertIsNone(span.parent_span_id, "a synthesized root span has no parent")

    def test_request_span_failure_does_not_break_request(self) -> None:
        """If ``REQUEST_TRACER.start_span`` raises, the dispatch still completes.

        The tracing path is best-effort; a tracer failure must never propagate
        to the caller or change the dispatch result.
        """
        from capmesh.tracing import Tracer

        broken = Tracer()
        broken.start_span = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("tracer down"))  # type: ignore[method-assign]
        with patch("capmesh.router.REQUEST_TRACER", broken):
            result = self.router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-broken-1",
            )
        self.assertFalse(result.get("isError"), "dispatch must still succeed when start_span raises")
        self.assertIn("results", result.get("structuredContent", {}))


class ServerTraceparentEchoTests(unittest.TestCase):
    """Drive a real subprocess server and assert the ``traceparent`` echo.

    ``serve_http`` installs signal handlers (main-thread only), so the server
    runs as a subprocess mirroring tests/test_server_request_id_thread.py. The
    subprocess cannot be introspected for spans; we assert the observable HTTP
    contract: the response carries a ``traceparent`` header, and an inbound
    traceparent is echoed back (continuing the trace).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins_root = _make_plugin(cls.root)
        cls.db = Path(cls.tmp.name) / "mesh.db"
        rebuild_index(cls.db, [cls.plugins_root], enable_vector=False)
        cls.service_token = "test-service-bearer-span"
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
    def _get(cls, path: str, *, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
        request = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read().decode("utf-8", errors="replace")
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, dict(exc.headers), body

    def test_server_echoes_traceparent(self) -> None:
        """An inbound traceparent on /health/live is echoed on the response."""
        inbound_trace_id = "c" * 32
        inbound_span_id = "d" * 16
        tp = _valid_traceparent(inbound_trace_id, inbound_span_id)
        status, headers, _body = self._get("/health/live", headers={"traceparent": tp})
        self.assertEqual(status, 200, "/health/live must remain 200")
        echoed = headers.get("traceparent")
        self.assertIsNotNone(echoed, "response must carry a traceparent header")
        self.assertTrue(echoed is not None)
        # The echoed traceparent must round-trip and reuse the inbound trace_id.
        from capmesh.tracing import parse_traceparent

        ctx = parse_traceparent(echoed)
        self.assertIsNotNone(ctx, "echoed traceparent must be well-formed")
        assert ctx is not None
        self.assertEqual(ctx.trace_id, inbound_trace_id, "echoed trace_id must match the inbound trace_id")

    def test_server_synthesizes_traceparent_when_absent(self) -> None:
        """No inbound traceparent -> the response still carries a fresh traceparent."""
        status, headers, _body = self._get("/health/live", headers={})
        self.assertEqual(status, 200)
        echoed = headers.get("traceparent")
        self.assertIsNotNone(echoed, "response must carry a traceparent even with no inbound header")
        from capmesh.tracing import parse_traceparent

        ctx = parse_traceparent(echoed)  # type: ignore[arg-type]
        self.assertIsNotNone(ctx, "synthesized traceparent must be well-formed")
        assert ctx is not None
        self.assertEqual(len(ctx.trace_id), 32)

    def test_traceparent_roundtrip_via_server(self) -> None:
        """A full inbound traceparent is echoed and the router span is its child.

        Drives /cap/search with an inbound traceparent (service-bearer authorized)
        and asserts the response echoes a traceparent carrying the same trace_id.
        The router-side span introspection is covered by the in-process tests
        above; here we assert the wire-level round-trip (inbound -> echoed) and
        that the request still returns its normal 200 result.
        """
        inbound_trace_id = "e" * 32
        inbound_span_id = "f" * 16
        tp = _valid_traceparent(inbound_trace_id, inbound_span_id)
        status, headers, _body = self._get(
            "/cap/search?q=brief&type=skill",
            headers={"Authorization": f"Bearer {self.service_token}", "traceparent": tp},
        )
        self.assertEqual(status, 200, f"/cap/search returned {status}")
        echoed = headers.get("traceparent")
        self.assertIsNotNone(echoed)
        from capmesh.tracing import parse_traceparent

        ctx = parse_traceparent(echoed)  # type: ignore[arg-type]
        self.assertIsNotNone(ctx)
        assert ctx is not None
        self.assertEqual(ctx.trace_id, inbound_trace_id, "echoed trace_id must match the inbound trace_id")

    def test_metrics_and_health_unaffected_by_traceparent_echo(self) -> None:
        """/metrics and /health/live continue to work with the traceparent echo wired."""
        m_status, _m_headers, _m_body = self._get("/metrics", headers={"traceparent": _valid_traceparent("1" * 32, "2" * 16)})
        self.assertEqual(m_status, 200, f"/metrics returned {m_status}")
        live_status, _h_headers, _h_body = self._get("/health/live")
        self.assertEqual(live_status, 200, f"/health/live returned {live_status}")


class HandleJsonrpcTraceparentThreadTests(unittest.TestCase):
    """In-process: ``handle_jsonrpc(traceparent=...)`` threads into the router span."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.previous_state_dir = os.environ.get("CAPMESH_STATE_DIR")
        self.addCleanup(lambda: os.environ.pop("CAPMESH_STATE_DIR", None) if self.previous_state_dir is None else os.environ.__setitem__("CAPMESH_STATE_DIR", self.previous_state_dir))
        os.environ["CAPMESH_STATE_DIR"] = str(self.root / "state")
        self.plugins_root = _make_plugin(self.root)
        self.db = self.root / "mesh.db"
        rebuild_index(self.db, [self.plugins_root], enable_vector=False)
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)
        self.router = CapabilityRouter(self.con, roots=(str(self.plugins_root),))
        from capmesh.tracing import Tracer

        self.tracer = Tracer()
        self._patch = patch("capmesh.router.REQUEST_TRACER", self.tracer)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.addCleanup(self.con.close)
        self.search_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "cap.search", "arguments": {"query": "executive brief", "type": "skill"}},
        }

    def test_handle_jsonrpc_threads_traceparent_into_span(self) -> None:
        """handle_jsonrpc(traceparent=...) flows into the router request span as parent."""
        inbound_trace_id = "9" * 32
        inbound_span_id = "8" * 16
        tp = _valid_traceparent(inbound_trace_id, inbound_span_id)
        response = handle_jsonrpc(self.router, self.search_request, http_request_id="req-tp-1", traceparent=tp)
        self.assertFalse(response["result"].get("isError"))
        spans = [s for s in self.tracer.ended_spans() if s.name == "request"]
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.context.trace_id, inbound_trace_id)
        self.assertEqual(span.parent_span_id, inbound_span_id)
        self.assertEqual(span.attributes.get("request_id"), "req-tp-1")


if __name__ == "__main__":
    unittest.main()
