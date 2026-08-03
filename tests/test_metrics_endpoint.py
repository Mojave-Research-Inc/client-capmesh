"""CM-13 metrics-endpoint slice: GET /metrics serves Prometheus text exposition.

``capmesh/metrics_export.py`` (already landed + green) exports
``render_prometheus(registry) -> str`` and ``sanitize_metric_name``.
``capmesh/lifecycle.py`` exposes the module-level ``GATE_METRICS`` registry.
``capmesh/server.py`` wires a public ``GET /metrics`` route that renders
``GATE_METRICS`` to Prometheus text exposition. These tests pin the HTTP
contract: 200 status, ``text/plain; version=0.0.4`` Content-Type, public (no
service token), counter exposition after a gate eval, a best-effort 500 on
render failure, and that /metrics does not shadow sibling routes.

The server is exercised both as a subprocess (the real HTTP transport, since
``serve_http`` installs signal handlers and is main-thread only) and in-process
for the deterministic counter-increment and render-failure cases (patchable
module symbols). ONLY edits ``capmesh/server.py`` and this test file.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def _make_plugin(root: Path) -> Path:
    """Create a minimal plugin with one skill so the catalog is non-empty."""
    import json

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


class MetricsEndpointSubprocessTests(unittest.TestCase):
    """Drive GET /metrics against a real subprocess Capmesh server.

    ``serve_http`` installs signal handlers (main-thread only), so the server
    runs as a subprocess mirroring tests/test_server_request_id_thread.py and
    tests/test_http_service_auth.py. A service bearer is configured so the
    mutating-route gate is armed; /metrics must still be reachable without it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins_root = _make_plugin(cls.root)
        cls.db = Path(cls.tmp.name) / "mesh.db"
        from capmesh.index import rebuild_index

        rebuild_index(cls.db, [cls.plugins_root], enable_vector=False)
        cls.service_token = "metrics-service-bearer"
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
    def _get_metrics(cls, *, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
        request = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}/metrics",
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read().decode("utf-8", errors="replace")
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, dict(exc.headers), body

    @classmethod
    def _get_health(cls, path: str) -> int:
        request = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_metrics_endpoint_returns_prometheus_text(self) -> None:
        """GET /metrics -> 200 with text/plain; version=0.0.4 Content-Type."""
        status, headers, body = self._get_metrics()
        self.assertEqual(status, 200, f"/metrics returned {status}: {body!r}")
        content_type = headers.get("Content-Type") or ""
        self.assertTrue(
            content_type.startswith("text/plain; version=0.0.4"),
            f"unexpected Content-Type: {content_type!r}",
        )
        # Content-Length must match the body length (server sets it explicitly).
        length_header = headers.get("Content-Length")
        if length_header is not None:
            self.assertEqual(int(length_header), len(body.encode("utf-8")))
        # An empty registry renders "" (no counters yet); an exercised registry
        # carries # HELP / # TYPE / sample lines. Either is valid here.
        if body != "":
            self.assertIn("# HELP capmesh_", body)
            self.assertIn("# TYPE capmesh_ counter", body)

    def test_metrics_endpoint_no_auth_required(self) -> None:
        """/metrics is a public scrape endpoint: 200 with NO service token.

        A Prometheus scraper sends no service token / X-Capmesh-Proxy-Token.
        The endpoint is a read-only GET exempt from service-token auth and
        from the mutating-route gate. Contrast: a mutating route would 401/403
        without the service token (not exercised here -- we only assert /metrics
        is reachable unauthenticated).
        """
        status, _headers, body = self._get_metrics()
        self.assertEqual(status, 200, f"unauthenticated /metrics returned {status}: {body!r}")
        # A 200 with no Authorization header proves the endpoint is not gated.
        # If it were auth-gated it would return 401 (write_unauthorized).
        self.assertNotIn("UNAUTHORIZED", body)

    def test_metrics_endpoint_does_not_break_other_routes(self) -> None:
        """/metrics did not shadow /health/live; it still returns its normal 200."""
        # /metrics first (the route under test).
        m_status, _m_headers, _m_body = self._get_metrics()
        self.assertEqual(m_status, 200)
        # /health/live is always 200/503 based only on DB health; the test DB is
        # readable so it must be 200, and /metrics must not have shadowed it.
        live_status = self._get_health("/health/live")
        self.assertEqual(live_status, 200, f"/health/live returned {live_status} after /metrics")
        # Re-probe /metrics to confirm it is still reachable after /health.
        m2_status, _m2_headers, _m2_body = self._get_metrics()
        self.assertEqual(m2_status, 200)


class MetricsEndpointInProcessTests(unittest.TestCase):
    """Deterministic, in-process assertions on the /metrics rendering path.

    These drive the module-level ``render_metrics_endpoint`` helper and the
    shared ``GATE_METRICS`` registry directly so the counter-increment and
    render-failure cases are deterministic (no subprocess sharing / timing).
    """

    def test_metrics_endpoint_increments_after_gate_eval(self) -> None:
        """After ``GATE_METRICS.increment``, /metrics renders the sanitized counter.

        Uses ``GATE_METRICS.increment`` directly for determinism. The dotted
        counter name is sanitized to a Prometheus metric name (dots -> underscores,
        ``capmesh_`` prefix), and the rendered block carries a ``# TYPE ... counter``
        line and a sample line ``capmesh_test_gate_passed 1``.
        """
        import capmesh.server as server_mod

        # Use a unique counter name per test run so the snapshot is deterministic
        # and does not collide with counters incremented by other tests on the
        # shared module-level registry.
        suffix = uuid.uuid4().hex[:8]
        counter_name = f"test.gate.passed.{suffix}"
        expected_metric = f"capmesh_test_gate_passed_{suffix}"
        server_mod.GATE_METRICS.increment(counter_name)
        body, status = server_mod.render_metrics_endpoint()
        self.assertEqual(status, 200)
        self.assertIn(f"# HELP {expected_metric} capmesh counter", body)
        self.assertIn(f"# TYPE {expected_metric} counter", body)
        self.assertIn(f"{expected_metric} 1", body)
        # The rendered body ends with a single trailing newline.
        self.assertTrue(body.endswith("\n"))

    def test_metrics_endpoint_failure_returns_500(self) -> None:
        """When ``render_prometheus`` raises, /metrics returns 500 with a text body.

        Patches ``capmesh.server.render_prometheus`` to raise ``RuntimeError``
        and calls the module-level ``render_metrics_endpoint`` helper, which
        wraps the render call in a best-effort try/except. The helper must NOT
        propagate the exception (the server must never crash) and must return a
        ``(body, 500)`` pair with a non-empty minimal text body. This is the
        exact contract the ``do_GET`` /metrics route passes to
        ``write_text(body, status=status, ...)`` so the wire response is 500.
        """
        from unittest.mock import patch

        import capmesh.server as server_mod

        with patch("capmesh.server.render_prometheus", side_effect=RuntimeError("boom")):
            body, status = server_mod.render_metrics_endpoint()
        self.assertEqual(status, 500, f"expected 500 on render failure, got {status}: {body!r}")
        self.assertGreater(len(body), 0, "failure body must be non-empty text")
        self.assertIsInstance(body, str)

        # Sanity: without the patch the helper renders a normal (200) string,
        # proving the patch only affected the failure path above and the module
        # is left in a working state.
        ok_body, ok_status = server_mod.render_metrics_endpoint()
        self.assertEqual(ok_status, 200)
        self.assertIsInstance(ok_body, str)


class MetricsEndpointRenderFailureWireTests(unittest.TestCase):
    """Observe the 500 over the real wire when ``render_prometheus`` raises.

    Boots a subprocess server via a ``-c`` wrapper that patches
    ``capmesh.server.render_prometheus`` to raise before importing the CLI (no
    sitecustomize / PYTHONPATH prepend, so the subprocess import path is
    untouched). Asserts GET /metrics returns 500 with a non-empty text body and
    that the server does not crash (``/health/live`` is still 200 afterwards).
    """

    def test_metrics_endpoint_failure_returns_500_over_wire(self) -> None:
        import textwrap

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        plugins_root = _make_plugin(root)
        db = Path(tmp.name) / "mesh.db"
        from capmesh.index import rebuild_index

        rebuild_index(db, [plugins_root], enable_vector=False)
        service_token = "metrics-fail-wire-bearer"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        wrapper = textwrap.dedent(
            """
            import os, sys
            from unittest.mock import patch
            # Patch render_prometheus BEFORE importing the CLI/server so the
            # /metrics handler sees the raising stub. The import path is left
            # untouched (no PYTHONPATH prepend).
            patch("capmesh.server.render_prometheus", side_effect=RuntimeError("boom")).start()
            from capmesh.cli import main
            sys.argv = [
                "capmesh",
                "--db", os.environ["CAPMESH_TEST_DB"],
                "serve-http",
                "--host", "127.0.0.1",
                "--port", os.environ["CAPMESH_TEST_PORT"],
            ]
            main()
            """
        )
        env = {
            **os.environ,
            "CAPMESH_BEARER_TOKEN": service_token,
            "CAPMESH_ENVIRONMENT": "production",
            "CAPMESH_NODE_ROLE": "authoritative",
            "CAPMESH_AUTHORITY_URL": "https://capmesh.example.com",
            "CAPMESH_ROOTS": str(plugins_root),
            "CAPMESH_TEST_DB": str(db),
            "CAPMESH_TEST_PORT": str(port),
        }
        server = subprocess.Popen(
            [sys.executable, "-c", wrapper],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    stderr = server.stderr.read() if server.stderr else ""
                    raise RuntimeError(f"server exited early: {stderr}")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health/live", timeout=0.5):
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise RuntimeError("server did not become ready")

            request = urllib.request.Request(f"http://127.0.0.1:{port}/metrics")
            status: int
            body: str
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    status = response.status
                    body = response.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read().decode("utf-8", errors="replace")
            self.assertEqual(status, 500, f"expected 500 over wire, got {status}: {body!r}")
            self.assertGreater(len(body), 0, "failure body must be non-empty text")

            # The server must NOT have crashed: /health/live is still reachable.
            live = urllib.request.urlopen(f"http://127.0.0.1:{port}/health/live", timeout=5)
            self.assertEqual(live.status, 200)
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            if server.stderr:
                server.stderr.close()


if __name__ == "__main__":
    unittest.main()
