"""Lock the auth policy on the /metrics endpoint (CM-13 observability slice).

``capmesh/server.py`` wires ``GET /metrics`` as a PUBLIC Prometheus scrape
endpoint that renders ``render_prometheus(GATE_METRICS)`` to Prometheus text
exposition. The endpoint is EXEMPT from the service-token auth gate because
Prometheus scrapers do not send service tokens. Mutating routes (POST/PUT/
PATCH/DELETE) still require the static service token via
``mutating_route_authorized`` (covered by tests/test_mutating_route_service_token.py).

These tests lock that security-relevant decision so a future lane cannot
silently re-gate /metrics (which would break Prometheus scrapers) or
accidentally de-gate a mutating route. They drive a real subprocess Capmesh
server (mirroring tests/test_metrics_endpoint.py and
tests/test_server_request_id_thread.py) configured with a service bearer in
production mode so the mutating-route gate is armed; /metrics must still be
reachable without it.

ONLY this test file is created. No capmesh/*.py source is edited.
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


def _make_plugin(root: Path) -> Path:
    """Create a minimal plugin with one skill so the catalog is non-empty."""
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


class MetricsAuthPolicySubprocessTests(unittest.TestCase):
    """Lock the /metrics auth policy over a real subprocess Capmesh server.

    ``serve_http`` installs signal handlers (main-thread only), so the server
    runs as a subprocess mirroring tests/test_metrics_endpoint.py and
    tests/test_mutating_route_service_token.py. A service bearer is configured
    and CAPMESH_ENVIRONMENT=production so the mutating-route gate is armed;
    /metrics must still be reachable without it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins_root = _make_plugin(cls.root)
        cls.db = Path(cls.tmp.name) / "mesh.db"
        from capmesh.index import rebuild_index

        rebuild_index(cls.db, [cls.plugins_root], enable_vector=False)
        cls.service_token = "metrics-auth-policy-service-bearer"
        cls.proxy_token = "metrics-auth-policy-proxy-bearer"
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
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{cls.port}/health/live", timeout=0.5
                ):
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    def _request(
        cls,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict | None = None,
    ) -> tuple[int, dict[str, str], str | None]:
        data = json.dumps(body or {}).encode() if body is not None else b""
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}{path}",
            data=data if method != "GET" else None,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), raw
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            return exc.code, dict(exc.headers), raw

    # ------------------------------------------------------------------
    # Contract: /metrics is a public read-only GET scrape endpoint
    # ------------------------------------------------------------------

    def test_metrics_get_reachable_without_service_token(self) -> None:
        """GET /metrics returns 200 with NO service token in the request.

        Locks: /metrics is public. A Prometheus scraper sends no service
        token / X-Capmesh-Proxy-Token, so the endpoint must be exempt from
        the service-token auth gate. The empty Authorization header is sent
        explicitly to prove even an empty bearer does not trip the gate.
        """
        status, _headers, body = self._request(
            "GET",
            "/metrics",
            headers={"Authorization": ""},
        )
        self.assertEqual(status, 200, f"/metrics returned {status}: {body!r}")
        if body is not None:
            self.assertNotIn("UNAUTHORIZED", body)

    def test_metrics_get_no_auth_header_at_all(self) -> None:
        """GET /metrics returns 200 with NO Authorization header whatsoever.

        Locks: /metrics is public even when the Authorization header is
        entirely absent (not just an empty value). This is the exact wire
        shape a Prometheus scraper produces.
        """
        status, _headers, body = self._request("GET", "/metrics", headers={})
        self.assertEqual(status, 200, f"/metrics returned {status}: {body!r}")
        if body is not None:
            self.assertNotIn("UNAUTHORIZED", body)

    def test_metrics_content_type_contract(self) -> None:
        """GET /metrics returns Content-Type starting with text/plain; version=0.0.4.

        Locks the Prometheus exposition format so a future lane cannot
        silently switch to a different content type (e.g. application/json
        or OpenMetrics) without updating scrapers.
        """
        status, headers, _body = self._request("GET", "/metrics", headers={})
        self.assertEqual(status, 200)
        content_type = headers.get("Content-Type") or ""
        self.assertTrue(
            content_type.startswith("text/plain; version=0.0.4"),
            f"unexpected Content-Type: {content_type!r}",
        )

    def test_metrics_is_get_only(self) -> None:
        """POST /metrics is NOT the scrape path: it hits the mutating-route gate.

        /metrics is wired only in ``do_GET``; ``do_POST`` does not special-case
        it, so a POST falls through to the mutating-route gate
        (``mutating_route_authorized``) which requires the service token.
        Without a service token the POST is rejected with 401 -- proving the
        public endpoint is a read-only GET surface, not a write surface.

        Locks: the public /metrics endpoint is GET-only; POSTing to it does
        not invoke the scrape renderer and is not de-gated alongside the
        GET scrape path.
        """
        # No service token, no proxy token: mutating_route_authorized() runs
        # before any path dispatch in do_POST and rejects with 401.
        status, _headers, body = self._request(
            "POST",
            "/metrics",
            headers={},
            body={},
        )
        self.assertIn(
            status,
            (401, 403, 404, 405),
            f"POST /metrics returned unexpected status {status}: {body!r}",
        )
        # The mutating-route gate (401 UNAUTHORIZED) is the documented
        # behavior for an ungated POST. A 401 confirms /metrics is not a
        # write surface. We assert it is NOT 200 (the scrape status).
        self.assertNotEqual(status, 200, "POST /metrics must not be the scrape path")

    # ------------------------------------------------------------------
    # Contract: de-gating was scoped to /metrics only, not blanket removal
    # ------------------------------------------------------------------

    def test_mutating_route_still_requires_token(self) -> None:
        """A representative mutating route still 401s without a service token.

        Uses POST /api/v1/stores, which is dispatched inside
        ``handle_api_post`` (a mutating write path) and is reached only after
        ``mutating_route_authorized`` passes. With a tailnet identity (proxy
        hop) but NO service token, the gate rejects with 401 -- proving the
        de-gating was scoped to /metrics only, not a blanket auth removal
        across all routes.

        The request body is rejected at the auth gate BEFORE any mutation
        occurs, so no data is actually written.
        """
        # Tailnet identity via the trusted proxy hop, but NO service token.
        headers = {
            "X-Capmesh-Proxy-Token": self.proxy_token,
            "Tailscale-User-Login": "policy-user@example.com",
            "Tailscale-User-Name": "Policy User",
        }
        status, _headers, body = self._request(
            "POST",
            "/api/v1/stores",
            headers=headers,
            body={"kind": "personal", "name": "should-not-be-created"},
        )
        self.assertIn(
            status,
            (401, 403),
            f"mutating route without service token returned {status}: {body!r}",
        )
        if body:
            self.assertIn("UNAUTHORIZED", body)


if __name__ == "__main__":
    unittest.main()
