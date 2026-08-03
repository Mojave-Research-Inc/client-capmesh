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


class MutatingRouteServiceTokenTests(unittest.TestCase):
    """IMPROVEMENT-PLAN CM-11: mutating routes require the static service token.

    CM-11 gate: a mutating HTTP route (POST/PUT/PATCH/DELETE that reaches the
    write path inside the asg-capmesh HTTP handler) requires BOTH
    (a) an authenticated principal AND (b) the static service token
    (CAPMESH_BEARER_TOKEN).  A bare tailnet identity with no service token is
    rejected with 401 so that a plain tailnet user cannot perform SCIM writes,
    admin mutations, or any other destructive operation.

    Read-only routes (SCIM GET, /api/v1/whoami, cap.search/load) are unaffected;
    they only pass the standard ``authorized()`` check.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "mesh.db"
        cls.service_token = "cm11-test-service-bearer"
        cls.proxy_token = "cm11-test-proxy-bearer"
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
                    raise RuntimeError(
                        f"test Capmesh server exited early: {stderr}"
                    )
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
        headers: dict[str, str],
        body: dict | None = None,
    ) -> tuple[int, dict[str, object]]:
        data = json.dumps(body or {}).encode() if body else b"{}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                **headers,
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def _tailnet_identity_headers(self) -> dict[str, str]:
        """Return a dict with a Tailscale-User-Login header and proxy token.

        These headers make ``self.principal()`` resolve to a non-guest identity
        (verified via the proxy hop), simulating an authenticated tailnet user.
        Crucially, NO ``Authorization: Bearer <service_token>`` is included,
        so the service-token check in ``mutating_route_authorized`` fails.
        """
        return {
            "X-Capmesh-Proxy-Token": self.proxy_token,
            "Tailscale-User-Login": "tailnet-user@example.com",
            "Tailscale-User-Name": "Tailnet User",
        }

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_scim_write_without_service_token_denied(self) -> None:
        """SCIM POST to /scim/v2/Users with tailnet identity but no service token -> 401."""
        status, payload = self._request(
            "POST",
            "/scim/v2/Users",
            self._tailnet_identity_headers(),
            body={
                "userName": "new-user@example.com",
                "emails": [{"value": "new-user@example.com"}],
            },
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_scim_put_without_service_token_denied(self) -> None:
        """SCIM PUT to /scim/v2/Users with tailnet identity but no service token -> 401."""
        status, payload = self._request(
            "PUT",
            "/scim/v2/Users/test-id-123",
            self._tailnet_identity_headers(),
            body={
                "userName": "updated@example.com",
                "emails": [{"value": "updated@example.com"}],
            },
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_scim_delete_without_service_token_denied(self) -> None:
        """SCIM DELETE to /scim/v2/Users with tailnet identity but no service token -> 401."""
        status, payload = self._request(
            "DELETE",
            "/scim/v2/Users/test-id-123",
            self._tailnet_identity_headers(),
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_scim_write_with_service_token_allowed(self) -> None:
        """SCIM POST with correct service token proceeds past the gate."""
        headers = dict(self._tailnet_identity_headers())
        headers["Authorization"] = f"Bearer {self.service_token}"
        status, payload = self._request(
            "POST",
            "/scim/v2/Users",
            headers,
            body={
                "userName": "service-user@example.com",
                "emails": [{"value": "service-user@example.com"}],
            },
        )
        # The gate passes; the handler runs.  The user may or may not already
        # exist, so we only assert the request is NOT rejected at the auth
        # gate (i.e., status is not 401).
        self.assertNotEqual(status, 401)
        # The gate passes; the handler may return a SCIM 403 (tenant
        # authorization) or a different downstream error, but it must NOT be
        # a 401 from the CM-11 mutating-route auth gate.
        self.assertIn("detail", payload)

    def test_scim_get_read_path_unaffected(self) -> None:
        """SCIM GET with tailnet identity and NO service token still succeeds."""
        headers = dict(self._tailnet_identity_headers())
        # Read-only: authorized() is used, not mutating_route_authorized().
        status, _payload = self._request(
            "GET",
            "/scim/v2/Users?filter=userName+eq+%27tailnet-user%40example.com%27",
            headers,
        )
        # The read path uses the standard authorized() gate, which accepts
        # an authenticated principal.  Status should not be 401.
        self.assertNotEqual(status, 401)

    def test_non_scim_mutating_route_requires_service_token(self) -> None:
        """PATCH /api/v1/capabilities/drafts/ also requires the service token.

        The CM-11 gate applies to ALL mutating HTTP routes (POST/PUT/PATCH/DELETE),
        not just SCIM endpoints.  If a non-SCIM mutating route exists, it must
        enforce the same dual-auth requirement.  This test exercises the PATCH
        /api/v1/capabilities/drafts/ endpoint which is a mutating route.
        """
        headers = self._tailnet_identity_headers()
        status, payload = self._request(
            "PATCH",
            "/api/v1/capabilities/drafts/test-cap-uri",
            headers,
            body={"action": "draft.update"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_patch_with_service_token_allowed(self) -> None:
        """PATCH with the service token passes the CM-11 gate."""
        headers = dict(self._tailnet_identity_headers())
        headers["Authorization"] = f"Bearer {self.service_token}"
        status, _payload = self._request(
            "PATCH",
            "/api/v1/capabilities/drafts/test-cap-uri",
            headers,
            body={"action": "draft.update"},
        )
        # The gate passes (not 401).
        self.assertNotEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
