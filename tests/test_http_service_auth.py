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


class HttpServiceAuthenticationTests(unittest.TestCase):
    """Exercise the real HTTP transport used behind authoritative-node nginx."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "mesh.db"
        cls.service_token = "test-service-bearer"
        cls.proxy_token = "test-proxy-bearer"
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

    @classmethod
    def request(cls, headers: dict[str, str]) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}/api/v1/whoami",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_proxy_hop_without_identity_or_service_bearer_fails_closed(self) -> None:
        status, payload = self.request(
            {"X-Capmesh-Proxy-Token": self.proxy_token}
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_loopback_superadmin_identity_without_proxy_token_fails_closed(self) -> None:
        status, payload = self.request(
            {"Tailscale-User-Login": "test-user@example.com"}
        )
        # A spoofed Tailscale-User-Login header with no proxy token must NOT
        # leak any identity document. The public /whoami endpoint rejects the
        # unauthenticated (tailnet-guest) principal with 401, so the asserted
        # superadmin identity is never honored and never surfaced.
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_static_bearer_through_proxy_resolves_service_identity(self) -> None:
        status, payload = self.request(
            {
                "X-Capmesh-Proxy-Token": self.proxy_token,
                "Authorization": f"Bearer {self.service_token}",
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["subject"], "capmesh-service")
        self.assertIn("app_service", payload["roles"])

    def test_verified_tailscale_proxy_identity_remains_bearer_free(self) -> None:
        status, payload = self.request(
            {
                "X-Capmesh-Proxy-Token": self.proxy_token,
                "Tailscale-User-Login": "service-test-owner@example.com",
                "Tailscale-User-Name": "Service Owner",
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["subject"], "service-test-owner@example.com")

    def test_loopback_login_without_proxy_token_denied(self) -> None:
        """Tailscale-User-Login alone must NOT resolve to asserted identity without proxy token."""
        status, payload = self.request(
            {"Tailscale-User-Login": "admin@example.com"}
        )
        # Without a valid proxy token the request is unauthenticated (resolves
        # to tailnet-guest), and the public identity endpoint rejects it with
        # 401 rather than leaking the guest identity document.
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")

    def test_loopback_login_with_valid_proxy_token_accepted(self) -> None:
        """Tailscale-User-Login resolves to asserted identity with correct proxy token."""
        status, payload = self.request(
            {
                "X-Capmesh-Proxy-Token": self.proxy_token,
                "Tailscale-User-Login": "admin@example.com",
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["subject"], "admin@example.com")
        # principal_from_tailscale_identity returns least-priv roles; elevation
        # comes only through audited role_assignments, not identity headers.
        self.assertIn("member", payload.get("roles", []))

    def test_loopback_login_with_wrong_proxy_token_denied(self) -> None:
        """Tailscale-User-Login resolves to low-priv with invalid proxy token."""
        status, payload = self.request(
            {
                "X-Capmesh-Proxy-Token": "wrong-token-12345",
                "Tailscale-User-Login": "admin@example.com",
            }
        )
        # With a wrong proxy token the request is unauthenticated; the public
        # identity endpoint rejects it with 401 (no identity leak).
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
