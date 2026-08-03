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
from pathlib import Path

# The on-disk canonical installers live at the repository root under install/.
# The contract: ``handle_install`` (capmesh/server.py) must serve these on-disk
# bytes verbatim over /install(.sh) and /install.ps1 when ``install/`` is
# present, keeping the in-code ``_install_sh``/``_install_ps1`` heredoc only as a
# fallback when ``install/`` is absent. This pins that behavior so a future
# heredoc drift cannot silently change what customers receive via
# ``curl -fsSL <base>/install.sh | sh``. While ``handle_install`` still serves
# the heredoc (R1-07 not yet landed), the bytes-equality assertions below FAIL
# by design -- the failure is the signal that the source must serve the on-disk
# canonical file before customers hit the install route.
INSTALL_DIR = Path(__file__).resolve().parent.parent / "install"
CANONICAL_INSTALL_SH = INSTALL_DIR / "install.sh"
CANONICAL_INSTALL_PS1 = INSTALL_DIR / "install.ps1"


class InstallServedBytesContractTests(unittest.TestCase):
    """R4-07: the served installers are byte-for-byte the on-disk canonical files.

    R1-07 makes ``handle_install`` (capmesh/server.py) serve the on-disk
    canonical ``install/install.sh`` + ``install/install.ps1`` when present,
    keeping the in-code ``_install_sh``/``_install_ps1`` heredoc only as a
    fallback when ``install/`` is absent. This contract test pins that
    behavior: the HTTP body served at ``/install.sh`` and ``/install.ps1``
    must equal the on-disk canonical file bytes exactly, and must carry the
    hardened verbs (whoami/search/bootstrap) plus the ``CAPMESH_BASE_URL``
    marker. Any drift between the heredoc and the canonical file — which
    would otherwise silently change what customers get via ``curl|sh`` —
    is caught here.

    DEPENDENCY (source lane, not this test lane): these assertions pass only
    once R1-07 lands in ``capmesh/server.py handle_install`` so it serves the
    on-disk bytes instead of the ``_install_sh``/``_install_ps1`` heredoc.
    Until then the byte-equality and marker cases below fail loudly — that
    failure IS the regression signal this guard exists to raise, not a test
    defect. This test file owns no source; do not weaken the assertions to
    match the heredoc (that would green-light the exact drift this guards).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "mesh.db"
        cls.service_token = "r407-test-service-bearer"
        cls.proxy_token = "r407-test-proxy-bearer"
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
    def _get_raw(cls, path: str) -> tuple[int, bytes]:
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}{path}",
            # The install routes are public (no-bearer, magic-install curl|sh),
            # so no Authorization header is supplied.
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    def test_install_sh_served_equals_on_disk_canonical(self) -> None:
        """GET /install.sh serves the on-disk install/install.sh bytes verbatim."""
        self.assertTrue(
            CANONICAL_INSTALL_SH.is_file(),
            f"canonical installer missing on disk: {CANONICAL_INSTALL_SH}",
        )
        expected = CANONICAL_INSTALL_SH.read_bytes()
        status, body = self._get_raw("/install.sh")
        self.assertEqual(status, 200, f"GET /install.sh returned {status}: {body!r}")
        self.assertEqual(
            body,
            expected,
            "served /install.sh body drifted from on-disk install/install.sh; "
            "a future heredoc drift would silently change what customers get via curl|sh",
        )

    def test_install_sh_served_carries_hardened_markers(self) -> None:
        """The served POSIX installer carries the CAPMESH_BASE_URL marker + verbs."""
        status, body = self._get_raw("/install.sh")
        self.assertEqual(status, 200, f"GET /install.sh returned {status}: {body!r}")
        text = body.decode("utf-8", errors="replace")
        # The canonical installer is keyed off CAPMESH_BASE_URL (not the legacy
        # CAPMESH_BASE heredoc marker) and exposes the hardened verbs a tailnet
        # user is expected to run: whoami, search, bootstrap.
        self.assertIn("CAPMESH_BASE_URL", text, "served install.sh missing CAPMESH_BASE_URL marker")
        for verb in ("whoami", "search", "bootstrap"):
            self.assertIn(verb, text, f"served install.sh missing hardened verb '{verb}'")

    def test_install_ps1_served_equals_on_disk_canonical(self) -> None:
        """GET /install.ps1 serves the on-disk install/install.ps1 bytes verbatim."""
        self.assertTrue(
            CANONICAL_INSTALL_PS1.is_file(),
            f"canonical installer missing on disk: {CANONICAL_INSTALL_PS1}",
        )
        expected = CANONICAL_INSTALL_PS1.read_bytes()
        status, body = self._get_raw("/install.ps1")
        self.assertEqual(status, 200, f"GET /install.ps1 returned {status}: {body!r}")
        self.assertEqual(
            body,
            expected,
            "served /install.ps1 body drifted from on-disk install/install.ps1; "
            "a future heredoc drift would silently change what customers get via irm|iex",
        )

    def test_install_ps1_served_carries_hardened_markers(self) -> None:
        """The served PowerShell installer carries the CAPMESH_BASE_URL marker + verbs."""
        status, body = self._get_raw("/install.ps1")
        self.assertEqual(status, 200, f"GET /install.ps1 returned {status}: {body!r}")
        text = body.decode("utf-8", errors="replace")
        self.assertIn("CAPMESH_BASE_URL", text, "served install.ps1 missing CAPMESH_BASE_URL marker")
        for verb in ("whoami", "search", "bootstrap"):
            self.assertIn(verb, text, f"served install.ps1 missing hardened verb '{verb}'")

    def test_install_route_alias_serves_same_canonical_bytes(self) -> None:
        """GET /install (the curl|sh alias) serves the same bytes as /install.sh."""
        status_sh, body_sh = self._get_raw("/install.sh")
        status_alias, body_alias = self._get_raw("/install")
        self.assertEqual(status_sh, 200, f"GET /install.sh returned {status_sh}")
        self.assertEqual(status_alias, 200, f"GET /install returned {status_alias}")
        self.assertEqual(
            body_alias,
            body_sh,
            "/install alias must serve the same canonical bytes as /install.sh",
        )


if __name__ == "__main__":
    unittest.main()
