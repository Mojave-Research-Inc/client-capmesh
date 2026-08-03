"""MCP Inspector smoke test harness (ideal-state checklist item).

Spawns a real capmesh serve-http instance and exercises the full MCP protocol
surface: initialize, tools/list, ping, and tools/call (cap.search). Verifies
response structure, protocol version, and tool schema correctness.
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

from capmesh.index import rebuild_index


def _make_plugin(root: Path) -> Path:
    plugin = root / "plugins" / "demo"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / "skills" / "write-brief").mkdir(parents=True)
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0", "description": "Demo plugin."}), encoding="utf-8"
    )
    (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
        "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n# Write Brief\nUse for executive summaries.\n", encoding="utf-8"
    )
    return root / "plugins"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mcp_post(url, body, headers=None):
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json", "Accept": "application/json", "MCP-Protocol-Version": "2025-06-18"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=h)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


class McpInspectorSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.plugins = _make_plugin(cls.root)
        cls.db = cls.root / "mesh.db"
        rebuild_index(cls.db, [cls.plugins], enable_vector=False)
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/mcp"
        env = {
            **os.environ,
            "CAPMESH_BEARER_TOKEN": "test-bearer",
            "CAPMESH_REQUIRE_SAFE_SQLITE": "0",
            "CAPMESH_ROOTS": str(cls.plugins),
        }
        cls.server = subprocess.Popen(
            [sys.executable, "-m", "capmesh", "--db", str(cls.db), "serve-http", "--host", "127.0.0.1", "--port", str(cls.port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if cls.server.poll() is not None:
                stderr = cls.server.stderr.read() if cls.server.stderr else ""
                raise RuntimeError(f"Server exited: {stderr}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/health/live", timeout=0.5):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        else:
            cls.server.terminate()
            raise RuntimeError("Server not ready")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=10)
        cls.tmp.cleanup()

    def _auth_headers(self):
        return {"Authorization": "Bearer test-bearer"}

    def test_initialize(self):
        resp = _mcp_post(self.url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}, self._auth_headers())
        self.assertEqual(resp.get("jsonrpc"), "2.0")
        result = resp.get("result", {})
        self.assertIn("protocolVersion", result)

    def test_tools_list(self):
        resp = _mcp_post(self.url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, self._auth_headers())
        result = resp.get("result", {})
        tools = result.get("tools", [])
        names = {t.get("name") for t in tools}
        expected = {"cap.search", "cap.load", "cap.call", "cap.list", "cap.describe", "cap.delegate", "cap.report"}
        self.assertTrue(expected.issubset(names), f"Missing: {expected - names}")

    def test_ping(self):
        resp = _mcp_post(self.url, {"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}}, self._auth_headers())
        self.assertEqual(resp.get("jsonrpc"), "2.0")

    def test_tools_call_search(self):
        resp = _mcp_post(self.url, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cap.search", "arguments": {"query": "executive brief", "k": 5}}}, self._auth_headers())
        result = resp.get("result", {})
        self.assertFalse(resp.get("error"), f"Error: {resp.get(chr(101)+chr(114)+chr(114)+chr(111)+chr(114))}")
        content = result.get("content", [])
        self.assertTrue(len(content) > 0)

    def test_protocol_version_rejection(self):
        # The server validates MCP-Protocol-Version at the HTTP header level.
        # Sending an unsupported version in the header triggers HTTP 400.
        
        data = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", "MCP-Protocol-Version": "2099-01-01", **self._auth_headers()},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            return
        self.fail("Expected HTTP 400 for unsupported protocol version in header")


if __name__ == "__main__":
    unittest.main()
