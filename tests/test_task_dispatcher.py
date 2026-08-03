"""Tests for the task_dispatcher module."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from capmesh.model_router import route_model
from capmesh.task_dispatcher import (
    BACKEND_TOOLS,
    DISPATCH_TIMEOUT,
    dispatch_queued_task,
    dispatch_task,
    list_dispatch_backends,
)


class TestDispatchTask(unittest.TestCase):
    def test_dispatch_with_explicit_routing(self) -> None:
        envelope = {"taskId": "cap-task-test", "task": "build this module", "agentUri": "cap://test/agent"}
        routing = route_model(risk_tier="high", task="build this module")
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"result": {"status": "ok"}}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = dispatch_task(envelope, routing=routing)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["backend"], routing["backend"])
            self.assertEqual(result["modelTier"], routing["modelTier"])

    def test_dispatch_with_routing_from_envelope(self) -> None:
        routing = route_model(risk_tier="low", task="simple task")
        envelope = {"taskId": "cap-task-test", "task": "simple task", "modelRouting": routing}
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"result": {"status": "ok"}}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = dispatch_task(envelope)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["modelTier"], routing["modelTier"])

    def test_dispatch_computes_routing_when_missing(self) -> None:
        envelope = {"taskId": "cap-task-test", "task": "review and verify code"}
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"result": {"status": "ok"}}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = dispatch_task(envelope)
            self.assertEqual(result["status"], "completed")
            self.assertIn("modelTier", result)

    def test_dispatch_gateway_error(self) -> None:
        envelope = {"taskId": "cap-task-test", "task": "build this"}
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"error": "backend unavailable"}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = dispatch_task(envelope)
            self.assertEqual(result["status"], "failed")
            self.assertIn("error", result)

    def test_dispatch_gateway_unreachable(self) -> None:
        envelope = {"taskId": "cap-task-test", "task": "build this"}
        with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
            result = dispatch_task(envelope)
            self.assertEqual(result["status"], "failed")
            self.assertIn("Gateway unreachable", result["error"])

    def test_dispatch_with_custom_gateway_url(self) -> None:
        envelope = {"taskId": "cap-task-test", "task": "build this"}
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"result": {"status": "ok"}}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            dispatch_task(envelope, gateway_url="http://custom:9999/mcp")
            # Verify the request was made to the custom URL
            request = mock_urlopen.call_args[0][0]
            self.assertIn("custom:9999", request.full_url)

    def test_dispatch_timeout_is_configurable(self) -> None:
        self.assertGreater(DISPATCH_TIMEOUT, 0)

    def test_backend_tools_mapping_covers_all_tiers(self) -> None:
        from capmesh.model_router import MODEL_TIERS, _backend_for
        for tier in MODEL_TIERS:
            backend = _backend_for(tier)
            self.assertIn(backend, BACKEND_TOOLS, f"Backend {backend} for tier {tier} not in BACKEND_TOOLS")


class TestListDispatchBackends(unittest.TestCase):
    def test_lists_all_four_backends(self) -> None:
        backends = list_dispatch_backends()
        self.assertEqual(len(backends), 4)
        names = [b["name"] for b in backends]
        self.assertIn("qwen-worker", names)
        self.assertIn("qwen-director", names)
        self.assertIn("glm", names)
        self.assertIn("opus", names)

    def test_each_backend_has_required_fields(self) -> None:
        for backend in list_dispatch_backends():
            self.assertIn("name", backend)
            self.assertIn("backend", backend)
            self.assertIn("tool", backend)
            self.assertIn("description", backend)
            self.assertIn("cost", backend)

    def test_qwen_and_glm_are_free(self) -> None:
        for backend in list_dispatch_backends():
            if backend["name"] in ("qwen-worker", "qwen-director", "glm"):
                self.assertEqual(backend["cost"], "free")

    def test_opus_is_paid(self) -> None:
        opus = next(b for b in list_dispatch_backends() if b["name"] == "opus")
        self.assertEqual(opus["cost"], "paid")


class TestDispatchQueuedTask(unittest.TestCase):
    def test_dispatch_nonexistent_task_raises(self) -> None:
        import sqlite3
        import tempfile
        from pathlib import Path

        from capmesh.task_runner import ensure_task_table

        with tempfile.TemporaryDirectory() as tmp:
            con = sqlite3.connect(str(Path(tmp) / "test.db"))
            con.row_factory = sqlite3.Row
            ensure_task_table(con)
            with self.assertRaises(ValueError):
                dispatch_queued_task(con, "nonexistent-task")
            con.close()


if __name__ == "__main__":
    unittest.main()
