from __future__ import annotations

import json
import os
import time
import unittest
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Self
from unittest import mock

import capmesh.index
from capmesh.index import DEFAULT_LEXICAL_EMBED_DIMS, embed_text

# TEI provider (the Qwen3 embedding service shape) pointed at a loopback URL so
# the allowlist guard passes without touching a real socket.
DIMS = 384
_BASE_ENV = {
    "CAPMESH_EMBEDDING_PROVIDER": "tei",
    "CAPMESH_TEI_EMBED_URL": "http://127.0.0.1:8090/embed",
    "CAPMESH_EMBEDDING_HARD_DEADLINE_SECONDS": "20",
    "CAPMESH_EMBEDDING_FAILURE_THRESHOLD": "3",
    "CAPMESH_EMBEDDING_COOLDOWN_SECONDS": "300",
}


def _reset_breaker() -> None:
    capmesh.index._embed_breaker_failures = 0
    capmesh.index._embed_breaker_tripped_until = 0.0


class _FakeResponse:
    """Minimal urlopen() context manager returning a fixed JSON body."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _ok_response(dims: int = DIMS) -> _FakeResponse:
    # TEI-style payload: a list whose first element is the embedding vector.
    payload = [[1.0] + [0.0] * (dims - 1)]
    return _FakeResponse(json.dumps(payload).encode("utf-8"))


class _HungFuture:
    """A future whose result() always misses a hard deadline."""

    def __init__(self) -> None:
        self.result_timeout: float | None = None

    def result(self, timeout: float | None = None) -> list[float]:
        self.result_timeout = timeout
        raise FuturesTimeoutError()

    def running(self) -> bool:
        # A trickling/hung endpoint keeps the worker thread alive past the
        # deadline, which is exactly what makes the hard deadline necessary.
        return True


class _HungExecutor:
    """Stand-in for ThreadPoolExecutor that returns a hung future."""

    instances = 0
    last: _HungExecutor | None = None

    def __init__(self, max_workers: int | None = None) -> None:
        _HungExecutor.instances += 1
        _HungExecutor.last = self
        self.future = _HungFuture()

    def submit(self, *_args: object, **_kw: object) -> _HungFuture:
        return self.future

    def shutdown(self, wait: bool = True) -> None:
        pass


class EmbedHardeningTests(unittest.TestCase):
    """Hard-deadline + circuit-breaker hardening for embed_text.

    The local embedding service can livelock and trickle bytes so the per-ocket
    timeout never fires; embed_text must instead bound the call with a hard
    wall-clock deadline and refuse to keep hammering a failing endpoint.
    """

    def setUp(self) -> None:
        _reset_breaker()
        _HungExecutor.instances = 0
        _HungExecutor.last = None

    def tearDown(self) -> None:
        _reset_breaker()

    def _env(self, **overrides: str) -> dict[str, str]:
        env = dict(_BASE_ENV)
        env.update(overrides)
        return env

    def test_hard_deadline_raises_and_trips_breaker(self) -> None:
        # (a) A hung endpoint (mocked executor/future timing out) raises
        # RuntimeError within the hard deadline and trips the breaker.
        with mock.patch.dict(os.environ, self._env(CAPMESH_EMBEDDING_HARD_DEADLINE_SECONDS="0.5")):
            with mock.patch("capmesh.index.ThreadPoolExecutor", _HungExecutor):
                with self.assertRaises(RuntimeError) as cm:
                    embed_text("anything")
            self.assertIn("hard deadline exceeded", str(cm.exception))
            self.assertIn("0.5s", str(cm.exception))
            # The hard deadline was actually wired into future.result().
            self.assertIsNotNone(_HungExecutor.last)
            self.assertEqual(_HungExecutor.last.future.result_timeout, 0.5)
            # A hard-deadline trips the breaker immediately (not after N failures).
            self.assertGreater(capmesh.index._embed_breaker_tripped_until, 0.0)
            # A follow-up call fails fast at the breaker, without a new executor /
            # network call.
            with mock.patch("capmesh.index.ThreadPoolExecutor", _HungExecutor):
                with self.assertRaises(RuntimeError) as cm2:
                    embed_text("anything")
            self.assertIn("circuit breaker open", str(cm2.exception))
            self.assertEqual(_HungExecutor.instances, 1, "breaker-open path must not build an executor")

    def test_threshold_consecutive_failures_fail_fast_without_network(self) -> None:
        # (b) After THRESHOLD consecutive failures, embed_text fails fast with
        # "circuit breaker open" without a network call.
        urlopen = mock.MagicMock(side_effect=OSError("connection refused"))
        with mock.patch.dict(os.environ, self._env(CAPMESH_EMBEDDING_FAILURE_THRESHOLD="3")):
            with mock.patch("capmesh.index.urlopen", urlopen):
                for _ in range(3):
                    with self.assertRaises(RuntimeError) as cm:
                        embed_text("x")
                    self.assertIn("local tei embedding unavailable", str(cm.exception))
                self.assertEqual(urlopen.call_count, 3)
                self.assertGreater(capmesh.index._embed_breaker_tripped_until, 0.0)
                # The 4th call fails fast at the breaker; urlopen is NOT called.
                with self.assertRaises(RuntimeError) as cm2:
                    embed_text("x")
        self.assertIn("circuit breaker open", str(cm2.exception))
        self.assertEqual(urlopen.call_count, 3, "breaker-open path must not touch the network")

    def test_successful_embed_resets_breaker(self) -> None:
        # (c) A successful embed resets the failure counter and clears a trip.
        with mock.patch.dict(os.environ, self._env()):
            # Pretend several prior failures and an expired trip.
            capmesh.index._embed_breaker_failures = 5
            capmesh.index._embed_breaker_tripped_until = time.monotonic() - 10.0
            urlopen = mock.MagicMock(return_value=_ok_response())
            with mock.patch("capmesh.index.urlopen", urlopen):
                result = embed_text("x")
            self.assertEqual(len(result), DIMS)
            self.assertEqual(capmesh.index._embed_breaker_failures, 0)
            self.assertEqual(capmesh.index._embed_breaker_tripped_until, 0.0)

    def test_lexical_path_unaffected_by_tripped_breaker(self) -> None:
        # (d) The lexical provider path works even when the breaker is tripped.
        with mock.patch.dict(os.environ, {"CAPMESH_EMBEDDING_PROVIDER": "lexical"}):
            # Trip the breaker hard so a network provider would be refused.
            capmesh.index._embed_breaker_tripped_until = float("inf")
            urlopen = mock.MagicMock()
            with mock.patch("capmesh.index.urlopen", urlopen):
                result = embed_text("some lexical text here")
            self.assertEqual(len(result), DEFAULT_LEXICAL_EMBED_DIMS)
            self.assertTrue(all(isinstance(v, float) for v in result))
            urlopen.assert_not_called()
            # Lexical must not touch the breaker state.
            self.assertEqual(capmesh.index._embed_breaker_failures, 0)

    def test_breaker_auto_resets_after_cooldown(self) -> None:
        # (e) The breaker auto-reopens after the cooldown elapses (mocked clock).
        clock = [0.0]

        def fake_monotonic() -> float:
            return clock[0]

        env = self._env(
            CAPMESH_EMBEDDING_FAILURE_THRESHOLD="1",
            CAPMESH_EMBEDDING_COOLDOWN_SECONDS="100",
        )
        with mock.patch.dict(os.environ, env), mock.patch("time.monotonic", fake_monotonic):
            # One failure trips the breaker (threshold=1) until 0 + 100 = 100.
            with mock.patch("capmesh.index.urlopen", mock.MagicMock(side_effect=OSError("down"))):
                with self.assertRaises(RuntimeError):
                    embed_text("x")
            self.assertAlmostEqual(capmesh.index._embed_breaker_tripped_until, 100.0)
            # While the cooldown is active, the breaker is open.
            clock[0] = 50.0
            with self.assertRaises(RuntimeError) as cm:
                embed_text("x")
            self.assertIn("circuit breaker open", str(cm.exception))
            # Advance past the cooldown: the breaker auto-reopens and a
            # successful embed fully resets the breaker state.
            clock[0] = 200.0
            with mock.patch("capmesh.index.urlopen", mock.MagicMock(return_value=_ok_response())):
                result = embed_text("x")
            self.assertEqual(len(result), DIMS)
            self.assertEqual(capmesh.index._embed_breaker_failures, 0)
            self.assertEqual(capmesh.index._embed_breaker_tripped_until, 0.0)


if __name__ == "__main__":
    unittest.main()
