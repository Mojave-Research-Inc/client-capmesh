"""Tests for ``capmesh.observability`` (CM-13 first slice).

These pin the self-contained observability helper surface: redaction of
sensitive fields, single-line structured JSON log emission (including the
non-serializable fallback), the ``GateDecision`` wire shape, and the
``MetricsRegistry`` counter semantics. The module under test imports only the
standard library, and so do these tests.
"""

from __future__ import annotations

import json
import logging

from capmesh.observability import (
    GateDecision,
    MetricsRegistry,
    format_gate_decision,
    log_event,
    redact,
)


class _ListHandler(logging.Handler):
    """A handler that captures LogRecords in a list for assertions."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _make_logger() -> tuple[logging.Logger, _ListHandler]:
    """Return an isolated logger plus its list-appending handler.

    ``handlers.clear()`` keeps the named logger isolated per test so a prior
    run's handler cannot accumulate records into the current assertion.
    """
    logger = logging.getLogger("capmesh.test.observability")
    logger.handlers.clear()
    handler = _ListHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger, handler


def test_redact_replaces_sensitive() -> None:
    result = redact({"token": "abc", "name": "keep", "Password": "x"})
    assert result["token"] == "[REDACTED]"
    assert result["Password"] == "[REDACTED]"
    assert result["name"] == "keep"


def test_redact_passthrough_nonsensitive() -> None:
    result = redact({"capability": "cap1", "count": 3})
    assert result == {"capability": "cap1", "count": 3}


def test_log_event_emits_single_json_line() -> None:
    logger, handler = _make_logger()
    log_event(logger, "gate.eval", gateName="g1", token="secret")
    assert len(handler.records) == 1
    msg = handler.records[0].getMessage()
    prefix = "capmesh.gate.eval "
    assert msg.startswith(prefix)
    assert "\n" not in msg
    parsed = json.loads(msg[len(prefix):])
    assert parsed["token"] == "[REDACTED]"
    assert parsed["gateName"] == "g1"


def test_log_event_handles_non_serializable() -> None:
    logger, handler = _make_logger()
    log_event(logger, "set.event", value={"a", "b"})
    assert len(handler.records) == 1
    msg = handler.records[0].getMessage()
    prefix = "capmesh.set.event "
    assert msg.startswith(prefix)
    assert "\n" not in msg
    parsed = json.loads(msg[len(prefix):])
    # The unserializable set is stringified via default=str rather than raised.
    assert isinstance(parsed["value"], str)


def test_format_gate_decision_keys() -> None:
    decision = GateDecision(
        gate_name="signature",
        capability_uri="cap://x",
        outcome="passed",
        request_id="r1",
        reason="ok",
    )
    assert format_gate_decision(decision) == {
        "gateName": "signature",
        "capabilityUri": "cap://x",
        "outcome": "passed",
        "requestId": "r1",
        "reason": "ok",
    }


def test_format_gate_decision_request_id_none() -> None:
    decision = GateDecision(
        gate_name="g",
        capability_uri="cap://x",
        outcome="skipped",
        request_id=None,
        reason="x",
    )
    result = format_gate_decision(decision)
    assert result["requestId"] is None


def test_metrics_registry_increment_get() -> None:
    registry = MetricsRegistry()
    registry.increment("promotions.passed")
    registry.increment("promotions.passed")
    assert registry.get("promotions.passed") == 2
    assert registry.get("missing") == 0


def test_metrics_registry_snapshot_sorted() -> None:
    registry = MetricsRegistry()
    registry.increment("b")
    registry.increment("a")
    registry.increment("a")
    assert registry.snapshot() == {"a": 2, "b": 1}
