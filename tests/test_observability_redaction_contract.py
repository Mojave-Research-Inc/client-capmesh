"""Contract tests pinning the redaction surface in ``capmesh.observability``.

These exhaustively lock the redaction contract: the ``SENSITIVE_KEYS`` tuple,
the ``redact`` function's shallow-copy + case-insensitive masking behavior, and
the ``log_event`` routing through ``redact`` before JSON serialization. They
assert the REAL current behavior (green today), not aspirational semantics.
"""

from __future__ import annotations

import json
import logging

from capmesh.observability import SENSITIVE_KEYS, log_event, redact


class _ListHandler(logging.Handler):
    """A handler that captures LogRecords in a list for assertions."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _make_logger() -> tuple[logging.Logger, _ListHandler]:
    """Return an isolated logger plus its list-appending handler."""
    logger = logging.getLogger("capmesh.test.observability.redaction")
    logger.handlers.clear()
    handler = _ListHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger, handler


def test_every_sensitive_key_redacted() -> None:
    """Every key in SENSITIVE_KEYS is redacted, not just a sample."""
    for key in SENSITIVE_KEYS:
        result = redact({key: "val"})
        assert result == {key: "[REDACTED]"}, f"key {key!r} was not redacted"


def test_case_insensitive_sensitive_keys() -> None:
    """Mixed-case sensitive keys match case-insensitively."""
    result = redact({"Token": "v", "PASSWORD": "v", "Api_Key": "v"})
    assert result == {"Token": "[REDACTED]", "PASSWORD": "[REDACTED]", "Api_Key": "[REDACTED]"}


def test_nonsensitive_passthrough() -> None:
    """Keys that never match a sensitive key pass through unchanged."""
    result = redact({"capability": "cap1", "count": 3, "verb": "search"})
    assert result == {"capability": "cap1", "count": 3, "verb": "search"}


def test_redact_returns_new_dict() -> None:
    """redact returns a new dict and does not mutate its input."""
    original = {"token": "x", "name": "n"}
    out = redact(original)
    assert out is not original
    assert out["token"] == "[REDACTED]"
    assert original["token"] == "x"


def test_redact_non_string_value() -> None:
    """Sensitive keys are redacted regardless of the value's type."""
    result = redact({"token": 12345, "secret": None, "password": ["a", "b"]})
    assert result == {
        "token": "[REDACTED]",
        "secret": "[REDACTED]",
        "password": "[REDACTED]",
    }


def test_custom_sensitive_keys_param() -> None:
    """A custom sensitive_keys tuple overrides the default SENSITIVE_KEYS."""
    result = redact({"ssn": "111-22-3333", "name": "n"}, sensitive_keys=("ssn",))
    assert result == {"ssn": "[REDACTED]", "name": "n"}


def test_empty_fields() -> None:
    """An empty fields dict passes through as an empty dict."""
    assert redact({}) == {}


def test_log_event_redacts_sensitive_kwarg() -> None:
    """log_event routes its kwargs through redact before JSON-serializing."""
    logger, handler = _make_logger()
    log_event(logger, "test.event", token="secret-value", capability="cap1")
    assert len(handler.records) == 1
    msg = handler.records[0].getMessage()
    assert "\n" not in msg
    prefix = "capmesh.test.event "
    assert msg.startswith(prefix)
    parsed = json.loads(msg[len(prefix):])
    assert parsed["token"] == "[REDACTED]"
    assert parsed["capability"] == "cap1"


def test_log_event_redacts_case_insensitive() -> None:
    """log_event redacts case-insensitive sensitive kwargs."""
    logger, handler = _make_logger()
    log_event(logger, "test.event", Authorization="bearer xyz")
    assert len(handler.records) == 1
    msg = handler.records[0].getMessage()
    prefix = "capmesh.test.event "
    assert msg.startswith(prefix)
    parsed = json.loads(msg[len(prefix):])
    assert parsed["Authorization"] == "[REDACTED]"


def test_no_newline_in_log_event() -> None:
    """The log_event message is a single line with no embedded newline."""
    logger, handler = _make_logger()
    log_event(logger, "test.event", token="a\nb", capability="cap1")
    assert len(handler.records) == 1
    msg = handler.records[0].getMessage()
    assert "\n" not in msg


def test_redact_is_shallow() -> None:
    """redact is shallow: nested dict values are not recursed into.

    A sensitive key buried in a nested dict is NOT redacted because redact
    only inspects the top-level keys (values are copied by reference).
    """
    result = redact({"outer": {"token": "v"}})
    assert result == {"outer": {"token": "v"}}
