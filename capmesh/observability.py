"""Bounded, self-contained observability helpers for the Capability Mesh.

First slice of plan item CM-13 (metrics/OTel + logging). This module is a
standalone helper layer: it imports ONLY the Python standard library and has
no dependency on any other ``capmesh`` module. A later wave will wire these
helpers into the live gate runner (``lifecycle.py``) and the HTTP routes
(``server.py`` / ``router.py``); this slice ships the surface itself.

Provided surface:
    * ``SENSITIVE_KEYS`` -- lowercase field keys whose values are redacted.
    * ``redact`` -- shallow-copy a fields dict, masking sensitive values.
    * ``log_event`` -- emit one structured JSON log line via a ``logging.Logger``.
    * ``GateDecision`` / ``format_gate_decision`` -- stable wire shape for a
      gate-evaluation outcome.
    * ``MetricsRegistry`` -- an in-memory counter registry with a sorted
      snapshot for deterministic export.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass

SENSITIVE_KEYS: tuple[str, ...] = (
    "token",
    "secret",
    "password",
    "api_key",
    "authorization",
    "cookie",
)


def redact(
    fields: dict[str, object],
    sensitive_keys: tuple[str, ...] = SENSITIVE_KEYS,
) -> dict[str, object]:
    """Return a shallow copy of ``fields`` with sensitive values masked.

    Any key whose lowercased form appears in ``sensitive_keys`` has its value
    replaced by the literal string ``"[REDACTED]"``. All other keys pass through
    unchanged (values are copied by reference, not deep-copied). Non-string keys
    can never match ``sensitive_keys`` and are preserved as-is.
    """
    lowered = {key.lower() for key in sensitive_keys}
    redacted: dict[str, object] = {}
    for key, value in fields.items():
        if isinstance(key, str) and key.lower() in lowered:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def log_event(logger: logging.Logger, event_type: str, **fields: object) -> None:
    """Emit one structured JSON log line via ``logger.info``.

    The record message is ``"capmesh." + event_type + " " + <json>`` where
    ``<json>`` is ``json.dumps(redact(fields), sort_keys=True, separators=(",", ":"))``.
    The compact separators keep the payload on a single line with no embedded
    newlines (``json.dumps`` escapes control characters in string values).

    If a field value is not JSON-serializable, the first ``json.dumps`` call
    raises ``TypeError``; the call is retried with ``default=str`` so the value
    is stringified rather than crashing the caller.
    """
    redacted = redact(fields)
    try:
        payload = json.dumps(redacted, sort_keys=True, separators=(",", ":"))
    except TypeError:
        payload = json.dumps(
            redacted, sort_keys=True, separators=(",", ":"), default=str
        )
    logger.info(f"capmesh.{event_type} {payload}")


@dataclass
class GateDecision:
    """A single gate-evaluation outcome.

    ``outcome`` is one of ``"passed"``, ``"failed"`` or ``"skipped"``.
    ``request_id`` may be ``None`` when no request correlation id is available.
    """

    gate_name: str
    capability_uri: str
    outcome: str
    request_id: str | None
    reason: str


def format_gate_decision(decision: GateDecision) -> dict[str, object]:
    """Return the stable wire-shape dict for a ``GateDecision``.

    Key names are camelCase (``gateName``, ``capabilityUri``, ``requestId``)
    so downstream parsers see a fixed contract regardless of the Python field
    names. ``requestId`` carries the ``request_id`` value, or ``None``.
    """
    return {
        "gateName": decision.gate_name,
        "capabilityUri": decision.capability_uri,
        "outcome": decision.outcome,
        "requestId": decision.request_id,
        "reason": decision.reason,
    }


class MetricsRegistry:
    """An in-memory counter registry.

    Counters are created on first ``increment`` (seeded at 0) and never removed.
    ``snapshot`` returns a fresh dict ordered by sorted key name so exported
    output is deterministic.

    Thread-safe: an internal lock guards the check-then-set increment and the
    dict-copy snapshot so concurrent callers (gate evaluations, /metrics scrape,
    CLI) cannot race on dict resize (audit finding #45).
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def increment(self, name: str, by: int = 1) -> None:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = 0
            self._counters[name] += by

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {key: self._counters[key] for key in sorted(self._counters)}
