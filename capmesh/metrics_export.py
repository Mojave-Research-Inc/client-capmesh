"""Bounded, self-contained Prometheus text-exposition helpers.

Second slice of plan item CM-13 (metrics). This module renders the in-memory
counters held by ``capmesh.observability.MetricsRegistry`` into the Prometheus
text exposition format so a later wave can serve the output from a
``/metrics`` HTTP endpoint.

The module is a standalone text renderer: it imports ONLY the Python standard
library (``re`` for character sanitisation) and, under ``TYPE_CHECKING`` only,
``MetricsRegistry`` from ``.observability`` for static type hints. It has no
runtime dependency on any other ``capmesh`` module -- in particular it never
imports ``governance``, ``server`` or ``lifecycle`` -- so it can be used
without risking import cycles.

Provided surface:
    * ``METRIC_PREFIX`` -- ``"capmesh_"`` namespace prefix for exported metrics.
    * ``sanitize_metric_name`` -- map an arbitrary counter name onto a valid
      Prometheus metric name (``[a-zA-Z_:][a-zA-Z0-9_:]*``).
    * ``render_counter`` -- render a single counter to a 3-line HELP/TYPE/sample
      exposition block.
    * ``render_prometheus`` -- render a whole registry snapshot to a Prometheus
      text exposition string.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Imported only for static type hints; never used at runtime so the module
    # stays free of any cross-module dependency.
    from .observability import MetricsRegistry

METRIC_PREFIX = "capmesh_"

# Prometheus metric names must match [a-zA-Z_:][a-zA-Z0-9_:]*. Any character
# outside this set is collapsed to a single underscore by ``sanitize_metric_name``.
_INVALID_METRIC_CHARS = re.compile(r"[^a-zA-Z0-9_:]")


def sanitize_metric_name(name: str) -> str:
    """Return a valid Prometheus metric name derived from ``name``.

    The transform is deterministic and idempotent:

    1. Every character not in ``[a-zA-Z0-9_:]`` becomes ``"_"`` so a dotted
       counter like ``"gate.signature.passed"`` maps to
       ``"gate_signature_passed"``.
    2. If the result does not already start with ``METRIC_PREFIX``
       (``"capmesh_"``) or an underscore, ``METRIC_PREFIX`` is prepended so
       every exported name lives under the ``capmesh_`` namespace and cannot
       collide with other exporters. This keeps the step idempotent: a name
       that already carries the prefix is not prefixed again.
    3. As a final guard, if the result would still start with a digit (a
       metric name must begin with a letter or underscore), ``METRIC_PREFIX``
       is prepended once more -- e.g. ``"2gates"`` -> ``"capmesh_2gates"``.
    """
    sanitized = _INVALID_METRIC_CHARS.sub("_", name)
    if not sanitized.startswith((METRIC_PREFIX, "_")):
        sanitized = METRIC_PREFIX + sanitized
    if sanitized[:1].isdigit():
        sanitized = METRIC_PREFIX + sanitized
    return sanitized


def render_counter(name: str, value: int) -> str:
    """Render a single counter to a 3-line Prometheus exposition block.

    The block is ``# HELP``, ``# TYPE`` and one sample line, joined by newlines
    with no trailing newline: callers such as :func:`render_prometheus` insert
    the separators between blocks and the final trailing newline. The metric
    name is run through :func:`sanitize_metric_name` so a counter name like
    ``"foo"`` is emitted as ``capmesh_foo``.
    """
    metric = sanitize_metric_name(name)
    help_line = f"# HELP {metric} capmesh counter"
    type_line = f"# TYPE {metric} counter"
    sample_line = f"{metric} {value}"
    return f"{help_line}\n{type_line}\n{sample_line}"


def render_prometheus(registry: MetricsRegistry) -> str:
    """Render ``registry.snapshot()`` to a Prometheus text exposition string.

    Accepts any object exposing a ``snapshot()`` method returning a mapping of
    counter name to integer count (duck-typed; no ``isinstance`` check is
    performed). For each ``(name, value)`` pair in sorted-by-name order the
    function emits a :func:`render_counter` block. Blocks are newline-separated
    and the output ends with a single trailing newline.

    Returns ``""`` (empty string, no lines) when the snapshot is empty.
    """
    snapshot = registry.snapshot()
    if not snapshot:
        return ""
    blocks = [render_counter(name, value) for name, value in sorted(snapshot.items())]
    return "\n".join(blocks) + "\n"
