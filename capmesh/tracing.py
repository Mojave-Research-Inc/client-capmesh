"""Bounded, self-contained OpenTelemetry-style tracing span model.

Slice 1 of plan item CM-13-full (OTel trace export). ``observability`` already
provides structured logs and a metrics counter registry; this module adds the
SPAN model for distributed traces. A later wave wires it into the gate runner
(``lifecycle.py``) and the request path (``server.py`` / ``router.py``); this
slice ships the model only.

This module imports ONLY the Python standard library and has no dependency on
any other ``capmesh`` module. It makes no ``datetime.now`` / ``time.time``
calls: all timestamps are caller-provided (``start_time_ns``, ``end_time_ns``,
event ``time_ns``), and id randomness comes from ``os.urandom`` (a CSPRNG, not
a clock), so the module is deterministic and testable.

Provided surface:
    * ``SpanContext`` -- W3C trace identity (trace_id, span_id, flags, state).
    * ``generate_trace_id`` / ``generate_span_id`` -- lowercase hex ids.
    * ``format_traceparent`` / ``parse_traceparent`` -- W3C traceparent header.
    * ``Span`` -- a unit of work: attributes, events, status, idempotent end.
    * ``Tracer`` -- mints spans and records ended spans for later export.
    * ``set_request_context`` / ``get_request_context`` -- stdlib ContextVar
      helpers for in-process request-span propagation (router sets, lifecycle
      reads) so gate spans link to the in-flight request span's trace.
"""

from __future__ import annotations

import contextvars
import os
from collections import deque
from dataclasses import dataclass, field

_TRACER_MAX_ENDED = int(os.environ.get("CAPMESH_TRACER_MAX_ENDED", "4096"))
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# CM-13-full request-context propagation: a stdlib ContextVar carrying the
# current request span's SpanContext. The HTTP request path (router.py) sets
# this when its ``request`` span starts and resets it when the dispatch ends;
# the gate runner (lifecycle.py) reads it to make gate spans children of the
# in-flight request span (same trace_id, gate span.parent_span_id == request
# span.span_id). With no request context set (e.g. a CLI ``capmesh gates`` run
# or a direct unit-test call) the value is None and gate spans remain root
# spans, preserving the prior behavior. The module stays stdlib-only.
_CURRENT_REQUEST_CONTEXT: contextvars.ContextVar[SpanContext | None] = (
    contextvars.ContextVar("capmesh_current_request_context", default=None)
)


@dataclass
class _RequestContextToken:
    """Opaque reset handle returned by ``set_request_context``.

    Wraps the raw stdlib ``contextvars.Token`` so the caller API matches the
    brief's ``token.reset()`` shape (the raw ``contextvars.Token`` has no
    ``reset`` method; reset is ``ContextVar.reset(token)``). ``reset`` is
    idempotent: a second call is a no-op so a double-finally never raises.
    """

    _token: contextvars.Token[SpanContext | None] = field()

    def reset(self) -> None:
        """Restore the request-context value that was active before the set.

        Safe to call more than once; only the first call touches the contextvar.
        """
        if self._token is None:
            return
        try:
            _CURRENT_REQUEST_CONTEXT.reset(self._token)
        except ValueError:
            # The token was already consumed (reset called twice, or the
            # contextvar context changed). Idempotent reset never raises.
            return
        self._token = None  # type: ignore[assignment]


def set_request_context(ctx: SpanContext | None) -> _RequestContextToken:
    """Bind ``ctx`` as the current request span context; return a reset handle.

    The caller MUST call ``reset()`` on the returned handle in a finally so the
    contextvar does not leak across requests (a leaked contextvar would wrongly
    link unrelated later gate spans to a stale request). Passing ``None`` is
    valid (clears the current context) and yields a handle that restores the
    prior value.
    """
    return _RequestContextToken(_token=_CURRENT_REQUEST_CONTEXT.set(ctx))


def get_request_context() -> SpanContext | None:
    """Return the current request span context, or None when none is set."""
    return _CURRENT_REQUEST_CONTEXT.get()


def _is_hex_of_length(value: str, length: int) -> bool:
    """Return True iff ``value`` is exactly ``length`` hex chars (any case).

    A character-class check is used rather than ``int(value, 16)`` so that an
    embedded ``0x`` prefix (which ``int`` with base 16 silently accepts) cannot
    sneak a non-hex character past validation.
    """
    if len(value) != length:
        return False
    return all(ch in _HEX_DIGITS for ch in value)


def generate_trace_id() -> str:
    """Return a fresh 32-char lowercase hex trace id."""
    return os.urandom(16).hex()


def generate_span_id() -> str:
    """Return a fresh 16-char lowercase hex span id."""
    return os.urandom(8).hex()


@dataclass
class SpanContext:
    """W3C trace-context identity for a span.

    ``trace_id`` is 32 hex chars, ``span_id`` is 16 hex chars, ``trace_flags``
    is 2 hex chars (default ``"01"`` = sampled), and ``trace_state`` is the
    vendor extension string (default empty). No validation is performed in the
    constructor; ``parse_traceparent`` validates inputs arriving from the wire.
    """

    trace_id: str
    span_id: str
    trace_flags: str = "01"
    trace_state: str = ""


def format_traceparent(ctx: SpanContext) -> str:
    """Format ``ctx`` as a W3C traceparent header: ``00-<trace_id>-<span_id>-<flags>``."""
    return f"00-{ctx.trace_id}-{ctx.span_id}-{ctx.trace_flags}"


def parse_traceparent(header: str) -> SpanContext | None:
    """Parse a W3C traceparent header into a ``SpanContext`` or return None.

    The expected format is ``00-<trace_id 32 hex>-<span_id 16 hex>-<flags 2 hex>``.
    Returns None when the header has the wrong number of dash-separated fields,
    a version other than ``00``, any segment of the wrong length, or any
    non-hex character. Hex is matched case-insensitively and emitted lowercase;
    ``trace_state`` is always empty on the parsed context (it travels in the
    separate ``tracestate`` header, not traceparent).
    """
    parts = header.split("-")
    if len(parts) != 4:
        return None
    version, trace_id, span_id, trace_flags = parts
    if version.lower() != "00":
        return None
    if not _is_hex_of_length(trace_id, 32):
        return None
    if not _is_hex_of_length(span_id, 16):
        return None
    if not _is_hex_of_length(trace_flags, 2):
        return None
    return SpanContext(
        trace_id=trace_id.lower(),
        span_id=span_id.lower(),
        trace_flags=trace_flags.lower(),
        trace_state="",
    )


@dataclass
class Span:
    """A single unit of work in a distributed trace.

    Timing is caller-provided: ``start_time_ns`` is required at construction
    and ``end_time_ns`` is set by an explicit ``end(end_time_ns)`` call.
    ``attributes`` maps string keys to scalar values (str/int/bool/float);
    ``events`` is an ordered list of ``{"name", "time_ns", "attributes"}``
    dicts appended via ``add_event``. ``status`` is one of ``"unset"``,
    ``"ok"`` or ``"error"`` (default ``"unset"``).

    ``end`` is idempotent: the first call records ``end_time_ns`` and notifies
    the owning ``Tracer`` (if any) so the span appears in ``ended_spans()``;
    later calls are no-ops. ``duration_ns`` returns ``end_time_ns -
    start_time_ns`` once ended, else ``0``.
    """

    name: str
    context: SpanContext
    start_time_ns: int
    parent_span_id: str | None = None
    end_time_ns: int | None = None
    attributes: dict[str, str | int | bool | float] = field(default_factory=dict)
    events: list[dict[str, object]] = field(default_factory=list)
    status: str = "unset"
    status_description: str = ""
    _tracer: Tracer | None = field(default=None, repr=False, compare=False)

    def set_attribute(
        self, key: str, value: str | int | bool | float  # noqa: PYI041
    ) -> None:
        """Set ``attributes[key] = value`` (overwriting any prior value).

        ``int`` is kept explicit alongside ``float`` (even though ``int`` is a
        subtype of ``float``) so callers see the full set of attribute scalar
        types the ``attributes`` dict stores; PYI041 is suppressed for that
        documentation value.
        """
        self.attributes[key] = value

    def add_event(
        self, name: str, time_ns: int, attributes: dict[str, object] | None = None
    ) -> None:
        """Append a ``{"name", "time_ns", "attributes"}`` event to ``events``."""
        self.events.append(
            {"name": name, "time_ns": time_ns, "attributes": attributes or {}}
        )

    def set_status(self, status: str, description: str = "") -> None:
        """Set ``status`` and ``status_description``."""
        self.status = status
        self.status_description = description

    def end(self, end_time_ns: int) -> None:
        """Record ``end_time_ns`` once; subsequent calls are no-ops."""
        if self.end_time_ns is not None:
            return
        self.end_time_ns = end_time_ns
        if self._tracer is not None:
            self._tracer._record_end(self)

    def duration_ns(self) -> int:
        """Return ``end_time_ns - start_time_ns``, or 0 if not yet ended."""
        if self.end_time_ns is None:
            return 0
        return self.end_time_ns - self.start_time_ns


class Tracer:
    """Mints spans for a service and records ended spans for export.

    ``start_span`` creates a fresh ``SpanContext``: a new ``trace_id`` when no
    ``parent_context`` is given, or the parent's ``trace_id`` and ``trace_flags``
    when one is; the ``span_id`` is always fresh. The ``parent_span_id`` is the
    explicit argument when present, else ``parent_context.span_id`` when a
    parent is supplied, else ``None`` for a root span. The Tracer does NOT
    auto-end spans; callers must call ``Span.end``. ``ended_spans`` returns a
    fresh list of spans that have had ``end`` called, in end order.
    """

    def __init__(self, service_name: str = "capmesh") -> None:
        self.service_name = service_name
        self._ended: deque[Span] = deque(maxlen=_TRACER_MAX_ENDED)

    def start_span(
        self,
        name: str,
        *,
        start_time_ns: int,
        parent_context: SpanContext | None = None,
        parent_span_id: str | None = None,
    ) -> Span:
        if parent_context is None:
            trace_id = generate_trace_id()
            trace_flags = "01"
        else:
            trace_id = parent_context.trace_id
            trace_flags = parent_context.trace_flags
        context = SpanContext(
            trace_id=trace_id,
            span_id=generate_span_id(),
            trace_flags=trace_flags,
            trace_state="",
        )
        if parent_span_id is None and parent_context is not None:
            parent_span_id = parent_context.span_id
        return Span(
            name=name,
            context=context,
            start_time_ns=start_time_ns,
            parent_span_id=parent_span_id,
            _tracer=self,
        )

    def _record_end(self, span: Span) -> None:
        self._ended.append(span)

    def ended_spans(self) -> list[Span]:
        return list(self._ended)
