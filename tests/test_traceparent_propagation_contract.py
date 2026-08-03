"""Contract tests for W3C traceparent + parent-child span propagation.

These lock the cross-module contracts in ``capmesh.tracing`` and
``capmesh.otlp_exporter`` that the server/router HTTP wiring depends on:

* ``format_traceparent`` / ``parse_traceparent`` shape, roundtrip, case
  handling and rejection of malformed headers.
* ``Tracer.start_span`` root-vs-child semantics: fresh trace id for roots,
  inherited trace id + trace_flags for children, and the precedence of an
  explicit ``parent_span_id`` argument over ``parent_context.span_id``.
* ``encode_batch`` OTLP envelope shape, including omission of
  ``parentSpanId`` for root spans and inclusion of ``parentSpanId`` for
  child spans (matching ``span_to_otlp``).
* The inbound-traceparent seeding contract: an inbound traceparent header
  parsed into a ``SpanContext`` and passed as ``parent_context`` reuses the
  inbound trace id, mints a fresh span id, and sets the inbound span id as
  the parent.

The module under test imports only the standard library and accepts
caller-provided timestamps, so these tests are deterministic (no real
clock, no network).
"""

from __future__ import annotations

import re

from capmesh.otlp_exporter import encode_batch
from capmesh.tracing import (
    SpanContext,
    Tracer,
    format_traceparent,
    parse_traceparent,
)

_HEX = r"^[0-9a-f]+$"


def test_format_traceparent_shape() -> None:
    ctx = SpanContext(trace_id="a" * 32, span_id="b" * 16, trace_flags="01")
    assert format_traceparent(ctx) == "00-" + "a" * 32 + "-" + "b" * 16 + "-01"


def test_traceparent_roundtrip() -> None:
    cases = [
        SpanContext(trace_id="a" * 32, span_id="b" * 16, trace_flags="01"),
        SpanContext(trace_id="a" * 32, span_id="b" * 16, trace_flags="00"),
        SpanContext(
            trace_id="0123456789abcdef0123456789abcdef",
            span_id="0123456789abcdef",
            trace_flags="01",
        ),
        SpanContext(
            trace_id="fedcba0987654321fedcba0987654321",
            span_id="fedcba0987654321",
            trace_flags="00",
        ),
    ]
    for ctx in cases:
        parsed = parse_traceparent(format_traceparent(ctx))
        assert parsed is not None
        assert parsed.trace_id == ctx.trace_id.lower()
        assert parsed.span_id == ctx.span_id.lower()
        assert parsed.trace_flags == ctx.trace_flags.lower()
        assert parsed.trace_state == ""


def test_parse_traceparent_rejects_invalid() -> None:
    # Wrong version.
    assert parse_traceparent("01-" + "a" * 32 + "-" + "b" * 16 + "-01") is None
    # Wrong field count.
    assert parse_traceparent("00-aa-bb") is None
    # trace_id wrong length (31 chars).
    assert parse_traceparent("00-" + "a" * 31 + "-" + "b" * 16 + "-01") is None
    # span_id wrong length (15 chars).
    assert parse_traceparent("00-" + "a" * 32 + "-" + "b" * 15 + "-01") is None
    # Non-hex char in trace_id.
    bad_trace = "00-" + "z" + "a" * 31 + "-" + "b" * 16 + "-01"
    assert parse_traceparent(bad_trace) is None
    # trace_flags wrong length (3 chars).
    assert parse_traceparent("00-" + "a" * 32 + "-" + "b" * 16 + "-001") is None


def test_parse_traceparent_case_insensitive_lowercased() -> None:
    parsed = parse_traceparent("00-" + "A" * 32 + "-" + "B" * 16 + "-01")
    assert parsed is not None
    assert parsed.trace_id == "a" * 32
    assert parsed.span_id == "b" * 16
    assert parsed.trace_flags == "01"


def test_start_span_root_has_no_parent() -> None:
    tracer = Tracer()
    span = tracer.start_span("root", start_time_ns=0)
    assert span.parent_span_id is None
    assert re.match(_HEX, span.context.trace_id) is not None
    assert len(span.context.trace_id) == 32
    assert re.match(_HEX, span.context.span_id) is not None
    assert len(span.context.span_id) == 16
    assert span.context.trace_id != span.context.span_id
    assert span.context.trace_flags == "01"


def test_start_span_child_inherits_parent_context() -> None:
    tracer = Tracer()
    parent = tracer.start_span("parent", start_time_ns=0)
    child = tracer.start_span("child", start_time_ns=1, parent_context=parent.context)
    assert child.context.trace_id == parent.context.trace_id
    assert child.context.span_id != parent.context.span_id
    assert child.parent_span_id == parent.context.span_id
    assert child.context.trace_flags == parent.context.trace_flags


def test_start_span_explicit_parent_span_id_overrides() -> None:
    tracer = Tracer()
    parent = tracer.start_span("parent", start_time_ns=0)
    explicit = "c" * 16
    child = tracer.start_span(
        "child",
        start_time_ns=1,
        parent_context=parent.context,
        parent_span_id=explicit,
    )
    assert child.parent_span_id == explicit
    assert child.parent_span_id != parent.context.span_id
    assert child.context.trace_id == parent.context.trace_id


def test_start_span_explicit_parent_span_id_without_context() -> None:
    tracer = Tracer()
    child = tracer.start_span("child", start_time_ns=0, parent_span_id="d" * 16)
    assert child.parent_span_id == "d" * 16
    # No parent_context -> root trace: fresh 32-hex trace id.
    assert re.match(_HEX, child.context.trace_id) is not None
    assert len(child.context.trace_id) == 32
    assert re.match(_HEX, child.context.span_id) is not None
    assert len(child.context.span_id) == 16


def test_encode_batch_omits_parent_span_id_for_root() -> None:
    tracer = Tracer()
    root = tracer.start_span("root", start_time_ns=0)
    root.end(10)
    otlp = encode_batch([root])
    span_dict = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert "parentSpanId" not in span_dict


def test_encode_batch_preserves_parent_span_id_for_child() -> None:
    tracer = Tracer()
    parent = tracer.start_span("parent", start_time_ns=0)
    child = tracer.start_span("child", start_time_ns=1, parent_context=parent.context)
    parent.end(2)
    child.end(3)
    otlp = encode_batch([child])
    span_dict = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert span_dict["parentSpanId"] == parent.context.span_id


def test_inbound_traceparent_seeds_child_trace() -> None:
    ctx = parse_traceparent("00-" + "a" * 32 + "-" + "b" * 16 + "-01")
    assert ctx is not None
    tracer = Tracer()
    req = tracer.start_span("request", start_time_ns=0, parent_context=ctx)
    # Inbound trace id is reused.
    assert req.context.trace_id == "a" * 32
    # A fresh span id is minted (not the inbound span id).
    assert req.context.span_id != "b" * 16
    # The inbound span id becomes the parent.
    assert req.parent_span_id == "b" * 16
