"""Tests for ``capmesh.tracing`` (CM-13-full slice 1: span model).

These pin the self-contained tracing surface: hex id generation, W3C
traceparent format/parse roundtrip and rejection of malformed headers, span
attribute/event/status mutation, idempotent end plus duration, and the Tracer's
trace-id reuse for child spans plus ended-span tracking. The module under test
imports only the standard library and accepts caller-provided timestamps, so
these tests are fully deterministic (no real clock is involved).
"""

from __future__ import annotations

import re

from capmesh.tracing import (
    Span,
    SpanContext,
    Tracer,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_request_context,
    parse_traceparent,
    set_request_context,
)


def test_generate_ids_hex_length() -> None:
    tid = generate_trace_id()
    sid = generate_span_id()
    assert len(tid) == 32
    assert len(sid) == 16
    assert re.match(r"^[0-9a-f]+$", tid) is not None
    assert re.match(r"^[0-9a-f]+$", sid) is not None


def test_format_parse_traceparent_roundtrip() -> None:
    ctx = SpanContext(trace_id="a" * 32, span_id="b" * 16, trace_flags="01")
    tp = format_traceparent(ctx)
    assert tp == f"00-{'a' * 32}-{'b' * 16}-01"
    parsed = parse_traceparent(tp)
    assert parsed is not None
    assert parsed == ctx


def test_parse_traceparent_invalid_returns_none() -> None:
    assert parse_traceparent("garbage") is None
    assert parse_traceparent("00-short-sid-01") is None
    assert parse_traceparent("01-...-...-01") is None


def test_span_set_attribute_add_event_status() -> None:
    ctx = SpanContext(trace_id="0" * 32, span_id="1" * 16)
    span = Span(name="http", context=ctx, start_time_ns=0)
    span.set_attribute("http.method", "GET")
    span.add_event("dispatch", 12345, {"k": "v"})
    span.set_status("ok", "done")
    assert span.attributes == {"http.method": "GET"}
    assert span.events == [
        {"name": "dispatch", "time_ns": 12345, "attributes": {"k": "v"}}
    ]
    assert span.status == "ok"
    assert span.status_description == "done"


def test_span_end_idempotent_and_duration() -> None:
    ctx = SpanContext(trace_id="0" * 32, span_id="1" * 16)
    span = Span(name="op", context=ctx, start_time_ns=1000)
    span.end(2000)
    span.end(3000)
    assert span.end_time_ns == 2000
    assert span.duration_ns() == 1000


def test_tracer_child_span_reuses_trace_id() -> None:
    tracer = Tracer()
    root = tracer.start_span("root", start_time_ns=1)
    child = tracer.start_span(
        "child", start_time_ns=2, parent_context=root.context
    )
    assert child.context.trace_id == root.context.trace_id
    assert child.context.span_id != root.context.span_id


def test_tracer_ended_spans() -> None:
    tracer = Tracer()
    span = tracer.start_span("a", start_time_ns=1)
    assert span not in tracer.ended_spans()
    span.end(2)
    assert span in tracer.ended_spans()
    unended = tracer.start_span("b", start_time_ns=3)
    assert unended not in tracer.ended_spans()


def test_tracer_root_span_new_trace_id() -> None:
    tracer = Tracer()
    a = tracer.start_span("a", start_time_ns=1)
    b = tracer.start_span("b", start_time_ns=2)
    assert a.context.trace_id != b.context.trace_id


def test_request_context_set_get_reset() -> None:
    """set_request_context returns a token; get returns it; reset restores None.

    Covers the basic lifecycle: get with no set returns None; set returns a
    token; get after set returns the bound context; reset(token) restores the
    prior value (None here). The contextvar is module-global so reset is
    mandatory to avoid leaking across callers.
    """
    # No request context is set by default; ensure a clean slate first.
    assert get_request_context() is None
    ctx = SpanContext(trace_id="a" * 32, span_id="b" * 16)
    token = set_request_context(ctx)
    assert get_request_context() is ctx
    token.reset()
    assert get_request_context() is None


def test_request_context_nested_set_then_reset_restores_outer() -> None:
    """A nested set within an outer set then inner reset restores the outer ctx.

    Locks the contextvars-stacking contract that the request path relies on:
    an inner ``set`` returns a token whose reset restores the immediately
    preceding value (the outer context), not None.
    """
    outer = SpanContext(trace_id="1" * 32, span_id="2" * 16)
    inner = SpanContext(trace_id="3" * 32, span_id="4" * 16)
    outer_token = set_request_context(outer)
    assert get_request_context() is outer
    inner_token = set_request_context(inner)
    assert get_request_context() is inner
    inner_token.reset()
    assert get_request_context() is outer
    outer_token.reset()
    assert get_request_context() is None
