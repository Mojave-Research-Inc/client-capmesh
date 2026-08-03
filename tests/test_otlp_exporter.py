"""Tests for ``capmesh.otlp_exporter`` (CM-13-full OTel trace export, slice 2+).

These pin the self-contained OTLP/HTTP JSON exporter: the per-value OTLP
attribute wrapper, single-span conversion (parent omission, typed attribute
values, status normalisation, event shaping), the ``resourceSpans`` envelope
(including the wired-in OTel ``Resource`` attributes and the module-level
``DEFAULT_RESOURCE``), endpoint resolution from env, and the best-effort
``export`` / ``flush_tracer`` contract (True on HTTP 200,
False-and-never-raise on any error, True for an empty tracer without any
network call).

The module under test imports the standard library plus ``.otel_resource``
at runtime and a ``TYPE_CHECKING``-guarded hint from ``.tracing``. The span
conversion / envelope tests use a lightweight stub span (no ``capmesh.tracing``
import needed); the ``flush_tracer`` tests exercise the real ``Tracer`` from
``capmesh.tracing`` (now landed) end-to-end through ``ended_spans`` ->
``encode_batch`` -> ``export``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Self

from capmesh.otel_resource import Resource
from capmesh.otlp_exporter import (
    DEFAULT_ENDPOINT,
    DEFAULT_RESOURCE,
    OtlpExporter,
    _value_to_otlp,
    encode_batch,
    span_to_otlp,
)
from capmesh.tracing import Tracer


class _StubContext:
    """Minimal stand-in for ``capmesh.tracing.SpanContext``."""

    def __init__(self, trace_id="t" * 32, span_id="s" * 16, trace_flags=0):
        self.trace_id = trace_id
        self.span_id = span_id
        self.trace_flags = trace_flags


class _StubSpan:
    """Minimal duck-typed stand-in for ``capmesh.tracing.Span``.

    Carries exactly the structural attributes ``span_to_otlp`` reads. No
    ``isinstance`` check is performed by the exporter, so this stub is
    sufficient to exercise the conversion.
    """

    def __init__(
        self,
        name="g",
        trace_id="t" * 32,
        span_id="s" * 16,
        trace_flags=0,
        parent_span_id=None,
        start_time_ns=1,
        end_time_ns=2,
        attributes=None,
        events=None,
        status="ok",
        status_description="done",
    ):
        self.name = name
        self.context = _StubContext(
            trace_id=trace_id, span_id=span_id, trace_flags=trace_flags
        )
        self.parent_span_id = parent_span_id
        self.start_time_ns = start_time_ns
        self.end_time_ns = end_time_ns
        self.attributes = attributes if attributes is not None else {}
        self.events = events if events is not None else []
        self.status = status
        self.status_description = status_description


class _FakeResponse:
    """Minimal stand-in for an ``urllib`` HTTP 200 response.

    Shared by the ``export`` / ``flush_tracer`` tests that patch
    ``urllib.request.urlopen``: supports the context-manager protocol used by
    the exporter (``with urlopen(...) as response``) and reports a 200 status.
    """

    status = 200

    def read(self) -> bytes:
        return b""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_span_to_otlp_basic() -> None:
    span = _StubSpan(
        name="g",
        trace_id="t" * 32,
        span_id="s" * 16,
        parent_span_id=None,
        start_time_ns=1,
        end_time_ns=2,
        attributes={"k": "v", "n": 3, "flag": True, "f": 1.5},
        events=[{"name": "e", "time_ns": 5, "attributes": {}}],
        status="ok",
        status_description="done",
    )
    result = span_to_otlp(span)

    assert result["traceId"] == "t" * 32
    assert result["spanId"] == "s" * 16
    assert result["name"] == "g"
    assert result["kind"] == "SPAN_KIND_INTERNAL"
    assert result["startTimeUnixNano"] == "1"
    assert result["endTimeUnixNano"] == "2"
    # parent_span_id is None -> the key is omitted entirely, not emitted null.
    assert "parentSpanId" not in result

    attrs = {a["key"]: a["value"] for a in result["attributes"]}
    assert attrs["k"] == {"stringValue": "v"}
    assert attrs["n"] == {"intValue": "3"}
    assert attrs["flag"] == {"boolValue": True}
    assert attrs["f"] == {"doubleValue": 1.5}

    assert result["events"] == [
        {"name": "e", "timeUnixNano": "5", "attributes": []}
    ]

    assert result["status"] == {"code": "OK", "message": "done"}


def test_span_to_otlp_with_parent() -> None:
    span = _StubSpan(parent_span_id="p" * 16)
    result = span_to_otlp(span)
    assert result["parentSpanId"] == "p" * 16


def test_encode_batch_envelope() -> None:
    span = _StubSpan()
    envelope = encode_batch([span])

    rs = envelope["resourceSpans"]
    assert len(rs) == 1
    assert rs[0]["resource"] == {"attributes": []}

    ss = rs[0]["scopeSpans"]
    assert len(ss) == 1
    assert ss[0]["scope"] == {"name": "capmesh"}
    assert len(ss[0]["spans"]) == 1
    assert ss[0]["spans"][0]["name"] == span.name


def test_value_to_otlp_types() -> None:
    assert _value_to_otlp("x") == {"stringValue": "x"}
    assert _value_to_otlp(3) == {"intValue": "3"}
    assert _value_to_otlp(True) == {"boolValue": True}
    assert _value_to_otlp(1.5) == {"doubleValue": 1.5}
    obj = object()
    assert _value_to_otlp(obj) == {"stringValue": str(obj)}


def test_export_success() -> None:
    original_urlopen = urllib.request.urlopen

    class _FakeResponse:
        status = 200

        def read(self) -> bytes:
            return b""

        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    def _fake_urlopen(_request, timeout=None):
        return _FakeResponse()

    urllib.request.urlopen = _fake_urlopen
    try:
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        assert exporter.export([_StubSpan()]) is True
    finally:
        urllib.request.urlopen = original_urlopen


def test_export_failure_returns_false_never_raises() -> None:
    original_urlopen = urllib.request.urlopen

    def _raise_urlopen(_request, timeout=None):
        raise urllib.error.URLError("x")

    urllib.request.urlopen = _raise_urlopen
    try:
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        result = exporter.export([_StubSpan()])
        assert result is False
    finally:
        urllib.request.urlopen = original_urlopen


def test_endpoint_from_env() -> None:
    key = "OTEL_EXPORTER_OTLP_ENDPOINT"
    original = os.environ.get(key)
    try:
        os.environ[key] = "http://env.example/v1/traces"
        exporter = OtlpExporter()
        assert exporter.endpoint == "http://env.example/v1/traces"

        os.environ.pop(key, None)
        exporter = OtlpExporter()
        assert exporter.endpoint == DEFAULT_ENDPOINT
    finally:
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original


# --- slice 2+: Resource wiring + flush_tracer ---


def test_encode_batch_with_resource() -> None:
    span = _StubSpan()
    resource = Resource(
        attributes={"service.name": "capmesh", "service.version": "1.0"}
    )
    envelope = encode_batch([span], resource=resource)

    rs = envelope["resourceSpans"]
    assert len(rs) == 1
    # ``Resource.to_otlp_attributes`` sorts by key, so service.name precedes
    # service.version.
    assert rs[0]["resource"]["attributes"] == [
        {"key": "service.name", "value": {"stringValue": "capmesh"}},
        {"key": "service.version", "value": {"stringValue": "1.0"}},
    ]
    # The scopeSpans shape is unchanged by the resource wiring.
    ss = rs[0]["scopeSpans"]
    assert len(ss) == 1
    assert ss[0]["scope"] == {"name": "capmesh"}
    assert len(ss[0]["spans"]) == 1


def test_encode_batch_default_empty_resource() -> None:
    span = _StubSpan()
    envelope = encode_batch([span])

    rs = envelope["resourceSpans"]
    assert len(rs) == 1
    # Omitting ``resource`` selects ``EMPTY_RESOURCE`` -> empty attributes list,
    # preserving the original slice's envelope shape (backward-compat).
    assert rs[0]["resource"]["attributes"] == []


def test_default_resource_module_constant() -> None:
    assert isinstance(DEFAULT_RESOURCE, Resource)
    assert "service.name" in DEFAULT_RESOURCE.attributes
    # The default service.name is "capmesh" unless ``OTEL_SERVICE_NAME``
    # overrides it in the running environment; ``DEFAULT_RESOURCE`` was built
    # at import time so it already reflects whichever value was present then.
    env_name = os.environ.get("OTEL_SERVICE_NAME")
    if not env_name:
        assert DEFAULT_RESOURCE.attributes["service.name"] == "capmesh"
    else:
        assert DEFAULT_RESOURCE.attributes["service.name"] == env_name


def test_export_with_resource_threads_through() -> None:
    original_urlopen = urllib.request.urlopen
    captured: dict[str, bytes] = {}

    def _fake_urlopen(request, timeout=None):
        captured["body"] = request.data
        return _FakeResponse()

    urllib.request.urlopen = _fake_urlopen
    try:
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        resource = Resource(attributes={"service.name": "x"})
        assert exporter.export([_StubSpan()], resource=resource) is True
    finally:
        urllib.request.urlopen = original_urlopen

    body = json.loads(captured["body"].decode("utf-8"))
    rs = body["resourceSpans"]
    assert len(rs) == 1
    assert {"key": "service.name", "value": {"stringValue": "x"}} in rs[0][
        "resource"
    ]["attributes"]


def test_flush_tracer_empty_returns_true() -> None:
    original_urlopen = urllib.request.urlopen
    calls: list[object] = []

    def _fake_urlopen(_request, timeout=None):
        calls.append(_request)
        raise AssertionError("urlopen must not be called for an empty tracer")

    urllib.request.urlopen = _fake_urlopen
    try:
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        assert exporter.flush_tracer(Tracer()) is True
    finally:
        urllib.request.urlopen = original_urlopen
    assert calls == []


def test_flush_tracer_with_spans() -> None:
    original_urlopen = urllib.request.urlopen
    captured: dict[str, bytes] = {}

    def _fake_urlopen(request, timeout=None):
        captured["body"] = request.data
        return _FakeResponse()

    urllib.request.urlopen = _fake_urlopen
    try:
        tracer = Tracer()
        span = tracer.start_span("work", start_time_ns=10)
        span.end(20)
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        assert exporter.flush_tracer(tracer) is True
    finally:
        urllib.request.urlopen = original_urlopen

    body = json.loads(captured["body"].decode("utf-8"))
    spans = body["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == "work"
    assert spans[0]["traceId"] == span.context.trace_id
    # The span's traceId is present and non-empty on the wire.
    assert spans[0]["traceId"]


def test_flush_tracer_failure_never_raises() -> None:
    original_urlopen = urllib.request.urlopen

    def _raise_urlopen(_request, timeout=None):
        raise urllib.error.URLError("boom")

    urllib.request.urlopen = _raise_urlopen
    try:
        tracer = Tracer()
        span = tracer.start_span("work", start_time_ns=10)
        span.end(20)
        exporter = OtlpExporter(endpoint="http://example/v1/traces")
        result = exporter.flush_tracer(tracer)
        assert result is False
    finally:
        urllib.request.urlopen = original_urlopen
