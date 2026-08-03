"""Bounded, self-contained OTLP/HTTP JSON trace exporter.

Second slice of plan item CM-13-full (OTel trace export). This module
converts ended ``Span`` objects produced by ``capmesh.tracing`` into the
OTLP/HTTP JSON traces envelope and POSTs the payload to an OTLP HTTP
collector endpoint.

The module is a standalone exporter: at runtime it imports the Python
standard library (``json``, ``urllib.request``, ``urllib.error``, ``os``)
plus ``.otel_resource`` (which is itself stdlib-only, so there is no import
cycle). ``Span`` / ``SpanContext`` / ``Tracer`` are imported from ``.tracing``
under ``TYPE_CHECKING`` only, so the exporter never triggers a runtime import
of the tracing module (or of ``governance``, ``server``, ``lifecycle``) and
can be used without risking an import cycle. The exporter is duck-typed: any
object exposing the documented span attributes is accepted, so tests can
exercise it with a lightweight stub instead of the real ``Span``.

No ``time`` / ``datetime`` clock calls are made here -- the exporter reads
``start_time_ns`` / ``end_time_ns`` from the spans it is handed and only
serialises them.

Provided surface:
    * ``DEFAULT_ENDPOINT`` -- the standard OTLP HTTP traces endpoint
      (``http://127.0.0.1:4318/v1/traces``).
    * ``DEFAULT_RESOURCE`` -- a module-level ``Resource`` built once at import
      from the ``OTEL_*`` environment via ``create_resource``; used as the
      default ``resourceSpans`` resource for ``export`` / ``flush_tracer``.
    * ``_value_to_otlp`` -- map a Python attribute value to its OTLP value
      wrapper (``stringValue`` / ``intValue`` / ``boolValue`` / ``doubleValue``).
    * ``span_to_otlp`` -- convert a single duck-typed ``Span`` to an OTLP
      span dict.
    * ``encode_batch`` -- wrap a list of span dicts in the OTLP/HTTP JSON
      ``resourceSpans`` envelope, attaching ``resource`` attributes
      (``EMPTY_RESOURCE`` when omitted, for backward compatibility).
    * ``OtlpExporter`` -- synchronous, best-effort exporter that POSTs the
      encoded batch to an OTLP HTTP endpoint and never raises; ``flush_tracer``
      ships a ``Tracer``'s ended spans in one batch.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

# Runtime import of ``.otel_resource``: that module is stdlib-only (``os``,
# ``dataclasses``) and has no ``capmesh`` dependency, so importing it here
# cannot form a cycle. ``Resource`` / ``EMPTY_RESOURCE`` / ``create_resource``
# are needed at call time (``to_otlp_attributes`` on the encode path and
# ``create_resource`` to build ``DEFAULT_RESOURCE`` at import time).
from .otel_resource import EMPTY_RESOURCE, Resource, create_resource

if TYPE_CHECKING:
    # Imported only for static type hints; never used at runtime so the module
    # stays free of any cross-module dependency and cannot form an import
    # cycle with ``capmesh.tracing`` (which is built by a concurrent lane).
    from .tracing import Span, SpanContext, Tracer

DEFAULT_ENDPOINT = "http://127.0.0.1:4318/v1/traces"

# Module-level default resource computed once at import time from the
# ``OTEL_SERVICE_NAME`` / ``OTEL_RESOURCE_ATTRIBUTES`` environment. Used by
# ``export`` (when no explicit ``resource`` is passed) and ``flush_tracer`` so
# every emitted batch carries a consistent service identity without callers
# having to thread a ``Resource`` through each call site.
DEFAULT_RESOURCE = create_resource()


def _value_to_otlp(value: object) -> dict[str, object]:
    """Map a Python attribute value to its OTLP ``value`` wrapper.

    OTLP attribute values are tagged unions: each carries exactly one of
    ``stringValue``, ``intValue``, ``boolValue`` or ``doubleValue``. The
    integer value is serialised as a string because the protobuf JSON
    mapping represents 64-bit ints as strings (this avoids float precision
    loss when the value round-trips through a JSON-aware collector).

    ``bool`` is tested before ``int`` because ``bool`` is a subclass of
    ``int`` in Python -- without that ordering ``True`` would be emitted as
    ``intValue:"True"`` instead of ``boolValue:true``. Any type that is not
    a ``str`` / ``bool`` / ``int`` / ``float`` falls back to ``stringValue``
    with the value coerced via ``str()``.
    """
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def span_to_otlp(span: Span) -> dict[str, object]:
    """Convert a duck-typed ``Span`` to an OTLP-style span dict.

    The span is accessed structurally (``.name``, ``.context.trace_id``,
    ``.context.span_id``, ``.parent_span_id``, ``.start_time_ns``,
    ``.end_time_ns``, ``.attributes``, ``.events``, ``.status``,
    ``.status_description``) so any object with those attributes works; no
    ``isinstance`` check is performed. ``parentSpanId`` is omitted entirely
    when ``parent_span_id`` is ``None`` (OTLP allows the field to be absent
    for root spans; emitting an explicit ``null`` is not desired here).

    Status codes are normalised: ``"ok"`` -> ``"OK"``, ``"error"`` ->
    ``"ERROR"``, anything else -> ``"STATUS_CODE_UNSPECIFIED"``. Timestamps
    are emitted as strings of nanoseconds, matching the protobuf JSON
    mapping for ``uint64`` fields. A span that never recorded an
    ``end_time_ns`` (falsy, e.g. ``0`` or ``None``) falls back to
    ``start_time_ns`` so the OTLP span always has a non-empty window.
    """
    ctx: SpanContext = span.context
    otlp_span: dict[str, object] = {
        "traceId": ctx.trace_id,
        "spanId": ctx.span_id,
        "name": span.name,
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(span.start_time_ns),
        "endTimeUnixNano": str(span.end_time_ns or span.start_time_ns),
        "attributes": [
            {"key": key, "value": _value_to_otlp(val)}
            for key, val in span.attributes.items()
        ],
        "events": [
            {
                "name": event["name"],
                "timeUnixNano": str(event["time_ns"]),
                "attributes": [],
            }
            for event in span.events
        ],
        "status": {
            "code": (
                span.status.upper()
                if span.status in ("ok", "error")
                else "STATUS_CODE_UNSPECIFIED"
            ),
            "message": span.status_description,
        },
    }
    if span.parent_span_id is not None:
        otlp_span["parentSpanId"] = span.parent_span_id
    return otlp_span


def encode_batch(
    spans: list[Span], resource: Resource | None = None
) -> dict[str, object]:
    """Wrap a list of spans in the OTLP/HTTP JSON ``resourceSpans`` envelope.

    The envelope has exactly one ``resourceSpans`` entry whose ``resource``
    carries the OTLP attributes of ``resource``. When ``resource`` is
    ``None`` the empty ``EMPTY_RESOURCE`` is used, so the ``resource``
    attributes list is ``[]`` -- this preserves the original slice's shape
    for callers that pass only ``spans`` (backward-compatible). The single
    ``scopeSpans`` entry names the instrumentation scope ``"capmesh"`` so
    downstream collectors attribute every span to this service.
    """
    if resource is None:
        resource = EMPTY_RESOURCE
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": resource.to_otlp_attributes()},
                "scopeSpans": [
                    {
                        "scope": {"name": "capmesh"},
                        "spans": [span_to_otlp(span) for span in spans],
                    }
                ],
            }
        ]
    }


class OtlpExporter:
    """Synchronous, best-effort OTLP/HTTP JSON trace exporter.

    The exporter encodes a batch of spans and POSTs the JSON payload to
    ``endpoint`` with ``Content-Type: application/json``. It is best-effort:
    ``export`` returns ``True`` on HTTP 200 and ``False`` on any error
    (``HTTPError`` / ``URLError`` / timeout / any other exception) and never
    raises -- a missing or failing collector must not crash the caller.

    Endpoint resolution order: an explicit ``endpoint`` argument wins;
    otherwise the ``OTEL_EXPORTER_OTLP_ENDPOINT`` environment variable is
    consulted; if that is empty, ``DEFAULT_ENDPOINT`` is used.
    """

    def __init__(self, endpoint: str | None = None, timeout: float = 5.0) -> None:
        if endpoint is None:
            endpoint = (
                os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "") or DEFAULT_ENDPOINT
            )
        self.endpoint = endpoint
        self.timeout = timeout

    def export(self, spans: list[Span], resource: Resource | None = None) -> bool:
        """Encode and POST a batch of spans; return ``True`` on HTTP 200.

        The payload is ``json.dumps`` with compact separators and sorted
        keys so the wire bytes are deterministic for a given batch. Any
        exception -- transport error, HTTP error response, timeout, or a
        serialisation failure -- is swallowed and reported as ``False`` so
        the caller never has to defend against a raise.

        ``resource`` supplies the ``resourceSpans`` resource attributes for
        the batch; ``None`` selects the module-level ``DEFAULT_RESOURCE``
        (built at import time from the ``OTEL_*`` environment) so a bare
        ``export(spans)`` call still emits a non-empty service identity.
        """
        try:
            batch_resource = resource if resource is not None else DEFAULT_RESOURCE
            payload = json.dumps(
                encode_batch(spans, resource=batch_resource),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            request = urllib.request.Request(
                self.endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
                return getattr(response, "status", 200) == 200
        except urllib.error.URLError:
            # Covers ``HTTPError`` (a subclass) and connection/timeout
            # failures reported by ``urllib``.
            return False
        except Exception:  # noqa: BLE001 - best-effort exporter must never raise
            # Any other failure (e.g. a serialisation or encoding error): the
            # exporter never raises.
            return False

    def flush_tracer(self, tracer: Tracer) -> bool:
        """Flush a ``Tracer``'s ended spans in one batch; never raise.

        Pulls ``tracer.ended_spans()``; when there is nothing to send the
        call returns ``True`` without touching the network. Otherwise the
        spans are encoded with ``DEFAULT_RESOURCE`` and POSTed via
        ``export`` (best-effort, never raises), so this method returns
        ``True`` on a 200 and ``False`` on any failure -- and never raises.
        """
        spans = tracer.ended_spans()
        if not spans:
            return True
        return self.export(spans, resource=DEFAULT_RESOURCE)

    def flush(self) -> None:
        """No-op: this exporter ships synchronously inside ``export``."""
