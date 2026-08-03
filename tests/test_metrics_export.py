"""Tests for ``capmesh.metrics_export`` (CM-13 second slice).

These pin the self-contained Prometheus text-exposition renderer: counter-name
sanitisation (namespacing, idempotence, leading-digit guard), the
single-counter 3-line block shape, the whole-registry exposition format, and
duck-typed acceptance of any object with a ``snapshot()`` method. The module
under test imports only the standard library plus an optional
``TYPE_CHECKING``-guarded hint from ``.observability``; these tests mirror that
boundary.
"""

from __future__ import annotations

from capmesh.metrics_export import (
    METRIC_PREFIX,
    render_counter,
    render_prometheus,
    sanitize_metric_name,
)
from capmesh.observability import MetricsRegistry


def test_metric_prefix_value() -> None:
    assert METRIC_PREFIX == "capmesh_"


def test_sanitize_replaces_dots() -> None:
    result = sanitize_metric_name("gate.signature.passed")
    assert result == "capmesh_gate_signature_passed"


def test_sanitize_handles_http_request() -> None:
    result = sanitize_metric_name("http.request")
    assert result == "capmesh_http_request"


def test_sanitize_does_not_double_prefix() -> None:
    result = sanitize_metric_name("capmesh_already_prefixed")
    assert result == "capmesh_already_prefixed"


def test_sanitize_leading_digit() -> None:
    result = sanitize_metric_name("2gates")
    assert result == "capmesh_2gates"
    # A leading-digit input must produce a name beginning with a letter or
    # underscore, never a digit.
    assert result[:1].isalpha() or result[:1] == "_"


def test_render_prometheus_empty() -> None:
    assert render_prometheus(MetricsRegistry()) == ""


def test_render_prometheus_format() -> None:
    registry = MetricsRegistry()
    registry.increment("gate.signature.passed")
    registry.increment("gate.signature.passed")
    registry.increment("http.request")
    output = render_prometheus(registry)

    # Single trailing newline, never two.
    assert output.endswith("\n")
    assert not output.endswith("\n\n")

    lines = output.split("\n")
    # The single trailing newline produces a final empty element.
    assert lines[-1] == ""
    body = lines[:-1]
    assert len(body) == 6  # two metrics * three lines each
    # No line carries trailing whitespace.
    for line in body:
        assert line == line.rstrip()

    assert "# HELP capmesh_gate_signature_passed capmesh counter" in body
    assert "# TYPE capmesh_gate_signature_passed counter" in body
    assert "capmesh_gate_signature_passed 2" in body
    assert "# HELP capmesh_http_request capmesh counter" in body
    assert "# TYPE capmesh_http_request counter" in body
    assert "capmesh_http_request 1" in body


def test_render_counter_single() -> None:
    block = render_counter("foo", 5)
    assert "# HELP" in block
    assert "# TYPE capmesh_foo counter" in block
    assert "capmesh_foo 5" in block


def test_render_prometheus_accepts_duck_typed() -> None:
    class _DuckRegistry:
        def snapshot(self) -> dict[str, int]:
            return {"x.y": 3}

    output = render_prometheus(_DuckRegistry())  # type: ignore[arg-type]
    assert "# HELP capmesh_x_y capmesh counter" in output
    assert "# TYPE capmesh_x_y counter" in output
    assert "capmesh_x_y 3" in output
    assert output.endswith("\n")
