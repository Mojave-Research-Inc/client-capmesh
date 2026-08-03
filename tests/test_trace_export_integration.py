"""Lock the in-process end-to-end CM-13-full trace-export path.

These tests pin the contract that gate spans produced by
``capmesh.lifecycle.review_capability`` are flushed through
``capmesh.otlp_exporter.OtlpExporter.flush_tracer`` as an OTLP
``resourceSpans`` envelope carrying the ``DEFAULT_RESOURCE``.

Pipeline under test (all in-process, no real collector):

    lifecycle.TRACER (module-level Tracer)
        -> review_capability emits one ``gate.<name>`` span per evaluated gate
        -> OtlpExporter.flush_tracer(tracer)
        -> encode_batch(spans, resource=DEFAULT_RESOURCE)
        -> urllib.request.urlopen(Request(data=<otlp json bytes>))   [mocked]

Findings confirmed from the source at test-author time:

* ``capmesh/lifecycle.py`` references ``TRACER`` as a module global (free
  variable) at call time inside the gate-eval loop, so patching
  ``lifecycle_mod.TRACER`` with a fresh ``Tracer()`` IS picked up by the gate
  code; the gate spans land in the patched tracer.

* ``capmesh/otlp_exporter.py``: ``flush_tracer`` returns ``True`` without
  touching the network when the tracer is empty; otherwise it calls
  ``export(tracer.ended_spans(), resource=DEFAULT_RESOURCE)``. ``export`` never
  raises (``urllib.error.URLError`` and any other exception are swallowed and
  reported as ``False``). The OTLP status code field is ``status.code`` with
  values ``"OK"`` / ``"ERROR"`` / ``"STATUS_CODE_UNSPECIFIED"``; ``parentSpanId``
  is omitted entirely when ``parent_span_id`` is ``None``; span attributes are
  ``{"key": k, "value": {"stringValue": v}}`` for string values. The resource
  attributes live at ``resourceSpans[0].resource.attributes`` and the spans at
  ``resourceSpans[0].scopeSpans[0].spans``.

* ``capmesh/otel_resource.py``: ``DEFAULT_RESOURCE`` (built at otlp_exporter
  import time via ``create_resource()``) carries ``service.name=capmesh`` (the
  runner does not set ``OTEL_SERVICE_NAME``).

These tests are TEST-ONLY: they do not edit any ``capmesh/*.py`` source file.
They replicate the temp-sqlite + signing-key harness from
``tests/test_lifecycle_observability_wiring.py`` inline rather than importing
from the sibling, and copy the ``_make_cap`` / ``_store`` / ``_digest`` pattern
from ``tests/test_gate_runner_request_id.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Self
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import review_capability
from capmesh.models import Capability, Principal
from capmesh.otlp_exporter import OtlpExporter
from capmesh.tracing import Tracer

_GATE_NAMES = (
    "sourceIntegrity",
    "tests",
    "retrievalEvals",
    "signature",
    "provenance",
    "promptInjectionScan",
    "riskTierPolicy",
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _make_cap(root: Path, name: str, *, content: str | None = None) -> Capability:
    source = root / name / "SKILL.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        content
        or f"---\nname: {name}\ndescription: {name} capability\n---\n# {name}\nOperate safely.\n",
        encoding="utf-8",
    )
    cap = Capability(
        uri=f"cap://user/asg/test/private/skill/test.{name}@0.1.0",
        capability_type="skill",
        name=name,
        version="0.1.0",
        title=name,
        description=f"{name} capability",
        package_path=str(source.parent),
        entrypoint="SKILL.md",
        source_path=str(source),
        source_kind="skill_markdown",
        source_system="test",
        canonical_key=f"skill:test:{name}:0.1.0",
        content_hash=_digest(source),
        risk_tier="low",
        mutating=False,
        lifecycle="draft",
        approval_state="draft",
        tenant_id="asg",
    )
    return cap


class _FakeResponse:
    """Minimal context-manager response for mocked ``urlopen``.

    ``export`` uses ``with urlopen(...) as response: response.read(); ...`` and
    then reads ``response.status``, so the fake must support ``__enter__`` /
    ``__exit__``, ``.read()`` and a ``.status`` attribute.
    """

    def __init__(self, status: int = 200) -> None:
        self.status = status

    def read(self) -> bytes:
        return b""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class TraceExportIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.key_path = self.root / "signing.pem"
        self.env = mock.patch.dict(
            os.environ,
            {
                "CAPMESH_ENVIRONMENT": "test",
                "CAPMESH_SIGNING_KEY_FILE": str(self.key_path),
            },
            clear=False,
        )
        self.env.start()
        self.con = connect(self.root / "mesh.db")
        init_db(self.con, enable_vector=False)
        self.admin = Principal(subject="admin@example.com", tenant_id="asg", roles=("org_admin",))
        # Deterministic collector endpoint; the real network is never reached
        # because urlopen is mocked in every test that flushes non-empty spans.
        self.exporter = OtlpExporter(
            endpoint="http://collector.test/v1/traces", timeout=1.0
        )

    def tearDown(self) -> None:
        self.con.close()
        self.env.stop()
        self.tmp.cleanup()

    def _store(self, cap: Capability) -> Capability:
        upsert_capability(self.con, cap)
        self.con.commit()
        stored = get_capability(self.con, cap.uri)
        assert stored is not None
        return stored

    def _drive_and_flush(self, cap: Capability) -> tuple[dict[str, object], mock.MagicMock]:
        """Drive review_capability under a fresh patched TRACER, then flush.

        Returns ``(body, urlopen_mock)`` where ``body`` is the json-decoded
        OTLP envelope POSTed to the (mocked) collector. Asserts the flush
        returned True and urlopen was called exactly once with the envelope.
        """
        fake = _FakeResponse(200)
        with mock.patch.object(lifecycle_mod, "TRACER", Tracer()) as tracer:
            review_capability(
                self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
            )
            self.assertGreater(
                len(tracer.ended_spans()),
                0,
                "review_capability emitted no gate spans to the patched TRACER",
            )
            with mock.patch(
                "capmesh.otlp_exporter.urllib.request.urlopen",
                return_value=fake,
            ) as urlopen_mock:
                flushed = self.exporter.flush_tracer(tracer)
        self.assertTrue(flushed, "flush_tracer should return True on HTTP 200")
        urlopen_mock.assert_called_once()
        posted_request = urlopen_mock.call_args[0][0]
        body = json.loads(posted_request.data)
        return body, urlopen_mock

    def test_gate_spans_flushed_to_otlp(self) -> None:
        """Gate spans flow through flush_tracer into a non-empty OTLP envelope.

        The envelope's ``scopeSpans[0].spans`` includes a span named
        ``gate.<one of the 7 gates>`` with a non-empty ``traceId``, no
        ``parentSpanId`` (gate spans are root spans), and attributes carrying
        ``gate.name`` / ``gate.outcome`` / ``capability.uri`` (the latter equal
        to the driven cap's uri).
        """
        cap = self._store(_make_cap(self.root, "flushbasic"))
        body, _ = self._drive_and_flush(cap)

        spans = body["resourceSpans"][0]["scopeSpans"][0]["spans"]
        self.assertTrue(spans, "OTLP envelope contains no spans")

        gate_spans = [s for s in spans if isinstance(s.get("name", ""), str) and s["name"].startswith("gate.")]
        self.assertTrue(gate_spans, f"no gate.* span in the envelope; names={[s.get('name') for s in spans]}")

        # Every emitted gate span is one of the 7 required gates and carries
        # the right attribute set + driven capability uri.
        for span in gate_spans:
            self.assertTrue(span["traceId"], f"empty traceId on span {span.get('name')!r}")
            gate = span["name"].split(".", 1)[1]
            self.assertIn(gate, _GATE_NAMES, f"span name {span['name']!r} not one of the 7 gates")
            # Gate spans are root spans: parentSpanId must be omitted entirely.
            self.assertNotIn("parentSpanId", span, f"root gate span unexpectedly carries parentSpanId: {span}")
            attrs = {_a["key"]: _a["value"] for _a in span["attributes"]}
            self.assertIn("gate.name", attrs)
            self.assertIn("gate.outcome", attrs)
            self.assertIn("capability.uri", attrs)
            self.assertEqual(attrs["gate.name"]["stringValue"], gate)
            self.assertIn(
                attrs["gate.outcome"]["stringValue"],
                {"passed", "failed", "skipped", "unknown"},
            )
            self.assertEqual(attrs["capability.uri"]["stringValue"], cap.uri)

    def test_flushed_envelope_carries_default_resource(self) -> None:
        """The flushed envelope's resource attributes carry service.name=capmesh.

        ``DEFAULT_RESOURCE`` is built at ``otlp_exporter`` import time via
        ``create_resource()`` with the default ``service.name=capmesh`` (the
        runner does not set ``OTEL_SERVICE_NAME``), and ``flush_tracer`` passes
        ``resource=DEFAULT_RESOURCE`` into ``export``.
        """
        cap = self._store(_make_cap(self.root, "flushres"))
        body, _ = self._drive_and_flush(cap)

        resource_attrs = body["resourceSpans"][0]["resource"]["attributes"]
        svc_name = None
        for attr in resource_attrs:
            if attr["key"] == "service.name":
                svc_name = attr["value"]["stringValue"]
                break
        self.assertIsNotNone(svc_name, "service.name absent from resource attributes")
        # DEFAULT_RESOURCE.service.name defaults to "capmesh"; assert the
        # default rather than env-robust presence since the runner does not set
        # OTEL_SERVICE_NAME.
        self.assertEqual(svc_name, "capmesh", "DEFAULT_RESOURCE service.name should be capmesh")

    def test_flush_empty_tracer_no_network(self) -> None:
        """An empty tracer flushes to True without touching the network."""
        empty_tracer = Tracer()  # NOT lifecycle.TRACER; never had a span ended.
        with mock.patch(
            "capmesh.otlp_exporter.urllib.request.urlopen"
        ) as urlopen_mock:
            result = self.exporter.flush_tracer(empty_tracer)
        self.assertTrue(result, "flush_tracer on an empty tracer should return True")
        urlopen_mock.assert_not_called()

    def test_flush_failure_never_raises(self) -> None:
        """A transport failure (URLError) is swallowed; flush_tracer returns False."""
        cap = self._store(_make_cap(self.root, "flushfail"))
        err = urllib.error.URLError("collector unreachable")
        with mock.patch.object(lifecycle_mod, "TRACER", Tracer()) as tracer:
            review_capability(
                self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
            )
            self.assertGreater(len(tracer.ended_spans()), 0)
            with mock.patch(
                "capmesh.otlp_exporter.urllib.request.urlopen",
                side_effect=err,
            ):
                result = self.exporter.flush_tracer(tracer)
        self.assertFalse(result, "flush_tracer should return False when export fails")

    def test_gate_span_status_exported(self) -> None:
        """Passing-gate spans export as OTLP status OK; failing-gate as ERROR.

        Two separate drives (each with its own fresh patched TRACER + flush):
        a passing low-risk cap yields a span whose ``status.code`` is ``OK``,
        and a cap whose source file is unlinked post-store (sourceIntegrity
        fails) yields a span whose ``status.code`` is ``ERROR``.
        """
        # Passing cap: all gates pass -> at least one OK-status span.
        cap_ok = self._store(_make_cap(self.root, "statusok"))
        body_ok, _ = self._drive_and_flush(cap_ok)
        spans_ok = body_ok["resourceSpans"][0]["scopeSpans"][0]["spans"]
        codes_ok = {s["status"]["code"] for s in spans_ok}
        self.assertIn("OK", codes_ok, f"no OK-status span in passing-cap flush: {codes_ok}")

        # Failing cap: unlink source -> sourceIntegrity (and prerequisite
        # tests/promptInjectionScan gates) fail -> at least one ERROR-status span.
        bad_cap = self._store(_make_cap(self.root, "statuserr"))
        Path(bad_cap.source_path).unlink()
        body_err, _ = self._drive_and_flush(bad_cap)
        spans_err = body_err["resourceSpans"][0]["scopeSpans"][0]["spans"]
        codes_err = {s["status"]["code"] for s in spans_err}
        self.assertIn("ERROR", codes_err, f"no ERROR-status span in failing-cap flush: {codes_err}")


if __name__ == "__main__":
    unittest.main()
