"""Lock the OTel span-emission contract in ``capmesh.lifecycle.review_capability``.

The gate runner emits one best-effort OTel span per evaluated gate via the
module-level ``TRACER`` (a ``capmesh.tracing.Tracer``). These tests pin the
contract: the tracer is exposed, a span is emitted per gate, the span name is
``gate.<gateName>``, the ``gate.name`` / ``gate.outcome`` / ``capability.uri``
attributes are set, the span status maps ``passed``->``ok`` and ``failed``->
``error``, and a tracing failure is swallowed (never breaks the gate runner).

These tests are TEST-ONLY: they assert the REAL current behavior of
``capmesh/lifecycle.py`` and do not edit any production source.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import TRACER, review_capability
from capmesh.models import Capability, Principal
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
_GATE_NAME_RE = re.compile(
    r"^gate\.(sourceIntegrity|tests|retrievalEvals|signature|provenance|promptInjectionScan|riskTierPolicy)$"
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


class LifecycleSpanEmissionTests(unittest.TestCase):
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

    def test_tracer_exposed(self) -> None:
        """The lifecycle module exposes a module-level Tracer singleton."""
        self.assertIsInstance(TRACER, Tracer)
        # The imported name is the same object referenced from the lifecycle
        # module namespace (a singleton, not a per-import copy).
        self.assertIs(lifecycle_mod.TRACER, TRACER)

    def test_review_capability_emits_span_per_gate(self) -> None:
        """Driving review_capability grows the tracer's ended spans."""
        cap = self._store(_make_cap(self.root, "spancount"))
        before = len(TRACER.ended_spans())
        review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        after = len(TRACER.ended_spans())
        # Robust to short-circuiting: at least one span must be emitted. In
        # practice the gate runner evaluates every gate, so this is typically 7.
        self.assertGreater(
            after - before,
            0,
            f"review_capability did not emit any OTel span: before={before} after={after}",
        )

    def test_span_name_is_gate_dot_name(self) -> None:
        """Every newly emitted span is named ``gate.<gateName>``."""
        cap = self._store(_make_cap(self.root, "spanname"))
        before = {id(s) for s in TRACER.ended_spans()}
        review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        new_spans = [s for s in TRACER.ended_spans() if id(s) not in before]
        self.assertTrue(new_spans, "no new spans were emitted by review_capability")
        for span in new_spans:
            self.assertIsNotNone(
                _GATE_NAME_RE.match(span.name),
                f"span name {span.name!r} does not match gate.<gateName>",
            )

    def test_span_attributes_set(self) -> None:
        """A new ended span carries gate.name, gate.outcome, capability.uri."""
        cap = self._store(_make_cap(self.root, "spanattrs"))
        before = {id(s) for s in TRACER.ended_spans()}
        review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        new_spans = [s for s in TRACER.ended_spans() if id(s) not in before]
        self.assertTrue(new_spans, "no new spans were emitted by review_capability")
        for span in new_spans:
            self.assertIn("gate.name", span.attributes)
            self.assertIn("gate.outcome", span.attributes)
            self.assertIn("capability.uri", span.attributes)
            self.assertIn(span.attributes["gate.name"], _GATE_NAMES)
            self.assertIn(
                span.attributes["gate.outcome"],
                {"passed", "failed", "skipped", "unknown"},
            )
            self.assertEqual(span.attributes["capability.uri"], cap.uri)

    def test_span_status_reflects_outcome(self) -> None:
        """passed->span.status 'ok'; failed->span.status 'error'."""
        # A properly stored low-risk cap passes every gate -> passed spans.
        cap = self._store(_make_cap(self.root, "spanok"))
        before_ok = {id(s) for s in TRACER.ended_spans()}
        review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        ok_spans = [s for s in TRACER.ended_spans() if id(s) not in before_ok]
        self.assertTrue(ok_spans, "no new spans emitted for the passing cap")
        passed_spans = [s for s in ok_spans if s.attributes.get("gate.outcome") == "passed"]
        self.assertTrue(passed_spans, "no passed-gate span was emitted")
        for span in passed_spans:
            self.assertEqual(span.status, "ok")

        # A cap whose source file has gone missing fails sourceIntegrity (and
        # the tests/promptInjectionScan prerequisite gates) -> failed spans.
        bad_cap = _make_cap(self.root, "spanerr")
        bad_cap = self._store(bad_cap)
        Path(bad_cap.source_path).unlink()
        before_err = {id(s) for s in TRACER.ended_spans()}
        review_capability(self.con, self.admin, {"capabilityUri": bad_cap.uri, "dryRun": True})
        err_spans = [s for s in TRACER.ended_spans() if id(s) not in before_err]
        self.assertTrue(err_spans, "no new spans emitted for the failing cap")
        failed_spans = [s for s in err_spans if s.attributes.get("gate.outcome") == "failed"]
        self.assertTrue(failed_spans, "no failed-gate span was emitted")
        for span in failed_spans:
            self.assertEqual(span.status, "error")

    def test_span_emission_failure_does_not_break_gate(self) -> None:
        """A TRACER.start_span raise is swallowed; review_capability still returns."""
        cap = self._store(_make_cap(self.root, "spanfail"))
        with mock.patch.object(
            lifecycle_mod.TRACER, "start_span", side_effect=RuntimeError("tracer boom")
        ):
            result = review_capability(
                self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
            )
        self.assertIsInstance(result, dict)
        self.assertIn("gates", result)


if __name__ == "__main__":
    unittest.main()
