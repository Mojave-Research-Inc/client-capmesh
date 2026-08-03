"""CM-13-full request-context link: gate spans are children of the request span.

``capmesh/lifecycle.py`` gate-span emission (``review_capability``) reads the
request-context contextvar (``capmesh.tracing.get_request_context``) and passes
it as ``parent_context`` to ``TRACER.start_span``. ``capmesh/router.py`` sets
that contextvar (``set_request_context(span.context)``) when its ``request``
span starts and resets it in a finally when the dispatch ends. The net effect:
when ``review_capability`` runs in the request path, every ``gate.<name>`` span
inherits the request span's trace_id and has ``parent_span_id == request span
.span_id``; when no request context is set (CLI ``capmesh gates`` run, or a
direct unit-test call), gate spans remain root spans (current behavior).

These tests lock the end-to-end link and the reset contract. They replicate the
temp-sqlite + signing-key harness from ``tests/test_lifecycle_observability_wiring.py``
inline (``_make_cap`` / ``_store`` / ``_digest``) and do NOT import from the
sibling. They are TEST-ONLY and edit no ``capmesh/*.py`` source file.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
import capmesh.router as router_mod
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import review_capability
from capmesh.models import Capability, Principal
from capmesh.tracing import Tracer, get_request_context, set_request_context


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


class _BaseLifecycleHarness(unittest.TestCase):
    """Shared temp-sqlite + signing-key harness (inline, not imported)."""

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


class GateSpanRequestLinkTests(_BaseLifecycleHarness):
    """End-to-end: gate spans link to the in-flight request span's trace."""

    def _drive_with_fresh_tracer(self, cap: Capability) -> Tracer:
        """Patch lifecycle_mod.TRACER with a fresh Tracer and drive review_capability.

        Returns the patched tracer so the test can inspect ``ended_spans()``.
        Gate spans land in this fresh tracer (lifecycle reads ``TRACER`` as a
        module-global free variable at call time, so the patch is picked up).
        """
        fresh = Tracer()
        with mock.patch.object(lifecycle_mod, "TRACER", fresh):
            review_capability(
                self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
            )
        return fresh

    def test_gate_span_is_child_of_request_span(self) -> None:
        """With a request context set, a gate span is a child of the request span.

        Simulate the request path by binding a request span context via
        ``set_request_context``, then drive ``review_capability`` on a low-risk
        cap under a fresh patched TRACER. A gate span in ``ended_spans()`` must
        carry the request span context's trace_id and have parent_span_id ==
        request span context.span_id. The contextvar is reset after.
        """
        cap = self._store(_make_cap(self.root, "child"))
        request_tracer = Tracer()
        request_span = request_tracer.start_span("request", start_time_ns=1)
        token = set_request_context(request_span.context)
        try:
            tracer = self._drive_with_fresh_tracer(cap)
        finally:
            token.reset()
        gate_spans = [s for s in tracer.ended_spans() if s.name.startswith("gate.")]
        self.assertTrue(gate_spans, "no gate.* span was emitted")
        for span in gate_spans:
            self.assertEqual(
                span.context.trace_id,
                request_span.context.trace_id,
                f"gate span {span.name!r} trace_id must match the request span trace_id",
            )
            self.assertEqual(
                span.parent_span_id,
                request_span.context.span_id,
                f"gate span {span.name!r} parent_span_id must be the request span id",
            )

    def test_gate_span_root_when_no_request_context(self) -> None:
        """With NO request context set, gate spans are root spans (current behavior).

        Drive ``review_capability`` with the contextvar cleared; a gate span in
        ``ended_spans()`` must have ``parent_span_id is None`` and a FRESH
        trace_id (not shared with any prior request context). This preserves the
        prior gate-runner behavior for CLI / direct unit-test callers.
        """
        # Belt-and-suspenders: ensure the contextvar is cleared before driving.
        # A prior test in this process may have left a value if its reset was
        # skipped; reset-until-None is safe (set_request_context(None) yields a
        # token we immediately reset to restore None).
        clear_token = set_request_context(None)
        try:
            cap = self._store(_make_cap(self.root, "root"))
            tracer = self._drive_with_fresh_tracer(cap)
        finally:
            clear_token.reset()
        self.assertIsNone(get_request_context(), "contextvar must be None after drive")
        gate_spans = [s for s in tracer.ended_spans() if s.name.startswith("gate.")]
        self.assertTrue(gate_spans, "no gate.* span was emitted")
        for span in gate_spans:
            self.assertIsNone(
                span.parent_span_id,
                f"gate span {span.name!r} must be a root span (parent_span_id is None)",
            )
            self.assertTrue(span.context.trace_id, "a root gate span has a fresh trace_id")

    def test_request_context_reset_prevents_leak(self) -> None:
        """reset(token) prevents a stale request context from leaking to later gates.

        Set request context A, reset it, then drive ``review_capability``; the
        emitted gate spans must NOT link to A: each has a trace_id != A.trace_id
        and parent_span_id is None (root span). This locks the contract that
        router.py's finally reset is load-bearing -- without it, an unrelated
        later gate run (e.g. a CLI ``capmesh gates`` call after an HTTP request)
        would wrongly inherit a stale request trace.
        """
        request_tracer = Tracer()
        stale = request_tracer.start_span("request", start_time_ns=1)
        token = set_request_context(stale.context)
        token.reset()  # simulate the router finally resetting the contextvar
        self.assertIsNone(get_request_context(), "contextvar must be None after reset")
        cap = self._store(_make_cap(self.root, "noleak"))
        tracer = self._drive_with_fresh_tracer(cap)
        gate_spans = [s for s in tracer.ended_spans() if s.name.startswith("gate.")]
        self.assertTrue(gate_spans, "no gate.* span was emitted")
        for span in gate_spans:
            self.assertNotEqual(
                span.context.trace_id,
                stale.context.trace_id,
                f"gate span {span.name!r} leaked the stale request trace_id",
            )
            self.assertIsNone(
                span.parent_span_id,
                f"gate span {span.name!r} must be a root span after reset",
            )

    def test_router_call_sets_and_resets_request_context(self) -> None:
        """CapabilityRouter.call sets the contextvar in flight and resets it after.

        Patches ``capmesh.router.REQUEST_TRACER`` with a fresh Tracer and calls
        ``CapabilityRouter.call`` with a stub handler that captures
        ``get_request_context()`` while the call is in flight. Asserts the
        captured value is the request span's context (non-None, equal to the
        request span context minted by the router) DURING the call, and that
        ``get_request_context()`` returns None AFTER the call returns (the
        finally reset it). This is the router-side half of the link contract.
        """
        # Minimal in-process index + router (the dispatch only needs to reach
        # the verb handler; the handler is stubbed so the index content does
        # not matter, but cap.search requires a working connection/roots).
        plugin = self.root / "plugins" / "demo-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / "skills" / "write-brief").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            '{"name": "demo-plugin", "version": "1.2.3", "description": "Demo."}',
            encoding="utf-8",
        )
        (plugin / "skills" / "write-brief" / "SKILL.md").write_text(
            "---\nname: write-brief\ndescription: Write concise executive briefs.\n---\n# Write Brief\n",
            encoding="utf-8",
        )
        from capmesh.index import rebuild_index
        from capmesh.router import CapabilityRouter

        db = self.root / "mesh.db"
        rebuild_index(db, [self.root / "plugins"], enable_vector=False)
        con = connect(db)
        init_db(con, enable_vector=False)
        router = CapabilityRouter(con, roots=(str(self.root / "plugins"),))
        self.addCleanup(con.close)

        fresh_tracer = Tracer()
        captured: list[object] = []

        def stub_search(params: dict, principal: Principal) -> dict[str, object]:
            # Capture the contextvar value WHILE the dispatch is in flight.
            captured.append(get_request_context())
            from capmesh.router import ok_result

            return ok_result("stub search.", {"stub": True})

        with mock.patch.object(router_mod, "REQUEST_TRACER", fresh_tracer), \
                mock.patch.object(router, "cap_search", side_effect=stub_search):
            router.call(
                "cap.search",
                {"query": "executive brief", "type": "skill"},
                request_id="req-link-1",
            )

        # DURING the call the contextvar held the request span's context.
        self.assertEqual(len(captured), 1, "stub handler must be called exactly once")
        in_flight = captured[0]
        self.assertIsNotNone(in_flight, "contextvar must be set while the dispatch is in flight")
        request_spans = [s for s in fresh_tracer.ended_spans() if s.name == "request"]
        self.assertEqual(len(request_spans), 1, "exactly one request span expected")
        request_span = request_spans[0]
        self.assertEqual(in_flight, request_span.context, "in-flight contextvar must equal the request span context")
        # AFTER the call the contextvar is None (the finally reset it).
        self.assertIsNone(get_request_context(), "contextvar must be None after the call returns")

    def test_gate_span_link_failure_does_not_break_gate(self) -> None:
        """A TRACER.start_span raise under a request context does not propagate.

        Patches ``lifecycle_mod.TRACER.start_span`` to raise while a request
        context is set, then drives ``review_capability``; it must still return
        its result dict (best-effort contract). This locks that the new
        parent_context wiring does not weaken the existing best-effort gate
        tracing.
        """
        cap = self._store(_make_cap(self.root, "linkfail"))
        request_tracer = Tracer()
        request_span = request_tracer.start_span("request", start_time_ns=1)
        token = set_request_context(request_span.context)
        try:
            fresh = Tracer()
            with mock.patch.object(lifecycle_mod, "TRACER", fresh), \
                    mock.patch.object(fresh, "start_span", side_effect=RuntimeError("tracer boom")):
                result = review_capability(
                    self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True}
                )
        finally:
            token.reset()
        self.assertIsInstance(result, dict)
        self.assertIn("gates", result)


if __name__ == "__main__":
    unittest.main()
