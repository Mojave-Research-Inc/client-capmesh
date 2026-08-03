from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from capmesh.index import _upsert_discovered, connect, init_db
from capmesh.models import Capability


class VectorRefreshTests(TestCase):
    def test_same_hash_reembeds_when_derived_index_text_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            con = connect(db)
            init_db(con, enable_vector=False)
            cap = Capability(
                uri="cap://asg.local/skill/vector-refresh@1.0.0",
                capability_type="skill",
                name="vector-refresh",
                version="1.0.0",
                title="Original title",
                description="Vector refresh regression.",
                package_path=tmp,
                entrypoint="SKILL.md",
                source_path=str(Path(tmp) / "SKILL.md"),
                source_kind="skill_markdown",
                source_system="test",
                canonical_key="skill:test:vector-refresh:1.0.0",
                content_hash="sha256:same-source-file",
                plugin="vector-test",
            )

            with mock.patch("capmesh.index._upsert_vector", return_value=True) as upsert_vector:
                _upsert_discovered(con, [cap], vector_enabled=True)
                self.assertFalse(upsert_vector.call_args.kwargs["index_text_unchanged"])

                _upsert_discovered(con, [cap], vector_enabled=True)
                self.assertTrue(upsert_vector.call_args.kwargs["index_text_unchanged"])

                changed = dataclasses.replace(cap, title="Derived title changed")
                _upsert_discovered(con, [changed], vector_enabled=True)
                self.assertFalse(upsert_vector.call_args.kwargs["index_text_unchanged"])
            con.close()


class VectorFailureLatchTests(TestCase):
    """One failed embed must not silently unvectorize the rest of the corpus.

    Observed 2026-07-27 after an embedding-model swap: the signature change
    correctly dropped capability_vec, then a single transient failure latched
    `vectors_ok` False for the remainder of the run. 179 of 3,479 capabilities
    got vectors; the run still reported success and hybrid search quietly
    degraded to FTS-only for 95% of the mesh.
    """

    def _caps(self, tmp: str, n: int) -> list[Capability]:
        return [
            Capability(
                uri=f"cap://asg.local/skill/latch-{i}@1.0.0",
                capability_type="skill",
                name=f"latch-{i}",
                version="1.0.0",
                title=f"Latch {i}",
                description="Vector latch regression.",
                package_path=tmp,
                entrypoint="SKILL.md",
                source_path=str(Path(tmp) / f"latch-{i}.md"),
                source_kind="skill_markdown",
                source_system="test",
                canonical_key=f"skill:test:latch-{i}:1.0.0",
                content_hash=f"sha256:latch-{i}",
                plugin="vector-test",
            )
            for i in range(n)
        ]

    def test_one_failure_does_not_stop_later_embeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "mesh.db")
            init_db(con, enable_vector=False)
            caps = self._caps(tmp, 5)
            calls = {"n": 0}

            def flaky(*_a, **_k):
                calls["n"] += 1
                return calls["n"] != 2  # only the 2nd embed fails

            with mock.patch("capmesh.index._upsert_vector", side_effect=flaky):
                changes = _upsert_discovered(con, caps, vector_enabled=True)

            self.assertEqual(calls["n"], 5, "every capability must still be attempted")
            self.assertEqual(changes["vectorsWritten"], 4)
            self.assertEqual(changes["vectorFailures"], 1)
            # An isolated bad row must NOT disable semantic search mesh-wide;
            # the failure is visible through the counts instead.
            self.assertTrue(changes["vectorsOk"])
            self.assertFalse(changes["vectorAborted"])
            con.close()

    def test_sustained_outage_aborts_instead_of_hammering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "mesh.db")
            init_db(con, enable_vector=False)
            caps = self._caps(tmp, 60)

            with mock.patch("capmesh.index._upsert_vector", return_value=False) as uv:
                changes = _upsert_discovered(con, caps, vector_enabled=True)

            self.assertEqual(uv.call_count, 25, "stop after sustained failure, not on the first")
            self.assertTrue(changes["vectorAborted"])
            self.assertFalse(changes["vectorsOk"])
            con.close()

    def test_all_healthy_reports_full_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            con = connect(Path(tmp) / "mesh.db")
            init_db(con, enable_vector=False)
            caps = self._caps(tmp, 5)
            with mock.patch("capmesh.index._upsert_vector", return_value=True):
                changes = _upsert_discovered(con, caps, vector_enabled=True)
            self.assertTrue(changes["vectorsOk"])
            self.assertEqual(changes["vectorsWritten"], 5)
            self.assertEqual(changes["vectorFailures"], 0)
            con.close()
