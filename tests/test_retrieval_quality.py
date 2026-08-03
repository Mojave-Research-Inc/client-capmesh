from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capmesh.cli import run_eval
from capmesh.index import connect, init_db, lexical_embedding, search, upsert_capability
from capmesh.models import Capability, Principal


def capability(name: str, kind: str, description: str, index: int) -> Capability:
    return Capability(
        uri=f"cap://user/asg/test/private/{kind}/quality.{name}@1.0.0",
        capability_type=kind,
        name=name,
        version="1.0.0",
        title=name.replace("-", " ").title(),
        description=description,
        package_path="/tmp/quality",
        entrypoint=f"{name}.md",
        source_path=f"/tmp/quality/{name}-{index}.md",
        source_kind=kind,
        source_system="asg-os.plugins",
        canonical_key=f"{kind}:quality:{name}:1.0.0",
        content_hash=f"sha256:{index:064x}",
    )


class RetrievalQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mesh.db"
        self.con = connect(self.db)
        init_db(self.con, enable_vector=False)

    def tearDown(self) -> None:
        self.con.close()
        self.tmp.cleanup()

    def test_exact_name_boost_and_type_filter_happen_before_limit(self) -> None:
        for index in range(80):
            upsert_capability(
                self.con,
                capability(f"generic-security-{index}", "agent", "MCP security prompt injection tooling", index + 1),
            )
        target = capability("mcp-security-gatekeeper", "skill", "Hardens MCP tools against prompt injection", 999)
        upsert_capability(self.con, target)
        self.con.commit()

        results = search(self.con, "mcp security gatekeeper", Principal(), k=3, capability_type="skill")

        self.assertEqual(results[0].capability.name, "mcp-security-gatekeeper")
        self.assertTrue(all(result.capability.capability_type == "skill" for result in results))
        self.assertIn("exact", results[0].matched_by)

    def test_lexical_embedding_is_deterministic_and_dimensioned(self) -> None:
        first = lexical_embedding("transactional sqlite migration", 384)
        second = lexical_embedding("transactional sqlite migration", 384)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 384)
        self.assertAlmostEqual(sum(value * value for value in first), 1.0, places=4)

    def test_eval_reports_recall_mrr_ndcg_and_threshold_failures(self) -> None:
        class FakeRouter:
            def call(self, _tool, payload):
                query = payload["query"]
                rows = (
                    [{"uri": "cap://wrong", "name": "wrong"}, {"uri": "cap://expected", "name": "expected-cap"}]
                    if query == "ranked"
                    else []
                )
                return {"isError": False, "structuredContent": {"results": rows}}

        eval_file = Path(self.tmp.name) / "eval.json"
        eval_file.write_text(
            json.dumps(
                {
                    "thresholds": {"recallAtK": 1.0, "mrrAtK": 0.75, "ndcgAtK": 0.8, "criticalRecallAtK": 1.0},
                    "cases": [
                        {"query": "ranked", "expectedAny": ["expected-cap"], "critical": True},
                        {"query": "missing", "expectedAny": ["absent"], "critical": True},
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = run_eval(FakeRouter(), str(eval_file), 10)

        self.assertEqual(result["recallAtK"], 0.5)
        self.assertEqual(result["mrrAtK"], 0.25)
        self.assertGreater(result["ndcgAtK"], 0.3)
        self.assertEqual(result["misses"], 1)
        self.assertFalse(result["passed"])
        self.assertTrue(result["failedThresholds"])


if __name__ == "__main__":
    unittest.main()
