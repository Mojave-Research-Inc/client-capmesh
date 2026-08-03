"""WAVE5-WIRING-b: lifecycle.py provenance gate is wired to capmesh.provenance.

These tests confirm that ``capmesh.lifecycle``'s provenance promotion gate
delegates to the standalone ``capmesh.provenance`` module
(``compute_provenance_status`` / ``to_jsonl_attestation`` / ``attestation_digest``)
instead of the former divergent ``asg.capmesh.internal-provenance/v1`` internal
schema. They do NOT edit ``capmesh.provenance`` or ``capmesh.signing``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capmesh.lifecycle as lifecycle_mod
from capmesh import provenance as provenance_mod
from capmesh.governance import (
    ensure_default_tenant,
    ensure_org_shared_namespace,
    submit_promotion,
)
from capmesh.index import connect, get_capability, init_db, upsert_capability
from capmesh.lifecycle import review_capability, run_promotion_gates
from capmesh.models import Capability, Principal


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _make_cap(
    root: Path,
    name: str,
    *,
    content_hash: str | None = None,
    source_commit: str | None = None,
    content: str | None = None,
) -> Capability:
    source = root / name / "SKILL.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        content
        or f"---\nname: {name}\ndescription: {name} capability\n---\n# {name}\nOperate safely.\n",
        encoding="utf-8",
    )
    metadata: dict[str, object] = {}
    if source_commit is not None:
        metadata["sourceCommit"] = source_commit
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
        content_hash=content_hash if content_hash is not None else _digest(source),
        risk_tier="low",
        mutating=False,
        lifecycle="draft",
        approval_state="draft",
        tenant_id="asg",
        metadata=metadata,
    )
    return cap


class LifecycleProvenanceWiringTests(unittest.TestCase):
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

    def test_lifecycle_uses_capmesh_provenance(self) -> None:
        """The provenance gate delegates to capmesh.provenance.compute_provenance_status."""
        # lifecycle imports the standalone module's function by name; confirm it
        # is the SAME callable, not a divergent copy.
        self.assertIs(lifecycle_mod.compute_provenance_status, provenance_mod.compute_provenance_status)
        cap = self._store(_make_cap(self.root, "wired", source_commit="abc123def456"))
        calls: list[dict[str, object]] = []
        original = provenance_mod.compute_provenance_status

        def spy(capability, source_commit, builder_identity, built_at):  # type: ignore[no-untyped-def]
            calls.append(
                {
                    "source_commit": source_commit,
                    "builder_identity": builder_identity,
                    "built_at": built_at,
                    "content_hash": capability.get("content_hash"),
                }
            )
            return original(capability, source_commit, builder_identity, built_at)

        # Patch the name lifecycle actually calls (its module-level binding).
        with mock.patch.object(lifecycle_mod, "compute_provenance_status", side_effect=spy):
            result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})

        self.assertTrue(calls, "compute_provenance_status was not invoked by the provenance gate")
        self.assertEqual(calls[0]["source_commit"], "abc123def456")
        self.assertEqual(calls[0]["content_hash"], cap.content_hash)
        self.assertEqual(calls[0]["builder_identity"], self.admin.subject)
        # built_at is an ISO8601 string produced by lifecycle (it owns the clock).
        self.assertIsInstance(calls[0]["built_at"], str)
        self.assertTrue(calls[0]["built_at"])
        # The provenance gate is reachable and reflects the delegated result.
        self.assertIn("provenance", result["gates"])

    def test_provenance_passed(self) -> None:
        """A cap with content_hash + real source_commit yields gate 'passed' and a
        digest that matches capmesh.provenance.attestation_digest(record)."""
        cap = self._store(_make_cap(self.root, "passed", source_commit="feedface00112233"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate = result["gates"]["provenance"]
        self.assertEqual(gate["state"], "passed")
        evidence = gate["evidence"]
        self.assertEqual(evidence["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertIn("digest", evidence)
        self.assertIn("attestation", evidence)

        # Recompute the record the same way lifecycle does and compare digests.
        provenance_record = provenance_mod.compute_provenance_status(
            {"content_hash": cap.content_hash, "canonical_uri": cap.uri},
            source_commit="feedface00112233",
            builder_identity=self.admin.subject,
            built_at=evidence["builtAt"],
        ).record
        assert provenance_record is not None
        expected_digest = provenance_mod.attestation_digest(provenance_record)
        self.assertEqual(evidence["digest"], expected_digest)
        # The attestation envelope is the canonical JSONL form.
        self.assertEqual(evidence["attestation"], provenance_mod.to_jsonl_attestation(provenance_record))

    def test_provenance_skipped_unknown_commit(self) -> None:
        """source_commit='unknown' -> gate 'skipped' (provenance best-effort)."""
        cap = self._store(_make_cap(self.root, "skipped", source_commit="unknown"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate = result["gates"]["provenance"]
        self.assertEqual(gate["state"], "skipped")
        self.assertEqual(gate["evidence"]["reason"], "source commit unknown")
        # Skipped provenance must not block approval (best-effort gate).
        self.assertTrue(result["passed"])

    def test_provenance_passed_when_no_commit_metadata(self) -> None:
        """A cap with no sourceCommit metadata falls back to content-addressed
        provenance (the content hash is the immutable build reference) and the
        gate passes. This preserves the pre-refactor behavior for commit-less
        capabilities: the provenance gate does not block approval."""
        cap = self._store(_make_cap(self.root, "nocommit"))
        self.assertNotIn("sourceCommit", cap.metadata)
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate = result["gates"]["provenance"]
        self.assertEqual(gate["state"], "passed")
        # The fallback source commit is the content hash.
        self.assertEqual(gate["evidence"]["sourceCommit"], cap.content_hash)
        self.assertTrue(result["passed"])

    def test_provenance_failed_no_content_hash(self) -> None:
        """A cap without content_hash -> provenance gate 'failed'."""
        cap = self._store(_make_cap(self.root, "nohash", content_hash="", source_commit="abc123"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate = result["gates"]["provenance"]
        self.assertEqual(gate["state"], "failed")
        self.assertEqual(gate["evidence"]["reason"], "capability missing content_hash")
        self.assertFalse(result["passed"])

    def test_provenance_failed_blocks_approval(self) -> None:
        """A failed provenance gate must not produce an approval."""
        cap = self._store(_make_cap(self.root, "failblock", content_hash="", source_commit="abc123"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": False})
        self.assertFalse(result["passed"])
        self.assertNotIn("approved", result)
        row = self.con.execute(
            "SELECT approval_state, provenance_status FROM capabilities WHERE uri = ?",
            (cap.uri,),
        ).fetchone()
        # Not approved: provenance_status stays unverified (no writeback).
        self.assertEqual(row["provenance_status"], "unchecked")

    def test_no_internal_provenance_schema(self) -> None:
        """The divergent 'asg.capmesh.internal-provenance/v1' string is gone from
        lifecycle.py and the SLSA predicateType is used instead."""
        lifecycle_path = Path(lifecycle_mod.__file__)
        source = lifecycle_path.read_text(encoding="utf-8")
        self.assertNotIn(
            "asg.capmesh.internal-provenance/v1",
            source,
            "lifecycle.py still references the divergent internal-provenance schema",
        )
        self.assertIn("https://slsa.dev/provenance/v1", source)

    def test_provenance_gate_uses_slsa_predicate_type(self) -> None:
        """The provenance gate evidence reports the SLSA predicateType on pass."""
        cap = self._store(_make_cap(self.root, "slsa", source_commit="cafef00dcafef00d"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        gate = result["gates"]["provenance"]
        self.assertEqual(gate["state"], "passed")
        self.assertEqual(gate["evidence"]["predicateType"], "https://slsa.dev/provenance/v1")

    def test_promotion_run_provenance_gate_wired(self) -> None:
        """run_promotion_gates also routes provenance through capmesh.provenance."""
        cap = self._store(_make_cap(self.root, "promo", source_commit="deadbeefdeadbeef"))
        ensure_default_tenant(self.con)
        namespace_id = ensure_org_shared_namespace(self.con)
        request = submit_promotion(
            self.con,
            self.admin,
            {"capabilityUri": cap.uri, "targetNamespaceId": namespace_id},
        )
        gates = run_promotion_gates(self.con, self.admin, {"requestId": request["id"]})
        self.assertEqual(gates["gates"]["provenance"]["state"], "passed")
        self.assertEqual(
            gates["gates"]["provenance"]["evidence"]["predicateType"],
            "https://slsa.dev/provenance/v1",
        )
        self.assertTrue(gates["passed"])

    def test_attestation_digest_is_sha256_of_jsonl(self) -> None:
        """The digest recorded by lifecycle equals sha256 of the JSONL attestation."""
        cap = self._store(_make_cap(self.root, "digest", source_commit="0123456789abcdef"))
        result = review_capability(self.con, self.admin, {"capabilityUri": cap.uri, "dryRun": True})
        evidence = result["gates"]["provenance"]["evidence"]
        self.assertEqual(
            evidence["digest"],
            hashlib.sha256(evidence["attestation"].encode()).hexdigest(),
        )
        # The attestation is a single JSON line (JSONL).
        self.assertNotIn("\n", evidence["attestation"])
        parsed = json.loads(evidence["attestation"])
        self.assertEqual(parsed["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(parsed["predicateType"], "https://slsa.dev/provenance/v1")


if __name__ == "__main__":
    unittest.main()
