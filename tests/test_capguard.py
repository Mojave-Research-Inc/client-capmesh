from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.capguard import (
    CapGuardError,
    QuarantineError,
    QuarantineReleaseBlocked,
    attestation_chain_valid,
    ensure_quarantine_tables,
    evaluate_release_policy,
    get_quarantine,
    issue_scan_attestation,
    list_attestations,
    list_quarantine,
    quarantine_capability,
    reject_from_quarantine,
    release_from_quarantine,
    scan_clean_attestation,
    verify_attestation_record,
)
from capmesh.cap_guard import CapGuardPolicy, evaluate_cap_guard_policy
from capmesh.index import connect, init_db
from capmesh.models import Capability
from capmesh.signing import trusted_signing_key_id


def _qtn(**overrides):
    base = dict(
        tenant_id="asg",
        capability_uri="cap://asg/skill/example@1.0.0",
        capability_type="skill",
        name="example",
        version="1.0.0",
        source_path="/repo/skills/example/SKILL.md",
        content_hash="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        reason="pending_scan",
        submitted_by="ingest@asg",
    )
    base.update(overrides)
    return base


def _clean_scan() -> dict:
    return {"passed": True, "findings": [], "criticalCount": 0, "highCount": 0}


def _blocked_scan() -> dict:
    return {
        "passed": False,
        "findings": [{"name": "shell_injection", "severity": "high", "description": "d"}],
        "criticalCount": 0,
        "highCount": 1,
    }


class CapGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "mesh.db"
        # Isolate the Ed25519 trust anchor per test so signing is deterministic
        # and does not touch the real capmesh state directory.
        self._env = mock.patch.dict(
            os.environ,
            {"CAPMESH_ENVIRONMENT": "test", "CAPMESH_SIGNING_KEY_FILE": str(self.root / "signing.pem")},
            clear=False,
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self.tmp.cleanup()

    def _con(self):
        con = connect(self.db, check_same_thread=False)
        init_db(con, enable_vector=False)
        return con

    # -- schema ----------------------------------------------------------

    def test_ensure_quarantine_tables_is_idempotent_and_init_db_creates_it(self) -> None:
        con = self._con()
        # init_db already ran ensure_quarantine_tables; calling again is a no-op.
        ensure_quarantine_tables(con)
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("capguard_quarantine", tables)
        self.assertIn("capguard_attestations", tables)
        con.close()

    def test_migration_v3(self) -> None:
        con = self._con()
        version = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        self.assertEqual(int(version), 3)
        con.close()

    def test_schema_version_constant_matches_migration_runner_head(self) -> None:
        # The published SCHEMA_VERSION constant MUST equal the head version the
        # migration runner advances a fresh database to. readiness rejects a
        # correctly migrated database when the two drift (CapGuard added
        # migration v3 but left the constant at 2, so readiness reported
        # schemaVersion ok=False actual=3 expected=2 and returned 503). Pin the
        # invariant so the next migration that forgets to bump the constant
        # fails here instead of in production.
        from capmesh import index as index_module
        from capmesh import migrations

        migrations.register_builtin_migrations()
        runner_head = migrations.REGISTRY[-1][0] if migrations.REGISTRY else 0
        self.assertEqual(
            index_module.SCHEMA_VERSION,
            runner_head,
            f"SCHEMA_VERSION={index_module.SCHEMA_VERSION} but migration runner head is {runner_head}",
        )
        self.assertEqual(index_module.SCHEMA_VERSION, 3)

    # -- quarantine store ------------------------------------------------

    def test_quarantine_capability_inserts_and_is_idempotent_for_same_content(self) -> None:
        con = self._con()
        first = quarantine_capability(con, **_qtn())
        second = quarantine_capability(con, **_qtn())
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["status"], "quarantined")
        self.assertEqual(first["reason"], "pending_scan")
        self.assertEqual(len(list_quarantine(con, tenant_id="asg", status="quarantined")), 1)
        con.close()

    def test_changed_content_hash_opens_a_fresh_quarantine_row(self) -> None:
        con = self._con()
        quarantine_capability(con, **_qtn())
        different = quarantine_capability(
            con, **_qtn(content_hash="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        )
        self.assertNotEqual(different["contentHash"], "sha256:a" + "a" * 63)
        rows = list_quarantine(con, tenant_id="asg", status="quarantined")
        self.assertEqual(len(rows), 2)
        con.close()

    def test_tenant_isolation_list_get_and_release(self) -> None:
        con = self._con()
        quarantine_capability(con, **_qtn(tenant_id="tenantA"))
        b = quarantine_capability(con, **_qtn(tenant_id="tenantB", capability_uri="cap://tenantB/skill/x@1.0.0"))
        # tenantA cannot see tenantB's item.
        self.assertIsNone(get_quarantine(con, b["id"], tenant_id="tenantA"))
        # tenantB cannot release tenantA's item via get_quarantine; release must fail closed.
        a = list_quarantine(con, tenant_id="tenantA")[0]
        with self.assertRaises(QuarantineError):
            release_from_quarantine(con, a["id"], tenant_id="tenantB", actor="op@b")
        # tenantA's item stays quarantined.
        self.assertEqual(get_quarantine(con, a["id"], tenant_id="tenantA")["status"], "quarantined")
        con.close()

    # -- fail-closed release --------------------------------------------

    def test_release_fails_closed_without_any_scan_attestation(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        with self.assertRaisesRegex(QuarantineReleaseBlocked, "no valid clean scan"):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        # Status is unchanged; no release attestation written.
        self.assertEqual(get_quarantine(con, record["id"], tenant_id="asg")["status"], "quarantined")
        self.assertEqual(list_attestations(con, record["id"], tenant_id="asg", attestation_type="release"), [])
        con.close()

    def test_clean_scan_attestation_enables_release(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        scan = issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        self.assertEqual(scan["verdict"], "clean")
        self.assertTrue(scan["verifies"])
        self.assertTrue(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        released = release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg", reason="scan_clean")
        self.assertEqual(released["status"], "released")
        self.assertIsNotNone(released["releasedAt"])
        releases = list_attestations(con, record["id"], tenant_id="asg", attestation_type="release")
        self.assertEqual(len(releases), 1)
        self.assertTrue(releases[0]["verifies"])
        con.close()

    def test_blocked_scan_keeps_capability_quarantined_and_blocks_release(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        scan = issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_blocked_scan())
        self.assertEqual(scan["verdict"], "blocked")
        self.assertIsNone(scan_clean_attestation(con, record["id"], tenant_id="asg"))
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        with self.assertRaises(QuarantineReleaseBlocked):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        self.assertEqual(get_quarantine(con, record["id"], tenant_id="asg")["status"], "quarantined")
        con.close()

    def test_blocked_rescan_supersedes_prior_clean_scan(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        self.assertTrue(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_blocked_scan())
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        with self.assertRaises(QuarantineReleaseBlocked):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        con.close()

    # -- content-hash binding --------------------------------------------

    def test_content_drift_after_clean_scan_blocks_release(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        # The source is swapped for malicious content after the clean scan.
        con.execute(
            "UPDATE capguard_quarantine SET content_hash = ? WHERE id = ?",
            ("sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", record["id"]),
        )
        con.commit()
        self.assertIsNone(scan_clean_attestation(con, record["id"], tenant_id="asg"))
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        with self.assertRaises(QuarantineReleaseBlocked):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        con.close()

    def test_tampered_envelope_fails_verification_and_blocks_release(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        scan = issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        # Tamper with the stored envelope so the signature no longer matches.
        row = con.execute(
            "SELECT envelope_json FROM capguard_attestations WHERE id = ?", (scan["id"],)
        ).fetchone()
        tampered = json.loads(row["envelope_json"])
        tampered["verdict"] = "blocked"  # change the signed payload
        con.execute(
            "UPDATE capguard_attestations SET envelope_json = ? WHERE id = ?",
            (json.dumps(tampered, sort_keys=True), scan["id"]),
        )
        con.commit()
        self.assertFalse(verify_attestation_record(con, scan["id"]))
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        with self.assertRaises(QuarantineReleaseBlocked):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        con.close()

    # -- trusted key rotation --------------------------------------------

    def test_release_fails_closed_when_trust_anchor_rotates(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        clean_id = trusted_signing_key_id()
        # Rotate to a different signing key and attempt release trusting only the new key.
        with mock.patch.dict(
            os.environ,
            {"CAPMESH_ENVIRONMENT": "test", "CAPMESH_SIGNING_KEY_FILE": str(self.root / "rotated.pem")},
            clear=False,
        ):
            from capmesh.signing import sign_attestation as _sign

            _sign({"bootstrap": "rotated"}, persist=True)  # materialize the rotated key
            rotated_id = trusted_signing_key_id()
        self.assertNotEqual(clean_id, rotated_id)
        self.assertIsNone(scan_clean_attestation(con, record["id"], tenant_id="asg", trusted_key_id=rotated_id))
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg", trusted_key_id=rotated_id))
        with self.assertRaises(QuarantineReleaseBlocked):
            release_from_quarantine(
                con, record["id"], tenant_id="asg", actor="op@asg", trusted_key_id=rotated_id
            )
        con.close()

    # -- reject path -----------------------------------------------------

    def test_reject_marks_rejected_and_blocks_later_release(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        rejected = reject_from_quarantine(con, record["id"], tenant_id="asg", actor="gc@asg", reason="malware confirmed")
        self.assertEqual(rejected["status"], "rejected")
        rejects = list_attestations(con, record["id"], tenant_id="asg", attestation_type="reject")
        self.assertEqual(len(rejects), 1)
        self.assertTrue(rejects[0]["verifies"])
        # A rejected item cannot be released afterwards even with a clean scan.
        with self.assertRaisesRegex(QuarantineError, "status 'rejected'"):
            release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")

    def test_reject_requires_a_reason(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        with self.assertRaises(QuarantineError):
            reject_from_quarantine(con, record["id"], tenant_id="asg", actor="gc@asg", reason="   ")

    # -- scan verdict derivation -----------------------------------------

    def test_error_scan_verdict_is_not_clean(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        scan = issue_scan_attestation(
            con, record["id"], tenant_id="asg", scan_result={"error": "File too large", "findings": []}
        )
        self.assertEqual(scan["verdict"], "error")
        self.assertFalse(attestation_chain_valid(con, record["id"], tenant_id="asg"))
        con.close()

    def test_low_severity_finding_is_clean_and_releasable(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        scan = issue_scan_attestation(
            con, record["id"],
            tenant_id="asg",
            scan_result={"passed": True, "findings": [{"name": "todo", "severity": "low"}], "criticalCount": 0, "highCount": 0},
        )
        self.assertEqual(scan["verdict"], "clean")
        released = release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        self.assertEqual(released["status"], "released")
        con.close()

    # -- validation ------------------------------------------------------

    def test_unsupported_reason_rejected(self) -> None:
        con = self._con()
        with self.assertRaises(QuarantineError):
            quarantine_capability(con, **_qtn(reason="bogus"))
        con.close()

    def test_scan_requires_active_quarantine(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        # Already released -> cannot scan again.
        with self.assertRaisesRegex(QuarantineError, "status 'released'"):
            issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        con.close()

    def test_missing_quarantine_id_raises(self) -> None:
        con = self._con()
        with self.assertRaises(QuarantineError):
            issue_scan_attestation(con, "qtn_missing", tenant_id="asg", scan_result=_clean_scan())
        with self.assertRaises(QuarantineError):
            release_from_quarantine(con, "qtn_missing", tenant_id="asg", actor="op@asg")
        con.close()

    def test_wrong_tenant_quarantine_id_is_not_found(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn(tenant_id="asg"))
        with self.assertRaises(QuarantineError):
            issue_scan_attestation(con, record["id"], tenant_id="other", scan_result=_clean_scan())
        con.close()

    # -- model-agnostic runtime policy bridge ---------------------------

    def _capability(self, *, risk_tier: str = "low", signature_status: str = "verified",
                    provenance_status: str = "verified", uri: str | None = None) -> Capability:
        return Capability(
            uri=uri or "cap://asg/skill/example@1.0.0",
            capability_type="skill",
            name="example",
            version="1.0.0",
            title="example",
            description="d",
            package_path="/repo/skills/example",
            entrypoint="SKILL.md",
            source_path="/repo/skills/example/SKILL.md",
            source_kind="local",
            source_system="local",
            canonical_key="example",
            content_hash="sha256:" + "a" * 64,
            risk_tier=risk_tier,
            signature_status=signature_status,
            provenance_status=provenance_status,
        )

    def test_evaluate_release_policy_returns_allow_for_clean_low_risk(self) -> None:
        verdict = evaluate_release_policy(
            self._capability(), scan_result=_clean_scan(), injection_result=True,
        )
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(verdict.isolation_mode, "none")

    def test_policy_bridge_blocks_release_on_unverified_signature(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        # Clean scan attestation exists, but the capability's signature is
        # unchecked -> the runtime policy quarantines before indexing, so the
        # release must be refused even though the attestation chain is valid.
        cap = self._capability(signature_status="unchecked", provenance_status="unchecked")
        with self.assertRaisesRegex(QuarantineReleaseBlocked, "runtime policy verdict 'quarantine'"):
            release_from_quarantine(
                con, record["id"], tenant_id="asg", actor="op@asg",
                capability=cap, scan_result=_clean_scan(),
            )
        self.assertEqual(get_quarantine(con, record["id"], tenant_id="asg")["status"], "quarantined")
        con.close()

    def test_policy_bridge_blocks_release_on_high_risk_unverified(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        # A high-risk capability with a failed signature check denies outright
        # (high severity), so release is refused and the policy verdict is
        # recorded in the audit payload.
        cap = self._capability(
            risk_tier="high", signature_status="failed", provenance_status="verified",
        )
        with self.assertRaisesRegex(QuarantineReleaseBlocked, "runtime policy verdict 'deny'"):
            release_from_quarantine(
                con, record["id"], tenant_id="asg", actor="op@asg",
                capability=cap, scan_result=_clean_scan(),
            )
        self.assertEqual(get_quarantine(con, record["id"], tenant_id="asg")["status"], "quarantined")
        con.close()

    def test_policy_bridge_releases_when_capability_passes_all_checks(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        cap = self._capability(risk_tier="high")  # verified signature + provenance
        released = release_from_quarantine(
            con, record["id"], tenant_id="asg", actor="op@asg",
            capability=cap, scan_result=_clean_scan(), injection_result=True,
        )
        self.assertEqual(released["status"], "released")
        # Camber isolation is required for a high-tier allow verdict.
        verdict = evaluate_cap_guard_policy(cap, _clean_scan(), injection_result=True)
        self.assertEqual(verdict.action, "allow")
        self.assertEqual(verdict.isolation_mode, "camber")
        con.close()

    def test_release_without_capability_still_works_on_attestation_alone(self) -> None:
        con = self._con()
        record = quarantine_capability(con, **_qtn())
        issue_scan_attestation(con, record["id"], tenant_id="asg", scan_result=_clean_scan())
        # No capability supplied -> release on attestation evidence alone
        # (the client path, which has no authority Capability).
        released = release_from_quarantine(con, record["id"], tenant_id="asg", actor="op@asg")
        self.assertEqual(released["status"], "released")
        con.close()


if __name__ == "__main__":
    unittest.main()
