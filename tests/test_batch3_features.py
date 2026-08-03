"""Tests for RFC 9728, token validation, signed allowlist, malware scan, and SLSA provenance."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capmesh.index import connect, init_db


class TestRFC9728(unittest.TestCase):
    def test_build_resource_metadata(self) -> None:
        from capmesh.rfc9728 import build_resource_metadata
        meta = build_resource_metadata(resource_url="https://capmesh.asg.ts.net")
        self.assertEqual(meta["resource"], "https://capmesh.asg.ts.net")
        self.assertIn("scopes_supported", meta)
        self.assertIn("bearer_methods_supported", meta)
        self.assertIn("signing_alg_values_supported", meta)

    def test_validate_resource_metadata(self) -> None:
        from capmesh.rfc9728 import validate_resource_metadata
        valid, err = validate_resource_metadata({"resource": "https://test.com"})
        self.assertTrue(valid)
        valid, err = validate_resource_metadata({})
        self.assertFalse(valid)
        self.assertIn("resource", err)

    def test_serve_resource_metadata(self) -> None:
        from capmesh.rfc9728 import serve_resource_metadata
        meta = serve_resource_metadata("https://capmesh.asg.ts.net")
        self.assertEqual(meta["resource"], "https://capmesh.asg.ts.net")


class TestTokenValidation(unittest.TestCase):
    def test_valid_claims(self) -> None:
        import time

        from capmesh.token_validation import validate_token_claims
        claims = {"exp": time.time() + 3600, "iss": "https://auth.test.com", "aud": "capmesh"}
        valid, _ = validate_token_claims(claims, expected_audience="capmesh", expected_issuer="https://auth.test.com")
        self.assertTrue(valid)

    def test_expired_token(self) -> None:
        from capmesh.token_validation import validate_token_claims
        claims = {"exp": 1}
        valid, err = validate_token_claims(claims)
        self.assertFalse(valid)
        self.assertIn("expired", err.lower())

    def test_audience_mismatch(self) -> None:
        import time

        from capmesh.token_validation import validate_token_claims
        claims = {"exp": time.time() + 3600, "aud": "wrong-audience"}
        valid, err = validate_token_claims(claims, expected_audience="capmesh")
        self.assertFalse(valid)
        self.assertIn("audience", err.lower())

    def test_issuer_mismatch(self) -> None:
        import time

        from capmesh.token_validation import validate_token_claims
        claims = {"exp": time.time() + 3600, "iss": "https://wrong.com"}
        valid, err = validate_token_claims(claims, expected_issuer="https://auth.test.com")
        self.assertFalse(valid)
        self.assertIn("issuer", err.lower())

    def test_resource_indicator(self) -> None:
        from capmesh.token_validation import validate_resource_indicator
        claims = {"aud": "https://capmesh.asg.ts.net"}
        valid, _ = validate_resource_indicator(claims, "https://capmesh.asg.ts.net")
        self.assertTrue(valid)
        valid, _err = validate_resource_indicator(claims, "https://other.com")
        self.assertFalse(valid)

    def test_token_validator_class(self) -> None:
        import time

        from capmesh.token_validation import TokenValidator
        validator = TokenValidator(issuer="https://auth.test.com", audiences=["capmesh"])
        claims = {"exp": time.time() + 3600, "iss": "https://auth.test.com", "aud": "capmesh"}
        valid, _ = validator.validate(claims)
        self.assertTrue(valid)


class TestSignedAllowlist(unittest.TestCase):
    def test_approve_and_check(self) -> None:
        from capmesh.signed_allowlist import approve_binding, is_binding_approved
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            approve_binding(con, "test:cap", "hash123", "key1", "sig1", approved_by="admin")
            self.assertTrue(is_binding_approved(con, "test:cap", "hash123"))
            con.close()

    def test_revoke_binding(self) -> None:
        from capmesh.signed_allowlist import approve_binding, is_binding_approved, revoke_binding
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            approve_binding(con, "test:cap", "hash123", "key1", "sig1", approved_by="admin")
            revoke_binding(con, "test:cap", "hash123")
            self.assertFalse(is_binding_approved(con, "test:cap", "hash123"))
            con.close()

    def test_list_approved_bindings(self) -> None:
        from capmesh.signed_allowlist import approve_binding, list_approved_bindings
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            approve_binding(con, "test:cap1", "hash1", "key1", "sig1", approved_by="admin")
            approve_binding(con, "test:cap2", "hash2", "key1", "sig2", approved_by="admin")
            bindings = list_approved_bindings(con)
            self.assertEqual(len(bindings), 2)
            con.close()

    def test_compute_binding_hash(self) -> None:
        from capmesh.signed_allowlist import compute_binding_hash
        h1 = compute_binding_hash("test:cap", "entry.py", "sha256:abc")
        h2 = compute_binding_hash("test:cap", "entry.py", "sha256:abc")
        h3 = compute_binding_hash("test:cap", "entry2.py", "sha256:abc")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


class TestMalwareScan(unittest.TestCase):
    def test_scan_clean_file(self) -> None:
        from capmesh.malware_scan import scan_file
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "clean.py"
            f.write_text("def hello():\n    return 'world'\n")
            result = scan_file(f)
            self.assertTrue(result["passed"])
            self.assertEqual(len(result.get("findings", [])), 0)

    def test_scan_malicious_file(self) -> None:
        from capmesh.malware_scan import scan_file
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "mal.py"
            f.write_text("os.chmod(\"/tmp/test\", 0o777)\n")
            result = scan_file(f)
            self.assertFalse(result["passed"])
            self.assertGreater(result["highCount"], 0)

    def test_scan_nonexistent_file(self) -> None:
        from capmesh.malware_scan import scan_file
        result = scan_file("/nonexistent/file.py")
        self.assertFalse(result["passed"])

    def test_scan_capability(self) -> None:
        from capmesh.malware_scan import scan_capability
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "test.db"
            con = connect(db)
            init_db(con)
            result = scan_capability(con, "nonexistent:cap")
            self.assertFalse(result["passed"])
            con.close()


class TestSLSAProvenance(unittest.TestCase):
    def test_build_provenance_statement(self) -> None:
        from capmesh.slsa_provenance import build_provenance_statement
        stmt = build_provenance_statement(subject_uri="test:cap", subject_hash="sha256:abc123")
        self.assertEqual(stmt["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(stmt["subject"][0]["name"], "test:cap")
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], "abc123")
        self.assertIn("buildDefinition", stmt["predicate"])
        self.assertIn("runDetails", stmt["predicate"])

    def test_compute_verification_summary(self) -> None:
        from capmesh.slsa_provenance import build_provenance_statement, compute_verification_summary
        stmt = build_provenance_statement(subject_uri="test:cap", subject_hash="sha256:abc")
        summary = compute_verification_summary(stmt, verified=True)
        self.assertTrue(summary["verified"])
        self.assertIn("provenanceHash", summary)
        self.assertEqual(summary["schema"], "capmesh.verification.v1")

    def test_build_keyless_signing_policy(self) -> None:
        from capmesh.slsa_provenance import build_keyless_signing_policy
        policy = build_keyless_signing_policy()
        self.assertEqual(policy["schema"], "capmesh.keyless-signing-policy.v1")
        self.assertTrue(policy["enforceTimestamp"])
        self.assertEqual(policy["maxAgeSeconds"], 86400)


if __name__ == "__main__":
    unittest.main()
