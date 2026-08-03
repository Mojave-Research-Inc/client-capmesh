from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.signing import (
    provision_production_signing_key,
    sign_attestation,
    trusted_signing_key_id,
    verify_attestation,
)


class SigningTests(unittest.TestCase):
    def test_provision_is_idempotent_secure_and_preserves_env(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            env_file = state / "capmesh.env"
            env_file.write_text("CAPMESH_ENVIRONMENT=production\nSECRET=preserved\n", encoding="utf-8")
            env_file.chmod(0o600)
            first = provision_production_signing_key(state, env_file, require_secure_state=False)
            second = provision_production_signing_key(state, env_file, require_secure_state=False)
            self.assertEqual(first["keyId"], second["keyId"])
            self.assertEqual(Path(first["keyPath"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)
            rendered = env_file.read_text(encoding="utf-8")
            self.assertIn("SECRET=preserved\n", rendered)
            self.assertEqual(rendered.count("CAPMESH_SIGNING_KEY_FILE="), 1)

    def test_attestation_must_match_trusted_key_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_key = Path(directory) / "first.pem"
            second_key = Path(directory) / "second.pem"
            with mock.patch.dict(
                os.environ,
                {"CAPMESH_ENVIRONMENT": "test", "CAPMESH_SIGNING_KEY_FILE": str(first_key)},
                clear=False,
            ):
                signed = sign_attestation({"schema": "test"}, persist=True)
                first_id = trusted_signing_key_id()
            with mock.patch.dict(
                os.environ,
                {"CAPMESH_ENVIRONMENT": "test", "CAPMESH_SIGNING_KEY_FILE": str(second_key)},
                clear=False,
            ):
                sign_attestation({"schema": "bootstrap-second-key"}, persist=True)
                second_id = trusted_signing_key_id()
            self.assertNotEqual(first_id, second_id)
            self.assertTrue(verify_attestation(signed, trusted_key_id=first_id))
            self.assertFalse(verify_attestation(signed, trusted_key_id=second_id))

    def test_key_id_is_covered_by_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "key.pem"
            with mock.patch.dict(
                os.environ,
                {"CAPMESH_ENVIRONMENT": "test", "CAPMESH_SIGNING_KEY_FILE": str(key_path)},
                clear=False,
            ):
                signed = sign_attestation({"schema": "test"}, persist=True)
            tampered = json.loads(json.dumps(signed))
            tampered["keyId"] = "sha256:" + "0" * 64
            self.assertFalse(verify_attestation(tampered))


if __name__ == "__main__":
    unittest.main()
