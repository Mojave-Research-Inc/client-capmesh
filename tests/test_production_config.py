from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capmesh.install_policy import configured_superadmin_auto_approval
from capmesh.production_config import configure_canonical_root


class ProductionConfigTests(unittest.TestCase):
    def test_legacy_plugin_root_is_migrated_and_auxiliary_roots_are_preserved(self) -> None:
        # The rendered superadmin actor is read from the environment at CALL time
        # (see install_policy.superadmin_actor). This test asserted the rendered
        # value without ever setting it, so it silently depended on a module
        # default -- and broke the moment that default changed. Pin it, so the
        # assertion tests rendering rather than a constant.
        with mock.patch.dict(
            "os.environ",
            {
                "CAPMESH_SUPERADMIN_ACTOR": "test-user@example.com",
                # Same reason as the actor: node_role.default_authority_url()
                # resolves this at call time, and the test asserts the rendered
                # value. Asserting an environment-derived value without setting
                # it only ever tested a module default. Every other test that
                # cares about the authority (test_mcp_security_readiness,
                # test_http_service_auth, test_ingest_transactional) pins the
                # same URL; this one did not.
                "CAPMESH_AUTHORITY_URL": "https://capmesh.example.com",
            },
            clear=False,
        ), tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            env_file = state / "capmesh.env"
            env_file.write_text(
                "CAPMESH_ENVIRONMENT=production\n"
                "CAPMESH_ROOTS=/opt/asg-os/plugins:/home/jason/.codex/skills\n"
                "CAPMESH_READY_MIN_CAPABILITIES=3936\n"
                "CAPMESH_MIN_HEALTHY=3936\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            canonical = state / "current" / "capability-roots" / "asg-os-plugins"
            first = configure_canonical_root(state, env_file, canonical, require_secure_state=False)
            second = configure_canonical_root(state, env_file, canonical, require_secure_state=False)
            self.assertEqual(first, second)
            rendered = env_file.read_text(encoding="utf-8")
            self.assertIn(f"CAPMESH_ROOTS={canonical}:/home/jason/.codex/skills\n", rendered)
            self.assertNotIn("/opt/asg-os/plugins", rendered)
            self.assertEqual(rendered.count("CAPMESH_ROOTS="), 1)
            self.assertEqual(rendered.count("CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE=1"), 1)
            self.assertEqual(rendered.count("CAPMESH_SUPERADMIN_ACTOR=test-user@example.com"), 1)
            self.assertEqual(rendered.count("CAPMESH_NODE_ROLE=authoritative"), 1)
            self.assertEqual(rendered.count("CAPMESH_AUTHORITY_URL=https://capmesh.example.com"), 1)
            self.assertEqual(rendered.count("CAPMESH_READY_MIN_CAPABILITIES=3000"), 1)
            self.assertEqual(rendered.count("CAPMESH_MIN_HEALTHY=3000"), 1)
            self.assertNotIn("3936", rendered)
            self.assertEqual(first["catalogHealthFloor"], "3000")
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

            replica = configure_canonical_root(
                state,
                env_file,
                canonical,
                require_secure_state=False,
                node_role="non-voting-raft",
            )
            self.assertEqual(replica["nodeRole"], "non-voting-raft")
            rendered = env_file.read_text(encoding="utf-8")
            self.assertEqual(rendered.count("CAPMESH_NODE_ROLE=non-voting-raft"), 1)
            self.assertNotIn("CAPMESH_NODE_ROLE=authoritative", rendered)

    def test_superadmin_auto_approval_is_explicit_and_identity_pinned(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE": "1",
                "CAPMESH_SUPERADMIN_ACTOR": "test-user@example.com",
                # The allowlist is what makes a SECOND identity acceptable and
                # "attacker@" not. The test asserted exactly that distinction
                # while never declaring the allowlist, so it could only have
                # passed against an implicit default -- i.e. a set of superadmins
                # nobody configured. Declare it.
                "CAPMESH_SUPERADMIN_ACTORS":
                    "test-user@example.com,test-admin@example.com",
            },
            clear=False,
        ):
            self.assertEqual(configured_superadmin_auto_approval(), "test-user@example.com")
            self.assertEqual(
                configured_superadmin_auto_approval("test-admin@example.com"),
                "test-admin@example.com",
            )
            self.assertIsNone(configured_superadmin_auto_approval("attacker@example.com"))
        with mock.patch.dict(
            "os.environ",
            {
                "CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE": "1",
                "CAPMESH_SUPERADMIN_ACTOR": "attacker@example.com",
                "CAPMESH_SUPERADMIN_ACTORS":
                    "test-user@example.com,test-admin@example.com",
            },
            clear=False,
        ), self.assertRaisesRegex(ValueError, "configured superadmin"):
            configured_superadmin_auto_approval()

    def test_unset_allowlist_pins_to_the_single_configured_actor(self) -> None:
        """With no allowlist, the single actor governs -- and nobody else does.

        This pins the fallback that fixes a real config trap: the sanitizer pass
        made CAPMESH_SUPERADMIN_ACTORS mandatory without a default or any caller
        setting it, so the allowlist was always empty and EVERY auto-approve
        raised "must be one of the configured superadmins: " against an empty
        list. That failed closed on a variable nobody knew existed.

        The fallback must not become a hole: an unset allowlist authorizes the
        configured actor ONLY, never an arbitrary requested identity.
        """
        with mock.patch.dict(
            "os.environ",
            {
                "CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE": "1",
                "CAPMESH_SUPERADMIN_ACTOR": "test-user@example.com",
                "CAPMESH_SUPERADMIN_ACTORS": "",
            },
            clear=False,
        ):
            self.assertEqual(configured_superadmin_auto_approval(), "test-user@example.com")
            self.assertIsNone(configured_superadmin_auto_approval("test-admin@example.com"))
            self.assertIsNone(configured_superadmin_auto_approval("attacker@example.com"))


if __name__ == "__main__":
    unittest.main()
