"""Tests for capmesh/cli.py ``store_keychain_secret`` — R4-08 (LANE 3).

The macOS ``security add-generic-password -w <secret>`` CLI has no stdin mode
for ``-w``, so passing the refresh token as an argv element leaks it via the
process table (``ps``/``ps auxe``) on a shared tailnet device. With
``asgcode-keychain`` absent we therefore skip the keychain ``security`` call by
default (the bearer token the client uses is already in the 0600 capmesh.env
file). An operator can opt back into the legacy argv path with
``CAPMESH_KEYCHAIN_ARGV_FALLBACK=1``; in that case the explicit argv-leak
warning must be emitted to stderr.

These tests mock ``command_exists`` and ``subprocess.run`` so they never touch
a real keychain or fork a real ``security`` process.
"""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr
from unittest import mock

from capmesh import cli as cli_module
from capmesh.cli import store_keychain_secret

SECRET = "super-secret-refresh-token-do-not-leak"
SERVICE = "asg-capmesh-m365-refresh"
ACCOUNT = "session-abc"


def _capture_argv_lists(mock_run: mock.MagicMock) -> list[list[str]]:
    """Flatten every argv list passed to the patched subprocess.run."""
    argv_lists: list[list[str]] = []
    for call in mock_run.call_args_list:
        # subprocess.run is invoked positionally with a single argv list.
        if call.args:
            argv_lists.append(list(call.args[0]))
    return argv_lists


class StoreKeychainSecretArgvLeakTests(unittest.TestCase):
    """R4-08: the refresh token must never reach argv via the macOS fallback."""

    def setUp(self) -> None:
        # Default: no opt-in. Each test may re-enable the fallback.
        self.env = mock.patch.dict(
            os.environ,
            {"CAPMESH_KEYCHAIN_ARGV_FALLBACK": ""},
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_default_skips_security_call_when_asgcode_keychain_absent(self) -> None:
        """asgcode-keychain absent + `security` present: skip the security call,
        do NOT place the secret in any argv, warn on stderr, return True."""
        with mock.patch.object(cli_module, "command_exists", side_effect=lambda name: name == "security"), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()) as err:
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertTrue(result, "default path must report success (bearer token persisted in env file)")
        self.assertIn("skipped", err.getvalue().lower())
        self.assertIn("argv", err.getvalue().lower())
        # subprocess.run must never have been invoked at all in the skip path.
        argv_lists = _capture_argv_lists(fake_subprocess.run)
        for argv in argv_lists:
            self.assertNotIn(SECRET, argv, f"secret leaked into argv: {argv}")
        fake_subprocess.run.assert_not_called()

    def test_secret_never_in_argv_on_default_path(self) -> None:
        """Even if subprocess.run were called, the secret value must not appear
        in any constructed argv list on the default (skip) path."""
        captured: list[list[str]] = []

        def fake_run(argv, **kwargs):
            captured.append(list(argv))
            return mock.MagicMock(returncode=0)

        with mock.patch.object(cli_module, "command_exists", side_effect=lambda name: name == "security"), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()):
            fake_subprocess.run = fake_run
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertTrue(result)
        for argv in captured:
            self.assertNotIn(SECRET, argv, f"secret value present in argv: {argv}")

    def test_opt_in_fallback_warns_and_stores_via_argv(self) -> None:
        """With CAPMESH_KEYCHAIN_ARGV_FALLBACK=1 the legacy argv path runs, but
        the mandatory stderr warning must be emitted so the operator knows the
        token is exposed via the process table."""
        self.env.stop()
        self.env = mock.patch.dict(
            os.environ,
            {"CAPMESH_KEYCHAIN_ARGV_FALLBACK": "1"},
            clear=False,
        )
        self.env.start()

        with mock.patch.object(cli_module, "command_exists", side_effect=lambda name: name == "security"), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()) as err:
            fake_subprocess.run = mock.MagicMock(return_value=mock.MagicMock(returncode=0))
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertTrue(result, "opt-in fallback that succeeds must return True")
        stderr_text = err.getvalue()
        self.assertIn("WARNING", stderr_text)
        self.assertIn("argv", stderr_text)
        self.assertIn("asgcode-keychain", stderr_text)
        # The legacy path legitimately passes the secret via argv — that is the
        # opt-in behavior under test; assert the call shape is the security CLI.
        argv_lists = _capture_argv_lists(fake_subprocess.run)
        add_calls = [a for a in argv_lists if "add-generic-password" in a]
        self.assertGreater(len(add_calls), 0, "opt-in path must invoke add-generic-password")
        self.assertTrue(any(SECRET in a for a in add_calls), "opt-in path stores the secret via -w argv")
        self.assertTrue(any("-w" in a for a in add_calls), "opt-in path must use the -w flag")

    def test_opt_in_fallback_failure_returns_false_with_warning(self) -> None:
        """If the opt-in security call fails, return False but still warn."""
        self.env.stop()
        self.env = mock.patch.dict(
            os.environ,
            {"CAPMESH_KEYCHAIN_ARGV_FALLBACK": "1"},
            clear=False,
        )
        self.env.start()

        with mock.patch.object(cli_module, "command_exists", side_effect=lambda name: name == "security"), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()) as err:
            fake_subprocess.run = mock.MagicMock(return_value=mock.MagicMock(returncode=1))
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertFalse(result, "a failed security call must return False")
        self.assertIn("WARNING", err.getvalue())

    def test_asgcode_keychain_preferred_path_unchanged(self) -> None:
        """When asgcode-keychain is present and succeeds, the macOS security
        fallback is never reached and no argv-leak warning is emitted."""
        captured: list[list[str]] = []

        def fake_run(argv, **kwargs):
            captured.append(list(argv))
            return mock.MagicMock(returncode=0)

        with mock.patch.object(cli_module, "command_exists", return_value=True), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()) as err:
            fake_subprocess.run = fake_run
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertTrue(result)
        self.assertEqual(err.getvalue(), "", "preferred path must emit no stderr warning")
        # Only the asgcode-keychain `set` call should have fired.
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][0], "asgcode-keychain")
        self.assertIn("asgcode-keychain", captured[0][0])

    def test_no_security_and_no_asgcode_keychain_returns_false(self) -> None:
        """Neither tool present: return False, no subprocess.run call."""
        with mock.patch.object(cli_module, "command_exists", return_value=False), \
             mock.patch.object(cli_module, "subprocess") as fake_subprocess, \
             redirect_stderr(io.StringIO()) as err:
            result = store_keychain_secret(SERVICE, ACCOUNT, SECRET)

        self.assertFalse(result)
        fake_subprocess.run.assert_not_called()
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
