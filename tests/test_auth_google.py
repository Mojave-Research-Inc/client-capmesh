"""Tests for capmesh/auth_google.py — Google OIDC auth flow helpers.

These tests exercise URL building, code exchange, and ID token verification
without hitting the Google OAuth servers (everything is mocked).
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

from capmesh.auth_google import (
    GOOGLE_ISSUERS,
    GOOGLE_OIDC_SCOPES,
    GoogleAuthError,
    build_google_auth_url,
    exchange_code_for_tokens,
    verify_google_id_token,
)


class ClientConfigTests(unittest.TestCase):
    """Test the internal _client_config helper."""

    def test_builds_standard_google_web_config(self) -> None:
        from capmesh.auth_google import _client_config
        config = _client_config("my-client-id", "my-client-secret")
        self.assertIn("web", config)
        web = config["web"]
        self.assertEqual(web["client_id"], "my-client-id")
        self.assertEqual(web["client_secret"], "my-client-secret")
        self.assertEqual(web["auth_uri"], "https://accounts.google.com/o/oauth2/v2/auth")
        self.assertEqual(web["token_uri"], "https://oauth2.googleapis.com/token")
        self.assertEqual(web["auth_provider_x509_cert_url"], "https://www.googleapis.com/oauth2/v1/certs")


class GoogleAuthConstantsTests(unittest.TestCase):
    """Test that constants are correctly defined."""

    def test_oidc_scopes_include_required_elements(self) -> None:
        self.assertIn("openid", GOOGLE_OIDC_SCOPES)
        self.assertIn("email", GOOGLE_OIDC_SCOPES)
        self.assertIn("profile", GOOGLE_OIDC_SCOPES)

    def test_issuers_include_both_forms(self) -> None:
        self.assertIn("accounts.google.com", GOOGLE_ISSUERS)
        self.assertIn("https://accounts.google.com", GOOGLE_ISSUERS)


class BuildAuthUrlTests(unittest.TestCase):
    """Test build_google_auth_url."""

    def test_returns_nonempty_url(self) -> None:
        url = build_google_auth_url("test-state", "http://localhost/callback", "client-id")
        self.assertIsInstance(url, str)
        self.assertTrue(len(url) > 0)
        self.assertIn("accounts.google.com", url)

    def test_url_contains_state_parameter(self) -> None:
        url = build_google_auth_url("my-csrf-state", "http://localhost/callback", "client-id")
        self.assertIn("my-csrf-state", url)

    def test_url_contains_redirect_uri(self) -> None:
        url = build_google_auth_url("state", "http://localhost:9999/oauth/callback", "client-id")
        parsed = urlparse(url)
        redirect_uri = parse_qs(parsed.query).get("redirect_uri", [""])[0]
        self.assertEqual(redirect_uri, "http://localhost:9999/oauth/callback")

    def test_url_contains_offline_access_type(self) -> None:
        url = build_google_auth_url("state", "http://localhost/callback", "client-id")
        self.assertIn("access_type=offline", url)

    def test_url_contains_select_account_prompt(self) -> None:
        url = build_google_auth_url("state", "http://localhost/callback", "client-id")
        self.assertIn("prompt=select_account", url)


class ExchangeCodeTests(unittest.TestCase):
    """Test exchange_code_for_tokens."""

    def test_exchanges_code_and_returns_id_token(self) -> None:
        mock_creds = mock.MagicMock()
        mock_creds.id_token = "fake.jwt.token"
        mock_creds.token = "fake.access.token"
        mock_creds.refresh_token = "fake.refresh.token"

        mock_flow = mock.MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.from_client_config = mock.MagicMock(return_value=mock_flow)

        with mock.patch("capmesh.auth_google.Flow", mock_flow):
            result = exchange_code_for_tokens(
                "auth-code-123",
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="http://localhost/callback",
            )
            self.assertEqual(result["id_token"], "fake.jwt.token")
            self.assertEqual(result["access_token"], "fake.access.token")
            self.assertEqual(result["refresh_token"], "fake.refresh.token")

    def test_raises_when_no_id_token_in_response(self) -> None:
        mock_creds = mock.MagicMock()
        mock_creds.id_token = None
        mock_creds.token = "fake.access.token"

        mock_flow = mock.MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.from_client_config = mock.MagicMock(return_value=mock_flow)

        with mock.patch("capmesh.auth_google.Flow", mock_flow):
            with self.assertRaisesRegex(GoogleAuthError, "did not include an id_token"):
                exchange_code_for_tokens(
                    "auth-code-123",
                    client_id="client-id",
                    client_secret="client-secret",
                    redirect_uri="http://localhost/callback",
                )

    def test_raises_on_token_fetch_failure(self) -> None:
        mock_flow = mock.MagicMock()
        mock_flow.from_client_config = mock.MagicMock(return_value=mock_flow)
        mock_flow.fetch_token.side_effect = Exception("network error")

        with mock.patch("capmesh.auth_google.Flow", mock_flow):
            with self.assertRaisesRegex(GoogleAuthError, "token exchange failed"):
                exchange_code_for_tokens(
                    "auth-code-123",
                    client_id="client-id",
                    client_secret="client-secret",
                    redirect_uri="http://localhost/callback",
                )


class VerifyIdTokenTests(unittest.TestCase):
    """Test verify_google_id_token."""

    def test_rejects_empty_token(self) -> None:
        with self.assertRaisesRegex(GoogleAuthError, "No id_token provided"):
            verify_google_id_token("", client_id="client-id")

    def test_rejects_empty_client_id(self) -> None:
        with self.assertRaisesRegex(GoogleAuthError, "not configured"):
            verify_google_id_token("some.token", client_id="")

    def test_rejects_bad_signature(self) -> None:
        # verify_oauth2_token raises ValueError for bad signature
        mock.MagicMock()
        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token") as mock_verify:
            mock_verify.side_effect = ValueError("signature verification failed")
            with self.assertRaisesRegex(GoogleAuthError, "verification failed"):
                verify_google_id_token("fake.token", client_id="client-id")

    def test_rejects_wrong_issuer(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "evil.attacker.com", "email": "attacker@evil.com", "email_verified": True, "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                with self.assertRaisesRegex(GoogleAuthError, "issuer .* is not accepted"):
                    verify_google_id_token("fake.token", client_id="client-id")

    def test_rejects_missing_email(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "accounts.google.com", "email_verified": True, "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                with self.assertRaisesRegex(GoogleAuthError, "did not contain an email claim"):
                    verify_google_id_token("fake.token", client_id="client-id")

    def test_rejects_unverified_email(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "accounts.google.com", "email": "user@example.com", "email_verified": False, "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                with self.assertRaisesRegex(GoogleAuthError, "email is not verified"):
                    verify_google_id_token("fake.token", client_id="client-id")

    def test_rejects_string_false_email_verified(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "accounts.google.com", "email": "user@example.com", "email_verified": "false", "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                with self.assertRaisesRegex(GoogleAuthError, "email is not verified"):
                    verify_google_id_token("fake.token", client_id="client-id")

    def test_returns_verified_user_claims(self) -> None:
        mock_request = mock.MagicMock()
        now = datetime.now(UTC)
        mock_claims = {
            "iss": "accounts.google.com",
            "email": " User@Example.COM ",
            "email_verified": True,
            "aud": "client-id",
            "sub": "112233445",
            "hd": "EXAMPLE.COM",
            "name": "Test User",
            "exp": now + timedelta(hours=1),
        }

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                result = verify_google_id_token("fake.token", client_id="client-id")
                self.assertEqual(result["email"], "user@example.com")
                self.assertTrue(result["email_verified"])
                self.assertEqual(result["sub"], "112233445")
                self.assertEqual(result["hd"], "example.com")
                self.assertEqual(result["name"], "Test User")

    def test_accepts_issuers_https_variant(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "https://accounts.google.com", "email": "user@example.com", "email_verified": True, "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                result = verify_google_id_token("fake.token", client_id="client-id")
                self.assertEqual(result["email"], "user@example.com")

    def test_accepts_string_true_email_verified(self) -> None:
        mock_request = mock.MagicMock()
        mock_claims = {"iss": "accounts.google.com", "email": "user@example.com", "email_verified": "true", "aud": "client-id", "sub": "123", "exp": datetime.now(UTC) + timedelta(hours=1)}

        with mock.patch("capmesh.auth_google.google_id_token.verify_oauth2_token", return_value=mock_claims):
            with mock.patch("capmesh.auth_google.GoogleAuthRequest", return_value=mock_request):
                result = verify_google_id_token("fake.token", client_id="client-id")
                self.assertEqual(result["email"], "user@example.com")


if __name__ == "__main__":
    unittest.main()
