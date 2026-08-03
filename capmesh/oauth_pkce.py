"""OAuth 2.1 Authorization Code + PKCE flow for remote HTTP transport.

Implements the OAuth 2.1 Authorization Code flow with PKCE (RFC 7636)
for the capmesh remote HTTP transport. Generates and verifies PKCE
challenges, builds authorization URLs, and exchanges authorization
codes for access tokens.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from .utils import utc_now

CODE_VERIFIER_LENGTH = 64
CODE_CHALLENGE_METHOD = "S256"


def generate_code_verifier() -> str:
    """Generate a random PKCE code verifier."""
    return secrets.token_urlsafe(CODE_VERIFIER_LENGTH)


def compute_code_challenge(verifier: str) -> str:
    """Compute the PKCE code challenge from a verifier (S256 method)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    scopes: list[str] | None = None,
    state: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> str:
    """Build an OAuth 2.1 authorization URL with PKCE."""
    from urllib.parse import urlencode
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": compute_code_challenge(code_verifier),
        "code_challenge_method": CODE_CHALLENGE_METHOD,
    }
    if scopes:
        params["scope"] = " ".join(scopes)
    if state:
        params["state"] = state
    if extra_params:
        params.update(extra_params)
    return f"{authorization_endpoint}?{urlencode(params)}"


def build_token_request(
    *,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    client_secret: str | None = None,
) -> dict[str, Any]:
    """Build a token exchange request body for the authorization code flow."""
    body: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        body["client_secret"] = client_secret
    return {
        "url": token_endpoint,
        "method": "POST",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": body,
    }


def validate_pkce(verifier: str, challenge: str, method: str = CODE_CHALLENGE_METHOD) -> bool:
    """Validate a PKCE code verifier against the stored challenge."""
    if method != "S256":
        return verifier == challenge
    computed = compute_code_challenge(verifier)
    return secrets.compare_digest(computed, challenge)


class PKCESession:
    """Tracks an in-progress OAuth 2.1 + PKCE authorization flow."""

    def __init__(self, client_id: str, redirect_uri: str, scopes: list[str] | None = None) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scopes or ["capmesh:read"]
        self.code_verifier = generate_code_verifier()
        self.code_challenge = compute_code_challenge(self.code_verifier)
        self.state = secrets.token_urlsafe(32)
        self.created_at = utc_now()

    def authorization_url(self, authorization_endpoint: str) -> str:
        return build_authorization_url(
            authorization_endpoint=authorization_endpoint,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_verifier=self.code_verifier,
            scopes=self.scopes,
            state=self.state,
        )

    def token_request(self, token_endpoint: str, code: str, client_secret: str | None = None) -> dict[str, Any]:
        return build_token_request(
            token_endpoint=token_endpoint,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code=code,
            code_verifier=self.code_verifier,
            client_secret=client_secret,
        )
