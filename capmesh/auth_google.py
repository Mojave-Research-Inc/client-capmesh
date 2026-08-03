"""Google OIDC (authorization-code) sign-in for capmesh.

This module is the Google analogue of the Microsoft 365 OAuth helpers in
``server.py``/``governance.py``. It runs the standard authorization-code flow
against Google's web OAuth client (the issued credentials are web clients, not
device clients, so the device-code flow used for M365 does not apply here).

Security posture:

* ID token verification is delegated entirely to the OFFICIAL Google auth SDK
  (``google.oauth2.id_token.verify_oauth2_token``). We do NOT hand-roll JWT or
  JWKS verification. The SDK validates the signature against Google's published
  keys, enforces ``aud == client_id``, enforces ``iss`` in the accepted Google
  issuer set, and enforces ``exp``.
* The caller's email is taken ONLY from the verified ID token claims, never from
  a request parameter, and ``email_verified`` must be true.
* Allowlist enforcement happens server-side in ``server.py`` before any capmesh
  session is minted (see ``email_is_allowed``).
"""

from __future__ import annotations

import os
from typing import Any

from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token
from google_auth_oauthlib.flow import Flow

# OIDC scopes: openid + email + profile is sufficient to obtain a verified email
# claim in the ID token. We deliberately request nothing broader.
GOOGLE_OIDC_SCOPES: list[str] = ["openid", "email", "profile"]

# Google's accepted ID token issuers. The SDK enforces this set internally; we
# pass it explicitly so the accepted issuers are pinned and auditable here.
GOOGLE_ISSUERS: tuple[str, ...] = ("accounts.google.com", "https://accounts.google.com")

DEFAULT_GOOGLE_REDIRECT_URI = os.environ.get("CAPMESH_GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/v1/auth/google/callback")


class _TimedGoogleAuthRequest(GoogleAuthRequest):
    """``google.auth.transport.requests.Request`` with a per-instance default timeout.

    ``verify_oauth2_token`` -> ``verify_token`` -> ``_fetch_certs`` calls
    ``request(certs_url, method="GET")`` with no ``timeout`` kwarg, so the SDK's
    own default (120s) would apply to the legacy x509 cert-fetch path. Subclassing
    lets us inject a bounded ``timeout`` into every outbound call WITHOUT the
    process-global ``socket.setdefaulttimeout`` mutation that raced with other
    request threads. (The modern JWK path uses PyJWKClient, which already has a
    bounded default and a JWK-set cache, so it is not affected.)
    """

    def __init__(self, timeout: float | None = None) -> None:
        super().__init__()
        self._timeout = timeout

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):  # type: ignore[override]
        return super().__call__(
            url,
            method=method,
            body=body,
            headers=headers,
            timeout=timeout if timeout is not None else self._timeout,
            **kwargs,
        )


class GoogleAuthError(RuntimeError):
    """Raised when the Google auth provider interaction fails."""


def _client_config(client_id: str, client_secret: str) -> dict[str, Any]:
    """Build the in-memory web-client config the oauthlib Flow expects.

    Avoids needing a client_secret.json file on disk; the credentials come from
    env vars resolved by the server.
    """

    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        }
    }


def build_google_auth_url(
    state: str,
    redirect_uri: str,
    client_id: str,
    *,
    client_secret: str | None = None,
) -> str:
    """Return the Google consent URL for the authorization-code flow.

    ``state`` is the capmesh OAuth session state (CSRF binding). ``client_secret``
    is optional for URL construction but accepted so callers can pass the full
    web-client config uniformly.
    """

    flow = Flow.from_client_config(
        _client_config(client_id, client_secret or os.environ.get("CAPMESH_GOOGLE_CLIENT_SECRET", "")),
        scopes=GOOGLE_OIDC_SCOPES,
    )
    flow.redirect_uri = redirect_uri
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account",
        state=state,
    )
    return authorization_url


def exchange_code_for_tokens(
    code: str,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    state: str | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Exchange an authorization code for Google tokens.

    Returns a dict containing at least ``id_token`` (a JWT string), plus
    ``access_token`` / ``refresh_token`` when granted. Raises ``GoogleAuthError``
    on any provider error. ``timeout`` (seconds) bounds the outbound HTTP calls
    to Google's token endpoint per call, instead of a process-global
    ``socket.setdefaulttimeout`` that races with other threads' socket ops.
    """

    flow = Flow.from_client_config(
        _client_config(client_id, client_secret),
        scopes=GOOGLE_OIDC_SCOPES,
        state=state,
    )
    flow.redirect_uri = redirect_uri
    try:
        flow.fetch_token(code=code, timeout=timeout)
    except Exception as exc:  # oauthlib raises a variety of exception types
        raise GoogleAuthError(f"Google token exchange failed: {exc}") from exc
    creds = flow.credentials
    raw_id_token = getattr(creds, "id_token", None)
    if not raw_id_token:
        raise GoogleAuthError("Google token response did not include an id_token.")
    return {
        "id_token": raw_id_token,
        "access_token": getattr(creds, "token", None),
        "refresh_token": getattr(creds, "refresh_token", None),
    }


def verify_google_id_token(id_token_str: str, client_id: str, *, timeout: float | None = None) -> dict[str, Any]:
    """Verify a Google ID token via the official SDK and return a minimal claim set.

    The SDK validates the JWT signature against Google's published keys and
    enforces ``aud == client_id``, ``iss`` in the Google issuer set, and ``exp``.
    On top of that we require ``email_verified`` to be true and an ``email`` to be
    present. The returned email is authoritative and comes solely from the token.
    ``timeout`` bounds the outbound JWKS/cert fetch per call instead of a
    process-global ``socket.setdefaulttimeout``.
    """

    if not id_token_str:
        raise GoogleAuthError("No id_token provided for verification.")
    if not client_id:
        raise GoogleAuthError("CAPMESH_GOOGLE_CLIENT_ID is not configured.")
    try:
        claims = google_id_token.verify_oauth2_token(
            id_token_str,
            _TimedGoogleAuthRequest(timeout=timeout),
            audience=client_id,
        )
    except ValueError as exc:
        # verify_oauth2_token raises ValueError for bad signature, wrong aud,
        # wrong iss, or expired token.
        raise GoogleAuthError(f"Google ID token verification failed: {exc}") from exc

    issuer = str(claims.get("iss", ""))
    if issuer not in GOOGLE_ISSUERS:
        raise GoogleAuthError(f"Google ID token issuer '{issuer}' is not accepted.")

    email = str(claims.get("email") or "").strip()
    email_verified = claims.get("email_verified")
    # Google may serialize email_verified as a bool or the string "true".
    verified = email_verified is True or str(email_verified).lower() == "true"
    if not email:
        raise GoogleAuthError("Google ID token did not contain an email claim.")
    if not verified:
        raise GoogleAuthError("Google account email is not verified (email_verified=false).")

    return {
        "email": email.lower(),
        "email_verified": True,
        "sub": str(claims.get("sub") or ""),
        "hd": str(claims.get("hd") or "").lower(),
        "name": claims.get("name"),
    }
