"""Token audience and issuer validation for OAuth 2.0 / OIDC tokens.

Validates JWT bearer tokens against configured issuer and audience
allowlists. Supports RFC 8707 resource indicators by checking the
"aud" claim matches the expected resource identifier.
"""

from __future__ import annotations

import time
from typing import Any

# Default clock skew tolerance in seconds
DEFAULT_CLOCK_SKEW_SECONDS = 30


def validate_token_claims(
    claims: dict[str, Any],
    *,
    expected_audience: str | list[str] | None = None,
    expected_issuer: str | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: float | None = None,
) -> tuple[bool, str]:
    """Validate JWT claims against expected audience and issuer.

    Returns (valid, error_message). An empty/None expected_audience or
    expected_issuer skips that check.
    """
    if not isinstance(claims, dict):
        return False, "Claims must be a dict"
    current_time = now if now is not None else time.time()

    # Check expiry
    exp = claims.get("exp")
    if exp is not None:
        try:
            exp_ts = float(exp)
            if current_time > exp_ts + clock_skew_seconds:
                return False, f"Token expired at {exp_ts}"
        except (ValueError, TypeError):
            return False, "Invalid exp claim"

    # Check not-before
    nbf = claims.get("nbf")
    if nbf is not None:
        try:
            nbf_ts = float(nbf)
            if current_time < nbf_ts - clock_skew_seconds:
                return False, f"Token not yet valid (nbf={nbf_ts})"
        except (ValueError, TypeError):
            return False, "Invalid nbf claim"

    # Check issuer
    if expected_issuer is not None:
        iss = str(claims.get("iss", ""))
        if iss != expected_issuer:
            return False, f"Token issuer mismatch: expected {expected_issuer}, got {iss}"

    # Check audience (RFC 8707 resource indicators)
    if expected_audience is not None:
        aud = claims.get("aud")
        if aud is None:
            return False, "Token missing aud claim"
        if isinstance(aud, str):
            aud = [aud]
        if isinstance(expected_audience, str):
            expected = [expected_audience]
        else:
            expected = expected_audience
        if not any(a in expected for a in aud):
            return False, f"Token audience mismatch: expected {expected}, got {aud}"

    return True, ""


def validate_resource_indicator(
    token_claims: dict[str, Any],
    resource_url: str,
    *,
    allowed_resources: list[str] | None = None,
) -> tuple[bool, str]:
    """Validate RFC 8707 resource indicator in a token.

    The "aud" claim must match the resource URL or an entry in
    allowed_resources. This enforces that tokens minted for one
    resource cannot be replayed against a different one.
    """
    aud = token_claims.get("aud")
    if aud is None:
        return False, "Token missing aud (resource indicator)"
    if isinstance(aud, str):
        aud = [aud]
    resources = [resource_url] + (allowed_resources or [])
    if not any(a in resources for a in aud):
        return False, f"Resource indicator does not match: expected one of {resources}, got {aud}"
    return True, ""


class TokenValidator:
    """Configurable token validator with issuer and audience allowlists."""

    def __init__(
        self,
        *,
        issuer: str | None = None,
        audiences: list[str] | None = None,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        self._issuer = issuer
        self._audiences = audiences or []
        self._clock_skew = clock_skew_seconds

    def validate(
        self,
        claims: dict[str, Any],
        *,
        resource_url: str | None = None,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Validate token claims with optional RFC 8707 resource indicator check."""
        valid, error = validate_token_claims(
            claims,
            expected_audience=self._audiences or None,
            expected_issuer=self._issuer,
            clock_skew_seconds=self._clock_skew,
            now=now,
        )
        if not valid:
            return False, error
        if resource_url:
            rvalid, rerror = validate_resource_indicator(claims, resource_url)
            if not rvalid:
                return False, rerror
        return True, ""
