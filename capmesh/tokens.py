from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
from datetime import UTC, datetime
from typing import Any

from .access_control import ROLE_RIGHTS
from .models import Principal
from .utils import (
    _CAPMESH_SESSION_TTL,
    _OAUTH_TOKEN_DELIVERY_TTL,
    DEFAULT_TENANT,
    _oauth_verify_signature_enabled,
    _production_environment,
    expires_in,
    json_dumps,
    json_loads,
    new_id,
    utc_now,
)


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_graph_client_state(con: sqlite3.Connection, supplied: str) -> bool:
    if not supplied:
        return False
    supplied_hash = hash_secret(supplied)
    row = con.execute(
        "SELECT 1 FROM graph_subscriptions WHERE client_state_hash = ? AND status IN ('planned', 'active') LIMIT 1",
        (supplied_hash,),
    ).fetchone()
    return row is not None


def mint_capmesh_token(
    con: sqlite3.Connection,
    principal: Principal,
    *,
    ttl_seconds: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .governance import audit_event, ensure_identity_for_principal
    if ttl_seconds is None:
        ttl_seconds = _CAPMESH_SESSION_TTL
    identity_id = ensure_identity_for_principal(con, principal)
    token = "cm_" + secrets.token_urlsafe(32)
    expires_at = expires_in(ttl_seconds)
    session_id = new_id("cms")
    principal_dict = {**principal.to_dict(), "identityId": identity_id, "authenticated": True}
    con.execute(
        """
        INSERT INTO capmesh_sessions(id, tenant_id, token_hash, identity_id, subject, principal_json, scopes_json, expires_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            principal.tenant_id or DEFAULT_TENANT,
            hash_secret(token),
            identity_id,
            principal.subject,
            json_dumps(principal_dict),
            json_dumps(list(principal.scopes)),
            expires_at,
            json_dumps(metadata or {}),
        ),
    )
    audit_event(
        con,
        event_type="auth.capmesh_session.issued",
        actor=principal.subject,
        actor_type="user",
        target=session_id,
        action="issue",
        decision="allow",
        payload={"expiresAt": expires_at, "metadata": sanitize_auth_metadata(metadata or {})},
        tenant_id=principal.tenant_id or DEFAULT_TENANT,
    )
    con.commit()
    return {
        "sessionId": session_id,
        "tenantId": principal.tenant_id or DEFAULT_TENANT,
        "bearerToken": token,
        "tokenType": "Bearer",
        "expiresAt": expires_at,
        "principal": principal_dict,
    }


def principal_from_bearer(con: sqlite3.Connection, token: str | None) -> Principal | None:
    if not token:
        return None
    row = con.execute(
        """
        SELECT * FROM capmesh_sessions
        WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
        LIMIT 1
        """,
        (hash_secret(token), utc_now()),
    ).fetchone()
    if row is None:
        return None
    raw = json_loads(row["principal_json"], {})
    raw["identityId"] = row["identity_id"] or raw.get("identityId")
    raw["tenantId"] = row["tenant_id"]
    # The separately stored scope set is authoritative so stale/tampered
    # principal JSON cannot silently widen a session after issuance.
    raw["scopes"] = json_loads(row["scopes_json"], [])
    raw["authenticated"] = True
    principal = Principal.from_dict(raw)
    # Resolve Entra group IDs to mesh group names now that we have a DB con.
    # This maps Entra ID group memberships to capmesh allow_groups so that
    # Entra group membership can gate capability access.
    if principal.groups:
        try:
            from .entra_groups import resolve_entra_groups_to_mesh_groups
            mesh_groups = resolve_entra_groups_to_mesh_groups(
                con, list(principal.groups), tenant_id=principal.tenant_id or DEFAULT_TENANT,
            )
            if mesh_groups:
                # Extend the principal's groups with resolved mesh group names
                from dataclasses import replace as _replace
                principal = _replace(principal, groups=tuple(set(principal.groups) | set(mesh_groups)))
        except Exception:  # noqa: BLE001, S110
            pass
    return principal


def revoke_capmesh_session(con: sqlite3.Connection, principal: Principal, session_id: str | None = None, token: str | None = None) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    if session_id:
        con.execute(
            "UPDATE capmesh_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id),
        )
        target = session_id
    elif token:
        con.execute(
            "UPDATE capmesh_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND tenant_id = ?",
            (hash_secret(token), tenant_id),
        )
        target = "token"
    else:
        con.execute(
            "UPDATE capmesh_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE subject = ? AND tenant_id = ? AND revoked_at IS NULL",
            (principal.subject, tenant_id),
        )
        target = principal.subject
    audit_event(con, event_type="auth.capmesh_session.revoked", actor=principal.subject, target=target, action="revoke", decision="allow", tenant_id=tenant_id)
    con.commit()
    return {"revoked": True, "target": target}


def auth_status(con: sqlite3.Connection, principal: Principal) -> dict[str, Any]:
    rows = con.execute(
        """
        SELECT id, subject, scopes_json, issued_at, expires_at, revoked_at
        FROM capmesh_sessions
        WHERE tenant_id = ? AND subject = ?
        ORDER BY issued_at DESC
        LIMIT 5
        """,
        (principal.tenant_id or DEFAULT_TENANT, principal.subject),
    ).fetchall()
    active = [row for row in rows if row["revoked_at"] is None and row["expires_at"] > utc_now()]
    return {
        "tenantId": principal.tenant_id or DEFAULT_TENANT,
        "subject": principal.subject,
        "authenticated": principal.authenticated,
        "activeSessionCount": len(active),
        "recentSessions": [
            {
                "id": row["id"],
                "subject": row["subject"],
                "scopes": json_loads(row["scopes_json"], []),
                "issuedAt": row["issued_at"],
                "expiresAt": row["expires_at"],
                "revoked": row["revoked_at"] is not None,
            }
            for row in rows
        ],
        "loginCommand": f"capmesh auth login --m365 --tenant {principal.tenant_id or DEFAULT_TENANT}",
        "doctorCommand": "capmesh auth doctor --json",
    }


def principal_from_entra_claims(claims: dict[str, Any], *, tenant_id: str = DEFAULT_TENANT) -> Principal:
    from .governance import corporate_identity_id
    email = str(
        claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("email")
        or claims.get("unique_name")
        or claims.get("oid")
        or ""
    ).strip()
    if not email:
        raise ValueError("Token claims did not contain a usable subject.")
    entra_roles = claims.get("roles") or []
    if not isinstance(entra_roles, list):
        entra_roles = []
    mapped_roles = tuple(role for role in (str(role) for role in entra_roles) if role in ROLE_RIGHTS)
    if not mapped_roles:
        mapped_roles = ("member",)
    groups_raw = claims.get("groups") or []
    if not isinstance(groups_raw, list):
        groups_raw = []
    # Resolve Entra group IDs to mesh group names via entra_groups bindings.
    # This lets Entra group membership gate capability access through
    # allow_groups without manual user-by-user provisioning.  Non-fatal
    # if the module or bindings are unavailable.
    # Store raw Entra group IDs; mesh group resolution happens in
    # principal_from_bearer where a DB con is available.
    groups_tuple = tuple(str(group) for group in groups_raw)
    scopes = ("cap:*",) if any(role in {"platform_admin", "org_admin"} for role in mapped_roles) else ("cap:search", "cap:load", "cap:call", "cap:delegate", "cap:report")
    return Principal(
        subject=email.lower(),
        tenant_id=tenant_id,
        identity_id=corporate_identity_id(
            tenant_id,
            email,
            str(claims.get("oid") or email.lower()),
        ),
        email=email.lower() if "@" in email else None,
        display_name=claims.get("name"),
        groups=groups_tuple,
        roles=mapped_roles,
        scopes=scopes,
        authenticated=True,
    )


def complete_oauth_session(
    con: sqlite3.Connection,
    state: str,
    *,
    token_response: dict[str, Any],
    client_id: str | None = None,
) -> dict[str, Any]:
    from .governance import audit_event, ensure_identity_for_principal
    row = con.execute("SELECT * FROM oauth_sessions WHERE state = ?", (state,)).fetchone()
    if row is None:
        raise ValueError("OAuth state was not found.")
    claims = verify_id_token(
        str(token_response.get("id_token") or ""),
        client_id=client_id,
        capmesh_tenant_id=row["tenant_id"],
    )
    directory_tenant_id = str(claims.get("tid") or "")
    if not directory_tenant_id:
        raise ValueError("ID token did not contain a tenant id.")
    expected_issuer = f"https://login.microsoftonline.com/{directory_tenant_id}/v2.0"
    actual_issuer = claims.get("iss", "")
    if actual_issuer not in _trusted_ms_issuers(directory_tenant_id):
        raise ValueError(f"ID token issuer '{actual_issuer}' did not match the resolved tenant issuer '{expected_issuer}'.")
    if client_id and claims.get("aud") != client_id:
        raise ValueError("ID token audience did not match the configured client id.")
    if row["nonce"] and claims.get("nonce") and claims["nonce"] != row["nonce"]:
        raise ValueError("ID token nonce did not match the OAuth session.")
    # Defense-in-depth: validate PKCE code challenge/verifier using the
    # dedicated oauth_pkce module. The session stores the code_challenge and
    # code_verifier_hash; validate_pkce confirms the S256 method was used.
    try:
        from .oauth_pkce import CODE_CHALLENGE_METHOD, validate_pkce
        stored_challenge = str(row["code_challenge"]) if "code_challenge" in row else ""
        if stored_challenge:
            # Reconstruct verifier from metadata for validation
            stored_meta = json_loads(row["metadata_json"], {}) if row["metadata_json"] else {}
            stored_verifier = str(stored_meta.get("codeVerifier") or "")
            if stored_verifier:
                valid_pkce, pkce_error = validate_pkce(stored_verifier, stored_challenge, CODE_CHALLENGE_METHOD)
                if not valid_pkce:
                    raise ValueError(f"PKCE validation failed: {pkce_error}")
    except ValueError:
        raise
    except Exception:  # noqa: BLE001, S110
        pass
    now = int(datetime.now(UTC).timestamp())
    if int(claims.get("exp") or 0) and int(claims["exp"]) <= now:
        raise ValueError("ID token is expired.")
    # Defense-in-depth: structured claim validation via the token_validation
    # module (RFC 8707 resource indicator + clock-skew-tolerant expiry/nbf).
    # The manual checks above already cover the essentials; this adds a
    # second layer so a gap in either path is caught by the other.
    from .token_validation import TokenValidator
    validator = TokenValidator(
        issuer=actual_issuer,
        audiences=[client_id] if client_id else None,
    )
    valid, validation_error = validator.validate(claims, now=float(now))
    if not valid:
        raise ValueError(f"ID token claim validation failed: {validation_error}")
    principal = principal_from_entra_claims(claims, tenant_id=row["tenant_id"])
    ensure_identity_for_principal(con, principal)
    token = mint_capmesh_token(
        con,
        principal,
        metadata={"source": "m365", "oauthSessionId": row["id"]},
    )
    metadata = json_loads(row["metadata_json"], {})
    # F-04: the PKCE verifier is only needed during the server-side code
    # exchange (already done above). Clear it so it does not linger at rest.
    metadata.pop("codeVerifier", None)
    metadata.update(
        {
            "m365": True,
            "claims": sanitize_claims(claims),
            "capmeshSessionId": token["sessionId"],
            "capmeshBearerToken": token["bearerToken"],
            "capmeshTokenExpiresAt": token["expiresAt"],
            "refreshTokenDelivered": False,
            # F-05: tokens are delivered exactly once to the polling client and
            # then nulled. Bound the at-rest window so an unconsumed token cannot
            # sit in the DB indefinitely.
            "tokenDeliveryExpiresAt": expires_in(_OAUTH_TOKEN_DELIVERY_TTL),
        }
    )
    if token_response.get("refresh_token"):
        metadata["m365RefreshToken"] = token_response["refresh_token"]
    con.execute(
        "UPDATE oauth_sessions SET status = 'completed', completed_at = CURRENT_TIMESTAMP, metadata_json = ? WHERE id = ?",
        (json_dumps(metadata), row["id"]),
    )
    audit_event(
        con,
        event_type="auth.m365.completed",
        actor=principal.subject,
        target=row["id"],
        action="login",
        decision="allow",
        payload={"capmeshSessionId": token["sessionId"]},
        tenant_id=row["tenant_id"],
    )
    con.commit()
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "status": "completed",
        "principal": principal.to_dict(),
        "capmeshSession": {
            "sessionId": token["sessionId"],
            "tokenType": token["tokenType"],
            "expiresAt": token["expiresAt"],
        },
    }


def oauth_session_status(con: sqlite3.Connection, session_id: str, *, consume_tokens: bool = False) -> dict[str, Any]:
    row = con.execute("SELECT * FROM oauth_sessions WHERE id = ? OR state = ?", (session_id, session_id)).fetchone()
    if row is None:
        raise ValueError("OAuth session not found.")
    metadata = json_loads(row["metadata_json"], {})
    payload: dict[str, Any] = {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "flow": row["flow"],
        "status": row["status"],
        "expiresAt": row["expires_at"],
        "completedAt": row["completed_at"],
        "principal": metadata.get("claims", {}),
        "capmeshSession": {
            "sessionId": metadata.get("capmeshSessionId"),
            "expiresAt": metadata.get("capmeshTokenExpiresAt"),
        }
        if metadata.get("capmeshSessionId")
        else None,
    }
    if consume_tokens and row["status"] == "completed":
        # F-05: refuse to hand back tokens past the bounded delivery window and
        # purge them from the row so they cannot be retrieved later.
        delivery_deadline = metadata.get("tokenDeliveryExpiresAt")
        expired = bool(delivery_deadline) and str(delivery_deadline) <= utc_now()
        if expired:
            payload["bearerToken"] = None
            payload["m365RefreshToken"] = None
            payload["tokenDeliveryExpired"] = True
        else:
            payload["bearerToken"] = metadata.get("capmeshBearerToken")
            payload["m365RefreshToken"] = metadata.get("m365RefreshToken")
            payload["refreshTokenDelivered"] = bool(payload.get("m365RefreshToken"))
        metadata["capmeshBearerToken"] = None
        metadata["m365RefreshToken"] = None
        if not expired:
            metadata["refreshTokenDelivered"] = bool(payload.get("m365RefreshToken"))
        con.execute("UPDATE oauth_sessions SET metadata_json = ? WHERE id = ?", (json_dumps(metadata), row["id"]))
        con.commit()
    return payload


def google_allowed_emails() -> set[str]:
    """Server-side Google invite allowlist (lowercased).

    Sourced from the CAPMESH_GOOGLE_ALLOWED_EMAILS env CSV. michel.d.paradis@gmail.com
    is always seeded so the initial invitee is allowlisted even before the env is
    set on the host. Extend the allowlist by adding to the env CSV.
    """

    seeded = {"michel.d.paradis@gmail.com"}
    raw = os.environ.get("CAPMESH_GOOGLE_ALLOWED_EMAILS", "")
    for item in raw.split(","):
        cleaned = item.strip().lower()
        if cleaned:
            seeded.add(cleaned)
    return seeded


def email_is_allowed(email: str, hosted_domain: str | None = None) -> bool:
    from .governance import CORPORATE_EMAIL_DOMAIN
    """Authorize verified Google users by invite or verified Workspace domain.

    Google documents ``hd`` as the domain-membership assertion; an email suffix
    alone is not sufficient. Explicitly invited external addresses remain valid.
    """

    normalized = email.strip().lower()
    if not normalized:
        return False
    if normalized in google_allowed_emails():
        return True
    return normalized.endswith(f"@{CORPORATE_EMAIL_DOMAIN}") and str(hosted_domain or "").strip().lower() == CORPORATE_EMAIL_DOMAIN


def principal_from_google_claims(claims: dict[str, Any], *, tenant_id: str = DEFAULT_TENANT) -> Principal:
    """Build a capmesh Principal bound to a verified Google email.

    ``claims`` MUST come from capmesh.auth_google.verify_google_id_token (i.e. the
    email is already signature-verified and email_verified==true). Roles default
    to member; the per-email atrace role grant then applies because the session is
    bound to the real email rather than the tailnet-guest fallback.
    """

    from .governance import corporate_identity_id

    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("Google claims did not contain a usable verified email.")
    sub = str(claims.get("sub") or email)
    # Google identities receive no implicit owner elevation. Administrative
    # rights must come from an audited capmesh role assignment.
    mapped_roles: tuple[str, ...] = ("member",)
    scopes: tuple[str, ...] = ("cap:search", "cap:load", "cap:call", "cap:delegate", "cap:report")
    return Principal(
        subject=email,
        tenant_id=tenant_id,
        identity_id=corporate_identity_id(tenant_id, email, sub),
        email=email,
        display_name=claims.get("name"),
        groups=(),
        roles=mapped_roles,
        scopes=scopes,
        authenticated=True,
    )


def complete_google_session(
    con: sqlite3.Connection,
    state: str,
    *,
    claims: dict[str, Any],
) -> dict[str, Any]:
    from .governance import audit_event, ensure_identity_for_principal
    """Mint a capmesh session for a verified, allowlisted Google identity.

    ``claims`` must already be verified by auth_google.verify_google_id_token and
    the email must already have passed email_is_allowed (enforced in server.py
    before this is called). Mirrors complete_oauth_session (M365) but uses Google
    claims and the same session machinery (mint_capmesh_token).
    """

    row = con.execute("SELECT * FROM oauth_sessions WHERE state = ?", (state,)).fetchone()
    if row is None:
        raise ValueError("OAuth state was not found.")
    principal = principal_from_google_claims(claims, tenant_id=row["tenant_id"])
    ensure_identity_for_principal(con, principal)
    token = mint_capmesh_token(
        con,
        principal,
        metadata={"source": "google", "oauthSessionId": row["id"]},
    )
    metadata = json_loads(row["metadata_json"], {})
    metadata.pop("codeVerifier", None)
    metadata.update(
        {
            "google": True,
            "claims": sanitize_claims(claims),
            "capmeshSessionId": token["sessionId"],
            "capmeshBearerToken": token["bearerToken"],
            "capmeshTokenExpiresAt": token["expiresAt"],
            "tokenDeliveryExpiresAt": expires_in(_OAUTH_TOKEN_DELIVERY_TTL),
        }
    )
    con.execute(
        "UPDATE oauth_sessions SET status = 'completed', completed_at = CURRENT_TIMESTAMP, metadata_json = ? WHERE id = ?",
        (json_dumps(metadata), row["id"]),
    )
    audit_event(
        con,
        event_type="auth.google.completed",
        actor=principal.subject,
        target=row["id"],
        action="login",
        decision="allow",
        payload={"capmeshSessionId": token["sessionId"]},
        tenant_id=row["tenant_id"],
    )
    con.commit()
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "status": "completed",
        "principal": principal.to_dict(),
        "capmeshSession": {
            "sessionId": token["sessionId"],
            "tokenType": token["tokenType"],
            "expiresAt": token["expiresAt"],
            "bearerToken": token["bearerToken"],
        },
    }




def sanitize_claims(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in claims.items()
        if key in {"aud", "iss", "tid", "oid", "name", "preferred_username", "upn", "email", "roles", "groups"}
    }


def sanitize_auth_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in metadata.items() if "token" not in key.lower() and "secret" not in key.lower()}


def decode_unverified_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT id_token WITHOUT signature verification.

    WARNING: This trusts the payload blindly. It is only safe for: (a) reading
    the issuer/tid to locate the right JWKS before verifying, or (b) the
    explicit break-glass path when CAPMESH_OAUTH_VERIFY_SIGNATURE is disabled.
    Never use it to establish identity in the normal auth path — use
    verify_id_token instead (F-03).
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Expected a JWT id_token in the token response.")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Could not decode id_token claims.") from exc
    if not isinstance(value, dict):
        raise TypeError("id_token payload must decode to an object.")
    return value


# Microsoft issuers are tenant-scoped. We trust the v2.0 and v1.0 (sts) forms
# for a CONCRETE tenant id only. "common"/"organizations" never appear as a
# real token issuer (the issued `iss` always carries the resolved tenant GUID),
# so they are intentionally NOT trusted here.
def _trusted_ms_issuers(tid: str) -> set[str]:
    return {
        f"https://login.microsoftonline.com/{tid}/v2.0",
        f"https://sts.windows.net/{tid}/",
    }


def verify_id_token(token: str, *, client_id: str | None, capmesh_tenant_id: str) -> dict[str, Any]:
    """Verify an M365 id_token signature against the tenant JWKS and return claims.

    This is the security-critical path (F-03). When CAPMESH_OAUTH_VERIFY_SIGNATURE
    is disabled (break-glass), it falls back to unverified decode and the caller's
    manual issuer/audience/nonce/exp checks still apply.
    """
    if not _oauth_verify_signature_enabled():
        if _production_environment():
            raise RuntimeError("CAPMESH_OAUTH_VERIFY_SIGNATURE cannot be disabled in production.")
        sys.stderr.write(
            "[capmesh] WARNING: development/test id_token signature verification is DISABLED "
            "(CAPMESH_OAUTH_VERIFY_SIGNATURE). Trusting unverified claims.\n"
        )
        return decode_unverified_jwt(token)

    # Validate the untrusted routing claims before importing the JWT client or
    # making a JWKS request. This rejects obviously foreign issuers locally.
    unverified = decode_unverified_jwt(token)
    tid = str(unverified.get("tid") or "")
    if not tid or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", tid):
        raise ValueError("id_token tenant id is missing or malformed.")
    expected_tid = os.environ.get("CAPMESH_ENTRA_TENANT_ID") or None
    if _production_environment() and not expected_tid:
        raise RuntimeError("CAPMESH_ENTRA_TENANT_ID is required in production.")
    if expected_tid and tid.lower() != expected_tid.lower():
        raise ValueError("id_token tenant does not match the configured Entra tenant.")
    issuer = str(unverified.get("iss") or "")
    if issuer not in _trusted_ms_issuers(tid):
        raise ValueError(f"id_token issuer '{issuer}' is not a trusted Microsoft issuer.")

    try:
        import jwt  # PyJWT
        from jwt import PyJWKClient
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "id_token signature verification requires PyJWT[crypto]. Install it on "
            "the capmesh service host, or set CAPMESH_OAUTH_VERIFY_SIGNATURE=0 as a "
            "documented break-glass."
        ) from exc

    jwks_uri = f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"

    try:
        signing_key = PyJWKClient(jwks_uri).get_signing_key_from_jwt(token)
        decode_kwargs: dict[str, Any] = {
            "algorithms": ["RS256"],
            "issuer": issuer,
            "options": {"verify_aud": bool(client_id)},
        }
        if client_id:
            decode_kwargs["audience"] = client_id
        claims = jwt.decode(token, signing_key.key, **decode_kwargs)
    except jwt.PyJWTError as exc:
        raise ValueError(f"id_token signature verification failed: {exc}") from exc
    if not isinstance(claims, dict):
        raise TypeError("id_token payload must decode to an object.")
    return claims




def create_oauth_session(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    flow: str,
    redirect_uri: str,
    scope: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    session_id = new_id("oauth")
    stored_metadata = {**(metadata or {}), "codeVerifier": verifier}
    con.execute(
        """
        INSERT INTO oauth_sessions(id, tenant_id, flow, state, code_challenge, code_verifier_hash, redirect_uri, scope, nonce, status, metadata_json, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (session_id, tenant_id, flow, state, challenge, hash_secret(verifier), redirect_uri, scope, nonce, json_dumps(stored_metadata), expires_in(600)),
    )
    con.commit()
    return {
        "id": session_id,
        "tenantId": tenant_id,
        "flow": flow,
        "state": state,
        "nonce": nonce,
        "codeVerifier": verifier,
        "codeChallenge": challenge,
        "redirectUri": redirect_uri,
        "scope": scope,
        "expiresIn": 600,
    }


def validate_oauth_callback(con: sqlite3.Connection, state: str, *, code: str | None = None, error: str | None = None) -> dict[str, Any]:
    row = con.execute("SELECT * FROM oauth_sessions WHERE state = ?", (state,)).fetchone()
    if row is None:
        raise ValueError("OAuth state was not found.")
    if row["status"] != "pending":
        raise ValueError("OAuth session is not pending.")
    if row["expires_at"] <= utc_now():
        con.execute("UPDATE oauth_sessions SET status = 'expired' WHERE id = ?", (row["id"],))
        con.commit()
        raise ValueError("OAuth session expired.")
    status = "failed" if error else "callback_received"
    con.execute(
        "UPDATE oauth_sessions SET status = ?, completed_at = CURRENT_TIMESTAMP, metadata_json = ? WHERE id = ?",
        (status, json_dumps({**json_loads(row["metadata_json"], {}), "callbackError": error, "codeReceived": bool(code)}), row["id"]),
    )
    con.commit()
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "state": state,
        "status": status,
        "codeReceived": bool(code),
        "tokenExchange": "not_performed_by_callback",
    }
