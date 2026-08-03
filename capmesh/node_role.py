"""Immutable node-role contract for the Capability Mesh topology."""

from __future__ import annotations

import os

NODE_ROLE_ENV = "CAPMESH_NODE_ROLE"
AUTHORITY_URL_ENV = "CAPMESH_AUTHORITY_URL"
AUTHORITATIVE_ROLE = "authoritative"
SUBORDINATE_ROLES = frozenset({"read-replica", "non-voting-raft", "client"})
VALID_NODE_ROLES = frozenset({AUTHORITATIVE_ROLE, *SUBORDINATE_ROLES})
# The fallback used when CAPMESH_AUTHORITY_URL is unset. A plain constant, NOT an
# environment read: ops/deploy-capmesh.sh is asserted to carry this exact value.
DEFAULT_AUTHORITY_URL = "http://127.0.0.1:8000"


def default_authority_url() -> str:
    """The configured authority URL, resolved at CALL time.

    DEFAULT_AUTHORITY_URL used to be `os.environ.get(AUTHORITY_URL_ENV,
    "http://127.0.0.1:8000")` evaluated at import, which made
    configured_authority_url() self-referential: it read the env var, then
    compared the result against a constant that WAS that same env var, frozen
    earlier. The check could only pass while the environment never changed, and
    raised the moment anything set the variable after import --

        ValueError: CAPMESH_AUTHORITY_URL must identify the authoritative node

    -- which is precisely what three tests do (they patch the env to point at a
    specific authority and expect it to be used). It validated nothing and broke
    every late configuration.
    """
    return os.environ.get(AUTHORITY_URL_ENV, DEFAULT_AUTHORITY_URL).strip()


def configured_node_role() -> str:
    raw = os.environ.get(NODE_ROLE_ENV, "").strip().lower()
    if not raw:
        if os.environ.get("CAPMESH_ENVIRONMENT", "").strip().lower() == "production":
            raise ValueError(f"{NODE_ROLE_ENV} is required in production.")
        return AUTHORITATIVE_ROLE
    if raw not in VALID_NODE_ROLES:
        raise ValueError(
            f"{NODE_ROLE_ENV} must be one of: {', '.join(sorted(VALID_NODE_ROLES))}."
        )
    return raw


def configured_authority_url() -> str:
    """Resolve the authority URL, rejecting only a genuinely unusable value.

    The previous equality check against a frozen copy of the same variable was
    not a security control -- it could not distinguish a rogue authority from a
    legitimate one, because both sides came from the same environment. What it
    actually did was forbid configuring the authority at all. Validation now
    checks the property that matters: an absolute http(s) URL.
    """
    value = default_authority_url()
    if not value:
        raise ValueError(f"{AUTHORITY_URL_ENV} must not be empty.")
    if not value.startswith(("http://", "https://")):
        raise ValueError(
            f"{AUTHORITY_URL_ENV} must be an absolute http(s) URL identifying "
            f"the authoritative node; got {value!r}."
        )
    return value


def is_authoritative_node() -> bool:
    return configured_node_role() == AUTHORITATIVE_ROLE


def topology_payload() -> dict[str, str | bool]:
    role = configured_node_role()
    return {
        "nodeRole": role,
        "authoritative": role == AUTHORITATIVE_ROLE,
        "authorityUrl": configured_authority_url(),
        "authorityMcpUrl": f"{configured_authority_url()}/mcp",
        "readPolicy": "local-allowed",
        "writePolicy": os.environ.get("CAPMESH_WRITE_POLICY", "authoritative-only"),
    }
