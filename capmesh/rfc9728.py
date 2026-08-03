"""RFC 9728 protected resource metadata endpoint.

Implements the RFC 9728 Protected Resource Metadata (RFC 8707 / OAuth 2.0
Protected Resource Metadata) specification. Exposes a /.well-known/
resource-metadata endpoint that returns metadata about the protected
resource, including supported scopes, token authorization servers,
and signing algorithms.
"""

from __future__ import annotations

from typing import Any

from .utils import utc_now

RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"


def build_resource_metadata(
    *,
    resource_url: str,
    authorization_servers: list[str] | None = None,
    scopes_supported: list[str] | None = None,
    bearer_methods: list[str] | None = None,
    jwks_uri: str | None = None,
    signing_alg_values: list[str] | None = None,
) -> dict[str, Any]:
    """Build the RFC 9728 protected resource metadata document.

    Returns a dict matching the RFC 9728 JSON schema.
    """
    metadata: dict[str, Any] = {
        "resource": resource_url,
        "authorization_servers": authorization_servers or [],
        "scopes_supported": scopes_supported or ["capmesh:read", "capmesh:write", "capmesh:admin"],
        "bearer_methods_supported": bearer_methods or ["header"],
        "issued_at": utc_now(),
    }
    if jwks_uri:
        metadata["jwks_uri"] = jwks_uri
    if signing_alg_values:
        metadata["signing_alg_values_supported"] = signing_alg_values
    else:
        metadata["signing_alg_values_supported"] = ["RS256", "ES256", "EdDSA"]
    metadata["resource_documentation"] = "https://capmesh.asg.ts.net/docs"
    metadata["resource_signing_alg_values_supported"] = metadata["signing_alg_values_supported"]
    return metadata


def validate_resource_metadata(metadata: dict[str, Any]) -> tuple[bool, str]:
    """Validate that a resource metadata document conforms to RFC 9728 requirements.

    Returns (valid, error_message).
    """
    if not isinstance(metadata, dict):
        return False, "Metadata must be a JSON object"
    if "resource" not in metadata or not str(metadata["resource"]).strip():
        return False, "Missing required field: resource"
    if "authorization_servers" in metadata and not isinstance(metadata["authorization_servers"], list):
        return False, "authorization_servers must be an array"
    if "scopes_supported" in metadata and not isinstance(metadata["scopes_supported"], list):
        return False, "scopes_supported must be an array"
    if "bearer_methods_supported" in metadata and not isinstance(metadata["bearer_methods_supported"], list):
        return False, "bearer_methods_supported must be an array"
    if "jwks_uri" in metadata and not str(metadata["jwks_uri"]).startswith("http"):
        return False, "jwks_uri must be an HTTP(S) URL"
    return True, ""


def serve_resource_metadata(resource_url: str, authorization_servers: list[str] | None = None) -> dict[str, Any]:
    """Build and validate the resource metadata for serving at the well-known endpoint."""
    metadata = build_resource_metadata(
        resource_url=resource_url,
        authorization_servers=authorization_servers or ["https://auth.asg.ts.net"],
    )
    valid, error = validate_resource_metadata(metadata)
    if not valid:
        raise ValueError(f"Invalid resource metadata: {error}")
    return metadata
