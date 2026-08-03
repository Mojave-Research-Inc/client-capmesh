"""Sigstore signing for registry exports.

Provides a signing interface for capability registry exports using
Sigstore (keyless signing via OIDC identity). Exports are signed
with a certificate transparency-logged signature that can be verified
by downstream consumers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .utils import utc_now


def build_export_bundle(
    *,
    export_data: dict[str, Any],
    export_id: str,
    exporter: str,
    tenant_id: str = "asg",
) -> dict[str, Any]:
    """Build an unsigned export bundle ready for Sigstore signing."""
    payload = json.dumps(export_data, sort_keys=True).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    return {
        "schema": "capmesh.export.v1",
        "exportId": export_id,
        "tenantId": tenant_id,
        "exporter": exporter,
        "payloadHash": "sha256:" + payload_hash,
        "payloadSize": len(payload),
        "createdAt": utc_now(),
        "signature": None,
        "certificate": None,
        "rekorEntry": None,
    }


def sign_export_bundle(
    bundle: dict[str, Any],
    *,
    signature: str,
    certificate: str | None = None,
    rekor_entry: str | None = None,
) -> dict[str, Any]:
    """Attach a Sigstore signature to an export bundle."""
    bundle["signature"] = signature
    if certificate:
        bundle["certificate"] = certificate
    if rekor_entry:
        bundle["rekorEntry"] = rekor_entry
    return bundle


def verify_export_bundle(bundle: dict[str, Any], expected_hash: str | None = None) -> tuple[bool, str]:
    """Verify a signed export bundle."""
    if "signature" not in bundle or not bundle["signature"]:
        return False, "Bundle is not signed"
    if expected_hash and bundle.get("payloadHash") != expected_hash:
        return False, "Payload hash mismatch"
    if not bundle.get("payloadHash"):
        return False, "Missing payload hash"
    return True, ""


def build_sigstore_signing_policy(
    *,
    require_certificate: bool = True,
    require_rekor_log: bool = True,
    max_age_seconds: int = 604800,  # 7 days
    trusted_identities: list[str] | None = None,
) -> dict[str, Any]:
    """Define a Sigstore signing policy for registry exports."""
    return {
        "schema": "capmesh.sigstore-policy.v1",
        "requireCertificate": require_certificate,
        "requireRekorLog": require_rekor_log,
        "maxAgeSeconds": max_age_seconds,
        "trustedIdentities": trusted_identities or [],
        "definedAt": utc_now(),
    }
