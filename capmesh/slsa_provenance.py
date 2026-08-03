"""SLSA provenance statements for generated registry artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .utils import utc_now

SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def build_provenance_statement(
    *,
    subject_uri: str,
    subject_hash: str,
    builder_id: str = "capmesh://builder",
    build_type: str = "https://capmesh.asg.ts.net/buildtypes/capability/v1",
    materials: list[dict[str, str]] | None = None,
    byproducts: list[dict[str, str]] | None = None,
    invocation: dict[str, Any] | None = None,
    build_started: str | None = None,
    build_finished: str | None = None,
) -> dict[str, Any]:
    """Build an SLSA v1.0 provenance statement for a registry artifact."""
    return {
        "_type": IN_TOTO_PAYLOAD_TYPE,
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [{"name": subject_uri, "digest": {"sha256": subject_hash.replace("sha256:", "")}}],
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": invocation or {},
                "internalParameters": {},
                "resolvedDependencies": materials or [],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": "", "startedOn": build_started or utc_now(), "finishedOn": build_finished or utc_now()},
                "byproducts": byproducts or [],
            },
        },
    }


def compute_verification_summary(
    provenance: dict[str, Any],
    *,
    verified: bool = True,
    verifier: str = "capmesh-verifier",
    verification_method: str = "hash-comparison",
    notes: str = "",
) -> dict[str, Any]:
    """Build a verification summary artifact for a provenance statement."""
    provenance_hash = hashlib.sha256(json.dumps(provenance, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "schema": "capmesh.verification.v1",
        "provenanceHash": "sha256:" + provenance_hash,
        "verified": verified,
        "verifier": verifier,
        "verificationMethod": verification_method,
        "subject": provenance.get("subject", []),
        "predicateType": provenance.get("predicateType", SLSA_PREDICATE_TYPE),
        "verifiedAt": utc_now(),
        "notes": notes,
    }


def build_keyless_signing_policy(
    *,
    identity_provider: str = "https://auth.asg.ts.net",
    issuer: str = "https://auth.asg.ts.net",
    required_san_pattern: str = "*.asg.ts.net",
    allowed_identities: list[str] | None = None,
) -> dict[str, Any]:
    """Define a keyless signing policy for registry artifacts."""
    return {
        "schema": "capmesh.keyless-signing-policy.v1",
        "identityProvider": identity_provider,
        "issuer": issuer,
        "requiredSANPattern": required_san_pattern,
        "allowedIdentities": allowed_identities or [],
        "trustedRoots": [],
        "enforceTimestamp": True,
        "maxAgeSeconds": 86400,
        "definedAt": utc_now(),
    }
