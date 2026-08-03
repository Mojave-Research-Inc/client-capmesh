"""Provenance promotion-gate infrastructure for the Capability Mesh.

This module is intentionally self-contained: it builds SLSA-style provenance
records and in-toto/DSSE attestations for ingested capabilities and computes a
``provenance_status`` that a LATER wave wires into ``governance.py``'s
provenance promotion gate. It does NOT import ``governance.py``, ``server.py``,
``cli.py``, or any other capmesh module.

Only the standard library is imported. ``built_at`` is always a caller-provided
ISO8601 UTC string; this module never reads the system clock (no ``datetime``/
``time`` calls), so two runs over the same inputs produce byte-identical
attestations and matching content-addressed digests.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ProvenanceRecord:
    """Content-addressed provenance record for one ingested capability.

    Fields:
        source_commit: git sha the capability was ingested from, or the literal
            string ``"unknown"`` when no commit is available.
        ingest_hash: sha256 hex of the ingested content. On the happy path this
            equals ``capability["content_hash"]``.
        builder_identity: id of the builder that produced the record, e.g.
            ``"capmesh-ingest@<hostname>"`` or a configured id.
        built_at: ISO8601 UTC timestamp the record was built. ALWAYS supplied
            by the caller; this module never reads the clock itself.
        predicate_type: SLSA provenance predicate type URI.
        subject_uri: the capability's ``canonical_uri`` (empty when absent).
    """

    source_commit: str
    ingest_hash: str
    builder_identity: str
    built_at: str
    predicate_type: str = "https://slsa.dev/provenance/v1"
    subject_uri: str = ""


@dataclass(frozen=True)
class ProvenanceResult:
    """Outcome of the provenance promotion-gate check."""

    status: Literal["passed", "failed", "skipped"]
    record: ProvenanceRecord | None
    reason: str


def compute_provenance_status(
    capability: dict[str, object],
    source_commit: str,
    builder_identity: str,
    built_at: str,
) -> ProvenanceResult:
    """Compute the provenance promotion-gate status for one capability.

    ``built_at`` is a caller-provided ISO8601 UTC string; it is never read from
    the system clock inside this function.

    Returns ``skipped`` when the source commit is unknown or empty, ``failed``
    when the capability has no content_hash, and ``passed`` (with a record)
    otherwise.
    """
    if not source_commit or source_commit == "unknown":
        return ProvenanceResult(
            status="skipped",
            record=None,
            reason="source commit unknown",
        )
    content_hash = capability.get("content_hash")
    if not content_hash:
        return ProvenanceResult(
            status="failed",
            record=None,
            reason="capability missing content_hash",
        )
    record = ProvenanceRecord(
        source_commit=source_commit,
        ingest_hash=str(content_hash),
        builder_identity=builder_identity,
        built_at=built_at,
        subject_uri=str(capability.get("canonical_uri", "")),
    )
    return ProvenanceResult(
        status="passed",
        record=record,
        reason="provenance record built",
    )


def to_jsonl_attestation(record: ProvenanceRecord) -> str:
    """Render the record as a single-line in-toto/SLSA statement envelope.

    The output is one JSON object on one line (no trailing newline), serialized
    with ``separators=(",", ":")`` and ``sort_keys=True`` so the byte stream is
    stable and the content-addressed digest is reproducible.
    """
    envelope: dict[str, object] = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": record.predicate_type,
        "subject": [
            {
                "uri": record.subject_uri,
                "digest": {"sha256": record.ingest_hash},
            }
        ],
        "predicate": {
            "builder": {"id": record.builder_identity},
            "buildType": "capmesh-ingest",
            "materials": [{"uri": f"git+{record.source_commit}"}],
            "startedAt": record.built_at,
            "finishedAt": record.built_at,
        },
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True)


def attestation_digest(record: ProvenanceRecord) -> str:
    """sha256 hex of the canonical JSONL attestation for ``record``."""
    return hashlib.sha256(to_jsonl_attestation(record).encode()).hexdigest()
