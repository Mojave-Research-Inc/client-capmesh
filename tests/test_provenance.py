"""Tests for capmesh.provenance — SLSA-style provenance gate infrastructure.

These tests exercise the self-contained provenance module only; they do not
import governance.py, server.py, or cli.py.
"""

from __future__ import annotations

import hashlib
import json

from capmesh.provenance import (
    attestation_digest,
    compute_provenance_status,
    to_jsonl_attestation,
)

_BUILT_AT = "2026-07-26T00:00:00Z"
_HASH = "a" * 64


def test_provenance_passed() -> None:
    capability = {
        "content_hash": _HASH,
        "canonical_uri": "cap://org/asg/x/shared/foo@1.0.0",
    }
    result = compute_provenance_status(
        capability,
        source_commit="abc123",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    )
    assert result.status == "passed"
    assert result.record is not None
    assert result.record.ingest_hash == _HASH
    assert result.record.source_commit == "abc123"
    assert result.record.builder_identity == "b@host"
    assert result.record.built_at == _BUILT_AT
    assert result.record.subject_uri == "cap://org/asg/x/shared/foo@1.0.0"
    assert result.record.predicate_type == "https://slsa.dev/provenance/v1"


def test_provenance_skipped_when_commit_unknown() -> None:
    capability = {"content_hash": _HASH, "canonical_uri": "cap://x"}
    result = compute_provenance_status(
        capability,
        source_commit="unknown",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    )
    assert result.status == "skipped"
    assert result.record is None
    assert result.reason == "source commit unknown"


def test_provenance_skipped_when_commit_empty() -> None:
    capability = {"content_hash": _HASH}
    result = compute_provenance_status(
        capability,
        source_commit="",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    )
    assert result.status == "skipped"
    assert result.record is None
    assert result.reason == "source commit unknown"


def test_provenance_failed_when_no_content_hash() -> None:
    capability = {"canonical_uri": "cap://x"}
    result = compute_provenance_status(
        capability,
        source_commit="abc123",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    )
    assert result.status == "failed"
    assert result.record is None
    assert result.reason == "capability missing content_hash"


def test_provenance_failed_when_content_hash_empty() -> None:
    capability = {"content_hash": "", "canonical_uri": "cap://x"}
    result = compute_provenance_status(
        capability,
        source_commit="abc123",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    )
    assert result.status == "failed"
    assert result.record is None


def test_attestation_jsonl_stable() -> None:
    record = compute_provenance_status(
        {"content_hash": "b" * 64, "canonical_uri": "cap://org/asg/y/bar@2.0.0"},
        source_commit="deadbeef",
        builder_identity="capmesh-ingest@host",
        built_at=_BUILT_AT,
    ).record
    assert record is not None

    line = to_jsonl_attestation(record)
    assert "\n" not in line

    parsed = json.loads(line)
    assert parsed["_type"] == "https://in-toto.io/Statement/v1"
    assert parsed["predicateType"] == "https://slsa.dev/provenance/v1"
    assert parsed["subject"][0]["uri"] == "cap://org/asg/y/bar@2.0.0"
    assert parsed["subject"][0]["digest"]["sha256"] == record.ingest_hash
    assert parsed["predicate"]["buildType"] == "capmesh-ingest"
    assert parsed["predicate"]["materials"][0]["uri"] == "git+deadbeef"
    assert parsed["predicate"]["startedAt"] == _BUILT_AT
    assert parsed["predicate"]["finishedAt"] == _BUILT_AT

    digest = attestation_digest(record)
    # Deterministic: calling twice yields the same digest.
    assert digest == attestation_digest(record)
    # The digest is the sha256 of the canonical attestation bytes.
    assert digest == hashlib.sha256(to_jsonl_attestation(record).encode()).hexdigest()
    assert len(digest) == 64


def test_attestation_has_builder_id() -> None:
    record = compute_provenance_status(
        {"content_hash": "c" * 64, "canonical_uri": "cap://z"},
        source_commit="facefeed",
        builder_identity="capmesh-ingest@node-7",
        built_at=_BUILT_AT,
    ).record
    assert record is not None

    line = to_jsonl_attestation(record)
    assert "capmesh-ingest@node-7" in line
    parsed = json.loads(line)
    assert parsed["predicate"]["builder"]["id"] == "capmesh-ingest@node-7"


def test_attestation_digest_changes_with_inputs() -> None:
    """A different ingest_hash must yield a different content-addressed digest."""
    base = compute_provenance_status(
        {"content_hash": "d" * 64, "canonical_uri": "cap://z"},
        source_commit="commit-1",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    ).record
    other = compute_provenance_status(
        {"content_hash": "e" * 64, "canonical_uri": "cap://z"},
        source_commit="commit-1",
        builder_identity="b@host",
        built_at=_BUILT_AT,
    ).record
    assert base is not None and other is not None
    assert attestation_digest(base) != attestation_digest(other)
