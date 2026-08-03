from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capmesh.report_receipts import (
    REPORT_RECEIPT_KEYS,
    ReportReceiptError,
    issue_report_receipt,
    verify_report_receipt,
)


def _receipt(private: Ed25519PrivateKey, *, now: int = 1_800_000_000, ttl: int = 900):
    return issue_report_receipt(
        signing_key=private,
        task_id="cap-task-" + "1" * 32,
        agent_uri="cap://org/asg/agent/workflow-verifier@1.0.0",
        bundle_digest="sha256:" + "2" * 64,
        capability_binding_digest="sha256:" + "3" * 64,
        outcome_digest="sha256:" + "4" * 64,
        outcome_status="OK",
        workflow_id="wf_report_receipt_1234",
        repo="/srv/asg/repo",
        worktree="/srv/asg/worktrees/wf_report_receipt_1234",
        base_commit="5" * 40,
        upstream_delegation_id="cap-task-" + "6" * 32,
        now=now,
        ttl_seconds=ttl,
    )


def test_report_receipt_matches_shared_schema_and_verifies() -> None:
    private = Ed25519PrivateKey.generate()
    receipt = _receipt(private)
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "capmesh_report_receipt.v1.json").read_text()
    )
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == REPORT_RECEIPT_KEYS
    assert schema["properties"]["schema"]["const"] == receipt["schema"]
    assert schema["properties"]["event"]["const"] == receipt["event"]
    assert schema["properties"]["provenance"]["const"] == receipt["provenance"]
    assert set(receipt) == REPORT_RECEIPT_KEYS
    assert verify_report_receipt(receipt, private.public_key(), now=1_800_000_001) == receipt


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repo", "/srv/asg/attacker"),
        ("worktree", "/tmp/escaped"),
        ("outcomeDigest", "sha256:" + "9" * 64),
        ("upstreamDelegationId", "cap-task-" + "7" * 32),
        ("bundleDigest", "sha256:" + "8" * 64),
    ],
)
def test_report_receipt_rejects_tampered_bindings(field: str, value: str) -> None:
    private = Ed25519PrivateKey.generate()
    tampered = copy.deepcopy(_receipt(private))
    tampered[field] = value
    with pytest.raises(ReportReceiptError, match="signature"):
        verify_report_receipt(tampered, private.public_key(), now=1_800_000_001)


def test_report_receipt_rejects_expiry_future_and_unknown_key() -> None:
    private = Ed25519PrivateKey.generate()
    receipt = _receipt(private, now=1_800_000_000, ttl=10)
    with pytest.raises(ReportReceiptError, match="expired"):
        verify_report_receipt(receipt, private.public_key(), now=1_800_000_010)
    with pytest.raises(ReportReceiptError, match="future"):
        verify_report_receipt(receipt, private.public_key(), now=1_799_999_900)
    with pytest.raises(ReportReceiptError, match="key_id"):
        verify_report_receipt(receipt, Ed25519PrivateKey.generate().public_key(), now=1_800_000_001)


def test_report_receipt_rejects_unsigned_or_noncanonical_shape() -> None:
    private = Ed25519PrivateKey.generate()
    unsigned = _receipt(private)
    unsigned.pop("signature")
    with pytest.raises(ReportReceiptError, match="fields"):
        verify_report_receipt(unsigned, private.public_key(), now=1_800_000_001)
    fabricated = _receipt(private)
    fabricated["authorization"] = "mutation"
    with pytest.raises(ReportReceiptError, match="fields"):
        verify_report_receipt(fabricated, private.public_key(), now=1_800_000_001)
