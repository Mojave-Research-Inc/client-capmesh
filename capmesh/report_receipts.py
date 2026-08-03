"""Canonical cpubox authority receipts for ``cap.report``.

The receipt format and domain separator are shared with ASGCode's durable
workflow verifier.  This module owns serialization and signature validation so
the authority can self-check every receipt before it is persisted or returned.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPORT_RECEIPT_SCHEMA = "capmesh.report.receipt.v1"
REPORT_RECEIPT_DOMAIN = b"ASGCODE:capmesh_report_receipt.v1\x00"
REPORT_PROVENANCE = "https://capmesh.asg.ts.net/tools/call#cap.report"
REPORT_RECEIPT_TTL_SECONDS = 1800
REPORT_RECEIPT_KEYS = {
    "schema", "authoritative", "event", "taskId", "agentUri",
    "bundleDigest", "capabilityBindingDigest", "outcomeDigest",
    "outcomeStatus", "workflowId", "repo", "worktree", "baseCommit",
    "upstreamDelegationId", "reportId", "acceptedAt", "provenance",
    "issued_at", "expires_at", "nonce", "key_id", "signature",
}
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_TASK_RE = re.compile(r"^cap-task-[a-f0-9]{32}$")
_REPORT_RE = re.compile(r"^cap-report-[a-f0-9]{32}$")
_WORKFLOW_RE = re.compile(r"^wf_[A-Za-z0-9_-]{8,120}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,160}$")
_KEY_ID_RE = re.compile(r"^ed25519:sha256:[a-f0-9]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
_OUTCOMES = {
    "OK", "NEED_HELP", "BLOCKED", "FAILED_VERIFY", "INFRA_DOWN",
    "POLICY_DENIED",
}


class ReportReceiptError(ValueError):
    """Raised when a report receipt is malformed, stale, or untrusted."""


def canonical_json(value: Any) -> bytes:
    """Match ASGCode's canonical receipt serialization byte-for-byte."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def authority_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return "ed25519:sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_unsigned(receipt: Mapping[str, Any], *, now: int, require_fresh: bool) -> None:
    if set(receipt) != REPORT_RECEIPT_KEYS:
        raise ReportReceiptError("report receipt fields are not canonical")
    if any((
        receipt.get("schema") != REPORT_RECEIPT_SCHEMA,
        receipt.get("authoritative") is not True,
        receipt.get("event") != "asgcode.workflow.stage",
        receipt.get("provenance") != REPORT_PROVENANCE,
        _TASK_RE.fullmatch(str(receipt.get("taskId") or "")) is None,
        not str(receipt.get("agentUri") or "").startswith("cap://"),
        _SHA256_RE.fullmatch(str(receipt.get("bundleDigest") or "")) is None,
        _SHA256_RE.fullmatch(str(receipt.get("capabilityBindingDigest") or "")) is None,
        _SHA256_RE.fullmatch(str(receipt.get("outcomeDigest") or "")) is None,
        receipt.get("outcomeStatus") not in _OUTCOMES,
        _WORKFLOW_RE.fullmatch(str(receipt.get("workflowId") or "")) is None,
        not isinstance(receipt.get("repo"), str) or not receipt.get("repo"),
        not isinstance(receipt.get("worktree"), str),
        _COMMIT_RE.fullmatch(str(receipt.get("baseCommit") or "")) is None,
        _TASK_RE.fullmatch(str(receipt.get("upstreamDelegationId") or "")) is None,
        _REPORT_RE.fullmatch(str(receipt.get("reportId") or "")) is None,
        not isinstance(receipt.get("acceptedAt"), str) or not receipt.get("acceptedAt"),
        _NONCE_RE.fullmatch(str(receipt.get("nonce") or "")) is None,
        _KEY_ID_RE.fullmatch(str(receipt.get("key_id") or "")) is None,
        _SIGNATURE_RE.fullmatch(str(receipt.get("signature") or "")) is None,
    )):
        raise ReportReceiptError("report receipt binding is malformed")
    issued_at = receipt.get("issued_at")
    expires_at = receipt.get("expires_at")
    if (
        not isinstance(issued_at, int) or isinstance(issued_at, bool)
        or not isinstance(expires_at, int) or isinstance(expires_at, bool)
        or issued_at >= expires_at or expires_at - issued_at > 86_400
    ):
        raise ReportReceiptError("report receipt validity interval is malformed")
    if require_fresh and (issued_at > now + 30 or expires_at <= now):
        raise ReportReceiptError("report receipt is expired or from the future")


def verify_report_receipt(
    receipt: Mapping[str, Any], public_key: Ed25519PublicKey, *,
    now: int | None = None, require_fresh: bool = True,
) -> dict[str, Any]:
    """Verify exact shape, freshness, key binding, domain, and signature."""
    value = dict(receipt)
    current = int(time.time()) if now is None else int(now)
    _validate_unsigned(value, now=current, require_fresh=require_fresh)
    if value["key_id"] != authority_key_id(public_key):
        raise ReportReceiptError("report receipt key_id mismatch")
    try:
        signature_text = value["signature"]
        signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        public_key.verify(
            signature,
            REPORT_RECEIPT_DOMAIN
            + canonical_json({key: item for key, item in value.items() if key != "signature"}),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ReportReceiptError("report receipt signature is invalid") from exc
    return value


def issue_report_receipt(
    *, signing_key: Ed25519PrivateKey, task_id: str, agent_uri: str,
    bundle_digest: str, capability_binding_digest: str, outcome_digest: str,
    outcome_status: str, workflow_id: str, repo: str, worktree: str,
    base_commit: str, upstream_delegation_id: str, now: int | None = None,
    ttl_seconds: int = REPORT_RECEIPT_TTL_SECONDS,
) -> dict[str, Any]:
    """Issue and self-verify one mutation-authoritative workflow receipt."""
    issued_at = int(time.time()) if now is None else int(now)
    ttl = int(ttl_seconds)
    if not 1 <= ttl <= 86_400:
        raise ReportReceiptError("report receipt ttl must be 1..86400 seconds")
    accepted_at = datetime.fromtimestamp(issued_at, UTC).isoformat().replace("+00:00", "Z")
    unsigned: dict[str, Any] = {
        "schema": REPORT_RECEIPT_SCHEMA,
        "authoritative": True,
        "event": "asgcode.workflow.stage",
        "taskId": task_id,
        "agentUri": agent_uri,
        "bundleDigest": bundle_digest,
        "capabilityBindingDigest": capability_binding_digest,
        "outcomeDigest": outcome_digest,
        "outcomeStatus": outcome_status,
        "workflowId": workflow_id,
        "repo": repo,
        "worktree": worktree,
        "baseCommit": base_commit,
        "upstreamDelegationId": upstream_delegation_id,
        "reportId": "cap-report-" + secrets.token_hex(16),
        "acceptedAt": accepted_at,
        "provenance": REPORT_PROVENANCE,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
        "nonce": secrets.token_urlsafe(24),
        "key_id": authority_key_id(signing_key.public_key()),
    }
    signature = signing_key.sign(REPORT_RECEIPT_DOMAIN + canonical_json(unsigned))
    receipt = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }
    return verify_report_receipt(receipt, signing_key.public_key(), now=issued_at)
