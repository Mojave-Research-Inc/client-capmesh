from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit import audit, state_dir, utc_now
from .auth import can_load, require_scope
from .authority_keys import ensure_authority_keypair
from .governance import dispatch_system_capability
from .index import coverage_report, get_capability, list_capabilities, search
from .manifest import DEFAULT_ROOTS
from .models import Capability, Principal
from .node_role import is_authoritative_node, topology_payload
from .observability import log_event
from .report_receipts import (
    REPORT_PROVENANCE,
    REPORT_RECEIPT_DOMAIN,
    authority_key_id,
    issue_report_receipt,
)
from .report_receipts import (
    canonical_json as canonical_report_json,
)
from .slo_tracking import record_latency as _record_slo
from .tracing import Tracer, parse_traceparent, set_request_context

# CM-13 (P2) structured-logging slice: every cap.<verb> dispatch carries a
# request-id and emits one structured log line. This module is a pure function
# dispatcher (``CapabilityRouter.call``) with no HTTP header access, so the
# request-id is accepted as an optional ``request_id`` argument on ``call``;
# callers that have header access (e.g. server.py) pass ``X-Request-Id`` in,
# and in-process/stdio callers omit it so a fresh id is generated here.
logger = logging.getLogger("capMesh.router")

# CM-13 structured-logging slice: one redacted JSON line per cap.<verb>
# dispatch via the dependency-free observability helper. Best-effort only.
_OBS_LOGGER = logging.getLogger("capmesh.router")

# CM-13-full: module-level Tracer for the HTTP request path. ``server.py``
# threads an inbound W3C traceparent (or None) into ``CapabilityRouter.call``;
# this Tracer mints one "request" span per dispatch and records it for OTel
# export. Best-effort only: a tracing failure must never break dispatch.
REQUEST_TRACER = Tracer()

# Free-text fields in a to_record() dict that should be bounded and delimited
# for safe LLM-facing rendering.
_METADATA_TEXT_FIELDS = (
    "description",
    "title",
    "summary",
    "instructions",
    "system-prompt",
    "sourceSystem",
)
# Hard cap for each text field; truncated content is suffixed with this marker.
_METADATA_FIELD_MAX = 4000

def strip_control_sequences(value: str) -> str:
    """Remove ANSI escape sequences and C0 control characters (except common whitespace).

    Retains \n, \t, \r, space (0x20) and printable ranges.  Everything else in
    the C0 (0x00-0x1F) and C1 (0x80-0x9F) blocks - including ESC (0x1B), BEL
    (0x07), and ANSI CSI sequences - is stripped.
    """
    # Strip ANSI CSI / ESC sequences first (\x1b[...m, \x1b[...H, etc.)
    cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", value)
    cleaned = re.sub(r"\x1b\][^\x07\x1b]*?(\x07|\x1b\\)", "", cleaned)
    # Remove remaining C0/C1 controls, keeping \n(0x0A) \t(0x09) \r(0x0D) space
    result = []
    for ch in cleaned:
        cp = ord(ch)
        if cp == 0x09 or cp == 0x0A or cp == 0x0D or cp == 0x20:
            result.append(ch)
        elif cp > 0x7E:
            result.append(ch)  # printable above ASCII
        elif cp < 0x20:
            pass  # drop other C0
        elif cp >= 0x80 and cp <= 0x9F:
            pass  # drop C1
        else:
            result.append(ch)
    return "".join(result)


def _wrap_free_text(value: str, field: str) -> str:
    """Sanitise a free-text metadata field for safe LLM-facing rendering.

    Strips ANSI / control sequences and caps length.  Visible delimiter
    wrapping (FIELD_START(...)/FIELD_END) was removed because the markers
    leaked into LLM-facing output and every model read the result as a
    broken serializer ('capmesh has to be repaired first').  The
    anti-injection goal (metadata must not be confused with agent
    instructions) is enforced by the consuming <system-reminder> framing,
    not by mangling the field text.  The field argument is retained for
    call-site compatibility.
    """
    escaped = strip_control_sequences(value)
    if len(escaped) > _METADATA_FIELD_MAX:
        escaped = escaped[:_METADATA_FIELD_MAX] + "... [truncated]"
    return escaped


def sanitize_metadata(record: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-copy of a to_record() dict, sanitised for LLM-facing output.

    - Strips ANSI / control sequences from every string value.
    - Caps description/title/summary/instructions/system-prompt to 4000 chars
      with a truncation marker.
    - Sanitises free-text metadata fields (strip controls + length cap).  The
      consuming <system-reminder> framing keeps them from being confused with
      agent instructions; field text is no longer delimiter-wrapped.
"""
    sanitized: dict[str, Any] = {}
    for key, val in record.items():
        if not isinstance(val, str):
            sanitized[key] = val
            continue
        stripped = strip_control_sequences(val)
        if key in _METADATA_TEXT_FIELDS:
            sanitized[key] = _wrap_free_text(stripped, key)
        else:
            sanitized[key] = stripped
    # Also deep-sanitise the keywords list
    if "keywords" in record and isinstance(record["keywords"], list):
        sanitized["keywords"] = [
            _wrap_free_text(strip_control_sequences(str(k)), "keyword") if isinstance(k, str) else k
            for k in record["keywords"]
        ]
    return sanitized

TOOL_NAMES = (
    "cap.search",
    "cap.load",
    "cap.call",
    "cap.list",
    "cap.describe",
    "cap.delegate",
    "cap.process",
    "cap.report",
)
CAPMESH_RECEIPT_DOMAIN = b"ASGCODE:capmesh_bundle_receipt.v1\x00"
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]{12,}")
_IMPLEMENTATION_RE = re.compile(
    r"\b(engineer|engineering|implement|develop|developer|build|coding|software|backend|frontend)\b"
)
_VERIFIER_RE = re.compile(r"\b(verif|validat|test|review|audit|quality|qa|correctness)\w*\b")
_SECURITY_RE = re.compile(
    r"\b(security|secure|threat|injection|sandbox|least privilege|zero[- ]trust)\b"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _canonical_scope_files(value: Any) -> list[str] | None:
    """Return a canonical bounded repo-relative scope, or ``None``.

    ``["**"]`` remains the explicit whole-repository scope.  Compiler-selected
    scopes are otherwise exact POSIX paths: rejecting normalization aliases and
    traversal keeps the signed scope unambiguous across platforms.
    """
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        return None
    if value == ["**"]:
        return value
    seen: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 4096
            or item != item.strip()
            or "\x00" in item
            or "\\" in item
            or re.match(r"^[A-Za-z]:", item)
        ):
            return None
        path = PurePosixPath(item)
        if (
            path.is_absolute()
            or path.as_posix() != item
            or any(part in {"", ".", ".."} for part in path.parts)
            or item == "**"
            or item in seen
        ):
            return None
        seen.add(item)
    return value


def _commit_policy_audit(con: sqlite3.Connection) -> None:
    """Release the request connection's policy-decision write transaction."""
    if con.in_transaction:
        con.commit()


def _authority_signer() -> Ed25519PrivateKey:
    authority_dir = state_dir() / "authority"
    path = Path(os.environ.get(
        "CAPMESH_AUTHORITY_SIGNING_KEY",
        authority_dir / "capmesh-authority-ed25519.pem",
    )).expanduser().absolute()
    public_candidate = Path(os.environ.get(
        "ASGCODE_CAPMESH_AUTHORITY_PUBLIC_KEY",
        authority_dir / "capmesh-authority-ed25519.pub.pem",
    )).expanduser()
    record_path = Path(os.environ.get(
        "CAPMESH_AUTHORITY_TRUST_RECORD",
        public_candidate.parent / "capmesh-authority-trust.v1.json",
    )).expanduser()
    ensure_authority_keypair(path, public_candidate, record_path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PermissionError("CapMesh authority signing key is not owner-controlled mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            private_pem = handle.read(65_537)
        if len(private_pem) > 65_536:
            raise ValueError("CapMesh authority signing key is oversized")
    finally:
        os.close(fd)
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("CapMesh authority signing key is invalid")
    return key


def _signed_bundle_receipt(*, task_id: str, workflow_id: str, bundle_hash: str, binding_hash: str) -> dict[str, Any]:
    key = _authority_signer()
    public_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    issued = int(datetime.now(UTC).timestamp())
    unsigned = {
        "schema": "capmesh_bundle_receipt.v1", "task_id": task_id,
        "workflow_id": workflow_id, "bundle_hash": bundle_hash, "binding_hash": binding_hash,
        "issued_at": issued, "expires_at": issued + 1800,
        "nonce": secrets.token_urlsafe(24),
        "key_id": "ed25519:sha256:" + hashlib.sha256(public_raw).hexdigest(),
    }
    signature = key.sign(CAPMESH_RECEIPT_DOMAIN + _canonical(unsigned))
    return {**unsigned, "signature": base64.urlsafe_b64encode(signature).decode().rstrip("=")}


def _verify_bundle_receipt(
    receipt: Any, *, task_id: str, workflow_id: str,
    bundle_hash: str, binding_hash: str,
) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema", "task_id", "workflow_id", "bundle_hash", "binding_hash",
        "issued_at", "expires_at", "nonce", "key_id", "signature",
    }:
        raise ValueError("upstream CapMesh authority receipt is not canonical")
    if any((
        receipt.get("schema") != "capmesh_bundle_receipt.v1",
        receipt.get("task_id") != task_id,
        receipt.get("workflow_id") != workflow_id,
        receipt.get("bundle_hash") != bundle_hash,
        receipt.get("binding_hash") != binding_hash,
        not isinstance(receipt.get("issued_at"), int),
        not isinstance(receipt.get("expires_at"), int),
        receipt.get("issued_at") >= receipt.get("expires_at"),
        receipt.get("issued_at") > int(datetime.now(UTC).timestamp()) + 30,
        receipt.get("expires_at") <= int(datetime.now(UTC).timestamp()),
        not isinstance(receipt.get("nonce"), str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{8,160}", receipt["nonce"]) is None,
        re.fullmatch(r"[A-Za-z0-9_-]{86}", str(receipt.get("signature") or "")) is None,
    )):
        raise ValueError("upstream CapMesh authority receipt binding is invalid")
    public = _authority_signer().public_key()
    if receipt.get("key_id") != authority_key_id(public):
        raise ValueError("upstream CapMesh authority receipt key id is invalid")
    try:
        signature_text = str(receipt["signature"])
        signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        public.verify(
            signature,
            CAPMESH_RECEIPT_DOMAIN
            + _canonical({key: value for key, value in receipt.items() if key != "signature"}),
        )
    except Exception as exc:
        raise ValueError("upstream CapMesh authority receipt signature is invalid") from exc


def _valid_titration_outcome(outcome: Any) -> tuple[bool, str]:
    required = {"schema", "workflow_id", "stage_id", "attempts", "status", "summary", "evidence"}
    optional = {"files_changed", "unmet_capability", "blocker", "requested_assistance", "risks"}
    if not isinstance(outcome, dict) or set(outcome) - (required | optional) or not required.issubset(outcome):
        return False, "canonical asgcode.outcome.v2 fields are required"
    if outcome.get("schema") != "asgcode.outcome.v2" or outcome.get("status") not in {
        "OK", "NEED_HELP", "BLOCKED", "FAILED_VERIFY", "INFRA_DOWN", "POLICY_DENIED",
    }:
        return False, "canonical asgcode.outcome.v2 status is required"
    if not isinstance(outcome.get("attempts"), int) or not 1 <= outcome["attempts"] <= 3:
        return False, "outcome attempts must be 1..3"
    if not isinstance(outcome.get("workflow_id"), str) or not 1 <= len(outcome["workflow_id"]) <= 128:
        return False, "outcome workflow_id is invalid"
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", str(outcome.get("stage_id") or "")):
        return False, "outcome stage_id is invalid"
    if not isinstance(outcome.get("summary"), str) or not 1 <= len(outcome["summary"]) <= 8000:
        return False, "outcome summary is invalid"
    evidence = outcome.get("evidence")
    if not isinstance(evidence, list):
        return False, "outcome evidence must be an array"
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"kind", "ref", "digest"}:
            return False, "outcome evidence item is not canonical"
        if item.get("kind") not in {"log", "test", "patch", "capmesh", "audit", "benchmark"}:
            return False, "outcome evidence kind is invalid"
        if not isinstance(item.get("ref"), str) or not item["ref"]:
            return False, "outcome evidence ref is invalid"
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(item.get("digest") or "")):
            return False, "outcome evidence digest is invalid"
    if outcome["status"] == "BLOCKED" and outcome.get("requested_assistance"):
        return False, "BLOCKED outcomes cannot request assistance"
    return True, ""


def _valid_workflow_stage_outcome(
    outcome: Any, *, task_id: str, workflow_id: str,
) -> tuple[bool, str]:
    required = {
        "schema", "workflow_id", "stage_id", "attempt", "status", "task_id",
        "bundle_id", "routing", "coverage", "benchmark",
    }
    if not isinstance(outcome, dict) or set(outcome) != required:
        return False, "canonical asgcode.capmesh-stage-report.v2 fields are required"
    if any((
        outcome.get("schema") != "asgcode.capmesh-stage-report.v2",
        outcome.get("workflow_id") != workflow_id,
        outcome.get("task_id") != task_id,
        outcome.get("status") not in {
            "OK", "NEED_HELP", "BLOCKED", "FAILED_VERIFY", "INFRA_DOWN",
            "POLICY_DENIED",
        },
        not isinstance(outcome.get("attempt"), int)
        or isinstance(outcome.get("attempt"), bool)
        or not 1 <= outcome["attempt"] <= 3,
        re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", str(outcome.get("stage_id") or "")) is None,
        not isinstance(outcome.get("bundle_id"), str)
        or not 1 <= len(outcome["bundle_id"]) <= 160,
    )):
        return False, "workflow stage outcome binding is invalid"
    routing = outcome.get("routing")
    if (
        not isinstance(routing, dict) or set(routing) != {"role", "mode"}
        or not all(isinstance(routing.get(key), str) and 1 <= len(routing[key]) <= 64 for key in routing)
    ):
        return False, "workflow stage routing evidence is invalid"
    coverage = outcome.get("coverage")
    if (
        not isinstance(coverage, dict)
        or set(coverage) != {"capability_bundle", "deterministic_evidence_items"}
        or coverage.get("capability_bundle") is not True
        or not isinstance(coverage.get("deterministic_evidence_items"), int)
        or isinstance(coverage.get("deterministic_evidence_items"), bool)
        or not 0 <= coverage["deterministic_evidence_items"] <= 10_000
    ):
        return False, "workflow stage coverage evidence is invalid"
    benchmark = outcome.get("benchmark")
    if (
        not isinstance(benchmark, dict) or set(benchmark) != {"verified", "tests"}
        or not isinstance(benchmark.get("verified"), bool)
        or benchmark["verified"] is not (outcome["status"] == "OK")
        or not isinstance(benchmark.get("tests"), list)
        or len(benchmark["tests"]) > 10_000
    ):
        return False, "workflow stage benchmark evidence is invalid"
    return True, ""


def _signed_advisory_report_receipt(
    *, signing_key: Ed25519PrivateKey, event: str, task_id: str, agent_uri: str,
    bundle_digest: str, binding_digest: str, outcome_digest: str,
    outcome_status: str,
) -> dict[str, Any]:
    """Preserve legacy titration telemetry without granting mutation authority."""
    issued = int(datetime.now(UTC).timestamp())
    unsigned = {
        "schema": "capmesh.report.receipt.v1",
        "reportId": "cap-report-" + uuid.uuid4().hex,
        "authoritative": True,
        "authorization": "advisory-audit-only",
        "event": event,
        "taskId": task_id,
        "agentUri": agent_uri,
        "bundleDigest": bundle_digest,
        "capabilityBindingDigest": binding_digest,
        "outcomeDigest": outcome_digest,
        "outcomeStatus": outcome_status,
        "acceptedAt": utc_now(),
        "provenance": REPORT_PROVENANCE,
        "issued_at": issued,
        "expires_at": issued + 1800,
        "nonce": secrets.token_urlsafe(24),
        "key_id": authority_key_id(signing_key.public_key()),
    }
    signature = signing_key.sign(REPORT_RECEIPT_DOMAIN + canonical_report_json(unsigned))
    return {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _sanitize_instructions(value: str, limit: int) -> str:
    text = str(value or "")[:max(0, limit)]
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1=<redacted>", text)
    return _BEARER_RE.sub("Bearer <redacted>", text)


def _frontmatter_tools(content: str) -> list[str]:
    if not content.startswith("---"):
        return []
    end = content.find("\n---", 3)
    front = content[3:end] if end > 0 else ""
    match = re.search(r"(?ms)^tools:\s*\n(?P<body>(?:\s+-\s+[^\n]+\n?)+)", front)
    if not match:
        return []
    return [
        line.split("-", 1)[1].strip().strip("\"'")
        for line in match.group("body").splitlines() if "-" in line
    ]


def _capability_text(cap: Capability) -> str:
    return " ".join((
        cap.name, cap.title, cap.description, cap.capability_type,
        cap.category or "", " ".join(cap.keywords),
    )).lower()[:4000]


def _load_authoritative_content(cap: Capability) -> tuple[str, str]:
    target = safe_file_target(cap.package_path, cap.entrypoint)
    if target is None:
        raise ValueError("capability entrypoint is missing")
    actual_hash, content = hash_and_read_content(target, detail="full")
    if not hmac_hash_equal(actual_hash, cap.content_hash):
        raise ValueError("capability catalog digest no longer matches content")
    return str(target), content


def _validate_root_authoritative_bundle(
    con: sqlite3.Connection,
    *,
    selected_agent: Capability,
    task: str,
    context: Any,
    principal: Principal,
) -> tuple[dict[str, Any], str, str]:
    """Resolve a caller proposal against catalog truth and compute its identities.

    A selector may propose a bundle, but only this authoritative cpubox boundary
    can attest it. Every lifecycle/integrity/entitlement fact is re-read from the
    catalog; caller-supplied hashes and trust labels are never treated as proof.
    """
    if not isinstance(context, dict) or context.get("schema") != "asgcode.capmesh.delegation.context.v1":
        raise ValueError("canonical delegation context is required")
    allowed_context = {
        "schema", "objective", "workflowId", "repo", "worktree", "baseCommit",
        "capabilityBundle", "capabilityBinding", "capabilityBundleHash",
        "capabilityBindingHash", "scopeHash", "scope", "upstreamDelegationId",
        "authorityEvidence",
    }
    if set(context) - allowed_context:
        raise ValueError("delegation context contains unsupported fields")
    objective = context.get("objective")
    workflow_id = str(context.get("workflowId") or "")
    bundle = context.get("capabilityBundle")
    binding = context.get("capabilityBinding")
    if not isinstance(objective, str) or not objective or len(objective) > 12000:
        raise ValueError("delegation objective must be 1..12000 characters")
    if not re.fullmatch(r"wf_[A-Za-z0-9_-]{8,120}", workflow_id):
        raise ValueError("delegation workflowId is invalid")
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema", "bundle_id", "task_shape_hash", "created_at", "trust_decision", "capabilities",
    }:
        raise ValueError("canonical capability_bundle.v1 is required")
    if bundle.get("schema") != "capability_bundle.v1" or bundle.get("trust_decision") != "authoritative":
        raise ValueError("capability bundle is not authoritative")
    if not re.fullmatch(r"capb_[A-Za-z0-9_-]{8,120}", str(bundle.get("bundle_id") or "")):
        raise ValueError("capability bundle id is invalid")
    try:
        created = datetime.fromisoformat(str(bundle.get("created_at") or "").replace("Z", "+00:00"))  # noqa: FURB162
    except ValueError as exc:
        raise ValueError("capability bundle creation time is invalid") from exc
    now = datetime.now(UTC)
    if created.tzinfo is None or created > now + timedelta(minutes=2) or now - created > timedelta(minutes=30):
        raise ValueError("capability bundle is stale or future-dated")
    scope = context.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "schema", "objective", "repo", "worktree", "workflowId", "baseCommit",
        "advisory", "files", "writeSet", "allowedTools", "networkPolicy",
        "dataClassification", "risk", "tests", "acceptanceCriteria", "budget",
        "contextReserveTokens", "completionSchema", "integration",
    }:
        raise ValueError("canonical workflow scope is required")
    scope_objective = str(scope.get("objective") or "")
    scope_files = _canonical_scope_files(scope.get("files"))
    expected_write_set = [] if scope.get("advisory") is True else scope_files
    expected_routing_objective = scope_objective
    if context.get("repo"):
        expected_routing_objective += (
            "\n\nVERIFIED REPOSITORY CONTEXT (bound by titrate):\n"
            + "REPOSITORY: " + str(context.get("repo") or "") + "\n"
            + "BASE_COMMIT: " + str(context.get("baseCommit") or "") + "\n"
            + "The downstream tool-capable durable ASGCode workflow can inspect this "
            + "repository. Do not report the repository as missing merely because this "
            + "routing stage has no filesystem tools."
        )
    if any((
        scope.get("schema") != "asgcode.workflow.scope.v1",
        objective != expected_routing_objective,
        scope.get("repo") != context.get("repo"),
        scope.get("worktree") != context.get("worktree"),
        scope.get("workflowId") != workflow_id,
        scope.get("baseCommit") != context.get("baseCommit"),
        scope_files is None,
        scope.get("writeSet") != expected_write_set,
        scope.get("allowedTools") != (["Read", "Search", "Bash"] + (
            [] if scope.get("advisory") is True else ["Write", "Edit"]
        )),
        scope.get("networkPolicy") != "disabled",
        scope.get("dataClassification") != "internal",
        scope.get("risk") != ("low" if scope.get("advisory") is True else "medium"),
        scope.get("tests") != ["repository-defined deterministic tests for affected surfaces"],
        scope.get("acceptanceCriteria") != [
            "all planned lanes return canonical OK outcomes",
            "deterministic verification passes",
            "serial integration completes without overlapping write sets",
        ],
        scope.get("budget") != {
            "maxLiveLanes": 10, "directorMax": 4, "workerMax": 6,
            "localCorrectionsPerSlice": 1, "codexCorrectionsPerSlice": 1,
        },
        scope.get("contextReserveTokens") != 41600,
        scope.get("completionSchema") != "asgcode.outcome.v2",
        scope.get("integration") != "serial",
    )):
        raise ValueError("workflow scope is not canonical or context-bound")
    if not _SHA256_RE.fullmatch(str(context.get("scopeHash") or "")) or context.get("scopeHash") != _sha(scope):
        raise ValueError("delegation scopeHash is invalid")
    if bundle.get("task_shape_hash") != "sha256:" + hashlib.sha256(objective.encode()).hexdigest():
        raise ValueError("capability bundle task shape does not match objective")
    proposed = bundle.get("capabilities")
    if not isinstance(proposed, list) or not 2 <= len(proposed) <= 4:
        raise ValueError("capability bundle must contain 2..4 capabilities")
    if not isinstance(binding, dict) or set(binding) != {
        "schema", "bundle", "bundle_hash", "trust", "role_coverage",
        "entitlements", "instructions", "read_requirement",
    }:
        raise ValueError("canonical capability binding is required")
    if binding.get("schema") != "asgcode.capability_binding.v1" or binding.get("bundle") != bundle:
        raise ValueError("capability binding bundle mismatch")

    resolved: list[Capability] = []
    seen: set[str] = set()
    content_by_uri: dict[str, tuple[str, str]] = {}
    exact_capability_keys = {
        "uri", "version", "digest", "lifecycle", "approval", "signature",
        "provenance", "risk_review", "instructions_digest", "tools",
        "agent_type", "advisory_only",
    }
    for item in proposed:
        if not isinstance(item, dict) or set(item) != exact_capability_keys:
            raise ValueError("capability bundle item fields are not canonical")
        uri = str(item.get("uri") or "")
        cap = get_capability(con, uri)
        if cap is None or uri in seen:
            raise ValueError("capability bundle contains missing or duplicate URI")
        if any((
            cap.version != item.get("version"), cap.content_hash != item.get("digest"),
            cap.lifecycle != "published" or item.get("lifecycle") != "published",
            cap.approval_state != "approved" or item.get("approval") != "approved",
            cap.signature_status != "verified" or item.get("signature") != "verified",
            cap.provenance_status != "verified" or item.get("provenance") != "verified",
            cap.risk_review_status != "approved" or item.get("risk_review") != "approved",
            item.get("advisory_only") is not False, item.get("agent_type") != cap.name,
        )):
            raise ValueError("capability bundle conflicts with authoritative catalog state")
        right = "delegate" if cap.uri == selected_agent.uri else "load"
        allowed, _reason = can_load(cap, principal, con=con, right=right)
        if not allowed:
            raise PermissionError("principal is not entitled to delegate every bundle capability")
        source_path, content = _load_authoritative_content(cap)
        if item.get("instructions_digest") != "sha256:" + hashlib.sha256(content.encode()).hexdigest():
            raise ValueError("capability instruction digest does not match authoritative content")
        if item.get("tools") != _frontmatter_tools(content):
            raise ValueError("capability tool declaration does not match authoritative content")
        seen.add(uri)
        resolved.append(cap)
        content_by_uri[uri] = (source_path, content)

    if selected_agent.uri not in seen or selected_agent.capability_type != "agent":
        raise ValueError("selected delegating agent is not in the authoritative bundle")
    instructions = binding.get("instructions")
    if not isinstance(instructions, list) or len(instructions) != len(resolved):
        raise ValueError("capability binding must include each bundle instruction exactly once")
    remaining = 16000
    for index, (item, cap) in enumerate(zip(instructions, resolved, strict=True)):
        if not isinstance(item, dict) or set(item) != {
            "uri", "digest", "instructions", "source_path", "loaded_via", "read_required",
        } or item.get("uri") != cap.uri:
            raise ValueError("capability binding instruction order or fields mismatch")
        expected = _sanitize_instructions(content_by_uri[cap.uri][1], min(8000, remaining))
        remaining -= len(expected)
        if any((
            item.get("instructions") != expected,
            item.get("digest") != "sha256:" + hashlib.sha256(expected.encode()).hexdigest(),
            item.get("loaded_via") != "cap.load --detail full",
            item.get("read_required") is not True,
            str(item.get("source_path") or "") not in {"", content_by_uri[cap.uri][0]},
        )):
            raise ValueError("capability binding instruction is not authority-derived")
    entitlements = binding.get("entitlements")
    if not isinstance(entitlements, dict) or set(entitlements) != seen or any(
        not isinstance(value, dict) or set(value) != {"status", "evidence"}
        or value.get("status") != "verified"
        or value.get("evidence") != "cap.load authorized current principal"
        for value in entitlements.values()
    ):
        raise ValueError("capability binding entitlement set is invalid")
    texts = [_capability_text(cap) for cap in resolved]
    security_needed = bool(_SECURITY_RE.search(objective.lower()))
    expected_coverage = {
        "primary_agent": True,
        "implementation": any(_IMPLEMENTATION_RE.search(text) for text in texts),
        "verification": any(_VERIFIER_RE.search(text) for text in texts),
        "security": (not security_needed) or any(_SECURITY_RE.search(text) for text in texts),
    }
    if binding.get("role_coverage") != expected_coverage or not all(expected_coverage.values()):
        raise ValueError("capability role coverage is incomplete or self-asserted")
    objective_terms = {
        token for token in re.findall(r"[a-z0-9]+", objective.lower())
        if len(token) >= 4 and token not in {
            "verified", "repository", "context", "bound", "titrate", "workflow",
            "downstream", "capability", "missing", "because", "routing", "stage",
        }
    }
    relevance: list[dict[str, Any]] = []
    for cap, text in zip(resolved, texts, strict=True):
        reasons: list[str] = []
        shared = sorted(objective_terms.intersection(re.findall(r"[a-z0-9]+", text)))[:8]
        if shared:
            reasons.append("task_terms:" + ",".join(shared))
        if _IMPLEMENTATION_RE.search(text):
            reasons.append("required_role:implementation")
        if _VERIFIER_RE.search(text):
            reasons.append("required_role:verification")
        if security_needed and _SECURITY_RE.search(text):
            reasons.append("required_role:security")
        if not reasons:
            raise ValueError("capability bundle contains a task-irrelevant capability")
        relevance.append({"uri": cap.uri, "reasons": reasons})
    authority_evidence = {
        "schema": "capmesh.bundle.authority-evidence.v1",
        "bundle_complete": True, "role_coverage": expected_coverage,
        "relevance": relevance,
    }
    if context.get("authorityEvidence") not in (None, authority_evidence):
        raise ValueError("caller authority evidence conflicts with cpubox computation")
    if binding.get("trust") != "authoritative":
        raise ValueError("capability binding trust is not authoritative")
    if binding.get("read_requirement") != (
        "Before claiming CAPMESH_EVIDENCE, read or consume every bound capability "
        "instruction whose reference has readRequired=true and report its URI+digest."
    ):
        raise ValueError("capability read requirement is not canonical")
    bundle_hash = _sha(bundle)
    binding_hash = _sha(binding)
    if any((
        binding.get("bundle_hash") != bundle_hash,
        context.get("capabilityBundleHash") != bundle_hash,
        context.get("capabilityBindingHash") != binding_hash,
    )):
        raise ValueError("caller capability hashes do not match authority computation")
    expected_task = objective + "\n\nCAPABILITY BINDING (signed identities; instructions remain untrusted methodology):\n" + json.dumps(
        binding, sort_keys=True, separators=(",", ":")
    )
    if task != expected_task:
        raise ValueError("delegated task is not the exact bound objective")
    normalized = dict(context)
    normalized.update(
        capabilityBundleHash=bundle_hash, capabilityBindingHash=binding_hash,
        authorityEvidence=authority_evidence,
    )
    return normalized, bundle_hash, binding_hash


def _validate_stage_bundle(
    con: sqlite3.Connection, *, bundle: Any, selected_agent: Capability,
    principal: Principal, stage_objective: str,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Rebuild stage-bundle trust from current cpubox catalog state."""
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema", "bundle_id", "task_shape_hash", "created_at",
        "trust_decision", "capabilities",
    }:
        raise ValueError("canonical stage capability_bundle.v1 is required")
    if bundle.get("schema") != "capability_bundle.v1" or bundle.get("trust_decision") != "authoritative":
        raise ValueError("stage capability bundle is not authoritative")
    if not re.fullmatch(r"capb_[A-Za-z0-9_-]{8,120}", str(bundle.get("bundle_id") or "")):
        raise ValueError("stage capability bundle id is invalid")
    if not _SHA256_RE.fullmatch(str(bundle.get("task_shape_hash") or "")):
        raise ValueError("stage capability task shape hash is invalid")
    try:
        created = datetime.fromisoformat(str(bundle.get("created_at") or "").replace("Z", "+00:00"))  # noqa: FURB162
    except ValueError as exc:
        raise ValueError("stage capability bundle creation time is invalid") from exc
    now = datetime.now(UTC)
    if created.tzinfo is None or created > now + timedelta(minutes=2) or now - created > timedelta(minutes=30):
        raise ValueError("stage capability bundle is stale or future-dated")
    proposed = bundle.get("capabilities")
    if not isinstance(proposed, list) or not 2 <= len(proposed) <= 4:
        raise ValueError("stage capability bundle must contain 2..4 capabilities")
    exact_keys = {
        "uri", "version", "digest", "lifecycle", "approval", "signature",
        "provenance", "risk_review", "instructions_digest", "tools",
        "agent_type", "advisory_only",
    }
    seen: set[str] = set()
    resolved: list[Capability] = []
    relevance: list[dict[str, Any]] = []
    objective_terms = {
        token for token in re.findall(r"[a-z0-9]+", stage_objective.lower())
        if len(token) >= 4 and token not in {
            "verified", "repository", "workflow", "capability", "stage",
        }
    }
    for item in proposed:
        if not isinstance(item, dict) or set(item) != exact_keys:
            raise ValueError("stage capability bundle item fields are not canonical")
        uri = str(item.get("uri") or "")
        cap = get_capability(con, uri)
        if cap is None or uri in seen:
            raise ValueError("stage capability bundle contains missing or duplicate URI")
        source_path, content = _load_authoritative_content(cap)
        del source_path
        if any((
            cap.version != item.get("version"), cap.content_hash != item.get("digest"),
            cap.lifecycle != "published" or item.get("lifecycle") != "published",
            cap.approval_state != "approved" or item.get("approval") != "approved",
            cap.signature_status != "verified" or item.get("signature") != "verified",
            cap.provenance_status != "verified" or item.get("provenance") != "verified",
            cap.risk_review_status != "approved" or item.get("risk_review") != "approved",
            item.get("advisory_only") is not False,
            item.get("agent_type") != cap.name,
            item.get("instructions_digest")
            != "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
            item.get("tools") != _frontmatter_tools(content),
        )):
            raise ValueError("stage capability bundle conflicts with authoritative catalog state")
        right = "delegate" if uri == selected_agent.uri else "load"
        allowed, _reason = can_load(cap, principal, con=con, right=right)
        if not allowed:
            raise PermissionError("principal is not entitled to every stage capability")
        text = _capability_text(cap)
        reasons: list[str] = []
        shared = sorted(objective_terms.intersection(re.findall(r"[a-z0-9]+", text)))[:8]
        if shared:
            reasons.append("task_terms:" + ",".join(shared))
        if _IMPLEMENTATION_RE.search(text):
            reasons.append("required_role:implementation")
        if _VERIFIER_RE.search(text):
            reasons.append("required_role:verification")
        if _SECURITY_RE.search(text):
            reasons.append("required_role:security")
        if not reasons:
            raise ValueError("stage capability bundle contains a task-irrelevant capability")
        relevance.append({"uri": uri, "reasons": reasons})
        seen.add(uri)
        resolved.append(cap)
    if selected_agent.uri not in seen or selected_agent.capability_type != "agent":
        raise ValueError("selected stage agent is not in the authoritative stage bundle")
    evidence = {
        "schema": "capmesh.stage-bundle.authority-evidence.v1",
        "bundle_complete": True,
        "relevance": relevance,
    }
    return bundle, _sha(bundle), evidence


def _validate_authoritative_bundle(
    con: sqlite3.Connection,
    *, selected_agent: Capability, task: str, context: Any, principal: Principal,
) -> tuple[dict[str, Any], str, str]:
    """Validate either a root titration delegation or an ASGCode stage."""
    if not isinstance(context, dict) or "stageCapabilityBundle" not in context:
        return _validate_root_authoritative_bundle(
            con, selected_agent=selected_agent, task=task,
            context=context, principal=principal,
        )

    stage_keys = {
        "capabilityBundle", "capabilityBinding", "capabilityBundleHash",
        "capabilityBindingHash", "stageCapabilityBundle",
        "stageCapabilityBundleHash", "scope", "scopeHash",
        "capmeshAuthorityReceipt", "workflowId", "repo", "worktree",
        "baseCommit", "upstreamDelegationId",
    }
    normalized_only = {"schema", "objective", "authorityEvidence", "stageAuthorityEvidence"}
    if set(context) - (stage_keys | normalized_only) or not stage_keys.issubset(context):
        raise ValueError("stage delegation context fields are not canonical")
    try:
        task_envelope = json.loads(task)
    except (TypeError, ValueError) as exc:
        raise ValueError("stage task envelope is not canonical JSON") from exc
    task_keys = {
        "schema", "workflow_id", "stage_id", "objective", "repository",
        "write_set", "bundle_id", "bundle_digest", "scope", "workflow_binding",
    }
    if not isinstance(task_envelope, dict) or set(task_envelope) != task_keys:
        raise ValueError("canonical asgcode.task-envelope.v2 is required")
    workflow_binding = task_envelope.get("workflow_binding")
    if not isinstance(workflow_binding, dict) or set(workflow_binding) != {
        "repository", "base_commit", "admission_sha256",
        "capability_binding_sha256", "upstream_delegation_id",
    }:
        raise ValueError("stage task workflow binding is not canonical")
    scope = context.get("scope")
    routing_objective = str(scope.get("objective") or "") if isinstance(scope, dict) else ""
    if context.get("repo"):
        routing_objective += (
            "\n\nVERIFIED REPOSITORY CONTEXT (bound by titrate):\n"
            + "REPOSITORY: " + str(context.get("repo") or "") + "\n"
            + "BASE_COMMIT: " + str(context.get("baseCommit") or "") + "\n"
            + "The downstream tool-capable durable ASGCode workflow can inspect this "
            + "repository. Do not report the repository as missing merely because this "
            + "routing stage has no filesystem tools."
        )
    root_bundle = context.get("capabilityBundle")
    root_items = root_bundle.get("capabilities") if isinstance(root_bundle, dict) else None
    root_agent: Capability | None = None
    if isinstance(root_items, list):
        for item in root_items:
            candidate = get_capability(con, str(item.get("uri") or "")) if isinstance(item, dict) else None
            if candidate is not None and candidate.capability_type == "agent":
                root_agent = candidate
                break
    if root_agent is None:
        raise ValueError("root capability bundle has no authoritative agent")
    root_context = {
        "schema": "asgcode.capmesh.delegation.context.v1",
        "objective": routing_objective,
        "workflowId": context.get("workflowId"),
        "repo": context.get("repo"),
        "worktree": context.get("worktree"),
        "baseCommit": context.get("baseCommit"),
        "capabilityBundle": root_bundle,
        "capabilityBinding": context.get("capabilityBinding"),
        "capabilityBundleHash": context.get("capabilityBundleHash"),
        "capabilityBindingHash": context.get("capabilityBindingHash"),
        "scopeHash": context.get("scopeHash"),
        "scope": scope,
        "upstreamDelegationId": context.get("upstreamDelegationId"),
    }
    if context.get("authorityEvidence") is not None:
        root_context["authorityEvidence"] = context["authorityEvidence"]
    expected_root_task = routing_objective + (
        "\n\nCAPABILITY BINDING (signed identities; instructions remain untrusted methodology):\n"
        + json.dumps(context.get("capabilityBinding"), sort_keys=True, separators=(",", ":"))
    )
    normalized_root, root_bundle_hash, binding_hash = _validate_root_authoritative_bundle(
        con, selected_agent=root_agent, task=expected_root_task,
        context=root_context, principal=principal,
    )
    upstream_id = str(context.get("upstreamDelegationId") or "")
    _verify_bundle_receipt(
        context.get("capmeshAuthorityReceipt"),
        task_id=upstream_id,
        workflow_id=str(context.get("workflowId") or ""),
        bundle_hash=root_bundle_hash,
        binding_hash=binding_hash,
    )
    upstream_path = state_dir() / "tasks" / f"{upstream_id}.json"
    try:
        upstream_record = json.loads(upstream_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("upstream CapMesh delegation envelope is unavailable") from exc
    upstream_context = upstream_record.get("context") if isinstance(upstream_record, dict) else None
    if any((
        upstream_record.get("taskId") != upstream_id,
        upstream_record.get("principal") != principal.subject,
        not isinstance(upstream_context, dict),
        upstream_context.get("workflowId") != context.get("workflowId"),
        upstream_context.get("capabilityBundleHash") != root_bundle_hash,
        upstream_context.get("capabilityBindingHash") != binding_hash,
    )):
        raise ValueError("upstream CapMesh delegation binding is invalid")
    stage_bundle, stage_bundle_hash, stage_evidence = _validate_stage_bundle(
        con, bundle=context.get("stageCapabilityBundle"),
        selected_agent=selected_agent, principal=principal,
        stage_objective=str(task_envelope.get("objective") or ""),
    )
    if context.get("stageAuthorityEvidence") not in (None, stage_evidence):
        raise ValueError("caller stage authority evidence conflicts with cpubox computation")
    if any((
        context.get("stageCapabilityBundleHash") != stage_bundle_hash,
        task_envelope.get("schema") != "asgcode.task-envelope.v2",
        task_envelope.get("workflow_id") != context.get("workflowId"),
        re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", str(task_envelope.get("stage_id") or "")) is None,
        not isinstance(task_envelope.get("objective"), str) or not task_envelope.get("objective"),
        task_envelope.get("repository") != context.get("repo"),
        not isinstance(task_envelope.get("write_set"), list),
        task_envelope.get("bundle_id") != stage_bundle.get("bundle_id"),
        task_envelope.get("bundle_digest") != stage_bundle_hash,
        task_envelope.get("scope") != scope,
        workflow_binding.get("repository") != context.get("repo"),
        workflow_binding.get("base_commit") != context.get("baseCommit"),
        not _SHA256_RE.fullmatch(str(workflow_binding.get("admission_sha256") or "")),
        workflow_binding.get("capability_binding_sha256") != binding_hash,
        workflow_binding.get("upstream_delegation_id") != context.get("upstreamDelegationId"),
        not re.fullmatch(r"cap-task-[a-f0-9]{32}", str(context.get("upstreamDelegationId") or "")),
    )):
        raise ValueError("stage task envelope does not match its authoritative workflow binding")
    normalized = {
        **normalized_root,
        "stageCapabilityBundle": stage_bundle,
        "stageCapabilityBundleHash": stage_bundle_hash,
        "capmeshAuthorityReceipt": context.get("capmeshAuthorityReceipt"),
        "upstreamDelegationId": context.get("upstreamDelegationId"),
        "stageAuthorityEvidence": stage_evidence,
    }
    return normalized, stage_bundle_hash, binding_hash


def tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "name": "cap.search",
            "description": "Search the capability mesh without loading full instructions. Use first for semantic discovery across ASG skills, agents, plugins, commands, and MCP packages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "k": {"type": "integer", "minimum": 1, "maximum": 50},
                    "type": {"type": "string"},
                    "principal": {"type": "object"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "cap.load",
            "description": "Load one selected capability lazily after search. Returns bounded metadata plus the requested entrypoint or referenced file only when authorized.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "name": {"type": "string"},
                    "detail": {"type": "string", "enum": ["metadata", "entrypoint", "full"]},
                    "fileRef": {"type": "string"},
                    "principal": {"type": "object"},
                },
            },
        },
        {
            "name": "cap.call",
            "description": "Invoke a callable capability or return the safe activation payload for non-executable skills and agents. Mutating calls require confirmation and are audited.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "name": {"type": "string"},
                    "args": {"type": "object"},
                    "dryRun": {"type": "boolean"},
                    "confirm": {"type": "boolean"},
                    "principal": {"type": "object"},
                },
            },
        },
        {
            "name": "cap.list",
            "description": "List capability records with cursor pagination and entitlement-aware filtering. Use for inventories and coverage checks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "plugin": {"type": "string"},
                    "cursor": {"type": "string"},
                    "pageSize": {"type": "integer", "minimum": 1, "maximum": 100},
                    "principal": {"type": "object"},
                },
            },
        },
        {
            "name": "cap.describe",
            "description": "Describe one capability by URI or name without loading large files. Use before deciding whether to load or delegate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "name": {"type": "string"},
                    "principal": {"type": "object"},
                },
            },
        },
        {
            "name": "cap.delegate",
            "description": "Create an audited delegated task envelope for an agent capability. This does not bulk-load all agents into context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "name": {"type": "string"},
                    "task": {"type": "string"},
                    "context": {"type": "object"},
                    "modelTier": {"type": "string", "enum": ["qwen-worker", "qwen-director", "glm", "opus"]},
                    "principal": {"type": "object"},
                },
                "required": ["task"],
            },
        },
        {
            "name": "cap.process",
            "description": "Process a queued task envelope by dispatching it to the routed model backend (Qwen, GLM, or Opus) via the ASG MCP gateway.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "taskId": {"type": "string"},
                    "principal": {"type": "object"},
                },
                "required": ["taskId"],
            },
        },
        {
            "name": "cap.report",
            "description": "Report router telemetry, eval results, coverage status, or agent feedback back into the mesh audit tables.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event": {"type": "string"},
                    "uri": {"type": "string"},
                    "payload": {"type": "object"},
                    "principal": {"type": "object"},
                },
                "required": ["event"],
            },
        },
    ]


class CapabilityRouter:
    def __init__(self, con, roots: tuple[str, ...] = DEFAULT_ROOTS):
        self.con = con
        self.roots = roots

    def call(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        request_id: str | None = None,
        traceparent: str | None = None,
        start_time_ns: int | None = None,
    ) -> dict[str, Any]:
        params = params or {}
        if tool not in TOOL_NAMES:
            return error(
                f"Unknown tool '{tool}'. Valid tools: {', '.join(TOOL_NAMES)}",
                code="TOOL_NOT_FOUND",
                details={"tool": tool, "validTools": list(TOOL_NAMES)},
            )
        principal = Principal.from_dict(params.get("principal"))
        # CM-13: resolve a request-id for this dispatch. ``X-Request-Id`` from an
        # upstream HTTP caller is passed in as ``request_id``; generate a fresh
        # id when absent so every dispatch is traceable in the structured log.
        rid = request_id or uuid.uuid4().hex
        verb = tool.split(".", 1)[1] if tool.startswith("cap.") else tool
        logger.info(
            "cap.%s",
            verb,
            extra={
                "request_id": rid,
                "subject": principal.subject,
                "verb": verb,
                "tenant": principal.tenant_id,
                "tool": tool,
            },
        )
        # CM-13: structured best-effort JSON log line alongside the legacy log.
        # Failure here must never break dispatch -- log_event wraps redaction
        # and json.dumps with its own TypeError fallback, but be defensive.
        try:
            log_event(
                _OBS_LOGGER,
                "request",
                request_id=rid,
                verb=verb,
                subject=principal.subject,
                tenant=principal.tenant_id,
                tool=tool,
            )
        except Exception:  # noqa: BLE001,S110
            pass
        # CM-13-full: record this dispatch as one "request" span. An inbound W3C
        # traceparent (when the HTTP caller supplied one) is parsed and used as
        # the parent context so the request span is a child of the inbound trace;
        # otherwise the Tracer synthesizes a fresh trace_id. Best-effort only: a
        # tracing failure is swallowed and never breaks the dispatch. The span
        # is ended (in a finally) with the same dispatch return value preserved.
        parent_context = None
        if traceparent:
            try:
                parent_context = parse_traceparent(traceparent)
            except Exception:  # noqa: BLE001
                parent_context = None
        span = None
        # CM-13-full request-context propagation: bind the request span's context
        # to a stdlib contextvar so the gate runner (lifecycle.py) can make its
        # gate spans children of THIS request span (same trace_id, gate
        # span.parent_span_id == request span.span_id). The token is reset in
        # the finally below so the contextvar never leaks across requests; a
        # leaked contextvar would wrongly link unrelated later gate spans to a
        # stale request. Best-effort: kept inside the existing try/except so a
        # contextvar failure never breaks the request.
        _req_ctx_token = None
        try:
            span = REQUEST_TRACER.start_span(
                "request",
                start_time_ns=start_time_ns if start_time_ns is not None else time.monotonic_ns(),
                parent_context=parent_context,
            )
            span.set_attribute("verb", verb)
            span.set_attribute("subject", principal.subject)
            span.set_attribute("tenant", principal.tenant_id)
            span.set_attribute("tool", tool)
            span.set_attribute("request_id", rid)
            _req_ctx_token = set_request_context(span.context)
        except Exception:  # noqa: BLE001
            span = None
        result: dict[str, Any] = error(f"Unhandled tool '{tool}'.")
        try:
            if tool == "cap.search":
                result = self.cap_search(params, principal)
                _record_slo("search", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.load":
                result = self.cap_load(params, principal)
                _record_slo("load", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.call":
                result = self.cap_call(params, principal)
                _record_slo("call", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.list":
                result = self.cap_list(params, principal)
                _record_slo("list", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.describe":
                result = self.cap_describe(params, principal)
                _record_slo("describe", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.delegate":
                result = self.cap_delegate(params, principal)
                _record_slo("delegate", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.process":
                result = self.cap_process(params, principal)
                _record_slo("process", (time.monotonic_ns() - (start_time_ns or time.monotonic_ns())) / 1e6)
            elif tool == "cap.report":
                result = self.cap_report(params, principal)
        except PermissionError as exc:
            audit("router.denied", principal, {"tool": tool, "error": str(exc)})
            result = error(
                "The authenticated principal is not authorized for this capability operation.",
                code="FORBIDDEN",
                details={"tool": tool},
            )
        except (json.JSONDecodeError, ValueError) as exc:
            audit("router.invalid_request", principal, {"tool": tool, "error": str(exc)})
            result = error(
                f"{tool} rejected the supplied arguments.",
                code="INVALID_ARGUMENT",
                details={"tool": tool},
            )
        except FileNotFoundError as exc:
            audit("router.resource_missing", principal, {"tool": tool, "error": str(exc)})
            result = error(
                f"{tool} could not find a required capability resource.",
                code="RESOURCE_NOT_FOUND",
                details={"tool": tool},
            )
        except sqlite3.Error as exc:
            audit("router.error", principal, {"tool": tool, "error": str(exc)})
            # Keep diagnostic detail in the redacted audit trail. Returning raw
            # exception strings to an MCP caller can disclose filesystem paths,
            # SQL fragments, or authorization internals.
            result = error(
                f"{tool} failed because the capability store could not complete the operation.",
                code="INTERNAL_ERROR",
                details={"tool": tool},
            )
        finally:
            # Reset the request-context contextvar best-effort so it never leaks
            # across requests. This runs whenever a token was captured (i.e. the
            # span started and the contextvar was set), independent of ``span``
            # end success. A leaked contextvar would wrongly link unrelated later
            # gate spans to a stale request.
            if _req_ctx_token is not None:
                try:
                    _req_ctx_token.reset()
                except Exception:  # noqa: BLE001,S110
                    pass
            if span is not None:
                try:
                    if result.get("isError"):
                        span.set_status("error")
                    else:
                        span.set_status("ok")
                    span.end(time.monotonic_ns())
                except Exception:  # noqa: BLE001,S110
                    pass
        return result

    def cap_search(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        ok, reason = require_scope(principal, "cap:search")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:search"})
        query = str(params.get("query") or "").strip()
        if not query:
            return error("query is required.", code="INVALID_ARGUMENT", details={"field": "query"})
        results = search(self.con, query, principal, k=int(params.get("k") or 10), capability_type=params.get("type"))
        audit("cap.search", principal, {"query": query, "count": len(results)})
        data = {
            "query": query,
            "results": [
                {
                    **sanitize_metadata(item.capability.to_record(stub=item.locked, include_paths=False)),
                    "score": round(item.score, 6),
                    "rank": item.rank,
                    "matchedBy": list(item.matched_by),
                    "locked": item.locked,
                }
                for item in results
            ],
        }
        lines = [f"Found {len(results)} capability match(es) for '{query}'."]
        for item in results[:8]:
            status = "locked" if item.locked else "loadable"
            lines.append(f"- {item.capability.uri} [{item.capability.capability_type}, {status}] {item.capability.title}")
        return ok_result("\n".join(lines), data)

    def cap_load(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        ok, reason = require_scope(principal, "cap:load")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:load"})
        cap = resolve_capability(self.con, params)
        if cap is None:
            return error("Capability not found. Run cap.search first.", code="CAPABILITY_NOT_FOUND")
        allowed, reason = can_load(cap, principal, con=self.con, right="load")
        if not allowed:
            audit("cap.load.denied", principal, {"uri": cap.uri, "reason": reason})
            return error(reason or "Capability not authorized.", code="FORBIDDEN", details={"uri": cap.uri})
        detail = str(params.get("detail") or "entrypoint")
        file_ref = params.get("fileRef")
        payload = cap.to_record(include_paths=True)
        if detail in {"entrypoint", "full"}:
            if cap.source_kind == "system_capability":
                return error(
                    "System capabilities expose metadata through cap.load and behavior through cap.call; server source bodies are not loadable.",
                    code="SYSTEM_BODY_NOT_LOADABLE",
                    details={"uri": cap.uri},
                )
            target = safe_file_target(cap.package_path, str(file_ref or cap.entrypoint))
            if target is None:
                return error("Requested file is outside the capability package.")
            expected_hash = content_hash_for_target(cap, target, file_ref=str(file_ref) if file_ref else None)
            if expected_hash is None:
                return error(
                    "Referenced file has no indexed digest and cannot be loaded safely.",
                    code="UNVERIFIED_FILE_REFERENCE",
                    details={"uri": cap.uri},
                )
            actual_hash, verified_content = hash_and_read_content(target, detail=detail)
            if not hmac_hash_equal(actual_hash, expected_hash):
                audit(
                    "cap.load.tamper_denied",
                    principal,
                    {"uri": cap.uri, "expectedHash": expected_hash, "actualHash": actual_hash},
                )
                return error(
                    "Capability content no longer matches its indexed digest. Re-ingest from an authoritative source before loading.",
                    code="CONTENT_HASH_MISMATCH",
                    details={"uri": cap.uri},
                )
            payload["loadedFile"] = str(target)
            payload["content"] = verified_content
        audit("cap.load", principal, {"uri": cap.uri, "detail": detail, "fileRef": file_ref})
        return ok_result(f"Loaded {cap.uri} ({detail}).", payload)

    def cap_call(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        ok, reason = require_scope(principal, "cap:call")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:call"})
        cap = resolve_capability(self.con, params)
        if cap is None:
            return error("Capability not found. Run cap.search first.", code="CAPABILITY_NOT_FOUND")
        allowed, reason = can_load(cap, principal, con=self.con, right="call")
        if not allowed:
            return error(reason or "Capability not authorized.", code="FORBIDDEN", details={"uri": cap.uri})
        dry_run = bool(params.get("dryRun", True))
        confirm = bool(params.get("confirm", False))
        if cap.mutating and not dry_run and not is_authoritative_node():
            return error(
                "Authoritative capability writes are served only by the authoritative node.",
                code="NOT_AUTHORITATIVE",
                details=topology_payload(),
            )
        if cap.mutating and not confirm:
            return error(
                "Mutating capability calls require confirm=true and should be dry-run first.",
                code="CONFIRMATION_REQUIRED",
                details={"uri": cap.uri},
            )
        audit("cap.call", principal, {"uri": cap.uri, "dryRun": dry_run, "confirm": confirm})
        if cap.metadata.get("systemCapability"):
            if dry_run:
                return ok_result(
                    "System capability dry run accepted; execution skipped.",
                    {"mode": "system_capability", "capability": cap.to_record(include_paths=False), "dryRun": True},
                )
            try:
                data = dispatch_system_capability(self.con, cap, params.get("args") or {}, principal)
            except PermissionError as exc:
                return error(str(exc), code="FORBIDDEN", details={"uri": cap.uri})
            except ValueError as exc:
                return error(str(exc), code="INVALID_ARGUMENT", details={"uri": cap.uri})
            return ok_result(f"System capability {cap.name} completed.", data)
        if cap.capability_type == "skill":
            return ok_result(
                "Skill capability activation prepared. Load the entrypoint and follow its progressive disclosure instructions.",
                {"mode": "skill_activation", "capability": cap.to_record(include_paths=False), "args": params.get("args") or {}},
            )
        if cap.capability_type == "agent":
            return self.cap_delegate({"uri": cap.uri, "task": str((params.get("args") or {}).get("task") or "Run delegated agent task.")}, principal)
        callable_spec = cap.metadata.get("callable") or cap.metadata.get("call")
        if not callable_spec:
            return ok_result(
                "Capability is registered and loadable but has no executable call binding.",
                {"mode": "metadata_only", "capability": cap.to_record(include_paths=False), "dryRun": dry_run},
            )
        if dry_run:
            return ok_result("Callable dry run accepted; execution skipped.", {"callable": callable_spec, "dryRun": True})
        # Check the signed allowlist: if the capability binding has been
        # explicitly approved (signed binding hash), permit execution.
        # Otherwise the call is blocked until allowlisted command execution
        # is configured.
        try:
            from .signed_allowlist import compute_binding_hash, is_binding_approved
            binding_hash = compute_binding_hash(cap.uri, cap.entrypoint or "", cap.content_hash or "")
            if is_binding_approved(self.con, cap.uri, binding_hash, tenant_id=principal.tenant_id or "asg"):
                return ok_result(
                    "Callable binding is allowlisted; execution permitted.",
                    {"callable": callable_spec, "bindingHash": binding_hash, "dryRun": False},
                )
        except Exception:  # noqa: BLE001, S110
            pass
        return error("Executable call bindings are registered but disabled until allowlisted command execution is configured.")

    def cap_list(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        data = list_capabilities(
            self.con,
            principal,
            capability_type=params.get("type"),
            plugin=params.get("plugin"),
            cursor=params.get("cursor"),
            page_size=int(params.get("pageSize") or 50),
        )
        audit("cap.list", principal, {"type": params.get("type"), "plugin": params.get("plugin"), "count": len(data["items"])})
        return ok_result(f"Listed {len(data['items'])} capability record(s).", data)

    def cap_describe(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        cap = resolve_capability(self.con, params)
        if cap is None:
            return error("Capability not found. Run cap.search first.", code="CAPABILITY_NOT_FOUND")
        allowed, reason = can_load(cap, principal, con=self.con, right="load")
        stub = not allowed
        audit("cap.describe", principal, {"uri": cap.uri, "stub": stub})
        data = cap.to_record(stub=stub, include_paths=allowed)
        if stub:
            data["authorization"] = reason
        return ok_result(f"Described {cap.uri}.", data)

    def cap_delegate(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        if not is_authoritative_node():
            return error(
                "Delegation writes are served only by the authoritative node.",
                code="NOT_AUTHORITATIVE",
                details=topology_payload(),
            )
        ok, reason = require_scope(principal, "cap:delegate")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:delegate"})
        cap = resolve_capability(self.con, params)
        if cap is None:
            return error("Agent capability not found. Run cap.search with type=agent first.", code="CAPABILITY_NOT_FOUND")
        allowed, reason = can_load(cap, principal, con=self.con, right="delegate")
        _commit_policy_audit(self.con)
        if not allowed:
            return error(reason or "Capability not authorized.", code="FORBIDDEN", details={"uri": cap.uri})
        if cap.capability_type != "agent":
            return error("cap.delegate requires an agent capability.", {"uri": cap.uri, "type": cap.capability_type})
        task = str(params.get("task") or "").strip()
        if not task:
            return error("task is required.")
        try:
            normalized_context, bundle_hash, binding_hash = _validate_authoritative_bundle(
                self.con, selected_agent=cap, task=task,
                context=params.get("context"), principal=principal,
            )
        except PermissionError:
            raise
        except ValueError as exc:
            return error(str(exc), code="INVALID_ARGUMENT")
        finally:
            _commit_policy_audit(self.con)
        task_id = "cap-task-" + uuid.uuid4().hex
        workflow_id = str(normalized_context["workflowId"])
        authority_receipt = _signed_bundle_receipt(
            task_id=task_id, workflow_id=workflow_id,
            bundle_hash=bundle_hash, binding_hash=binding_hash,
        )
        record = {
            "taskId": task_id,
            "ts": utc_now(),
            "agentUri": cap.uri,
            "agentName": cap.name,
            "task": task,
            "context": normalized_context,
            "capmeshBundleReceipt": authority_receipt,
            "principal": principal.subject,
            "status": "queued",
            "note": "Task envelope created for an external agent runner. No bulk agent context was loaded.",
        }
        # Route the task to the cheapest capable model tier (GLM/Qwen/Opus).
        # The routing is advisory and can be overridden by passing modelTier
        # in the delegation params.
        try:
            from .model_router import route_model
            model_override = str(params.get("modelTier") or "").strip() or None
            routing = route_model(
                risk_tier=cap.risk_tier,
                capability_type=cap.capability_type,
                mutating=cap.mutating,
                task=task,
                metadata=cap.metadata,
                override=model_override,
            )
            record["modelRouting"] = routing
        except Exception:  # noqa: BLE001, S110
            pass
        tasks_dir = state_dir() / "tasks"
        tasks_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(tasks_dir, 0o700)
        task_path = tasks_dir / f"{task_id}.json"
        fd = os.open(task_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        audit("cap.delegate", principal, {"uri": cap.uri, "taskId": task_id})
        # Also persist the task envelope in the DB-backed task_envelopes table
        # so that task_runner can list and process queued tasks.  The JSON file
        # remains the authoritative copy; the DB entry is a queryable index.
        try:
            from .task_runner import create_task_envelope
            create_task_envelope(
                self.con,
                capability_uri=cap.uri,
                principal=principal.subject,
                task_envelope=record,
                tenant_id=principal.tenant_id or "asg",
                commit=False,
            )
        except Exception:  # noqa: BLE001, S110
            pass
        # Sign the export bundle with sigstore if available.  Non-fatal:
        # if sigstore is unavailable, the unsigned bundle is still valid.
        try:
            from .sigstore_signing import build_export_bundle, build_sigstore_signing_policy
            bundle = build_export_bundle(
                capability_uri=cap.uri,
                task_id=task_id,
                principal=principal.subject,
                content_hash=cap.content_hash or "",
            )
            record["exportBundle"] = bundle
            record["signingPolicy"] = build_sigstore_signing_policy()
        except Exception:  # noqa: BLE001, S110
            pass
        return ok_result(f"Delegation envelope created for {cap.name}: {task_id}.", record)

    def cap_process(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        """Process a queued task envelope by dispatching it to the routed model backend."""
        if not is_authoritative_node():
            return error(
                "Task processing is served only by the authoritative node.",
                code="NOT_AUTHORITATIVE",
                details=topology_payload(),
            )
        ok, reason = require_scope(principal, "cap:delegate")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:delegate"})
        task_id = str(params.get("taskId") or "").strip()
        if not task_id:
            return error("taskId is required.")
        try:
            from .task_dispatcher import dispatch_queued_task
            result = dispatch_queued_task(
                self.con,
                task_id,
                tenant_id=principal.tenant_id or "asg",
            )
            audit("cap.process", principal, {"taskId": task_id, "backend": result.get("backend"), "status": result.get("status")})
            if result.get("status") == "failed":
                return error(
                    f"Task dispatch failed: {result.get('error', 'unknown error')}",
                    code="DISPATCH_FAILED",
                    details=result,
                )
            return ok_result(f"Task {task_id} processed via {result.get('backend')}.", result)
        except ValueError as exc:
            return error(str(exc), code="TASK_NOT_FOUND")
        except Exception as exc:  # noqa: BLE001
            return error(f"Task processing failed: {exc}", code="INTERNAL_ERROR")

    def cap_report(self, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        if not is_authoritative_node():
            return error(
                "Capability reports are accepted only by the authoritative node.",
                code="NOT_AUTHORITATIVE",
                details=topology_payload(),
            )
        ok, reason = require_scope(principal, "cap:report")
        if not ok:
            return error(reason or "Not authorized.", code="INSUFFICIENT_SCOPE", details={"requiredScope": "cap:report"})
        event = str(params.get("event") or "").strip()
        if not event:
            return error("event is required.")
        payload = params.get("payload") or {}
        extra = {}
        if event in {"asgcode.titration.stage", "asgcode.workflow.stage"}:
            if not isinstance(payload, dict) or payload.get("schema") != "asgcode.capability_report.v1":
                return error("asgcode titration report schema is required.", code="INVALID_ARGUMENT")
            report_keys = {
                "schema", "taskId", "agentUri", "bundleDigest",
                "capabilityBindingDigest", "outcomeDigest", "outcome",
            }
            if event == "asgcode.workflow.stage":
                report_keys.add("workflowBinding")
            if set(payload) != report_keys:
                return error("capability report fields are not canonical.", code="INVALID_ARGUMENT")
            task_id = str(payload.get("taskId") or "")
            uri = str(params.get("uri") or "")
            agent_uri = str(payload.get("agentUri") or "")
            bundle_digest = str(payload.get("bundleDigest") or "")
            binding_digest = str(payload.get("capabilityBindingDigest") or "")
            outcome_digest = str(payload.get("outcomeDigest") or "")
            outcome = payload.get("outcome")
            if not re.fullmatch(r"cap-task-[a-f0-9]{32}", task_id):
                return error("valid delegated taskId is required.", code="INVALID_ARGUMENT")
            if not uri.startswith("cap://") or agent_uri != uri:
                return error("report URI does not match delegated agent URI.", code="INVALID_ARGUMENT")
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", bundle_digest):
                return error("valid capability bundle digest is required.", code="INVALID_ARGUMENT")
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", binding_digest):
                return error("valid capability binding digest is required.", code="INVALID_ARGUMENT")
            if event == "asgcode.workflow.stage":
                workflow_hint = payload.get("workflowBinding")
                hinted_workflow_id = str(
                    workflow_hint.get("workflowId")
                    if isinstance(workflow_hint, dict) else ""
                )
                valid_outcome, outcome_reason = _valid_workflow_stage_outcome(
                    outcome, task_id=task_id, workflow_id=hinted_workflow_id,
                )
            else:
                valid_outcome, outcome_reason = _valid_titration_outcome(outcome)
            if not valid_outcome:
                return error(outcome_reason, code="INVALID_ARGUMENT")
            canonical_outcome = json.dumps(outcome, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            actual_outcome_digest = "sha256:" + hashlib.sha256(canonical_outcome).hexdigest()
            if outcome_digest != actual_outcome_digest:
                return error("outcome digest mismatch.", code="INVALID_ARGUMENT")
            task_path = state_dir() / "tasks" / f"{task_id}.json"
            try:
                task_record = json.loads(task_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return error("delegated task envelope not found.", code="DELEGATION_NOT_FOUND")
            if task_record.get("taskId") != task_id or task_record.get("agentUri") != uri:
                return error("delegated task binding mismatch.", code="FORBIDDEN")
            if task_record.get("principal") != principal.subject:
                return error("delegated task principal binding mismatch.", code="FORBIDDEN")
            task_context = task_record.get("context") if isinstance(task_record.get("context"), dict) else {}
            delegated_cap = get_capability(self.con, uri)
            if delegated_cap is None:
                return error("delegated capability no longer exists.", code="POLICY_DENIED")
            try:
                authoritative_context, authority_bundle_digest, authority_binding_digest = _validate_authoritative_bundle(
                    self.con, selected_agent=delegated_cap,
                    task=str(task_record.get("task") or ""), context=task_context,
                    principal=principal,
                )
            except (PermissionError, ValueError):
                return error("delegated capability authority is no longer valid.", code="POLICY_DENIED")
            finally:
                _commit_policy_audit(self.con)
            if any((
                authoritative_context != task_context,
                authority_bundle_digest != bundle_digest,
                authority_binding_digest != binding_digest,
                outcome.get("workflow_id") != task_context.get("workflowId"),
                event == "asgcode.titration.stage" and outcome.get("stage_id") != "titration",
            )):
                return error("report does not match current authoritative delegation.", code="FORBIDDEN")
            delegated_bundle_digest = (
                task_context.get("stageCapabilityBundleHash")
                if event == "asgcode.workflow.stage"
                else task_context.get("capabilityBundleHash")
            )
            if delegated_bundle_digest != bundle_digest:
                return error("capability bundle digest does not match delegation.", code="FORBIDDEN")
            if task_context.get("capabilityBindingHash") != binding_digest:
                return error("capability binding digest does not match delegation.", code="FORBIDDEN")
            workflow_binding = payload.get("workflowBinding")
            workflow_receipt: dict[str, str] = {}
            if event == "asgcode.workflow.stage":
                required_workflow_keys = {
                    "workflowId", "repo", "worktree", "baseCommit", "upstreamDelegationId",
                }
                if not isinstance(workflow_binding, dict) or set(workflow_binding) != required_workflow_keys:
                    return error("canonical workflowBinding is required for workflow stage reports.", code="INVALID_ARGUMENT")
                if not re.fullmatch(r"wf_[A-Za-z0-9_-]{8,120}", str(workflow_binding.get("workflowId") or "")):
                    return error("workflowBinding workflowId is invalid.", code="INVALID_ARGUMENT")
                if not re.fullmatch(r"[a-f0-9]{40}", str(workflow_binding.get("baseCommit") or "")):
                    return error("workflowBinding baseCommit is invalid.", code="INVALID_ARGUMENT")
                if not re.fullmatch(r"cap-task-[a-f0-9]{32}", str(workflow_binding.get("upstreamDelegationId") or "")):
                    return error("workflowBinding upstreamDelegationId is invalid.", code="INVALID_ARGUMENT")
                expected_context = {
                    "workflowId": workflow_binding["workflowId"],
                    "repo": workflow_binding["repo"],
                    "worktree": workflow_binding["worktree"],
                    "baseCommit": workflow_binding["baseCommit"],
                    "upstreamDelegationId": workflow_binding["upstreamDelegationId"],
                }
                if any(task_context.get(key) != value for key, value in expected_context.items()):
                    return error("workflowBinding does not match delegated task context.", code="FORBIDDEN")
                workflow_receipt = expected_context
            signing_key = _authority_signer()
            if event == "asgcode.workflow.stage":
                extra["receipt"] = issue_report_receipt(
                    signing_key=signing_key,
                    task_id=task_id,
                    agent_uri=uri,
                    bundle_digest=bundle_digest,
                    capability_binding_digest=binding_digest,
                    outcome_digest=outcome_digest,
                    outcome_status=str(outcome.get("status") or ""),
                    workflow_id=workflow_receipt["workflowId"],
                    repo=workflow_receipt["repo"],
                    worktree=workflow_receipt["worktree"],
                    base_commit=workflow_receipt["baseCommit"],
                    upstream_delegation_id=workflow_receipt["upstreamDelegationId"],
                )
            else:
                extra["receipt"] = _signed_advisory_report_receipt(
                    signing_key=signing_key,
                    event=event,
                    task_id=task_id,
                    agent_uri=uri,
                    bundle_digest=bundle_digest,
                    binding_digest=binding_digest,
                    outcome_digest=outcome_digest,
                    outcome_status=str(outcome.get("status") or ""),
                )
            try:
                self.con.execute("SAVEPOINT capmesh_authoritative_report")
                self.con.execute(
                    """INSERT INTO authoritative_router_reports(
                           event, task_id, report_id, nonce, principal,
                           report_digest, receipt_json
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event, task_id, extra["receipt"]["reportId"],
                        extra["receipt"]["nonce"], principal.subject,
                        _sha({"event": event, "uri": uri, "payload": payload}),
                        json.dumps(extra["receipt"], sort_keys=True, separators=(",", ":")),
                    ),
                )
                self.con.execute(
                    "INSERT INTO router_reports(event, uri, principal, payload_json) VALUES (?, ?, ?, ?)",
                    (event, uri, principal.subject, json.dumps(payload, sort_keys=True)),
                )
                self.con.execute("RELEASE SAVEPOINT capmesh_authoritative_report")
                self.con.commit()
            except sqlite3.IntegrityError:
                self.con.execute("ROLLBACK TO SAVEPOINT capmesh_authoritative_report")
                self.con.execute("RELEASE SAVEPOINT capmesh_authoritative_report")
                audit(
                    "cap.report.replay_denied", principal,
                    {"event": event, "uri": uri, "taskId": task_id},
                )
                return error(
                    "this delegated stage already has an authoritative report.",
                    code="POLICY_DENIED",
                )
        else:
            self.con.execute(
                "INSERT INTO router_reports(event, uri, principal, payload_json) VALUES (?, ?, ?, ?)",
                (event, params.get("uri"), principal.subject, json.dumps(payload, sort_keys=True)),
            )
            self.con.commit()
        audit("cap.report", principal, {"event": event, "uri": params.get("uri")})
        if event == "coverage.check":
            extra["coverage"] = coverage_report(self.con, self.roots)
        return ok_result(f"Reported {event}.", {"event": event, "uri": params.get("uri"), **extra})


def resolve_capability(con: sqlite3.Connection, params: dict[str, Any]) -> Capability | None:
    identifier = params.get("uri") or params.get("name")
    if not identifier:
        return None
    return get_capability(con, str(identifier))


def safe_file_target(package_path: str, ref: str) -> Path | None:
    root = Path(package_path).expanduser().resolve()
    target = (root / ref).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    if not target.exists() or not target.is_file():
        return None
    return target


def hash_and_read_content(path: Path, *, detail: str) -> tuple[str, str]:
    """Hash and capture bounded bytes from one file descriptor (no TOCTOU reopen)."""

    limit = 400_000 if detail == "full" else 80_000
    digest = hashlib.sha256()
    captured = bytearray()
    truncated = False
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            remaining = max(0, limit - len(captured))
            if remaining:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
    text = bytes(captured).decode("utf-8", errors="replace")
    if truncated:
        text += "\n\n[TRUNCATED: request detail=full for a larger bounded view.]"
    return "sha256:" + digest.hexdigest(), text


def hmac_hash_equal(actual: str, expected: str) -> bool:
    # ``compare_digest`` avoids introducing content-dependent timing behavior
    # at a trust boundary. Both values are non-secret, but uniform comparison is
    # cheap and avoids accidental partial/prefix comparisons.
    import hmac

    return hmac.compare_digest(actual, expected)


def content_hash_for_target(cap: Capability, target: Path, *, file_ref: str | None) -> str | None:
    source = Path(cap.source_path).expanduser().resolve()
    if target == source or not file_ref or file_ref == cap.entrypoint:
        return cap.content_hash
    hashes = cap.metadata.get("fileHashes") or {}
    if not isinstance(hashes, dict):
        return None
    candidate = hashes.get(file_ref)
    return str(candidate) if isinstance(candidate, str) and candidate.startswith("sha256:") else None


def ok_result(text: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": text},
            {"type": "text", "text": json.dumps(data, indent=2, sort_keys=True)},
        ],
        "structuredContent": data,
        "isError": False,
    }


def error(
    message: str,
    data: dict[str, Any] | None = None,
    *,
    code: str = "CAPABILITY_MESH_ERROR",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # ``data`` is retained as a compatibility alias for existing callers. New
    # code should use ``details`` and a stable machine-readable ``code``.
    payload = {"error": {"code": code, "message": message, "details": details if details is not None else (data or {})}}
    return {
        "content": [
            {"type": "text", "text": message},
            {"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)},
        ],
        "structuredContent": payload,
        "isError": True,
    }
