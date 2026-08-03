"""Governed static review gates for capability approval and promotion.

The review attestation is an internal Ed25519 signed envelope.  The provenance
promotion gate delegates to the standalone ``capmesh.provenance`` module, which
builds SLSA-style in-toto/DSSE statements (predicateType
``https://slsa.dev/provenance/v1``) and content-addressed digests.  The signed
envelope itself is deliberately not represented as Sigstore or a
transparency-log proof.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

from .models import Capability, Principal, normalize_path
from .observability import (
    GateDecision,
    MetricsRegistry,
    format_gate_decision,
    log_event,
)
from .provenance import (
    attestation_digest,
    compute_provenance_status,
    to_jsonl_attestation,
)
from .signing import sign_attestation, trusted_signing_key_id, verify_attestation
from .tracing import Tracer, get_request_context

# Best-effort observability for the gate runner (CM-13 wiring). A logging or
# metric failure must never break a gate evaluation; every call site below is
# wrapped so observability stays best-effort. ``GATE_METRICS`` is exposed at
# module level so tests and ops can import and assert on it.
_OBS_LOGGER = logging.getLogger("capmesh.lifecycle")
GATE_METRICS = MetricsRegistry()
# CM-13-full OTel trace export: a module-level Tracer. Each gate evaluation is
# recorded as a span (best-effort, never breaks the gate runner). Ended spans
# are collected by the Tracer; a later wave flushes them via otlp_exporter.
TRACER = Tracer()


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024
MAX_BATCH = 500
REQUIRED_GATES = (
    "sourceIntegrity",
    "tests",
    "retrievalEvals",
    "signature",
    "provenance",
    "promptInjectionScan",
    "riskTierPolicy",
)

def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _bounded_evidence(value: Any) -> str:
    encoded = _json(value).encode("utf-8")
    if len(encoded) <= MAX_EVIDENCE_BYTES:
        return encoded.decode("utf-8")
    return _json(
        {
            "truncated": True,
            "encodedBytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    )


def _gate(state: str, *, code: str, warnings: list[str] | None = None, **details: Any) -> dict[str, Any]:
    return {
        "state": state,
        "evidence": {
            "code": code,
            "warnings": list(warnings or ()),
            **details,
        },
    }


def _attestation_envelope(
    cap: Capability,
    *,
    scope: str,
    target_namespace_id: str | None,
    reviewer: str,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "schema": "https://slsa.dev/provenance/v1",
        "tenantId": cap.tenant_id,
        "capabilityUri": cap.uri,
        "canonicalKey": cap.canonical_key,
        "contentHash": cap.content_hash,
        "sourceSystem": cap.source_system,
        "sourcePath": normalize_path(cap.source_path),
        "reviewScope": scope,
        "targetNamespaceId": target_namespace_id,
        "reviewer": reviewer,
        "timestamp": timestamp,
        "assurance": "internal-ed25519;not-sigstore-or-transparency-log",
    }


def _source_bytes(cap: Capability) -> tuple[bytes | None, dict[str, Any]]:
    path = Path(cap.source_path).expanduser()
    if not path.exists() or path.is_symlink():
        return None, _gate("failed", code="source_missing", path=normalize_path(path))
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None, _gate("failed", code="source_open_failed", path=normalize_path(path))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, _gate("failed", code="source_not_regular_file", path=normalize_path(path))
        if info.st_size > MAX_SOURCE_BYTES:
            return None, _gate("failed", code="source_too_large", sizeBytes=info.st_size, limitBytes=MAX_SOURCE_BYTES)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            content = handle.read(MAX_SOURCE_BYTES + 1)
        if len(content) > MAX_SOURCE_BYTES:
            return None, _gate("failed", code="source_too_large", sizeBytes=len(content), limitBytes=MAX_SOURCE_BYTES)
    finally:
        os.close(fd)
    actual = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual != cap.content_hash:
        return None, _gate(
            "failed",
            code="content_hash_mismatch",
            expectedHash=cap.content_hash,
            actualHash=actual,
            sizeBytes=len(content),
        )
    return content, _gate("passed", code="source_hash_verified", contentHash=actual, sizeBytes=len(content))


def _frontmatter_fields(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    fields: dict[str, str] = {}
    lines = parts[1].splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$", line)
        if match:
            value = match.group(2).strip()
            if not value:
                continuation: list[str] = []
                index += 1
                while index < len(lines) and (lines[index].startswith(" ") or lines[index].startswith("\t")):
                    continuation.append(lines[index].strip())
                    index += 1
                value = " ".join(continuation).strip().strip('"').strip("'")
                fields[match.group(1).lower()] = value
                continue
            fields[match.group(1).lower()] = value
        index += 1
    return fields


def _metadata_gate(cap: Capability, content: bytes) -> dict[str, Any]:
    text = content.decode("utf-8", errors="replace")
    missing = [name for name, value in (("name", cap.name), ("title", cap.title), ("description", cap.description)) if not str(value).strip()]
    details: dict[str, Any] = {"type": cap.capability_type, "sourceKind": cap.source_kind}
    suffix = Path(cap.source_path).suffix.lower()
    if suffix == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            return _gate("failed", code="invalid_json", line=exc.lineno, column=exc.colno)
        if not isinstance(parsed, dict):
            return _gate("failed", code="json_root_not_object")
        details["jsonObject"] = True
        if cap.capability_type == "plugin" and not str(parsed.get("name") or cap.name).strip():
            missing.append("plugin.name")
        if cap.capability_type == "mcp_server":
            direct_servers = any(
                isinstance(value, dict) and (value.get("command") or value.get("url") or value.get("type"))
                for value in parsed.values()
            )
            if not (parsed.get("mcpServers") or parsed.get("command") or parsed.get("url") or parsed.get("transport") or direct_servers):
                missing.append("mcp_server.connection")
    elif suffix in {".md", ".mdx"} and cap.capability_type in {"skill", "agent", "command"}:
        frontmatter = _frontmatter_fields(text)
        if frontmatter:
            if cap.capability_type == "skill" and not frontmatter.get("description"):
                missing.append("frontmatter.description")
            details["frontmatter"] = True
        elif not re.search(r"(?m)^#\s+\S", text):
            missing.append("markdown.heading")
    if missing:
        return _gate("failed", code="metadata_invalid", missing=sorted(set(missing)), **details)
    return _gate("passed", code="metadata_validated_static_only", **details)


def _retrieval_gate(con: sqlite3.Connection, cap: Capability) -> dict[str, Any]:
    source = con.execute("SELECT 1 FROM capability_sources WHERE uri = ? LIMIT 1", (cap.uri,)).fetchone()
    fts = con.execute("SELECT 1 FROM capability_fts WHERE uri = ? LIMIT 1", (cap.uri,)).fetchone()
    if source is None or fts is None:
        return _gate("failed", code="retrieval_index_incomplete", sourceIndexed=source is not None, ftsIndexed=fts is not None)
    return _gate("passed", code="retrieval_index_verified", sourceIndexed=True, ftsIndexed=True)


def _prompt_injection_gate(cap: Capability, content: bytes) -> dict[str, Any]:
    """Prompt-injection scan gate wired to ``capmesh.injection_allowlist``.

    Runs ``scan_prompt_injection`` (governance) over the cap's name, title,
    description and decoded source text to collect flagged phrases, wraps each
    into the ``{"phrase": ...}`` hit shape the allowlist expects, and delegates
    pass/fail to ``injection_allowlist.should_block``. Real injection
    indicators (e.g. ``exfiltrate``) block the gate; benign authoring phrases
    (``act as``, ``system prompt``, ``you are``) are downgraded to
    ``info``/``allowed`` by the allowlist so legitimate agent/skill
    definitions -- e.g. a cap named ``*-system-prompt`` -- are not blocked as
    false positives. Downgraded (non-blocking) hits surface as gate warnings.

    ``cap.plugin`` is passed through so security-domain vocabulary
    (``exfiltrate``, ``bypass auth``) inside an offensive-security/DFIR package
    downgrades to ``info`` instead of blocking -- a red-team reporting skill
    cannot describe itself without those words. Injection *imperatives* still
    block everywhere, including in those packages.

    ``injection_allowlist`` is imported locally so tests can monkeypatch
    ``should_block`` by patching the attribute on the ``capmesh.injection_allowlist``
    module (the gate reads ``injection_allowlist.should_block`` at call time).
    """
    from . import injection_allowlist
    from .governance import scan_prompt_injection

    # Scan the two surfaces SEPARATELY. Concatenating them made every hit
    # unattributable, so a payload literal buried in a red-team corpus body was
    # indistinguishable from an imperative planted in a description -- and the
    # description is the one cap.search broadcasts into unrelated agents.
    source_text = content.decode("utf-8", errors="replace")
    metadata_text = "\n".join([cap.name or "", cap.title or "", cap.description or ""])
    capability_kind = cap.capability_type
    capability_plugin = cap.plugin

    metadata_hits = [{"phrase": p} for p in scan_prompt_injection(metadata_text)]
    body_hits = [{"phrase": p} for p in scan_prompt_injection(source_text)]

    meta_blocking, meta_ok = injection_allowlist.filter_scan_hits(
        metadata_hits, cap.name, capability_kind, capability_plugin,
        injection_allowlist.SURFACE_METADATA,
    )
    body_blocking, body_ok = injection_allowlist.filter_scan_hits(
        body_hits, cap.name, capability_kind, capability_plugin,
        injection_allowlist.SURFACE_BODY,
    )
    # Tag each hit with the surface it came from so gate output says WHERE.
    for hit in meta_blocking + meta_ok:
        hit["surface"] = injection_allowlist.SURFACE_METADATA
    for hit in body_blocking + body_ok:
        hit["surface"] = injection_allowlist.SURFACE_BODY

    if meta_blocking or body_blocking:
        blocking = meta_blocking + body_blocking
        phrases = sorted({str(hit.get("phrase", "")) for hit in blocking})
        reasons = sorted({str(hit.get("reason", "")) for hit in blocking})
        surfaces = sorted({str(hit.get("surface", "")) for hit in blocking})
        return _gate(
            "failed",
            code="prompt_injection_blocked",
            blockingPhrases=phrases,
            reasons=reasons,
            blockingSurfaces=surfaces,
        )
    # Benign hits are downgraded to info/allowed -- not blocking. Surface them
    # as warnings so reviewers still see the flagged wording, and record the
    # downgraded severities as details for consumers that read them.
    non_blocking = meta_ok + body_ok
    warnings = [
        f"prompt_injection_downgraded:{hit.get('surface', '')}:{hit.get('phrase', '')}"
        for hit in non_blocking
    ]
    downgraded = [
        {
            "phrase": hit.get("phrase", ""),
            "severity": hit.get("severity", ""),
            "surface": hit.get("surface", ""),
        }
        for hit in non_blocking
    ]
    return _gate(
        "passed",
        code="no_blocking_prompt_injection",
        warnings=warnings,
        hits=downgraded,
    )


def _scope_for(con: sqlite3.Connection, cap: Capability, target_namespace_id: str | None, requested: str | None) -> tuple[str, str | None]:
    if requested:
        normalized = requested.strip().lower().replace("-", "_")
        if normalized not in {"private", "org", "all_users"}:
            raise ValueError("reviewScope must be private, org, or all_users.")
        return normalized, target_namespace_id
    namespace_id = target_namespace_id or cap.namespace_id
    if namespace_id:
        row = con.execute(
            "SELECT s.kind FROM namespaces n JOIN stores s ON s.id = n.store_id WHERE n.id = ?",
            (namespace_id,),
        ).fetchone()
        if row is not None:
            kind = str(row["kind"])
            if kind == "all_users":
                return "all_users", namespace_id
            if kind == "org":
                return "org", namespace_id
    return "private", namespace_id


def _risk_gate(cap: Capability, scope: str, *, approved_exception: bool) -> dict[str, Any]:
    warnings: list[str] = []
    if scope == "all_users" and (cap.mutating or cap.risk_tier in {"high", "critical"}):
        return _gate("failed", code="all_users_risk_policy", riskTier=cap.risk_tier, mutating=cap.mutating)
    if scope == "org" and cap.risk_tier == "critical" and not approved_exception:
        return _gate("failed", code="org_critical_requires_exception", riskTier=cap.risk_tier)
    if scope == "private" and (cap.mutating or cap.risk_tier in {"high", "critical"}):
        warnings.append("private_scope_high_risk_or_mutating")
    return _gate(
        "passed",
        code="risk_policy_satisfied",
        warnings=warnings,
        scope=scope,
        riskTier=cap.risk_tier,
        mutating=cap.mutating,
        approvedException=approved_exception,
    )


def _provenance_gate(
    cap: Capability,
    *,
    reviewer: str,
    built_at: str,
) -> dict[str, Any]:
    """Build the provenance promotion gate from the standalone provenance module.

    Delegates to ``capmesh.provenance.compute_provenance_status`` and renders
    the SLSA in-toto/DSSE statement via ``to_jsonl_attestation`` /
    ``attestation_digest``.  ``built_at`` is the caller-owned ISO8601 timestamp;
    this function never reads the system clock.

    ``source_commit`` is taken from ``cap.metadata["sourceCommit"]`` when present.
    When that key is absent the capability has no VCS provenance, so the gate
    falls back to the content hash as the immutable build reference
    (content-addressed provenance) and ``compute_provenance_status`` returns
    ``passed``. An explicit ``source_commit="unknown"`` (or empty) sentinel is
    honored as ``skipped`` — provenance is best-effort for capabilities whose
    source commit is genuinely unknown.  ``builder_identity`` is the reviewing
    principal, which is the identity that produced this provenance record.
    """
    explicit_commit = cap.metadata.get("sourceCommit")
    if explicit_commit:
        source_commit = str(explicit_commit)
    else:
        # No VCS commit recorded: use the content hash as the immutable source
        # reference so a content-addressed capability still yields a SLSA record.
        source_commit = cap.content_hash
    capability_view: dict[str, object] = {
        "content_hash": cap.content_hash,
        "canonical_uri": cap.uri,
    }
    result = compute_provenance_status(
        capability_view,
        source_commit=source_commit,
        builder_identity=reviewer,
        built_at=built_at,
    )
    if result.status == "passed" and result.record is not None:
        record = result.record
        return _gate(
            "passed",
            code="provenance_record_built",
            reason=result.reason,
            status=result.status,
            sourceCommit=source_commit,
            builderIdentity=record.builder_identity,
            builtAt=record.built_at,
            predicateType=record.predicate_type,
            attestation=to_jsonl_attestation(record),
            digest=attestation_digest(record),
        )
    # ``skipped`` (unknown/empty source commit) and ``failed`` (no content_hash)
    # both surface the standalone module's reason verbatim.
    return _gate(
        result.status,
        code="provenance_unverified" if result.status == "failed" else "provenance_skipped",
        reason=result.reason,
        status=result.status,
        sourceCommit=source_commit,
    )


def _evaluate(
    con: sqlite3.Connection,
    cap: Capability,
    *,
    scope: str,
    target_namespace_id: str | None,
    reviewer: str,
    persist_signature: bool,
    approved_exception: bool,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    content, integrity = _source_bytes(cap)
    gates: dict[str, dict[str, Any]] = {"sourceIntegrity": integrity}
    if content is None:
        for name in ("tests", "promptInjectionScan"):
            gates[name] = _gate("failed", code="source_integrity_prerequisite_failed")
    else:
        gates["tests"] = _metadata_gate(cap, content)
        gates["promptInjectionScan"] = _prompt_injection_gate(cap, content)
    gates["retrievalEvals"] = _retrieval_gate(con, cap)
    gates["riskTierPolicy"] = _risk_gate(cap, scope, approved_exception=approved_exception)
    attestation: dict[str, Any] | None = None
    # ``built_at`` is captured once so the signed review envelope and the SLSA
    # provenance record share a timestamp within one review run. lifecycle owns
    # the clock; capmesh.provenance never reads it.
    built_at = ""
    try:
        from .governance import utc_now

        built_at = utc_now()
        attestation = sign_attestation(
            _attestation_envelope(
                cap,
                scope=scope,
                target_namespace_id=target_namespace_id,
                reviewer=reviewer,
                timestamp=built_at,
            ),
            persist=persist_signature,
        )
        gates["signature"] = _gate("passed", code="ed25519_signature_verified", algorithm="Ed25519")
    except Exception as exc:  # noqa: BLE001
        safe_error = f"{type(exc).__name__}: {str(exc)[:240]}"
        gates["signature"] = _gate("failed", code="signature_unavailable", error=safe_error)
    # Provenance is computed independently of signing: it builds an SLSA-style
    # provenance record via capmesh.provenance rather than piggybacking on the
    # signed review envelope.
    gates["provenance"] = _provenance_gate(cap, reviewer=reviewer, built_at=built_at)
    return gates, attestation


def _all_passed(gates: dict[str, dict[str, Any]]) -> bool:
    # Provenance is best-effort for capabilities without git provenance: a
    # ``skipped`` provenance gate (unknown source commit) does not block
    # approval. Every other gate must strictly pass.
    return all(
        gates.get(name, {}).get("state") in {"passed", "skipped"} if name == "provenance"
        else gates.get(name, {}).get("state") == "passed"
        for name in REQUIRED_GATES
    )


def _authorize(con: sqlite3.Connection, principal: Principal) -> None:
    from .governance import evaluate_access

    resource = f"tenant:{principal.tenant_id or 'asg'}"
    for right in ("manage", "approve"):
        allowed, reason = evaluate_access(con, principal, right=right, resource_uri=resource, audit=False)
        if not allowed:
            raise PermissionError(reason or f"{right} right required.")


def review_capability(
    con: sqlite3.Connection,
    principal: Principal,
    payload: dict[str, Any],
    *,
    commit: bool = True,
) -> dict[str, Any]:
    _authorize(con, principal)
    identifier = str(payload.get("capabilityUri") or payload.get("uri") or "").strip()
    if not identifier:
        raise ValueError("capabilityUri is required.")
    from .governance import audit_event, new_id
    from .index import get_capability

    cap = get_capability(con, identifier)
    if cap is None or cap.tenant_id != (principal.tenant_id or "asg"):
        raise ValueError("Capability not found in the current tenant.")
    dry_run = bool(payload.get("dryRun", True))
    scope, namespace_id = _scope_for(con, cap, payload.get("targetNamespaceId"), payload.get("reviewScope"))
    gates, attestation = _evaluate(
        con,
        cap,
        scope=scope,
        target_namespace_id=namespace_id,
        reviewer=principal.subject,
        persist_signature=not dry_run,
        approved_exception=bool(payload.get("approvedRiskException", False)),
    )
    # Best-effort observability: emit one structured ``gate.eval`` log event and
    # one ``gate.<name>.<outcome>`` counter per evaluated gate. ``review_batch``
    # and ``approve_catalog`` both drive ``review_capability``, so instrumenting
    # here covers the full gate-runner surface. Observability is best-effort: a
    # logging or metric failure is swallowed and never breaks the gate runner.
    for _gate_name, _gate_result in gates.items():
        _gate_outcome = str(_gate_result.get("state", "unknown"))
        _gate_reason = str(_gate_result.get("evidence", {}).get("code", ""))
        try:
            log_event(
                _OBS_LOGGER,
                "gate.eval",
                **format_gate_decision(
                    GateDecision(
                        gate_name=_gate_name,
                        capability_uri=cap.uri,
                        outcome=_gate_outcome,
                        request_id=None,
                        reason=_gate_reason,
                    )
                ),
            )
        except Exception:  # noqa: BLE001,S110
            pass
        try:
            GATE_METRICS.increment(f"gate.{_gate_name}.{_gate_outcome}")
        except Exception:  # noqa: BLE001,S110
            pass
        # CM-13-full: record this gate evaluation as an OTel span. Best-effort;
        # a tracing failure is swallowed and never breaks the gate runner. The
        # gate span is linked to the in-flight HTTP request span (when one is
        # present on the stdlib contextvar) by passing the request context as
        # parent_context: the gate span inherits the request's trace_id and its
        # parent_span_id becomes the request span's span_id. When no request
        # context is set (e.g. a CLI ``capmesh gates`` run or a direct unit-test
        # call) _parent_ctx is None and the gate span is a root span, preserving
        # the prior behavior.
        try:
            _parent_ctx = get_request_context()
            _span = TRACER.start_span(
                f"gate.{_gate_name}",
                start_time_ns=int(_gate_result.get("startedAtNs", 0)) or 0,
                parent_context=_parent_ctx,
            )
            _span.set_attribute("gate.name", _gate_name)
            _span.set_attribute("gate.outcome", _gate_outcome)
            _span.set_attribute("capability.uri", cap.uri)
            if _gate_reason:
                _span.set_attribute("gate.reason", _gate_reason)
            _span.set_status(
                "ok" if _gate_outcome == "passed" else ("error" if _gate_outcome == "failed" else "unset"),
                _gate_reason,
            )
            _span.end(int(_gate_result.get("endedAtNs", 0)) or 0)
        except Exception:  # noqa: BLE001,S110
            pass
    passed = _all_passed(gates)
    result: dict[str, Any] = {
        "capabilityUri": cap.uri,
        "contentHash": cap.content_hash,
        "reviewScope": scope,
        "dryRun": dry_run,
        "passed": passed,
        "gates": gates,
    }
    if dry_run or not passed:
        return result
    reviewed_at = str(attestation["envelope"]["timestamp"])
    existing = con.execute(
        """SELECT id FROM capability_reviews
           WHERE tenant_id = ? AND capability_uri = ? AND content_hash = ? AND review_scope = ?""",
        (cap.tenant_id, cap.uri, cap.content_hash, scope),
    ).fetchone()
    con.execute(
        """INSERT INTO capability_reviews(
               id, tenant_id, capability_uri, content_hash, review_scope, gate_state,
               evidence_json, reviewer, reviewed_at, attestation_json
           ) VALUES (?, ?, ?, ?, ?, 'passed', ?, ?, ?, ?)
           ON CONFLICT(tenant_id, capability_uri, content_hash, review_scope) DO NOTHING""",
        (
            new_id("crv"),
            cap.tenant_id,
            cap.uri,
            cap.content_hash,
            scope,
            _bounded_evidence(gates),
            principal.subject,
            reviewed_at,
            _json(attestation),
        ),
    )
    con.execute(
        """UPDATE capabilities
           SET approval_state = 'approved', lifecycle = 'published',
               signature_status = 'verified', provenance_status = 'verified',
               risk_review_status = 'approved', updated_at = CURRENT_TIMESTAMP
           WHERE uri = ? AND content_hash = ?""",
        (cap.uri, cap.content_hash),
    )
    audit_event(
        con,
        tenant_id=cap.tenant_id,
        event_type="capability.review.approved",
        actor=principal.subject,
        target=cap.uri,
        action="review",
        decision="allow",
        payload={
            "contentHash": cap.content_hash,
            "reviewScope": scope,
            "idempotent": existing is not None,
            "approvedRiskException": bool(payload.get("approvedRiskException", False)),
        },
    )
    if commit:
        con.commit()
    result.update({"approved": True, "idempotent": existing is not None})
    return result


def review_batch(
    con: sqlite3.Connection,
    principal: Principal,
    payload: dict[str, Any],
    *,
    commit: bool = True,
) -> dict[str, Any]:
    _authorize(con, principal)
    try:
        limit = int(payload.get("limit", 100))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer between 1 and 500.") from exc
    if limit < 1 or limit > MAX_BATCH:
        raise ValueError("limit must be between 1 and 500.")
    after_uri = str(payload.get("afterUri") or "")
    dry_run = bool(payload.get("dryRun", True))
    include_approved = bool(payload.get("includeApproved", False))
    # Releasing SQLite's outermost SAVEPOINT commits it.  Establish a real
    # transaction first so commit=False remains genuinely caller-controlled.
    if not dry_run and not con.in_transaction:
        con.execute("BEGIN IMMEDIATE")
    if include_approved:
        rows = con.execute(
            """SELECT uri FROM capabilities
               WHERE tenant_id = ? AND source_kind != 'system_capability'
                 AND approval_state IN ('approved', 'draft', 'pending') AND uri > ?
                 AND (approval_state != 'approved' OR signature_status != 'verified'
                      OR provenance_status != 'verified' OR risk_review_status != 'approved')
               ORDER BY uri LIMIT ?""",
            (principal.tenant_id or "asg", after_uri, limit + 1),
        ).fetchall()
    else:
        rows = con.execute(
            """SELECT uri FROM capabilities
               WHERE tenant_id = ? AND source_kind != 'system_capability'
                 AND approval_state IN ('draft', 'pending') AND uri > ?
               ORDER BY uri LIMIT ?""",
            (principal.tenant_id or "asg", after_uri, limit + 1),
        ).fetchall()
    page = rows[:limit]
    items: list[dict[str, Any]] = []
    for index, row in enumerate(page):
        savepoint = f"capmesh_review_{index}"
        if not dry_run:
            con.execute(f"SAVEPOINT {savepoint}")
        try:
            item_payload = {
                **payload,
                "capabilityUri": row["uri"],
                "dryRun": dry_run,
            }
            item = review_capability(con, principal, item_payload, commit=False)
            items.append(item)
            if not dry_run:
                con.execute(f"RELEASE SAVEPOINT {savepoint}")
        except Exception as exc:  # noqa: BLE001
            if not dry_run:
                con.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                con.execute(f"RELEASE SAVEPOINT {savepoint}")
            items.append({"capabilityUri": row["uri"], "passed": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
    if not dry_run and commit:
        con.commit()
    return {
        "dryRun": dry_run,
        "includeApproved": include_approved,
        "limit": limit,
        "items": items,
        "processed": len(items),
        "passed": sum(1 for item in items if item.get("passed")),
        "approved": sum(1 for item in items if item.get("approved")),
        "failed": sum(1 for item in items if not item.get("passed")),
        "nextAfterUri": page[-1]["uri"] if len(rows) > limit and page else None,
    }


def approve_catalog(
    con: sqlite3.Connection,
    principal: Principal,
    *,
    commit: bool = True,
) -> dict[str, Any]:
    """Approve every passing non-system capability as one transaction.

    A failed gate leaves the caller's transaction uncommitted.  Standalone
    callers are rolled back so a catalog can never be partially activated.
    """

    _authorize(con, principal)
    after_uri = ""
    totals = {"processed": 0, "passed": 0, "approved": 0, "failed": 0}
    failures: list[dict[str, Any]] = []
    while True:
        page = review_batch(
            con,
            principal,
            {
                "dryRun": False,
                "includeApproved": True,
                "afterUri": after_uri,
                "limit": MAX_BATCH,
            },
            commit=False,
        )
        for key in totals:
            totals[key] += int(page[key])
        failures.extend(item for item in page["items"] if not item.get("passed"))
        cursor = page.get("nextAfterUri")
        if not cursor:
            break
        after_uri = str(cursor)

    remaining_query = """SELECT COUNT(*) FROM capabilities
           WHERE tenant_id = ? AND source_kind != 'system_capability'
             AND (approval_state != 'approved' OR lifecycle != 'published'
                  OR signature_status != 'verified' OR provenance_status != 'verified'
                  OR risk_review_status != 'approved')"""
    remaining = int(con.execute(remaining_query, (principal.tenant_id or "asg",)).fetchone()[0])
    catalog_approved = totals["failed"] == 0 and remaining == 0
    if commit:
        if catalog_approved:
            con.commit()
        else:
            con.rollback()
            remaining = int(con.execute(remaining_query, (principal.tenant_id or "asg",)).fetchone()[0])
    return {
        **totals,
        "remainingNonCompliant": remaining,
        "catalogApproved": catalog_approved,
        "failures": failures[:100],
        "failuresTruncated": len(failures) > 100,
    }


def run_promotion_gates(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    _authorize(con, principal)
    request_id = str(payload.get("requestId") or payload.get("id") or "").strip()
    if not request_id:
        raise ValueError("requestId is required.")
    from .governance import audit_event, new_id
    from .index import get_capability

    row = con.execute(
        "SELECT * FROM promotion_requests WHERE id = ? AND tenant_id = ?",
        (request_id, principal.tenant_id or "asg"),
    ).fetchone()
    if row is None:
        raise ValueError("Promotion request not found.")
    if row["state"] != "pending":
        raise ValueError("Only pending promotion requests can run gates.")
    cap = get_capability(con, str(row["capability_uri"]))
    if cap is None:
        raise ValueError("Promotion source capability not found.")
    scope, namespace_id = _scope_for(con, cap, str(row["target_namespace_id"] or "") or None, None)
    gates, attestation = _evaluate(
        con,
        cap,
        scope=scope,
        target_namespace_id=namespace_id,
        reviewer=principal.subject,
        persist_signature=True,
        approved_exception=bool(payload.get("approvedRiskException", False)),
    )
    gate_states = {name: gate["state"] for name, gate in gates.items()}
    # CM-13 observability: emit one gate.eval event + gate.<name>.<outcome> metric
    # per evaluated gate, best-effort (never breaks the gate runner). Unlike
    # review_capability (which hardcodes request_id=None), run_promotion_gates
    # has a real request_id, so it flows into GateDecision for end-to-end
    # request correlation across the gate-eval log lines.
    for _gate_name, _gate_result in gates.items():
        _gate_outcome = str(_gate_result.get("state", "unknown"))
        _gate_reason = str(_gate_result.get("evidence", {}).get("code", ""))
        try:
            log_event(
                _OBS_LOGGER,
                "gate.eval",
                **format_gate_decision(
                    GateDecision(
                        gate_name=_gate_name,
                        capability_uri=cap.uri,
                        outcome=_gate_outcome,
                        request_id=request_id,
                        reason=_gate_reason,
                    )
                ),
            )
        except Exception:  # noqa: BLE001,S110
            pass
        try:
            GATE_METRICS.increment(f"gate.{_gate_name}.{_gate_outcome}")
        except Exception:  # noqa: BLE001,S110
            pass
    run_at = str(attestation["envelope"]["timestamp"]) if attestation else ""
    for name, gate in gates.items():
        con.execute(
            """INSERT INTO promotion_gate_runs(
                   id, request_id, gate_name, content_hash, state, evidence_json,
                   runner, run_at, attestation_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(request_id, gate_name, content_hash) DO UPDATE SET
                   state = excluded.state, evidence_json = excluded.evidence_json,
                   runner = excluded.runner, run_at = excluded.run_at,
                   attestation_json = excluded.attestation_json""",
            (
                new_id("pgr"),
                request_id,
                name,
                cap.content_hash,
                gate["state"],
                _bounded_evidence(gate["evidence"]),
                principal.subject,
                run_at,
                _json(attestation or {}),
            ),
        )
    con.execute("UPDATE promotion_requests SET gates_json = ? WHERE id = ?", (_json(gate_states), request_id))
    passed = _all_passed(gates)
    if passed:
        con.execute(
            """UPDATE capabilities SET signature_status = 'verified', provenance_status = 'verified',
               risk_review_status = 'approved', updated_at = CURRENT_TIMESTAMP
               WHERE uri = ? AND content_hash = ?""",
            (cap.uri, cap.content_hash),
        )
    audit_event(
        con,
        tenant_id=cap.tenant_id,
        event_type="promotion.gates.completed",
        actor=principal.subject,
        target=request_id,
        action="promotion.run",
        decision="allow" if passed else "deny",
        payload={
            "capabilityUri": cap.uri,
            "contentHash": cap.content_hash,
            "gates": gate_states,
            "approvedRiskException": bool(payload.get("approvedRiskException", False)),
        },
    )
    con.commit()
    return {
        "requestId": request_id,
        "capabilityUri": cap.uri,
        "contentHash": cap.content_hash,
        "reviewScope": scope,
        "passed": passed,
        "gates": gates,
    }


def gate_status(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    _authorize(con, principal)
    uri = str(payload.get("capabilityUri") or payload.get("uri") or "").strip()
    request_id = str(payload.get("requestId") or "").strip()
    result: dict[str, Any] = {}
    try:
        trusted_key = trusted_signing_key_id()
    except Exception:  # noqa: BLE001
        trusted_key = None
    if uri:
        current = con.execute("SELECT content_hash FROM capabilities WHERE tenant_id = ? AND uri = ?", (principal.tenant_id or "asg", uri)).fetchone()
        rows = con.execute(
            """SELECT * FROM capability_reviews WHERE tenant_id = ? AND capability_uri = ?
               ORDER BY reviewed_at DESC LIMIT 20""",
            (principal.tenant_id or "asg", uri),
        ).fetchall()
        result["capabilityUri"] = uri
        result["reviews"] = [
            {
                "contentHash": row["content_hash"],
                "reviewScope": row["review_scope"],
                "state": row["gate_state"],
                "reviewer": row["reviewer"],
                "reviewedAt": row["reviewed_at"],
                "evidence": json.loads(row["evidence_json"]),
                "attestationVerified": bool(trusted_key) and verify_attestation(
                    json.loads(row["attestation_json"]), trusted_key_id=trusted_key
                ),
                "stale": current is None or row["content_hash"] != current["content_hash"],
            }
            for row in rows
        ]
    if request_id:
        rows = con.execute(
            """SELECT * FROM promotion_gate_runs WHERE request_id = ? ORDER BY run_at DESC, gate_name LIMIT 100""",
            (request_id,),
        ).fetchall()
        result["requestId"] = request_id
        result["promotionGates"] = [
            {
                "gate": row["gate_name"],
                "contentHash": row["content_hash"],
                "state": row["state"],
                "runner": row["runner"],
                "runAt": row["run_at"],
                "evidence": json.loads(row["evidence_json"]),
                "attestationVerified": bool(trusted_key) and verify_attestation(
                    json.loads(row["attestation_json"]), trusted_key_id=trusted_key
                ),
            }
            for row in rows
        ]
    if not uri and not request_id:
        counts = con.execute(
            """SELECT approval_state, COUNT(*) AS count FROM capabilities
               WHERE tenant_id = ? GROUP BY approval_state ORDER BY approval_state""",
            (principal.tenant_id or "asg",),
        ).fetchall()
        result["counts"] = {row["approval_state"]: row["count"] for row in counts}
    return result


def verify_catalog(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dry-run every non-system capability against the current gate policy."""
    _authorize(con, principal)
    options = payload or {}
    try:
        maximum = int(options.get("maxCapabilities", 10_000))
    except (TypeError, ValueError) as exc:
        raise ValueError("maxCapabilities must be an integer between 1 and 10000.") from exc
    if maximum < 1 or maximum > 10_000:
        raise ValueError("maxCapabilities must be between 1 and 10000.")
    rows = con.execute(
        """SELECT uri FROM capabilities
           WHERE tenant_id = ? AND source_kind != 'system_capability'
           ORDER BY uri LIMIT ?""",
        (principal.tenant_id or "asg", maximum + 1),
    ).fetchall()
    if len(rows) > maximum:
        raise ValueError(f"Catalog contains more than maxCapabilities={maximum}; increase the explicit bound.")
    failures: list[dict[str, Any]] = []
    warning_count = 0
    for row in rows:
        result = review_capability(
            con,
            principal,
            {"capabilityUri": row["uri"], "dryRun": True},
            commit=False,
        )
        warning_count += sum(len(gate.get("evidence", {}).get("warnings", ())) for gate in result["gates"].values())
        if not result["passed"]:
            failures.append(
                {
                    "capabilityUri": result["capabilityUri"],
                    "failedGates": sorted(name for name, gate in result["gates"].items() if gate.get("state") != "passed"),
                }
            )
    return {
        "dryRun": True,
        "processed": len(rows),
        "passed": len(rows) - len(failures),
        "failed": len(failures),
        "warnings": warning_count,
        "catalogPassed": not failures,
        "failures": failures[:100],
        "failuresTruncated": len(failures) > 100,
    }


def dispatch_gate_action(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "status").strip().lower()
    if action == "review":
        return review_capability(con, principal, payload)
    if action == "review-batch":
        return review_batch(con, principal, payload)
    if action == "promotion.run":
        return run_promotion_gates(con, principal, payload)
    if action == "status":
        return gate_status(con, principal, payload)
    if action == "verify-catalog":
        return verify_catalog(con, principal, payload)
    raise ValueError("system.gates action must be review, review-batch, promotion.run, status, or verify-catalog.")
