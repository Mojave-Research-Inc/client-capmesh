from __future__ import annotations

import json
import sqlite3
from typing import Any

from .access_control import evaluate_access
from .models import Principal
from .prompt_injection import evaluate_prompt_injection_scan
from .risk_policy import default_promotion_gates, evaluate_risk_tier_policy
from .utils import DEFAULT_TENANT, _production_environment, json_dumps, json_loads, new_id


def submit_promotion(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    capability_uri = str(payload.get("capabilityUri") or payload.get("uri") or "")
    target_namespace_id = str(payload.get("targetNamespaceId") or "")
    if not capability_uri or not target_namespace_id:
        raise ValueError("capabilityUri and targetNamespaceId are required.")
    capability = None
    capability_row = con.execute(
        "SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?",
        (capability_uri, tenant_id),
    ).fetchone()
    if capability_row is None:
        raise ValueError("Capability was not found in this tenant.")
    from .index import capability_from_row

    capability = capability_from_row(capability_row)
    allowed, reason = evaluate_access(con, principal, right="submit", capability=capability, resource_uri=capability_uri)
    if not allowed:
        raise PermissionError(reason)
    target = con.execute(
        """
        SELECT n.id, n.lifecycle, s.kind, s.disabled_at
        FROM namespaces AS n
        JOIN stores AS s ON s.id = n.store_id AND s.tenant_id = n.tenant_id
        WHERE n.id = ? AND n.tenant_id = ?
        """,
        (target_namespace_id, tenant_id),
    ).fetchone()
    if target is None:
        raise ValueError("Promotion target namespace was not found in this tenant.")
    if target["kind"] not in {"org", "all_users"}:
        raise ValueError("Promotion targets must be an organization or everyone namespace.")
    if target["lifecycle"] != "active" or target["disabled_at"] is not None:
        raise ValueError("Promotion target namespace is not active.")
    if target["kind"] == "org":
        org = con.execute(
            """
            SELECT o.status
            FROM organizations AS o
            JOIN namespaces AS n ON n.store_id = o.store_id AND n.tenant_id = o.tenant_id
            WHERE n.id = ? AND o.tenant_id = ?
            """,
            (target_namespace_id, tenant_id),
        ).fetchone()
        if org is None or org["status"] != "active":
            raise ValueError("Promotion target organization is not active.")
    request_id = new_id("prq")
    # Submitters never author their own gate state. Gate results are written only
    # by the trusted gate runner and are re-checked by approval.
    gates = default_promotion_gates()
    # Determine the vault target for the riskTierPolicy gate population.
    store_row = con.execute(
        "SELECT kind FROM stores WHERE id = (SELECT store_id FROM namespaces WHERE id = ?)",
        (target_namespace_id,),
    ).fetchone()
    target_vault = str(store_row["kind"]) if store_row is not None else "unknown"
    if target_vault == "all_users":
        gates["riskTierPolicy"] = "pending"
        # Population of the actual pass/fail is done by the gate runner at
        # approve time via evaluate_risk_tier_policy.
    con.execute(
        """
        INSERT INTO promotion_requests(id, tenant_id, capability_uri, source_store_id, target_namespace_id, requested_by, state, title, rationale, version, gates_json)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        """,
        (
            request_id,
            tenant_id,
            capability_uri,
            capability.store_id,
            target_namespace_id,
            principal.subject,
            str(payload.get("title") or ""),
            str(payload.get("rationale") or ""),
            str(payload.get("version") or ""),
            json_dumps(gates),
        ),
    )
    con.execute(
        """
        INSERT INTO approval_steps(id, request_id, step_name, assigned_to_type, assigned_to_id)
        VALUES (?, ?, 'namespace_admin_review', 'role', 'namespace_admin')
        """,
        (new_id("apv"), request_id),
    )
    con.execute("UPDATE capabilities SET submitted_by = ?, approval_state = 'pending' WHERE uri = ?", (principal.subject, capability_uri))
    from .index import refresh_catalog_generation

    refresh_catalog_generation(con)
    audit_event(con, event_type="promotion.submitted", actor=principal.subject, target=capability_uri, action="submit", decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return promotion_record(con.execute("SELECT * FROM promotion_requests WHERE id = ?", (request_id,)).fetchone())


def list_requests(con: sqlite3.Connection, principal: Principal, state: str | None = None) -> list[dict[str, Any]]:
    params: list[Any] = [principal.tenant_id]
    where = ["tenant_id = ?"]
    if state:
        where.append("state = ?")
        params.append(state)
    rows = con.execute(f"SELECT * FROM promotion_requests WHERE {' AND '.join(where)} ORDER BY created_at DESC", params).fetchall()
    return [promotion_record(row) for row in rows]


def approve_request(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    from .governance import audit_event

    tenant_id = principal.tenant_id or DEFAULT_TENANT
    request_id = str(payload.get("requestId") or payload.get("id") or "")
    decision = str(payload.get("decision") or "approve")
    if decision not in {"approve", "reject", "recall", "demote", "yank"}:
        raise ValueError("Unsupported approval decision.")
    allowed, reason = evaluate_access(con, principal, right="approve", resource_uri=f"promotion:{request_id}")
    if not allowed:
        raise PermissionError(reason)
    row = con.execute("SELECT * FROM promotion_requests WHERE id = ? AND tenant_id = ?", (request_id, tenant_id)).fetchone()
    if row is None:
        raise ValueError("Promotion request not found.")
    new_state = {
        "approve": "approved",
        "reject": "rejected",
        "recall": "recalled",
        "demote": "demoted",
        "yank": "yanked",
    }[decision]
    # Enforce promotion gates BEFORE any mutation. Approving over pending gates
    # (signature, provenance, promptInjectionScan, riskTierPolicy, ...) requires
    # an explicit, audited override — it is no longer a silent warning (F-13).
    # Computed up front so a refusal raises with zero partial writes.
    gate_override_marker: str | None = None
    gate_states: dict[str, str] = {}
    gates: dict[str, str] = {}
    promoted_uri = str(row["capability_uri"])
    if decision == "approve":
        gate_row = con.execute("SELECT gates_json FROM promotion_requests WHERE id = ?", (request_id,)).fetchone()
        pending_gates: list[str] = []
        if gate_row is not None and gate_row["gates_json"]:
            try:
                gates = json.loads(gate_row["gates_json"])
                if isinstance(gates, dict):
                    gate_states = {str(name): str(state) for name, state in gates.items()}
                    pending_gates = [name for name, state in gates.items() if state != "passed"]
                elif isinstance(gates, list):
                    gate_states = {
                        str(item.get("name") or ""): str(item.get("state") or "")
                        for item in gates
                        if isinstance(item, dict) and item.get("name")
                    }
                    pending_gates = [g.get("name", "") for g in gates if g.get("state") != "passed"]
            except (json.JSONDecodeError, TypeError, KeyError):
                # Malformed gate data is treated as a pending gate, not skipped.
                pending_gates = ["__malformed_gates_json__"]
        # WAVE5-WIRING-c: run the full lifecycle gate set so every promotion
        # evaluates sourceIntegrity, tests, retrievalEvals, signature,
        # provenance, promptInjectionScan and riskTierPolicy -- not just the
        # two ad-hoc re-evaluations below. The gate runner is the authoritative
        # source for the per-gate states written to gates_json, so its results
        # replace the stale "pending" states recorded at submit time.
        #
        # The ad-hoc riskTierPolicy/promptInjectionScan evaluations below are
        # retained for backward compatibility: they raise with specific gate
        # names/messages that existing tests and audit messages assert, and
        # they are scope-aware in a way the gate runner is not (the ad-hoc
        # promptInjectionScan is ``skipped`` for private targets, while the
        # gate runner scans every target). So the ad-hoc value wins for those
        # two gates; the gate runner authoritatively supplies the remaining
        # gates (sourceIntegrity, tests, retrievalEvals, signature, provenance)
        # the ad-hoc path never evaluated, and a failed one of those blocks at
        # the explicit gate-runner failure check after the ad-hoc raises.
        #
        # Lazy import mirrors the auto-approval path (line ~4168) to avoid the
        # governance<->lifecycle import cycle. dryRun=True so the gate runner
        # does NOT commit, persist a signing key, or write capability_reviews
        # -- approve_request owns the final transaction.
        gate_runner_failed: list[str] = []
        # ``_ADHOC_OWNED_GATES`` are evaluated ad-hoc below; their authoritative
        # enforcement (and the specific raise message) belongs to the ad-hoc
        # path, so a gate-runner failure on those is not separately enforced
        # here (the ad-hoc raise fires first with its own message).
        _adhoc_owned = {"riskTierPolicy", "promptInjectionScan"}
        try:
            from .lifecycle import review_capability as _review_capability

            gate_runner_result = _review_capability(
                con,
                principal,
                {
                    "capabilityUri": row["capability_uri"],
                    "targetNamespaceId": row["target_namespace_id"],
                    "dryRun": True,
                    "approvedRiskException": bool(payload.get("approvedRiskException", False)),
                },
            )
            runner_gates = gate_runner_result.get("gates") or {}
            for name in default_promotion_gates():
                gate_entry = runner_gates.get(name)
                if not isinstance(gate_entry, dict) or "state" not in gate_entry:
                    continue
                gates[name] = str(gate_entry["state"])
            # Recompute the pending view from the authoritative merged gates so
            # the F-13 check below is not fooled by stale "pending" states
            # recorded at submit time. ``failed`` is NOT pending here -- a
            # gate-runner failure is enforced by the explicit gate-runner
            # failure check after the ad-hoc raises, and the ad-hoc-owned gates
            # are enforced by the ad-hoc raises. ``skipped`` is allowed for
            # provenance (best-effort for capabilities without git provenance).
            gate_states = {str(name): str(state) for name, state in gates.items()}
            pending_gates = [
                name
                for name, state in gates.items()
                if state not in {"passed", "skipped", "failed"}
            ]
            gate_runner_failed = [
                name
                for name, state in gates.items()
                if name not in _adhoc_owned and state not in {"passed", "skipped"}
            ]
            # Persist the authoritative per-gate states now so the evaluated
            # values are recorded even when a refusal follows (mirrors
            # run_promotion_gates, which writes gates_json before the pass
            # check). The request state itself is only mutated at the end, so
            # this is not a partial promotion write.
            con.execute(
                "UPDATE promotion_requests SET gates_json = ? WHERE id = ?",
                (json_dumps(gates), request_id),
            )
        except (ValueError, PermissionError):
            # The gate runner could not evaluate (e.g. the source capability
            # is missing, or the principal lacks the manage right the gate
            # runner authorizes with). Fall back to the stored/ad-hoc gates so
            # a synthetic/legacy request still flows -- the ad-hoc
            # riskTierPolicy/promptInjectionScan raises below remain the
            # enforcement, and the F-13 pending-gate check still applies.
            gate_runner_failed = []
        if pending_gates and not bool(payload.get("overridePendingGates")):
            raise PermissionError(
                "Promotion gates still pending: "
                + ", ".join(pending_gates)
                + ". Re-approve with overridePendingGates=true to force."
            )
        if pending_gates and _production_environment():
            raise PermissionError(
                "Production promotion is fail-closed: pending security/provenance gates cannot be overridden."
            )
        if _production_environment():
            required_gates = set(default_promotion_gates())
            unmet = sorted(name for name in required_gates if gate_states.get(name) != "passed")
            if unmet:
                raise PermissionError(
                    "Production promotion requires authoritative passed gates: " + ", ".join(unmet)
                )
            security = con.execute(
                "SELECT signature_status, provenance_status, risk_review_status FROM capabilities WHERE uri = ?",
                (row["capability_uri"],),
            ).fetchone()
            if (
                security is None
                or security["signature_status"] != "verified"
                or security["provenance_status"] != "verified"
                or security["risk_review_status"] != "approved"
            ):
                raise PermissionError(
                    "Production promotion requires a verified content signature, verified provenance, and approved risk review."
                )
        # Evaluate riskTierPolicy gate for all-user namespace promotions.
        risk_tier_gate_ok: bool | None = None
        risk_tier_gate_reason: str = ""
        promo_ns_row = con.execute(
            "SELECT n.id, n.store_id FROM namespaces n WHERE n.id = ?",
            (row["target_namespace_id"],),
        ).fetchone()
        if promo_ns_row is not None:
            cap_row = con.execute(
                "SELECT risk_tier FROM capabilities WHERE uri = ?",
                (row["capability_uri"],),
            ).fetchone()
            store_kind_row = con.execute(
                "SELECT kind FROM stores WHERE id = ?",
                (promo_ns_row["store_id"],),
            ).fetchone()
            if cap_row is not None and store_kind_row is not None:
                risk_tier_val = str(cap_row["risk_tier"] or "unknown")
                vault_val = str(store_kind_row["kind"] or "unknown")
                risk_tier_gate_ok, risk_tier_gate_reason = evaluate_risk_tier_policy(risk_tier_val, vault_val, "")
                # Record the gate result in the request so downstream audit captures it.
                gates["riskTierPolicy"] = "passed" if risk_tier_gate_ok else "failed"
        # If riskTierPolicy gate failed, refuse the approval unless overridden.
        if risk_tier_gate_ok is False and not bool(payload.get("overridePendingGates")):
            raise PermissionError(
                    f"riskTierPolicy gate failed: {risk_tier_gate_reason}. "
                    "Request state remains pending — use overridePendingGates=true to force."
                )
        # CM-04: evaluate the promptInjectionScan gate for everyone/org promotion
        # targets. Real injection indicators block the promotion; benign
        # authoring phrases are downgraded to info/allowed by the allowlist so
        # legitimate agent/skill definitions are not blocked as false positives.
        injection_gate_state, injection_gate_reason = evaluate_prompt_injection_scan(
            con, row["capability_uri"], row["target_namespace_id"]
        )
        gates["promptInjectionScan"] = injection_gate_state
        if injection_gate_state == "failed" and not bool(payload.get("overridePendingGates")):
            raise PermissionError(
                f"promptInjectionScan gate failed: {injection_gate_reason}. "
                "Request state remains pending — use overridePendingGates=true to force."
            )
        # WAVE5-WIRING-c: enforce gate-runner failures for the gates the ad-hoc
        # path does not evaluate (sourceIntegrity, tests, retrievalEvals,
        # signature, provenance). riskTierPolicy/promptInjectionScan are already
        # enforced above with their own specific raise messages. Provenance may
        # be ``skipped`` (best-effort for capabilities without git provenance).
        if gate_runner_failed and not bool(payload.get("overridePendingGates")):
            failed_names = ", ".join(gate_runner_failed)
            raise PermissionError(
                f"Promotion gate(s) failed: {failed_names}. "
                "Request state remains pending — use overridePendingGates=true to force."
            )
        if pending_gates:
            gate_override_marker = f"[OVERRIDE: approved with pending gates: {', '.join(pending_gates)}]"
            note = payload.get("note") or ""
            payload["note"] = f"{note} {gate_override_marker}" if note else gate_override_marker
        promo_ns = con.execute(
            "SELECT store_id, uri_prefix FROM namespaces WHERE id = ?", (row["target_namespace_id"],)
        ).fetchone()
        promo_cap = con.execute(
            "SELECT store_id, type, name, version, plugin FROM capabilities WHERE uri = ?",
            (row["capability_uri"],),
        ).fetchone()
        if promo_ns is None or promo_cap is None:
            if _production_environment():
                raise ValueError("Promotion source capability or target namespace is missing.")
            promoted_uri = str(row["capability_uri"])
        else:
            # The promoted address MUST carry the plugin qualifier, matching how
            # ingest composes every other URI (manifest.capability_uri ->
            # "{plugin}.{name}@{version}"). 701 of the 794 org rows already have it.
            #
            # Omitting it silently collapses distinct capabilities onto one address:
            # measured on this catalog, promoting the 2655 private rows without the
            # qualifier produced 449 collision groups / 591 rows that the clash guard
            # below would reject, and landed the survivors at addresses no client
            # could resolve. Two live examples that differ ONLY by plugin:
            #   anthropic-code-agent-sdk-dev.agent-sdk-verifier-py
            #   anthropic-official-agent-sdk-dev.agent-sdk-verifier-py
            # With the qualifier restored: 0 collisions.
            #
            # slugify matches manifest.capability_uri exactly so promotion and ingest
            # can never diverge again; "global" is the same sentinel ingest uses for
            # an unowned capability.
            from .manifest import slugify as _slugify

            _plug = _slugify(promo_cap["plugin"] or "global")
            _name = _slugify(str(promo_cap["name"]))
            promoted_uri = (
                f"{str(promo_ns['uri_prefix']).rstrip('/')}/"
                f"{promo_cap['type']}/{_plug}.{_name}@{promo_cap['version']}"
            )
        target_store_id = promo_ns["store_id"] if promo_ns is not None else (
            promo_cap["store_id"] if promo_cap is not None else None
        )
        if promoted_uri != row["capability_uri"]:
            clash = con.execute(
                "SELECT uri FROM capabilities WHERE uri = ?", (promoted_uri,)
            ).fetchone()
            if clash is not None:
                raise ValueError(f"Promotion target URI already exists: {promoted_uri}")
    # WAVE5-WIRING-c: re-persist gates_json with the ad-hoc riskTierPolicy/
    # promptInjectionScan values now merged in (the early gate-runner write
    # captured the other five gates). This is part of the final committed
    # mutation, so a refusal above leaves the request state untouched (the
    # early gate-runner gates_json write is the only pre-mutation write and
    # mirrors run_promotion_gates, which also writes gates_json before the
    # pass check).
    if decision == "approve" and gates:
        con.execute(
            "UPDATE promotion_requests SET gates_json = ? WHERE id = ?",
            (json_dumps(gates), request_id),
        )
    con.execute("UPDATE promotion_requests SET state = ?, decided_at = CURRENT_TIMESTAMP WHERE id = ?", (new_state, request_id))
    con.execute(
        """
        UPDATE approval_steps
        SET state = ?, decision_by = ?, decision_note = ?, decided_at = CURRENT_TIMESTAMP
        WHERE request_id = ? AND state = 'pending'
        """,
        (new_state, principal.subject, str(payload.get("note") or ""), request_id),
    )
    if decision == "approve":
        if gate_override_marker is not None:
            audit_event(
                con,
                event_type="promotion.gate_override",
                actor=principal.subject,
                target=row["capability_uri"],
                action="override",
                decision="allow",
                payload={"requestId": request_id, "note": gate_override_marker},
                tenant_id=tenant_id,
            )
        con.execute(
            """
            UPDATE capabilities
            SET approval_state = 'approved',
                -- An approved promotion must also leave draft lifecycle behind. Previously
                -- approval_state flipped to 'approved' while lifecycle stayed 'draft', so a
                -- promoted capability was permanently counted noncompliant by
                -- ops/sync-nonvoting-member.sh (which requires approved/published/verified/
                -- verified/approved) and the non-voting replica sync aborted. Scoped with CASE
                -- so an explicitly retired/recalled/yanked row is never silently republished.
                lifecycle = CASE WHEN lifecycle IN ('draft', 'published') THEN 'published' ELSE lifecycle END,
                store_id = ?,
                namespace_id = ?,
                promoted_from_uri = COALESCE(promoted_from_uri, uri),
                signature_status = CASE WHEN signature_status = 'unchecked' THEN 'pending' ELSE signature_status END,
                provenance_status = CASE WHEN provenance_status = 'unchecked' THEN 'pending' ELSE provenance_status END,
                risk_review_status = CASE WHEN risk_review_status = 'pending' THEN 'approved' ELSE risk_review_status END
            WHERE uri = ?
            """,
            (
                target_store_id,
                row["target_namespace_id"],
                row["capability_uri"],
            ),
        )
        # F-14: promotion must ALSO re-mint the capability URI into the target namespace.
        # Previously only namespace_id was updated, leaving the row addressable at its old
        # (private) URI. Result: "half-promoted" capabilities — namespace flipped, URI stale,
        # so the capability never resolves at its org address. Mirrors the canonical
        # composition used at create/ingest: {namespace.uri_prefix}/{type}/{name}@{version}.
        if promoted_uri != row["capability_uri"]:
            # capability_sources.uri carries a FK -> capabilities.uri with
            # on_update = NO ACTION, so defer enforcement until every dependent
            # record has moved. Any failure aborts the whole promotion.
            con.execute("PRAGMA defer_foreign_keys = ON")
            con.execute(
                "UPDATE capabilities SET uri = ? WHERE uri = ?",
                (promoted_uri, row["capability_uri"]),
            )
            con.execute(
                "UPDATE capability_sources SET uri = ? WHERE uri = ?",
                (promoted_uri, row["capability_uri"]),
            )
            con.execute(
                "UPDATE capability_fts SET uri = ? WHERE rowid = (SELECT id FROM capabilities WHERE uri = ?)",
                (promoted_uri, promoted_uri),
            )
            con.execute(
                "UPDATE promotion_requests SET capability_uri = ? WHERE id = ?",
                (promoted_uri, request_id),
            )
            con.execute(
                "UPDATE relationship_tuples SET object = ? WHERE tenant_id = ? AND object = ?",
                (promoted_uri, tenant_id, row["capability_uri"]),
            )
            con.execute(
                "UPDATE shares SET capability_uri = ? WHERE capability_uri = ?",
                (promoted_uri, row["capability_uri"]),
            )
    elif decision in {"reject", "recall", "demote", "yank"}:
        con.execute("UPDATE capabilities SET approval_state = ? WHERE uri = ?", (new_state, row["capability_uri"]))
    from .index import refresh_catalog_generation

    refresh_catalog_generation(con)
    audit_target = promoted_uri if decision == "approve" else row["capability_uri"]
    audit_event(con, event_type=f"promotion.{new_state}", actor=principal.subject, target=audit_target, action=decision, decision="allow", payload=payload, tenant_id=tenant_id)
    con.commit()
    return promotion_record(con.execute("SELECT * FROM promotion_requests WHERE id = ?", (request_id,)).fetchone())


def promotion_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "tenantId": row["tenant_id"],
        "capabilityUri": row["capability_uri"],
        "sourceStoreId": row["source_store_id"],
        "targetNamespaceId": row["target_namespace_id"],
        "requestedBy": row["requested_by"],
        "state": row["state"],
        "title": row["title"],
        "rationale": row["rationale"],
        "version": row["version"],
        "gates": json_loads(row["gates_json"], {}),
        "createdAt": row["created_at"],
        "decidedAt": row["decided_at"],
    }

