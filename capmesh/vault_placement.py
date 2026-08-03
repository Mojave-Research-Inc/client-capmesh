"""Vault-placement subsystem (CM-12 slice of ``governance.py``).

This module holds the self-contained vault-placement helpers extracted from
``capmesh.governance`` as part of the governance.py decomposition (plan item
CM-12). The public surface of ``governance.py`` is unchanged: every name moved
here is re-imported by ``governance.py`` so existing ``from capmesh.governance
import apply_vault_placement`` call sites and tests continue to work.

Moved names:
    - ``_manifest_uri_tail`` -- prefix-strip helper for manifest/placed URIs.
    - ``_vault_match_key`` -- CM-05 symmetric plugin-prefix normalization.
    - ``_vault_placement_collision`` -- CM-01 cross-batch collision guard helper.
    - ``apply_vault_placement`` -- place a cap at the org / all-user namespace.

``apply_vault_placement`` reaches for general namespace, audit and risk-tier
helpers that are NOT purely vault-placement and therefore remain in
``governance.py``. To avoid a circular import, those helpers are pulled in with
a lazy import inside the function body (``governance`` imports this module at
its own top level, so a module-top reverse import would cycle). All other
helpers in this file are stdlib + ``.models`` only and fully self-contained.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import replace

from .models import Capability


def _manifest_uri_tail(uri: str) -> str:
    """Extract the canonical ``{type}/{plugin}.{name}@{version}`` tail from a
    manifest target URI (``cap://org/.../shared/<tail>`` or
    ``cap://all/<tenant>/everyone/<tail>``). Falls back to the trailing two
    segments if the URI shape is unexpected."""
    for marker in ("/shared/", "/everyone/"):
        idx = uri.find(marker)
        if idx != -1:
            return uri[idx + len(marker):]
    parts = uri.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else uri


def _vault_match_key(tail: str) -> str:
    """Normalize a canonical tail to ``{type}/{basename}@{version}`` by dropping a
    single leading plugin-prefix segment from the name component.

    Manifest URIs and live caps may carry different plugin-prefix segments for the
    same underlying capability (e.g. ``agent/global.foo@0.1.0`` vs
    ``agent/agentic-flow-specialists-2026.foo@0.1.0``). Stripping the leading
    Scoped plugin identities use hyphens rather than dots, preserving the one-dot
    boundary between plugin identity and a capability name that may itself contain
    dots.
    """
    if "/" not in tail:
        return tail
    typ, rest = tail.split("/", 1)
    rest = re.sub(r"^[^.@/]+\.", "", rest, count=1)
    return typ + "/" + rest


def _vault_placement_collision(
    con: sqlite3.Connection,
    capability: Capability,
    match_key: str,
    target_namespace_id: str,
    tenant_id: str,
) -> dict[str, str] | None:
    """Return ``{uri, content_hash}`` of an existing DISTINCT capability already
    placed at ``target_namespace_id`` under the same canonical ``match_key``,
    or ``None`` when no collision exists.

    CM-01 guard helper. ``_vault_match_key`` (CM-05, symmetric and unchanged)
    strips a single plugin-prefix segment from both manifest URIs and live
    caps so they match across stale/real prefixes. The residual risk is that
    two DISTINCT capabilities normalize to the SAME canonical_key and silently
    collapse onto one target namespace. This helper detects that case.

    DISTINCT means different ``content_hash``: a re-ingest of the same cap
    (same content_hash) is idempotent and NOT a collision. Content-hash is the
    content identity, so two caps with different content are genuinely
    distinct even when their plugin prefixes collapse to the same key; two
    caps with the same content are the same cap and may both be re-placed.

    The placed cap's canonical tail is recovered from its placed URI via
    ``_manifest_uri_tail`` (a placed URI is ``<target_namespace_prefix>/<tail>``),
    so no Capability reconstruction or index.py import is needed -- the guard
    stays entirely within governance.py and reuses the same normalization the
    matcher already applies.
    """
    rows = con.execute(
        "SELECT uri, content_hash FROM capabilities WHERE tenant_id = ? AND namespace_id = ?",
        (tenant_id, target_namespace_id),
    ).fetchall()
    for row in rows:
        if row["content_hash"] == capability.content_hash:
            continue  # same content -- re-ingest of the same cap, not a collision
        if _vault_match_key(_manifest_uri_tail(row["uri"])) == match_key:
            return {"uri": row["uri"], "content_hash": row["content_hash"]}
    return None


def apply_vault_placement(
    con: sqlite3.Connection,
    capability: Capability,
    placement_index: dict[str, str],
) -> Capability | None:
    """If ``capability`` is named in the placement index, file it into the org or
    all-user namespace. Returns the placed Capability, or None when the cap is not
    in the manifest (caller keeps the default private placement).

    Drafts matching a manifest tail ARE placed at the target namespace but retain
    their draft lifecycle/approval_state — placement does not promote.

    For drafts targeting the all-user vault, the riskTierPolicy gate is enforced:
    high/critical risk drafts are NOT placed to all-user and return None instead.

    Ensures the target namespace exists before assignment.
    """
    # Lazy import: general namespace / audit / risk-tier helpers live in
    # ``governance.py`` (they are NOT purely vault-placement). ``governance``
    # imports this module at its own top level, so a module-top reverse import
    # would cycle; resolving them at call time keeps the dependency one-way.
    from .governance import (
        DEFAULT_TENANT,
        DEFAULT_USER_SUBJECT,
        all_users_namespace_id,
        all_users_namespace_prefix,
        all_users_store_id,
        audit_event,
        capability_canonical_tail,
        ensure_all_users_namespace,
        ensure_org_shared_namespace,
        evaluate_risk_tier_policy,
        org_shared_namespace_id,
        org_shared_namespace_prefix,
        org_store_id,
        user_namespace_capability_uri,
    )

    if not placement_index:
        return None
    if capability.source_kind == "system_capability" or capability.uri.startswith("cap://system/"):
        return None
    vault = placement_index.get(_vault_match_key(capability_canonical_tail(capability)))
    if vault not in {"org", "all"}:
        return None

    # Drafts targeting all-user vault must pass the riskTierPolicy gate.
    # A draft that would be denied placement to all-user is left in the source
    # namespace (return None). This is intentional: drafts are unapproved and
    # should not leak to the all-user namespace without review.
    is_draft = capability.approval_state == "draft" or capability.lifecycle == "draft"
    if is_draft and vault == "all":
        risk_tier = capability.risk_tier or "unknown"
        ok, _reason = evaluate_risk_tier_policy(risk_tier, vault, capability.visibility)
        if not ok:
            return None

    tenant_id = capability.tenant_id or DEFAULT_TENANT
    tail = capability_canonical_tail(capability)
    if vault == "org":
        ensure_org_shared_namespace(con, tenant_id)
        target_store = org_store_id(tenant_id)
        target_ns = org_shared_namespace_id(tenant_id)
        target_uri = f"{org_shared_namespace_prefix(tenant_id)}/{tail}"
        visibility = "internal"
    else:  # "all"
        ensure_all_users_namespace(con, tenant_id)
        target_store = all_users_store_id(tenant_id)
        target_ns = all_users_namespace_id(tenant_id)
        target_uri = f"{all_users_namespace_prefix(tenant_id)}/{tail}"
        visibility = "internal"

    # CM-01 vault placement collision guard.
    #
    # _vault_match_key (CM-05, DONE) symmetrically strips the plugin-prefix from
    # both manifest URIs and live caps, so a cap matches a manifest entry across
    # stale/real plugin prefixes. The residual risk: two DISTINCT capabilities
    # (different source / different content_hash) normalize to the SAME
    # canonical_key and placement silently collapses them onto one target
    # namespace -- two rows claiming the manifest's "one key = one cap" slot.
    #
    # Choice: REFUSE the second placement rather than suffix-disambiguating the
    # canonical_key (e.g. <key>-<short hash>). A silent rename would hide two
    # caps behind one key and break the manifest contract; the manifest owner
    # asked for ONE cap at that key, not two. Refusing leaves the second cap in
    # its source namespace (caller falls back to apply_default_user_namespace)
    # where an operator can see it, recorded as a vault_placement.collision
    # audit event naming both caps and the colliding key. The first cap to claim
    # the key wins; re-ingest of the SAME cap (same content_hash) is idempotent
    # and re-places normally -- the guard's content_hash check skips it.
    #
    # This guard detects cross-batch collisions (the first cap is already
    # persisted when the second is placed). Within a single ingest batch neither
    # cap is persisted yet, so the DB lookup cannot see the sibling; that
    # intra-batch case is reported by the CM-10 coverage detector
    # (placementDroppedKeys in index.py), which this guard complements.
    match_key = _vault_match_key(tail)
    colliding = _vault_placement_collision(con, capability, match_key, target_ns, tenant_id)
    if colliding is not None:
        audit_event(
            con,
            event_type="vault_placement.collision",
            actor="capmesh-system",
            actor_type="service",
            target=capability.uri,
            action="place",
            decision="deny",
            reason="vault placement refused: canonical_key already held by a distinct capability",
            payload={
                "incomingUri": capability.uri,
                "incomingContentHash": capability.content_hash,
                "existingUri": colliding["uri"],
                "existingContentHash": colliding["content_hash"],
                "canonicalKey": match_key,
                "targetNamespace": target_ns,
                "vault": vault,
            },
            tenant_id=tenant_id,
        )
        return None

    # The "original private uri" is the default-user (private) uri this cap would
    # otherwise have received, not the raw source uri.
    private_uri = user_namespace_capability_uri(capability)
    metadata = dict(capability.metadata)
    metadata.setdefault("originalUri", private_uri)
    metadata.setdefault("originalOwner", capability.owner)
    metadata["vaultPlacement"] = vault
    # Drafts are placed at the target namespace but retain their draft state;
    # published/approved caps continue to be promoted as before.
    if is_draft:
        return replace(
            capability,
            uri=target_uri,
            tenant_id=tenant_id,
            store_id=target_store,
            namespace_id=target_ns,
            visibility=visibility,
            discovery_mode="public",
            owner="asg-platform",
            created_by=capability.created_by or DEFAULT_USER_SUBJECT,
            promoted_from_uri=capability.promoted_from_uri or private_uri,
            metadata=metadata,
        )
    return replace(
        capability,
        uri=target_uri,
        tenant_id=tenant_id,
        store_id=target_store,
        namespace_id=target_ns,
        visibility=visibility,
        discovery_mode="public",
        owner="asg-platform",
        created_by=capability.created_by or DEFAULT_USER_SUBJECT,
        promoted_from_uri=capability.promoted_from_uri or private_uri,
        approval_state="approved",
        share_state="shared",
        lifecycle="published",
        metadata=metadata,
    )
