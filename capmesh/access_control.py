from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from typing import Any

from .models import Capability, Principal
from .utils import (
    DEFAULT_TENANT,
    _production_environment,
    json_dumps,
    json_loads,
    new_id,
    stable_id,
    utc_now,
)

RIGHTS = (
    "discover",
    "load",
    "call",
    "delegate",
    "share",
    "submit",
    "publish",
    "approve",
    "manage",
    "audit",
)

# Rights that require step-up authorization when the capability is high-risk
STEP_UP_RIGHTS = {"manage", "approve", "publish"}
STEP_UP_RISK_TIERS = {"high", "critical"}


def requires_step_up(right: str, capability: Capability | None) -> bool:
    """Check whether a right+capability combination requires step-up auth.

    Destructive or high-risk calls (manage/approve/publish on high/critical
    risk-tier capabilities) require step-up authorization beyond the base
    session. The caller is responsible for enforcing the step-up challenge.
    """
    if right not in STEP_UP_RIGHTS:
        return False
    if capability is None:
        return False
    return capability.risk_tier in STEP_UP_RISK_TIERS
GLOBAL_ROLE_GRANT_ROLES = {"platform_admin", "org_admin"}

ROLE_RIGHTS: dict[str, set[str]] = {
    "member": {"discover", "load", "call"},
    "vibe_coder": {"discover", "load", "call", "delegate", "share", "submit"},
    "publisher": {"discover", "load", "call", "submit", "publish"},
    "namespace_admin": {"discover", "load", "call", "delegate", "share", "submit", "publish", "approve", "manage", "audit"},
    "org_admin": set(RIGHTS),
    "platform_admin": set(RIGHTS),
    "auditor": {"discover", "load", "audit"},
    "app_service": {"discover", "load", "call", "delegate"},
}

_ORG_FOR_STORE_CACHE: dict[tuple[str, str], str | None] = {}
def subject_refs(principal: Principal) -> set[str]:
    identity_id = principal.identity_id or stable_id("idn", principal.tenant_id or DEFAULT_TENANT, principal.subject)
    refs = {f"user:{principal.subject}", f"identity:{identity_id}"}
    if principal.email and principal.email != principal.subject:
        refs.add(f"user:{principal.email}")
    if principal.app_id:
        refs.add(f"app:{principal.app_id}")
    refs.update(f"group:{group}" for group in principal.groups)
    refs.update(f"role:{role}" for role in principal.roles)
    return refs
def role_has_right(role: str, right: str) -> bool:
    rights = ROLE_RIGHTS.get(role, set())
    return right in rights or "manage" in rights
def global_role_has_right(role: str, right: str) -> bool:
    if role in GLOBAL_ROLE_GRANT_ROLES:
        return role_has_right(role, right)
    return role == "auditor" and right in {"discover", "load", "audit"}
def is_disabled(con: sqlite3.Connection, principal: Principal) -> bool:
    if principal.disabled or not principal.authenticated:
        return True
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    params: list[Any] = [tenant_id, principal.subject]
    clauses = ["user_name = ?"]
    if principal.identity_id:
        clauses.append("id = ?")
        params.append(principal.identity_id)
    if principal.email:
        clauses.append("email = ?")
        params.append(principal.email)
    row = con.execute(
        f"SELECT active FROM identities WHERE tenant_id = ? AND ({' OR '.join(clauses)}) ORDER BY updated_at DESC LIMIT 1",
        params,
    ).fetchone()
    return bool(row is not None and int(row["active"]) == 0)
def resource_refs(capability: Capability | None, resource_uri: str | None = None) -> list[str]:
    refs: list[str] = []
    if capability is not None:
        refs.append(capability.uri)
        if capability.namespace_id:
            refs.append(f"namespace:{capability.namespace_id}")
        if capability.store_id:
            refs.append(f"store:{capability.store_id}")
        refs.append(f"tenant:{capability.tenant_id or DEFAULT_TENANT}")
    elif resource_uri:
        refs.append(resource_uri)
    return refs
def has_formal_promotion_record(con: sqlite3.Connection, capability: Capability) -> bool:
    """Return whether governance has an audited promotion record for this URI.

    ``promoted_from_uri`` is also used as lineage for static, code-reviewed vault
    placement during ingestion.  Only the formal promotion workflow creates a
    ``promotion_requests`` row, so that row is the authoritative discriminator
    for production attestation enforcement.
    """
    row = con.execute(
        "SELECT 1 FROM promotion_requests WHERE tenant_id = ? AND capability_uri = ? LIMIT 1",
        (capability.tenant_id or DEFAULT_TENANT, capability.uri),
    ).fetchone()
    return row is not None
def evaluate_access(
    con: sqlite3.Connection,
    principal: Principal,
    *,
    right: str,
    capability: Capability | None = None,
    resource_uri: str | None = None,
    audit: bool = True,
) -> tuple[bool, str]:
    if right not in RIGHTS:
        return False, f"Unsupported right: {right}"
    tenant_id = principal.tenant_id or getattr(capability, "tenant_id", None) or DEFAULT_TENANT
    resources = resource_refs(capability, resource_uri)
    subjects = subject_refs(principal)
    decision = "deny"
    reason = "No matching grant."

    blocked_states = {"rejected", "recalled", "demoted", "yanked"}
    blocked_lifecycles = {"disabled", "deleted", "retired", "recalled", "yanked"}
    integrity_required = bool(
        capability
        and _production_environment()
        and capability.promoted_from_uri
        and has_formal_promotion_record(con, capability)
        and right in {"discover", "load", "call", "delegate"}
    )

    if is_disabled(con, principal):
        reason = "Principal is disabled or unauthenticated."
    elif capability and (
        capability.approval_state in blocked_states or capability.lifecycle in blocked_lifecycles
    ):
       reason = "Capability is inactive, recalled, demoted, rejected, or yanked."
    elif requires_step_up(right, capability) and not getattr(principal, "step_up_authenticated", False):
        reason = "Step-up authentication required for high-risk or destructive operation."
    elif integrity_required and (
        capability.approval_state != "approved"
        or capability.signature_status != "verified"
        or capability.provenance_status != "verified"
        or capability.risk_review_status != "approved"
    ):
        reason = "Promoted capability integrity or approval state is not valid for production use."
    elif tuple_match(con, tenant_id, resources, {f"deny_{right}", "deny"}, subjects):
        reason = "Explicit deny relationship matched."
    elif any(global_role_has_right(role, right) for role in principal.roles):
        decision, reason = "allow", "Principal role grants the requested right."
    elif active_role_grant(con, tenant_id, subjects, right, capability=capability, resource_uri=resource_uri):
        decision, reason = "allow", "Active role assignment grants the requested right."
    elif share_grant(con, tenant_id, subjects, capability.uri if capability else resource_uri or "", right):
        decision, reason = "allow", "Active share grants the requested right."
    elif tuple_match(con, tenant_id, resources, {right, f"grant_{right}", "owner"}, subjects):
        decision, reason = "allow", "Relationship tuple grants the requested right."
    elif capability and namespace_member_grant(con, tenant_id, capability.namespace_id, subjects, right):
        decision, reason = "allow", "Namespace membership grants the requested right."
    elif capability and store_owner_grant(con, capability, principal, right):
        decision, reason = "allow", "Store ownership grants the requested right."
    elif capability and manifest_grant(capability, principal, right):
        decision, reason = "allow", "Capability manifest grant matches the principal."
    elif capability and owner_grant(capability, principal, right):
        decision, reason = "allow", "Owner rights grant the requested right."
    elif capability and all_users_store_grant(con, capability, principal, right):
        decision, reason = "allow", "All-user store grants read-only access to authenticated tenant users."
    elif capability and org_membership_grant(con, capability, principal, right):
        decision, reason = "allow", "Org membership grants read access to the org store."
    elif capability and default_visibility_grant(con, capability, principal, right):
        decision, reason = "allow", "Default visibility grants the requested right."

    allowed = decision == "allow"
    if audit:
        record_policy_decision(
            con,
            tenant_id=tenant_id,
            principal=principal,
            action=right,
            resource_uri=capability.uri if capability else resource_uri or "",
            decision=decision,
            reason=reason,
            inputs={"subjects": sorted(subjects), "resources": resources},
        )
    return allowed, None if allowed else reason
def manifest_grant(capability: Capability, principal: Principal, right: str) -> bool:
    if right not in {"discover", "load", "call", "delegate"}:
        return False
    if capability.allow_users and principal.subject in capability.allow_users:
        return True
    if capability.allow_groups and set(principal.groups).intersection(capability.allow_groups):
        return True
    return bool(
        capability.required_scopes
        and set(capability.required_scopes).issubset(set(principal.scopes))
    )
def tuple_match(
    con: sqlite3.Connection,
    tenant_id: str,
    objects: Iterable[str],
    relations: set[str],
    users: set[str],
) -> bool:
    objects = tuple(objects)
    if not objects or not relations or not users:
        return False
    object_marks = ",".join("?" for _ in objects)
    relation_marks = ",".join("?" for _ in relations)
    user_marks = ",".join("?" for _ in users)
    row = con.execute(
        f"""
        SELECT 1 FROM relationship_tuples
        WHERE tenant_id = ?
          AND object IN ({object_marks})
          AND relation IN ({relation_marks})
          AND user IN ({user_marks})
        LIMIT 1
        """,
        (tenant_id, *objects, *relations, *users),
    ).fetchone()
    return row is not None
def active_role_grant(
    con: sqlite3.Connection,
    tenant_id: str,
    subjects: set[str],
    right: str,
    *,
    capability: Capability | None = None,
    resource_uri: str | None = None,
) -> bool:
    if not subjects:
        return False
    subject_pairs = []
    for ref in subjects:
        subject_type, _, subject_id = ref.partition(":")
        subject_pairs.append((subject_type, subject_id))
    rows = con.execute(
        """
        SELECT subject_type, subject_id, role, scope_type, scope_id, expires_at
        FROM role_assignments
        WHERE tenant_id = ? AND revoked_at IS NULL
        """,
        (tenant_id,),
    ).fetchall()
    now = utc_now()
    for row in rows:
        if (row["subject_type"], row["subject_id"]) not in subject_pairs:
            continue
        if row["expires_at"] and row["expires_at"] <= now:
            continue
        if row["scope_type"] == "org":
            # Org-scoped grants (per-user org membership, Design B) need a DB
            # lookup to map the capability's store back to its organization, so
            # they are resolved here rather than in the con-less scope matcher.
            if not _org_scope_matches(con, row, tenant_id, capability, resource_uri):
                continue
        elif not role_assignment_scope_matches(row, tenant_id, capability, resource_uri):
            continue
        if role_has_right(row["role"], right):
            return True
    return False
def org_id_for_store(con: sqlite3.Connection, store_id: str | None, tenant_id: str) -> str | None:
    """Return the organization id that owns ``store_id`` (an org store), or None.

    Cached per (tenant_id, store_id); the org<->store binding is created once at
    store-create time and never moves, so a process-lifetime cache is safe.
    """
    if not store_id:
        return None
    key = (tenant_id, store_id)
    if key in _ORG_FOR_STORE_CACHE:
        return _ORG_FOR_STORE_CACHE[key]
    row = con.execute(
        "SELECT id FROM organizations WHERE store_id = ? AND tenant_id = ?",
        (store_id, tenant_id),
    ).fetchone()
    org_id = row["id"] if row is not None else None
    _ORG_FOR_STORE_CACHE[key] = org_id
    return org_id
def _org_scope_matches(
    con: sqlite3.Connection,
    row: sqlite3.Row,
    tenant_id: str,
    capability: Capability | None,
    resource_uri: str | None,
) -> bool:
    """Match an org-scoped role_assignment (scope_type=='org', scope_id==<org id>)."""
    scope_id = row["scope_id"]
    if capability is None:
        # Direct resource addressing (e.g. manage on the org itself).
        return resource_uri in {f"org:{scope_id}", scope_id}
    cap_tenant = capability.tenant_id or tenant_id
    return org_id_for_store(con, capability.store_id, cap_tenant) == scope_id
def role_assignment_scope_matches(
    row: sqlite3.Row,
    tenant_id: str,
    capability: Capability | None,
    resource_uri: str | None,
) -> bool:
    scope_type = row["scope_type"]
    scope_id = row["scope_id"]
    if scope_type == "tenant":
        return scope_id in {tenant_id, "*"}
    if capability is None:
        return resource_uri in {f"{scope_type}:{scope_id}", scope_id}
    if scope_type == "store":
        return scope_id == capability.store_id
    if scope_type == "namespace":
        return scope_id == capability.namespace_id
    if scope_type in {"capability", "resource", "object"}:
        return scope_id in {capability.uri, resource_uri}
    return False
def namespace_member_grant(
    con: sqlite3.Connection,
    tenant_id: str,
    namespace_id: str | None,
    subjects: set[str],
    right: str,
) -> bool:
    if not namespace_id or not subjects:
        return False
    rows = con.execute(
        """
        SELECT subject_type, subject_id, role, rights_json
        FROM namespace_members
        WHERE namespace_id = ? AND revoked_at IS NULL
        """,
        (namespace_id,),
    ).fetchall()
    for row in rows:
        if f"{row['subject_type']}:{row['subject_id']}" not in subjects:
            continue
        rights = set(json_loads(row["rights_json"], []))
        if right in rights or "manage" in rights or role_has_right(row["role"], right):
            return True
    return False
def store_owner_grant(con: sqlite3.Connection, capability: Capability, principal: Principal, right: str) -> bool:
    if right not in {"discover", "load", "call", "delegate", "share", "submit", "manage"}:
        return False
    if not capability.store_id:
        return False
    row = con.execute(
        "SELECT kind, owner_identity_id, owner_app_id FROM stores WHERE id = ? AND tenant_id = ?",
        (capability.store_id, capability.tenant_id or DEFAULT_TENANT),
    ).fetchone()
    if row is None:
        return False
    identity_id = principal.identity_id or stable_id("idn", principal.tenant_id or DEFAULT_TENANT, principal.subject)
    if row["kind"] in {"user_private", "user_shared"} and row["owner_identity_id"] == identity_id:
        return True
    return bool(
        row["kind"] == "app"
        and principal.app_id
        and row["owner_app_id"] == principal.app_id
    )
def all_users_store_grant(con: sqlite3.Connection, capability: Capability, principal: Principal, right: str) -> bool:
    """Grant read-only (discover/load/call) on capabilities in an all_users store to
    every AUTHENTICATED tenant user.

    The {discover, load, call} whitelist is the hard cap: share/submit/publish/approve/
    manage/delegate/audit fall through to the normal cascade, where only store_owner
    (NULL owner => never matches a user), role_assignment (admin), or explicit
    relationship_tuples grant them — so writes require platform/org/namespace admin.
    Cross-tenant leakage is prevented by scoping the store lookup to the capability's
    own tenant and requiring the principal's tenant to match it.
    """
    if right not in {"discover", "load", "call"}:  # read-only rights ONLY
        return False
    if not principal.authenticated:  # tenant users only, no anonymous
        return False
    if not capability.store_id:
        return False
    cap_tenant = capability.tenant_id or DEFAULT_TENANT
    principal_tenant = principal.tenant_id or DEFAULT_TENANT
    if cap_tenant != principal_tenant:  # no cross-tenant access
        return False
    row = con.execute(
        "SELECT kind FROM stores WHERE id = ? AND tenant_id = ?",
        (capability.store_id, cap_tenant),
    ).fetchone()
    return row is not None and row["kind"] == "all_users"
def share_grant(con: sqlite3.Connection, tenant_id: str, subjects: set[str], capability_uri: str, right: str) -> bool:
    if not capability_uri:
        return False
    rows = con.execute(
        """
        SELECT subject_type, subject_id, rights_json, expires_at
        FROM shares
        WHERE tenant_id = ? AND capability_uri = ? AND state = 'active' AND revoked_at IS NULL
        """,
        (tenant_id, capability_uri),
    ).fetchall()
    now = utc_now()
    for row in rows:
        ref = f"{row['subject_type']}:{row['subject_id']}"
        if ref not in subjects:
            continue
        if row["expires_at"] and row["expires_at"] <= now:
            continue
        rights = set(json_loads(row["rights_json"], []))
        if right in rights or "manage" in rights:
            return True
    return False
def owner_grant(capability: Capability, principal: Principal, right: str) -> bool:
    if right not in {"discover", "load", "call", "delegate", "share", "submit", "manage"}:
        return False
    owner = capability.created_by or capability.owner
    return owner in {principal.subject, principal.identity_id} or owner in principal.groups
def _store_is_org(con: sqlite3.Connection, store_id: str | None, tenant_id: str) -> bool:
    if not store_id:
        return False
    row = con.execute(
        "SELECT 1 FROM stores WHERE id = ? AND tenant_id = ? AND kind = 'org'",
        (store_id, tenant_id),
    ).fetchone()
    return row is not None
def org_membership_grant(con: sqlite3.Connection, capability: Capability, principal: Principal, right: str) -> bool:
    """Design B: gate ORG store capabilities behind per-user org membership.

    Membership is modelled as a role_assignment with scope_type=='org' (role
    'member' or elevated 'namespace_admin'/'org_admin'). For an org store, grant
    the read-tier rights {discover, load, call} ONLY when the principal is an
    active member of THAT org (or has a global org_admin/platform_admin role).

    Non-org stores return False so the rest of the cascade is unaffected. Members
    of org A are NOT granted org B's capabilities — the org-scoped role_assignment
    must name the capability's own organization. Explicit per-capability shares and
    relationship tuples are evaluated EARLIER in the cascade, so a non-member who
    was explicitly shared a single org capability still gets it.
    """
    if right not in {"discover", "load", "call"}:
        return False
    if not principal.authenticated:
        return False
    cap_tenant = capability.tenant_id or principal.tenant_id or DEFAULT_TENANT
    if not _store_is_org(con, capability.store_id, cap_tenant):
        return False
    # Global org_admin / platform_admin already short-circuited earlier in
    # evaluate_access via global_role_has_right; this re-check covers the case
    # where the role was granted as a tenant-scoped role_assignment.
    subjects = subject_refs(principal)
    return active_role_grant(con, cap_tenant, subjects, right, capability=capability)
def default_visibility_grant(con: sqlite3.Connection, capability: Capability, principal: Principal, right: str) -> bool:
    if right not in {"discover", "load", "call"}:
        return False
    cap_tenant = capability.tenant_id or principal.tenant_id or DEFAULT_TENANT
    is_org_store = _store_is_org(con, capability.store_id, cap_tenant)
    if capability.visibility == "public":
        # Public org capabilities remain openly visible by design; the membership
        # gate only governs the default 'internal' bulk of an org store.
        return True
    if is_org_store:
        # Design B carve-out: internal-visibility org capabilities are NO LONGER
        # granted by mere authentication. Membership is enforced by
        # org_membership_grant earlier in the cascade.
        return False
    return capability.visibility == "internal" and principal.authenticated
def record_policy_decision(
    con: sqlite3.Connection,
    *,
    tenant_id: str,
    principal: Principal,
    action: str,
    resource_uri: str,
    decision: str,
    reason: str,
    inputs: dict[str, Any] | None = None,
) -> None:
    con.execute(
        """
        INSERT INTO policy_decisions(id, tenant_id, principal, action, resource_uri, decision, reason, inputs_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (new_id("pd"), tenant_id, principal.subject, action, resource_uri, decision, reason, json_dumps(inputs or {})),
    )
