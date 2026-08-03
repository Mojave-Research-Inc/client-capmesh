from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .access_control import (  # noqa: F401
    _ORG_FOR_STORE_CACHE,
    GLOBAL_ROLE_GRANT_ROLES,
    RIGHTS,
    ROLE_RIGHTS,
    _org_scope_matches,
    _store_is_org,
    active_role_grant,
    all_users_store_grant,
    default_visibility_grant,
    evaluate_access,
    global_role_has_right,
    has_formal_promotion_record,
    is_disabled,
    manifest_grant,
    namespace_member_grant,
    org_id_for_store,
    org_membership_grant,
    owner_grant,
    record_policy_decision,
    resource_refs,
    role_assignment_scope_matches,
    role_has_right,
    share_grant,
    store_owner_grant,
    subject_refs,
    tuple_match,
)
from .audit import state_dir
from .help import help_payload, onboarding_payload
from .install_policy import SUPERADMIN_ACTORS
from .models import Capability, Principal, normalize_path
from .promotions import (  # noqa: F401
    approve_request,
    list_requests,
    promotion_record,
    submit_promotion,
)
from .prompt_injection import (  # noqa: F401
    _HOMOGLYPHS,
    _INJECTION_PHRASES,
    _ZERO_WIDTH,
    evaluate_prompt_injection_scan,
    scan_prompt_injection,
)
from .risk_policy import default_promotion_gates, evaluate_risk_tier_policy  # noqa: F401
from .roles_orgs import (  # noqa: F401
    _resolve_org,
    add_org_member,
    assign_role,
    list_audit_events,
    list_org_members,
    list_organizations,
    list_roles,
    remove_org_member,
    require_admin_or_audit,
    revoke_role,
    role_record,
)
from .stores import (  # noqa: F401
    create_namespace,
    create_share,
    create_store,
    default_store_prefix,
    list_namespaces,
    list_shares,
    list_stores,
    namespace_record,
    revoke_share,
    share_record,
    store_record,
)
from .sync import (  # noqa: F401
    create_teams_binding,
    list_teams_bindings,
    plan_graph_subscription,
    sync_summary,
    tag_to_group,
    teams_binding_record,
    upsert_group_from_tailnet,
    upsert_identity_from_tailnet,
)
from .tokens import (  # noqa: F401
    auth_status,
    complete_google_session,
    complete_oauth_session,
    create_oauth_session,
    decode_unverified_jwt,
    email_is_allowed,
    google_allowed_emails,
    hash_secret,
    mint_capmesh_token,
    oauth_session_status,
    principal_from_bearer,
    principal_from_entra_claims,
    principal_from_google_claims,
    revoke_capmesh_session,
    sanitize_auth_metadata,
    sanitize_claims,
    validate_graph_client_state,
    validate_oauth_callback,
    verify_id_token,
)
from .utils import (  # noqa: F401
    _CAPMESH_SESSION_TTL,
    _OAUTH_TOKEN_DELIVERY_TTL,
    DEFAULT_TENANT,
    _oauth_verify_signature_enabled,
    _production_environment,
    expires_in,
    json_dumps,
    json_loads,
    new_id,
    stable_id,
    utc_now,
)
from .vault_placement import (  # noqa: F401
    _manifest_uri_tail,
    _vault_match_key,
    _vault_placement_collision,
    apply_vault_placement,
)

# Must match the tenant the SCHEMA itself defaults to. Both governance.py:234 and
# index.py declare `tenant_id TEXT NOT NULL DEFAULT 'asg'`, and lifecycle.py falls
# back to `principal.tenant_id or "asg"` in ~10 places. The sanitization pass
# changed only this Python constant to "default", desynchronizing it from the
# schema and from every fallback: rows landed under 'asg' while helpers resolved
# ids for 'default', producing FOREIGN KEY failures and uri-prefix mismatches
# across the suite.
#
# Aligned to the schema rather than rewriting the SQL: those are column DEFAULT
# clauses, so changing them is a migration against existing databases, and a
# constant cannot be referenced from DDL anyway. Still env-overridable, so this
# is a default that agrees with the schema, not a hardcoded identity.







DEFAULT_USER_SUBJECT = os.environ.get("CAPMESH_DEFAULT_USER_SUBJECT", "admin@example.com")
SUPERADMIN_SUBJECTS = SUPERADMIN_ACTORS


def _break_glass_active(con, principal):
    """Check if a break-glass session is active for this principal."""
    try:
        from .break_glass import is_break_glass_active
        rows = con.execute(
            "SELECT id FROM break_glass_sessions WHERE tenant_id = ? AND principal = ? AND revoked_at IS NULL AND expires_at > ?",
            (principal.tenant_id or DEFAULT_TENANT, principal.subject, utc_now()),
        ).fetchall()
        for row in rows:
            if is_break_glass_active(con, str(row["id"]), tenant_id=principal.tenant_id or DEFAULT_TENANT):
                return True
    except Exception:  # noqa: BLE001, S110
        pass
    return False


def superadmin_subjects() -> tuple[str, ...]:
    """Operator-approved superadmins, resolved at CALL time.

    SUPERADMIN_SUBJECTS aliases install_policy.SUPERADMIN_ACTORS, which parses
    CAPMESH_SUPERADMIN_ACTORS once at import. Anything that configures the
    policy after import -- a service that loads config then initializes, a test
    fixture -- was invisible, and because the allowlist is deliberately
    fail-closed (an unset variable grants nobody) the practical result was that
    ensure_platform_superadmins() silently granted nothing at all.

    Falls back to the single CAPMESH_SUPERADMIN_ACTOR when the allowlist is
    unset, matching configured_superadmin_auto_approval() exactly. One identity
    source, one fallback rule, so the two cannot disagree about who is a
    superadmin. Still fail-closed: with neither variable set this returns empty
    and nobody is granted.
    """
    from .install_policy import _parse_superadmin_actors, superadmin_actor

    actors = _parse_superadmin_actors()
    if actors:
        return actors
    single = superadmin_actor().strip().lower()
    return (single,) if single else ()
CORPORATE_EMAIL_DOMAIN = os.environ.get("CAPMESH_CORPORATE_EMAIL_DOMAIN", "example.com")
DEFAULT_ORG_SLUG = os.environ.get("CAPMESH_DEFAULT_ORG_SLUG", "the-company")
# Must read as the display form of DEFAULT_ORG_SLUG above ("the-company"). The
# sanitization pass rewrote the slug and the display name to different
# placeholders, so the org rendered as "the operator" while its slug said
# "the-company" -- two names for one organization.
DEFAULT_ORG_DISPLAY_NAME = os.environ.get("CAPMESH_DEFAULT_ORG_DISPLAY_NAME", "the company")
LOCAL_SERVICE_APP_ID = "capmesh-service"


SYSTEM_CAPABILITIES = (
    ("system.help", "Show capmesh syntax, examples, JSON schemas, and LLM/coder operating guidance.", f"cap://system/{DEFAULT_TENANT}/help@0.1.0", "low", ("discover", "load", "call")),
    ("system.onboard", "Guide a tailnet user or LLM client through M365 sign-in, gateway setup, direct MCP fallback, and diagnostics.", f"cap://system/{DEFAULT_TENANT}/onboard@0.1.0", "low", ("discover", "load", "call")),
    ("system.auth", "Inspect capmesh auth status and return safe refresh/login guidance without exposing raw secrets.", f"cap://system/{DEFAULT_TENANT}/auth@0.1.0", "medium", ("discover", "load", "call")),
    ("system.capabilities", "Create, edit, diff, validate, share, submit, and prepare Git review artifacts for capabilities where permitted.", f"cap://system/{DEFAULT_TENANT}/capabilities@0.1.0", "high", ("discover", "load", "call", "share", "submit", "manage")),
    ("system.me", "Show the current capmesh identity, tenant, roles, groups, stores, and namespace grants.", f"cap://system/{DEFAULT_TENANT}/me@0.1.0", "low", ("discover", "load", "call")),
    ("system.stores", "List or create capmesh stores for users, org namespaces, apps, the tenant-wide all-user (everyone) store, and system governance.", f"cap://system/{DEFAULT_TENANT}/stores@0.1.0", "medium", ("discover", "load", "call", "manage")),
    ("system.namespaces", "List or create governed namespaces under user, org, app, or system stores.", f"cap://system/{DEFAULT_TENANT}/namespaces@0.1.0", "medium", ("discover", "load", "call", "manage")),
    ("system.share", "Share or revoke selected capabilities with users, groups, roles, or app service identities.", f"cap://system/{DEFAULT_TENANT}/share@0.1.0", "medium", ("discover", "load", "call", "share")),
    ("system.submit", "Submit private or shared capabilities for immutable org namespace promotion.", f"cap://system/{DEFAULT_TENANT}/submit@0.1.0", "medium", ("discover", "load", "call", "submit")),
    ("system.requests", "List promotion requests and approval state for a tenant.", f"cap://system/{DEFAULT_TENANT}/requests@0.1.0", "low", ("discover", "load", "call")),
    ("system.gates", "Run static integrity, provenance, prompt-safety, retrieval, and risk gates before approving capabilities.", f"cap://system/{DEFAULT_TENANT}/gates@0.1.0", "high", ("discover", "load", "call", "approve", "manage")),
    ("system.approve", "Approve, reject, recall, demote, or yank promotion requests with audit records.", f"cap://system/{DEFAULT_TENANT}/approve@0.1.0", "high", ("discover", "load", "call", "approve")),
    ("system.roles", "Assign, revoke, and list capmesh role grants and OpenFGA-compatible relationship tuples.", f"cap://system/{DEFAULT_TENANT}/roles@0.1.0", "high", ("discover", "load", "call", "manage")),
    ("system.audit", "Query sanitized governance audit events and policy decisions.", f"cap://system/{DEFAULT_TENANT}/audit@0.1.0", "medium", ("discover", "load", "call", "audit")),
    ("system.sync", "Inspect SCIM, Graph subscription, Teams binding, and reconciliation state.", f"cap://system/{DEFAULT_TENANT}/sync@0.1.0", "medium", ("discover", "load", "call", "manage")),
)



def init_governance_schema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            entra_tenant_id TEXT,
            issuer TEXT,
            jwks_uri TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS identities (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            external_id TEXT,
            user_name TEXT NOT NULL,
            display_name TEXT,
            email TEXT,
            identity_type TEXT NOT NULL DEFAULT 'human',
            entra_object_id TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, user_name),
            UNIQUE(tenant_id, external_id)
        );

        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            external_id TEXT,
            display_name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, display_name),
            UNIQUE(tenant_id, external_id)
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            source TEXT NOT NULL DEFAULT 'scim',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(group_id, identity_id)
        );

        CREATE TABLE IF NOT EXISTS apps (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            app_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            service_principal_id TEXT,
            owner_identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
            active INTEGER NOT NULL DEFAULT 1,
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, app_id)
        );

        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            slug TEXT NOT NULL,
            display_name TEXT NOT NULL,
            store_id TEXT REFERENCES stores(id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'active',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, slug)
        );

        CREATE TABLE IF NOT EXISTS stores (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            uri_prefix TEXT NOT NULL UNIQUE,
            owner_identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
            owner_app_id TEXT REFERENCES apps(id) ON DELETE SET NULL,
            disabled_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS namespaces (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            store_id TEXT NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            uri_prefix TEXT NOT NULL UNIQUE,
            visibility TEXT NOT NULL DEFAULT 'internal',
            owner TEXT NOT NULL DEFAULT 'asg',
            description TEXT NOT NULL DEFAULT '',
            lifecycle TEXT NOT NULL DEFAULT 'active',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, store_id, name)
        );

        CREATE TABLE IF NOT EXISTS namespace_members (
            id TEXT PRIMARY KEY,
            namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            role TEXT NOT NULL,
            rights_json TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            created_by TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS role_assignments (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            role TEXT NOT NULL,
            scope_type TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            created_by TEXT,
            expires_at TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS relationship_tuples (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            object TEXT NOT NULL,
            relation TEXT NOT NULL,
            user TEXT NOT NULL,
            condition_json TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, object, relation, user)
        );

        CREATE TABLE IF NOT EXISTS policy_decisions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            principal TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_uri TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            inputs_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS shares (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            capability_uri TEXT NOT NULL,
            from_identity_id TEXT,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            rights_json TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS promotion_requests (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            capability_uri TEXT NOT NULL,
            source_store_id TEXT,
            target_namespace_id TEXT,
            requested_by TEXT,
            state TEXT NOT NULL DEFAULT 'pending',
            title TEXT NOT NULL DEFAULT '',
            rationale TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            gates_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            decided_at TEXT
        );

        CREATE TABLE IF NOT EXISTS approval_steps (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL REFERENCES promotion_requests(id) ON DELETE CASCADE,
            step_name TEXT NOT NULL,
            assigned_to_type TEXT,
            assigned_to_id TEXT,
            state TEXT NOT NULL DEFAULT 'pending',
            decision_by TEXT,
            decision_note TEXT,
            decided_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS oauth_sessions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            flow TEXT NOT NULL,
            state TEXT NOT NULL UNIQUE,
            code_challenge TEXT,
            code_verifier_hash TEXT,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL,
            nonce TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS capmesh_sessions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            identity_id TEXT,
            subject TEXT NOT NULL,
            principal_json TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS scim_sync_state (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            resource_type TEXT NOT NULL,
            external_id TEXT NOT NULL,
            internal_id TEXT NOT NULL,
            version TEXT,
            raw_json TEXT NOT NULL DEFAULT '{}',
            last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, resource_type, external_id)
        );

        CREATE TABLE IF NOT EXISTS graph_subscriptions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            subscription_id TEXT,
            resource TEXT NOT NULL,
            change_type TEXT NOT NULL,
            notification_url TEXT NOT NULL,
            client_state_hash TEXT NOT NULL,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'planned',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            renewed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS teams_bindings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            team_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            channel_name TEXT NOT NULL DEFAULT '',
            approval_url_base TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            actor_type TEXT NOT NULL DEFAULT 'user',
            target TEXT,
            action TEXT,
            decision TEXT,
            reason TEXT,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_identities_tenant_active ON identities(tenant_id, active);
        CREATE INDEX IF NOT EXISTS idx_groups_tenant_active ON groups(tenant_id, active);
        CREATE INDEX IF NOT EXISTS idx_organizations_tenant_slug ON organizations(tenant_id, slug);
        CREATE INDEX IF NOT EXISTS idx_stores_tenant_kind ON stores(tenant_id, kind);
        CREATE INDEX IF NOT EXISTS idx_namespaces_tenant_visibility ON namespaces(tenant_id, visibility);
        CREATE INDEX IF NOT EXISTS idx_roles_subject ON role_assignments(tenant_id, subject_type, subject_id, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_roles_org ON role_assignments(tenant_id, scope_type, scope_id, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_tuples_object_relation ON relationship_tuples(tenant_id, object, relation);
        CREATE INDEX IF NOT EXISTS idx_policy_decisions_resource ON policy_decisions(tenant_id, resource_uri, created_at);
        CREATE INDEX IF NOT EXISTS idx_shares_capability ON shares(tenant_id, capability_uri, state);
        CREATE INDEX IF NOT EXISTS idx_promotions_state ON promotion_requests(tenant_id, state, created_at);
        CREATE INDEX IF NOT EXISTS idx_promotions_capability ON promotion_requests(tenant_id, capability_uri);
        CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(tenant_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_capmesh_sessions_token ON capmesh_sessions(token_hash, expires_at, revoked_at);

        CREATE TABLE IF NOT EXISTS capability_reviews (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            capability_uri TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            review_scope TEXT NOT NULL,
            gate_state TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            reviewer TEXT NOT NULL,
            reviewed_at TEXT NOT NULL,
            attestation_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, capability_uri, content_hash, review_scope)
        );

        CREATE TABLE IF NOT EXISTS promotion_gate_runs (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL REFERENCES promotion_requests(id) ON DELETE CASCADE,
            gate_name TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            runner TEXT NOT NULL,
            run_at TEXT NOT NULL,
            attestation_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(request_id, gate_name, content_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_capability_reviews_latest
            ON capability_reviews(tenant_id, capability_uri, reviewed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_promotion_gate_runs_latest
            ON promotion_gate_runs(request_id, run_at DESC);

        CREATE TABLE IF NOT EXISTS break_glass_sessions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            principal TEXT NOT NULL,
            reason TEXT NOT NULL,
            granted_by TEXT NOT NULL,
            ttl_minutes INTEGER NOT NULL DEFAULT 30,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_break_glass_active ON break_glass_sessions(tenant_id, principal, revoked_at, expires_at);
        """
    )
    ensure_columns(
        con,
        "capabilities",
        {
            "tenant_id": "TEXT NOT NULL DEFAULT 'asg'",
            "store_id": "TEXT",
            "namespace_id": "TEXT",
            "created_by": "TEXT",
            "submitted_by": "TEXT",
            "promoted_from_uri": "TEXT",
            "approval_state": "TEXT NOT NULL DEFAULT 'published'",
            "share_state": "TEXT NOT NULL DEFAULT 'not_shared'",
            "signature_status": "TEXT NOT NULL DEFAULT 'unchecked'",
            "provenance_status": "TEXT NOT NULL DEFAULT 'unchecked'",
           "risk_review_status": "TEXT NOT NULL DEFAULT 'pending'",
            "source_commit": "TEXT",
            "license": "TEXT",
        },
    )
    con.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_capabilities_tenant_store ON capabilities(tenant_id, store_id);
        CREATE INDEX IF NOT EXISTS idx_capabilities_namespace ON capabilities(namespace_id, approval_state);
       CREATE INDEX IF NOT EXISTS idx_capabilities_governance ON capabilities(approval_state, share_state, signature_status, provenance_status);

       CREATE TABLE IF NOT EXISTS registry_log (
           id TEXT PRIMARY KEY,
           sequence INTEGER NOT NULL UNIQUE,
           event_type TEXT NOT NULL,
           actor TEXT NOT NULL,
           target_uri TEXT,
           action TEXT NOT NULL,
           payload_json TEXT NOT NULL,
           prev_hash TEXT,
           entry_hash TEXT NOT NULL UNIQUE,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
       );
       CREATE INDEX IF NOT EXISTS idx_registry_log_seq ON registry_log(sequence);
       CREATE INDEX IF NOT EXISTS idx_registry_log_hash ON registry_log(entry_hash);
       """
   )
    ensure_default_tenant(con)
    ensure_platform_superadmins(con)
    ensure_local_service_org_access(con)


_SQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Allowed column DDL fragments for additive migrations. Kept to a strict
# allowlist so this generic helper can never become a SQL-injection sink even
# if a future caller passes attacker-influenced values. No comma: a single
# ADD COLUMN takes exactly one column definition, so a comma can only ever be
# an attempt to smuggle a second clause.
_SAFE_COLUMN_DDL = re.compile(r"^[A-Za-z0-9_ ()']+$")


def ensure_columns(con: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    if not _SQL_IDENTIFIER.match(table):
        raise ValueError(f"Unsafe table identifier: {table!r}")
    existing = {row["name"] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, ddl in columns.items():
        if not _SQL_IDENTIFIER.match(name):
            raise ValueError(f"Unsafe column identifier: {name!r}")
        if not _SAFE_COLUMN_DDL.match(ddl):
            raise ValueError(f"Unsafe column DDL for {name!r}: {ddl!r}")
        if name not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def ensure_default_tenant(
    con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT
) -> str:
    """Bootstrap a tenant's rows: tenant, identity, stores, org, namespaces.

    tenant_id is a PARAMETER, not a constant. The tenant-sanitization pass
    parameterized every caller -- ensure_org_shared_namespace(con, tenant_id),
    ensure_all_users_namespace(con, tenant_id) -- while this function kept
    `tenant_id = DEFAULT_TENANT` hardcoded. So a caller working on tenant "asg"
    bootstrapped tenant "default", then inserted a namespace referencing
    org_store_id("asg"), a store that was never created:

        sqlite3.IntegrityError: FOREIGN KEY constraint failed

    That single mismatch accounted for the largest cluster of the 60 failures
    (12 in test_capmesh, 4 in test_vault_placement, more elsewhere).

    Fixed here rather than by restoring the old hardcoded tenant name, because
    the callers are right: bootstrap must serve whichever tenant it is asked
    about. Hardcoding would have re-broken multi-tenancy to make the symptom go
    away.
    """
    # Read-first fast path: if the default tenant is already bootstrapped, skip ALL the
    # writes below so secondary processes (serve-http, CLI ingest) can start read-only and
    # do not contend for a write lock against a long-lived holder (e.g. the gateway backend).
    # WAL + busy_timeout only help when a write is genuinely needed; a fully-initialized DB
    # must not attempt writes just to start. First-time init (no row) still falls through.
    try:
        _row = con.execute(
            "SELECT display_name, status FROM tenants WHERE id = ?", (tenant_id,)
        ).fetchone()
    except sqlite3.OperationalError:
        _row = None  # tenants table not created yet (first init) — fall through to writes
    if _row is not None:
        _dn = _row["display_name"] if hasattr(_row, "keys") else _row[0]
        _st = _row["status"] if hasattr(_row, "keys") else _row[1]
        if _st == "active" and _dn == DEFAULT_ORG_DISPLAY_NAME:
            return tenant_id
    con.execute(
        """
        INSERT OR IGNORE INTO tenants(id, slug, display_name, status)
        VALUES (?, ?, ?, 'active')
        """,
        # slug follows the tenant being bootstrapped, not the module default --
        # otherwise every tenant row would carry the default tenant's slug.
        (tenant_id, tenant_id, DEFAULT_ORG_DISPLAY_NAME),
    )
    con.execute(
        """
        UPDATE tenants
        SET display_name = ?, status = 'active', updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (DEFAULT_ORG_DISPLAY_NAME, tenant_id),
    )
    default_identity_id = default_user_identity_id(tenant_id)
    con.execute(
        """
        INSERT OR IGNORE INTO identities(id, tenant_id, external_id, user_name, display_name, email, identity_type, active, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, 'human', 1, ?)
        """,
        (
            default_identity_id,
            tenant_id,
            DEFAULT_USER_SUBJECT,
            DEFAULT_USER_SUBJECT,
            DEFAULT_USER_SUBJECT,
            DEFAULT_USER_SUBJECT,
            json_dumps({"defaultOwner": True}),
        ),
    )
    for kind, label, prefix in (
        ("user_private", "Private", default_user_store_prefix(tenant_id)),
        ("user_shared", "Shared", f"cap://user/{tenant_id}/{default_identity_id}/shared"),
    ):
        con.execute(
            """
            INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, owner_identity_id, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_id("store", tenant_id, kind, default_identity_id),
                tenant_id,
                kind,
                f"{DEFAULT_USER_SUBJECT} {label}",
                prefix,
                default_identity_id,
                json_dumps({"auto": True, "defaultOwner": True}),
            ),
        )
    private_store_id = default_user_private_store_id(tenant_id)
    con.execute(
        """
        INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, 'personal', ?, 'protected', ?, 'Default private namespace for current ingested capabilities.', ?)
        """,
        (
            default_user_private_namespace_id(tenant_id),
            tenant_id,
            private_store_id,
            default_user_namespace_prefix(tenant_id),
            DEFAULT_USER_SUBJECT,
            json_dumps({"auto": True, "defaultOwner": True}),
        ),
    )
    org_store_id = stable_id("store", tenant_id, "org", DEFAULT_ORG_SLUG)
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, metadata_json)
        VALUES (?, ?, 'org', ?, ?, ?)
        """,
        (
            org_store_id,
            tenant_id,
            f"{DEFAULT_ORG_DISPLAY_NAME} Org Store",
            f"cap://org/{tenant_id}/{DEFAULT_ORG_SLUG}",
            json_dumps({"auto": True, "defaultOrg": True}),
        ),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO organizations(id, tenant_id, slug, display_name, store_id, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            stable_id("org", tenant_id, DEFAULT_ORG_SLUG),
            tenant_id,
            DEFAULT_ORG_SLUG,
            DEFAULT_ORG_DISPLAY_NAME,
            org_store_id,
            json_dumps({"defaultOrg": True}),
        ),
    )
    system_store_id = stable_id("store", tenant_id, "system", "system")
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, metadata_json)
        VALUES (?, ?, 'system', 'System Governance', ?, ?)
        """,
        (system_store_id, tenant_id, f"cap://system/{tenant_id}", json_dumps({"managed": True})),
    )
    system_namespace_id = stable_id("ns", tenant_id, system_store_id, "system")
    con.execute(
        """
        INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, 'system', ?, 'protected', 'asg-platform', 'Built-in governance capabilities.', ?)
        """,
        (system_namespace_id, tenant_id, system_store_id, f"cap://system/{tenant_id}", json_dumps({"managed": True})),
    )
    # All-user ("everyone") store: tenant-wide, read-only for every authenticated
    # tenant user (discover/load/call granted by all_users_store_grant). Platform-owned
    # (owner_identity_id NULL) so no ordinary user can write/manage it. Exactly one
    # per tenant via the fixed UNIQUE uri_prefix cap://all/<tenant>.
    all_store_id = all_users_store_id(tenant_id)
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, owner_identity_id, metadata_json)
        VALUES (?, ?, 'all_users', ?, ?, NULL, ?)
        """,
        (
            all_store_id,
            tenant_id,
            f"{DEFAULT_ORG_DISPLAY_NAME} All Users Store",
            all_users_store_prefix(tenant_id),
            json_dumps({"auto": True, "allUsers": True}),
        ),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, 'everyone', ?, 'internal', 'asg-platform', 'Tenant-wide capabilities visible to every authenticated user.', ?)
        """,
        (
            all_users_namespace_id(tenant_id),
            tenant_id,
            all_store_id,
            all_users_namespace_prefix(tenant_id),
            json_dumps({"auto": True, "allUsers": True}),
        ),
    )
    return tenant_id


def ensure_platform_superadmins(con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT) -> None:
    """Idempotently enforce the operator-approved tenant superadmins.

    The deterministic assignment id prevents duplicate grants across concurrent
    service workers. A read-first path avoids taking SQLite's global write lock
    after the grants are correct.
    """

    for subject in superadmin_subjects():
        assignment_id = stable_id("rol", tenant_id, "platform-superadmin", subject)
        row = con.execute(
            """
            SELECT subject_type, subject_id, role, scope_type, scope_id, source, revoked_at
            FROM role_assignments WHERE id = ?
            """,
            (assignment_id,),
        ).fetchone()
        correct = bool(
            row is not None
            and row["subject_type"] == "user"
            and row["subject_id"] == subject
            and row["role"] == "platform_admin"
            and row["scope_type"] == "tenant"
            and row["scope_id"] == tenant_id
            and row["source"] == "operator-policy"
            and row["revoked_at"] is None
        )
        if correct:
            continue
        con.execute(
            """
            INSERT INTO role_assignments(
                id, tenant_id, subject_type, subject_id, role, scope_type,
                scope_id, source, created_by, revoked_at, updated_at
            ) VALUES (?, ?, 'user', ?, 'platform_admin', 'tenant', ?,
                      'operator-policy', 'capmesh-system', NULL, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                tenant_id=excluded.tenant_id,
                subject_type=excluded.subject_type,
                subject_id=excluded.subject_id,
                role=excluded.role,
                scope_type=excluded.scope_type,
                scope_id=excluded.scope_id,
                source=excluded.source,
                created_by=excluded.created_by,
                revoked_at=NULL,
                updated_at=CURRENT_TIMESTAMP
            """,
            (assignment_id, tenant_id, subject, tenant_id),
        )
        audit_event(
            con,
            event_type="role.operator_policy_enforced",
            actor="capmesh-system",
            actor_type="service",
            target=assignment_id,
            action="assign",
            decision="allow",
            payload={"subject": subject, "role": "platform_admin", "scope": f"tenant:{tenant_id}"},
            tenant_id=tenant_id,
        )


def ensure_local_service_org_access(con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT) -> None:
    """Grant the authoritative node service identity least-privilege default-org access.

    The static service bearer authenticates as ``app:capmesh-service``.  Its
    principal role describes what the application may do, while this audited,
    org-scoped assignment determines where it may do it.  Keeping the grant at
    ``app_service`` (rather than an admin role) permits discover/load/call/
    delegate without publish, approve, or manage rights.
    """

    org_id = stable_id("org", tenant_id, DEFAULT_ORG_SLUG)
    assignment_id = stable_id(
        "rol", tenant_id, "local-service-org-access", LOCAL_SERVICE_APP_ID, org_id
    )
    row = con.execute(
        """
        SELECT subject_type, subject_id, role, scope_type, scope_id, source, revoked_at
        FROM role_assignments WHERE id = ?
        """,
        (assignment_id,),
    ).fetchone()
    correct = bool(
        row is not None
        and row["subject_type"] == "app"
        and row["subject_id"] == LOCAL_SERVICE_APP_ID
        and row["role"] == "app_service"
        and row["scope_type"] == "org"
        and row["scope_id"] == org_id
        and row["source"] == "authority-policy"
        and row["revoked_at"] is None
    )
    if correct:
        return
    con.execute(
        """
        INSERT INTO role_assignments(
            id, tenant_id, subject_type, subject_id, role, scope_type,
            scope_id, source, created_by, revoked_at, updated_at
        ) VALUES (?, ?, 'app', ?, 'app_service', 'org', ?,
                  'authority-policy', 'capmesh-system', NULL, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id=excluded.tenant_id,
            subject_type=excluded.subject_type,
            subject_id=excluded.subject_id,
            role=excluded.role,
            scope_type=excluded.scope_type,
            scope_id=excluded.scope_id,
            source=excluded.source,
            created_by=excluded.created_by,
            revoked_at=NULL,
            updated_at=CURRENT_TIMESTAMP
        """,
        (assignment_id, tenant_id, LOCAL_SERVICE_APP_ID, org_id),
    )
    audit_event(
        con,
        event_type="role.authority_policy_enforced",
        actor="capmesh-system",
        actor_type="service",
        target=assignment_id,
        action="assign",
        decision="allow",
        payload={
            "subject": f"app:{LOCAL_SERVICE_APP_ID}",
            "role": "app_service",
            "scope": f"org:{org_id}",
        },
        tenant_id=tenant_id,
    )


def corporate_identity_id(tenant_id: str, email: str, provider_subject: str) -> str:
    """Federate verified ASG identities across Tailscale, Entra, and Google.

    Provider subject identifiers remain the authentication authority. Only a
    signature-verified corporate-domain email is used as the cross-provider
    Capmesh identity key; invited external Google accounts remain keyed by the
    provider's stable ``sub`` value.
    """

    normalized_email = email.strip().lower()
    identity_key = normalized_email if normalized_email.endswith(f"@{CORPORATE_EMAIL_DOMAIN}") else provider_subject
    return stable_id("idn", tenant_id, identity_key)


def default_user_identity_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("idn", tenant_id, DEFAULT_USER_SUBJECT)


def default_user_private_store_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("store", tenant_id, "user_private", default_user_identity_id(tenant_id))


def default_user_private_namespace_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("ns", tenant_id, default_user_private_store_id(tenant_id), "personal")


def default_user_store_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    return f"cap://user/{tenant_id}/{default_user_identity_id(tenant_id)}/private"


def all_users_store_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("store", tenant_id, "all_users", "all")


def all_users_store_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    # One per tenant; deterministic and NOT store_id-suffixed so the UNIQUE
    # stores.uri_prefix constraint allows exactly one all_users store per tenant.
    return f"cap://all/{tenant_id}"


def all_users_namespace_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("ns", tenant_id, all_users_store_id(tenant_id), "everyone")


def all_users_namespace_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    return f"cap://all/{tenant_id}/everyone"


def default_user_namespace_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    return f"{default_user_store_prefix(tenant_id)}/personal"


def org_store_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("store", tenant_id, "org", DEFAULT_ORG_SLUG)


def org_store_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    return f"cap://org/{tenant_id}/{DEFAULT_ORG_SLUG}"


def org_shared_namespace_id(tenant_id: str = DEFAULT_TENANT) -> str:
    return stable_id("ns", tenant_id, org_store_id(tenant_id), "shared")


def org_shared_namespace_prefix(tenant_id: str = DEFAULT_TENANT) -> str:
    return f"{org_store_prefix(tenant_id)}/shared"


def ensure_org_shared_namespace(con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT) -> str:
    """Ensure the org-shared namespace (and its org store) exist; return its id.

    ``ensure_default_tenant`` already creates the org store + organization row for
    the tenant it is given, so this only has to backfill the ``shared`` namespace
    used as the org vault target. It must be given THIS tenant -- the namespace
    insert below has a foreign key onto org_store_id(tenant_id).
    """
    ensure_default_tenant(con, tenant_id)
    ns_id = org_shared_namespace_id(tenant_id)
    con.execute(
        """
        INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, 'shared', ?, 'internal', 'asg-platform', 'Org-internal shared capabilities promoted via the vault-placement manifest.', ?)
        """,
        (
            ns_id,
            tenant_id,
            org_store_id(tenant_id),
            org_shared_namespace_prefix(tenant_id),
            json_dumps({"auto": True, "vaultPlacement": True}),
        ),
    )
    return ns_id


def ensure_all_users_namespace(con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT) -> str:
    """Ensure the tenant-wide all-user ('everyone') namespace exists; return its id."""
    ensure_default_tenant(con, tenant_id)
    return all_users_namespace_id(tenant_id)


def slug(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "unnamed"


def user_namespace_capability_uri(capability: Capability) -> str:
    plugin = slug(capability.plugin or "global")
    name = slug(capability.name)
    version = "".join(
        ch.lower() if ch.isalnum() or ch in ".-" else "-"
        for ch in (capability.version or "0.1.0")
    ).strip(".-") or "0.1.0"
    return f"{default_user_namespace_prefix(capability.tenant_id or DEFAULT_TENANT)}/{capability.capability_type}/{plugin}.{name}@{version}"


def apply_default_user_namespace(capability: Capability) -> Capability:
    if capability.source_kind == "system_capability" or capability.uri.startswith("cap://system/"):
        return capability
    tenant_id = capability.tenant_id or DEFAULT_TENANT
    current_uri = capability.uri
    if current_uri.startswith(("cap://user/", "cap://org/", "cap://app/", "cap://all/")):
        return replace(capability, tenant_id=tenant_id)
    target_prefix = default_user_namespace_prefix(tenant_id).rstrip("/") + "/"
    should_rewrite_uri = not current_uri.startswith(target_prefix)
    metadata = dict(capability.metadata)
    metadata["defaultUserNamespace"] = True
    metadata.setdefault("originalUri", current_uri)
    metadata.setdefault("originalOwner", capability.owner)
    return replace(
        capability,
        uri=user_namespace_capability_uri(capability) if should_rewrite_uri else current_uri,
        tenant_id=tenant_id,
        store_id=default_user_private_store_id(tenant_id),
        namespace_id=default_user_private_namespace_id(tenant_id),
        visibility="protected",
        discovery_mode="hidden",
        owner=DEFAULT_USER_SUBJECT,
        created_by=DEFAULT_USER_SUBJECT,
        approval_state="draft" if capability.approval_state in {"published", "approved"} else capability.approval_state,
        lifecycle="draft" if capability.lifecycle in {"active", "published"} else capability.lifecycle,
        metadata=metadata,
    )


def capability_canonical_tail(capability: Capability) -> str:
    """Return the ``{type}/{plugin}.{name}@{version}`` tail used to match a cap
    against the vault-placement manifest, independent of which namespace prefix
    it currently lives under."""
    full = user_namespace_capability_uri(capability)
    prefix = default_user_namespace_prefix(capability.tenant_id or DEFAULT_TENANT).rstrip("/") + "/"
    return full.removeprefix(prefix)


def load_vault_placement_index(path: str | Path) -> dict[str, str]:
    """Load vault-placement.json into a {canonical_tail: vault} index.

    Tolerant of an absent file (returns an empty index = no-op). The manifest is
    keyed by the placement *target* URI; we index by canonical tail so the lookup
    works against a freshly-ingested cap before its URI has been rewritten.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"[capmesh] warning: failed to read vault placement manifest {p}: {exc}\n")
        return {}
    index: dict[str, str] = {}
    for entry in data.get("placements", []):
        uri = str(entry.get("uri") or "")
        vault = str(entry.get("vault") or "")
        if not uri or vault not in {"org", "all"}:
            continue
        index[_vault_match_key(_manifest_uri_tail(uri))] = vault
    return index


def builtin_system_capabilities() -> list[Capability]:
    package = normalize_path(Path(__file__).resolve().parent)
    caps: list[Capability] = []
    for name, description, uri, risk_tier, rights in SYSTEM_CAPABILITIES:
        caps.append(
            Capability(
                uri=uri,
                capability_type="workflow",
                name=name,
                version="0.1.0",
                title=name.replace(".", " ").title(),
                description=description,
                package_path=package,
                entrypoint="governance.py",
                source_path=normalize_path(Path(__file__).resolve()),
                source_kind="system_capability",
                source_system="capmesh.system",
                canonical_key=f"workflow:system:{name}:0.1.0",
                content_hash="sha256:" + hashlib.sha256(f"{name}:{description}".encode()).hexdigest(),
                visibility="protected" if name not in {"system.me", "system.requests", "system.help", "system.onboard", "system.auth", "system.capabilities"} else "internal",
                discovery_mode="locked" if risk_tier == "high" else "public",
                owner="asg-platform",
                plugin="capmesh-system",
                category="governance",
                keywords=("governance", "identity", "namespace", "store", "approval", name),
                required_scopes=tuple(f"cap.{right}:system" for right in rights if right not in {"discover", "load", "call"}),
                risk_tier=risk_tier,
                mutating=name in {"system.auth", "system.capabilities", "system.stores", "system.namespaces", "system.share", "system.submit", "system.gates", "system.approve", "system.roles", "system.sync"},
                lifecycle="published",
                tenant_id=DEFAULT_TENANT,
                store_id=stable_id("store", DEFAULT_TENANT, "system", "system"),
                namespace_id=stable_id("ns", DEFAULT_TENANT, stable_id("store", DEFAULT_TENANT, "system", "system"), "system"),
                created_by="capmesh-system",
                approval_state="approved",
                signature_status="system",
                provenance_status="system",
                risk_review_status="approved",
                metadata={"systemCapability": True, "rights": list(rights)},
            )
        )
    return caps


def ensure_identity_for_principal(con: sqlite3.Connection, principal: Principal) -> str:
    subject = principal.subject or ""
    subject = subject[:256] if len(subject) > 256 else subject
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    identity_id = principal.identity_id or stable_id("idn", tenant_id, subject)
    email = principal.email or (subject if "@" in subject else None)
    user_name = principal.subject
    display_name = principal.display_name or principal.subject

    # raw_json is built LAZILY. Serialising principal.to_dict() on every call cost a JSON
    # encode per request purely to have something to compare against, on the hottest path in
    # the service. The cheap scalar columns below discriminate almost every real case, so the
    # encode only happens when they all match (or when we are actually about to write).
    _raw_json: str | None = None

    def raw_json_value() -> str:
        nonlocal _raw_json
        if _raw_json is None:
            _raw_json = json_dumps({"principal": principal.to_dict()})
        return _raw_json

    # FAST PATH: return without writing when this identity is already correct.
    #
    # This function used to run its INSERT ... ON CONFLICT DO UPDATE unconditionally, so
    # EVERY call wrote — even when nothing had changed. /api/v1/whoami calls it, commits,
    # then calls list_stores() which calls it AGAIN: two writes plus a commit per request.
    # Twelve worker processes share one SQLite file and therefore one write lock, so those
    # writes serialize globally. Measured 2026-07-19: 24 concurrent whoami requests through
    # the nginx LB produced 144/144 failures, every one exceeding a 20s client timeout, and
    # left the write lock wedged. /health stayed green throughout because it never writes,
    # which is why this was invisible for so long.
    #
    # busy_timeout was NOT the problem — it is already 60s (index.py). The requests were not
    # erroring, they were queueing behind each other and outliving the client.
    #
    # Identity provisioning is genuinely first-contact work. Reading first turns the steady
    # state (same user, unchanged attributes) into a pure read, which WAL serves concurrently
    # without taking the write lock at all. The write still happens on real first contact and
    # on any attribute change, so behaviour is unchanged — only the redundant writes go away.
    row = con.execute(
        "SELECT user_name, display_name, email, identity_type, active, raw_json "
        "FROM identities WHERE id = ? AND tenant_id = ?",
        (identity_id, tenant_id),
    ).fetchone()
    if row is not None:
        # COALESCE semantics below mean a NULL incoming value never clears a stored one;
        # mirror that here or the fast path would diverge from the write path.
        unchanged = (
            row["user_name"] == user_name
            and (display_name is None or row["display_name"] == display_name)
            and (email is None or row["email"] == email)
            and row["identity_type"] == "human"
            and int(row["active"] or 0) == 1
            # LAST on purpose: `and` short-circuits, so the JSON encode only runs when every
            # cheap scalar above already matched.
            and row["raw_json"] == raw_json_value()
        )
        if unchanged:
            # ensure_principal_stores() issues INSERT OR IGNORE against stores and
            # namespaces. "OR IGNORE" still opens a write transaction and takes the
            # single global write lock even when every row already exists, so calling
            # it here would leave most of the contention in place. Both stores are
            # created together and never removed independently, so their presence is a
            # sound proxy for "provisioning already done".
            provisioned = con.execute(
                "SELECT COUNT(*) AS n FROM stores WHERE tenant_id = ? AND owner_identity_id = ? "
                "AND kind IN ('user_private','user_shared')",
                (tenant_id, identity_id),
            ).fetchone()
            if provisioned is not None and int(provisioned["n"] or 0) >= 2:
                return identity_id
            ensure_principal_stores(con, principal, identity_id)
            return identity_id

    ensure_default_tenant(con)
    con.execute(
        """
        INSERT INTO identities(id, tenant_id, external_id, user_name, display_name, email, identity_type, active, raw_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'human', 1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            user_name=excluded.user_name,
            display_name=COALESCE(excluded.display_name, identities.display_name),
            email=COALESCE(excluded.email, identities.email),
            active=excluded.active,
            raw_json=excluded.raw_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            identity_id,
            tenant_id,
            principal.subject,
            principal.subject,
            principal.display_name or principal.subject,
            email,
            raw_json_value(),
        ),
    )
    ensure_principal_stores(con, principal, identity_id)
    return identity_id


def ensure_principal_stores(con: sqlite3.Connection, principal: Principal, identity_id: str | None = None) -> None:
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    identity_id = identity_id or principal.identity_id or stable_id("idn", tenant_id, principal.subject)
    safe_subject = principal.subject.replace("/", "_").replace(":", "_")
    for kind, label, prefix in (
        ("user_private", "Private", f"cap://user/{tenant_id}/{identity_id}/private"),
        ("user_shared", "Shared", f"cap://user/{tenant_id}/{identity_id}/shared"),
    ):
        store_id = stable_id("store", tenant_id, kind, identity_id)
        con.execute(
            """
            INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, owner_identity_id, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (store_id, tenant_id, kind, f"{safe_subject} {label}", prefix, identity_id, json_dumps({"auto": True})),
        )
        default_namespace = "personal" if kind == "user_private" else "shared"
        con.execute(
            """
            INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
            VALUES (?, ?, ?, ?, ?, 'protected', ?, ?, ?)
            """,
            (
                stable_id("ns", tenant_id, store_id, default_namespace),
                tenant_id,
                store_id,
                default_namespace,
                f"{prefix}/{default_namespace}",
                principal.subject,
                f"Default {label.lower()} namespace for {principal.subject}.",
                json_dumps({"auto": True}),
            ),
        )
    org_store_id = stable_id("store", tenant_id, "org", DEFAULT_ORG_SLUG)
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, metadata_json)
        VALUES (?, ?, 'org', ?, ?, ?)
        """,
        (
            org_store_id,
            tenant_id,
            f"{DEFAULT_ORG_DISPLAY_NAME} Org Store",
            f"cap://org/{tenant_id}/{DEFAULT_ORG_SLUG}",
            json_dumps({"auto": True, "defaultOrg": True}),
        ),
    )
















































def audit_event(
    con: sqlite3.Connection,
    *,
    event_type: str,
    actor: str,
    target: str | None = None,
    action: str | None = None,
    decision: str | None = None,
    reason: str | None = None,
    payload: dict[str, Any] | None = None,
    tenant_id: str = DEFAULT_TENANT,
    actor_type: str = "user",
) -> str:
    event_id = new_id("aud")
    con.execute(
        """
        INSERT INTO audit_events(id, tenant_id, event_type, actor, actor_type, target, action, decision, reason, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, tenant_id, event_type, actor, actor_type, target, action, decision, reason, json_dumps(payload or {})),
    )
    # Mirror capability-specific mutations into the tamper-evident hash-chained
    # registry log so that governance actions are independently verifiable.
    # Direct INSERT (no executescript) to avoid implicit COMMIT that would
    # release savepoints in the caller's transaction.  The registry_log table
    # is created by init_governance_schema; if it does not exist yet (e.g.
    # in a minimal test fixture), the INSERT is silently skipped.
    if event_type.startswith("capability.") and action and action not in (None, "read", "list", "status"):
        try:
            from .registry_log import _compute_entry_hash
            last = con.execute(
                "SELECT sequence, entry_hash FROM registry_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if last is None:
                _seq, _prev = 1, None
            else:
                _seq, _prev = int(last["sequence"]) + 1, str(last["entry_hash"])
            _payload_str = json_dumps({"decision": decision, "reason": reason, **(payload or {})})
            _entry_hash = _compute_entry_hash(_seq, event_type, actor, target, action, _payload_str, _prev)
            con.execute(
                """INSERT INTO registry_log(id, sequence, event_type, actor, target_uri, action, payload_json, prev_hash, entry_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_id("rlog"), _seq, event_type, actor, target, action, _payload_str, _prev, _entry_hash, utc_now()),
            )
        except Exception:  # noqa: BLE001, S110
            pass
    return event_id


def current_user(con: sqlite3.Connection, principal: Principal) -> dict[str, Any]:
    identity_id = ensure_identity_for_principal(con, principal)
    # Commit ONLY if that actually wrote. con.in_transaction is False when the fast path
    # took no write, and committing nothing still costs a round trip through SQLite on the
    # hottest endpoint in the service. Correctness is unchanged: if a write did happen,
    # in_transaction is True and we commit exactly as before.
    if con.in_transaction:
        con.commit()
    return {
        "tenant": principal.tenant_id,
        "subject": principal.subject,
        "identityId": identity_id,
        "email": principal.email,
        "groups": list(principal.groups),
        "roles": list(principal.roles),
        # ensure=False: ensure_identity_for_principal ran three lines up. Re-running it here
        # repeated two SELECTs per request for a guarantee already established in this call.
        "stores": list_stores(con, principal, ensure=False),
        # Include namespace ownership info so the UI can show which
        # namespaces a user owns.  Non-fatal if the module is unavailable.
        "namespaceOwnership": _namespace_ownership_safe(con, principal),
    }


def _namespace_ownership_safe(con, principal):
    """Return namespace ownership info, non-fatal on failure."""
    try:
        from .namespace_owners import namespaces_by_owner
        return namespaces_by_owner(con, principal.subject, tenant_id=principal.tenant_id or DEFAULT_TENANT)
    except Exception:  # noqa: BLE001
        return []


def manage_capability(con: sqlite3.Connection, principal: Principal, args: dict[str, Any]) -> dict[str, Any]:
    action = str(args.get("action") or "template")
    if action == "template":
        return capability_template()
    if action in {"draft.create", "create"}:
        return create_capability_draft(con, principal, args)
    if action in {"draft.update", "update"}:
        return update_capability_draft(con, principal, args)
    if action in {"draft.diff", "diff"}:
        return diff_capability_draft(con, principal, args)
    if action in {"validate", "draft.validate"}:
        return validate_capability_draft(con, principal, args)
    if action in {"publish-private", "draft.publish-private"}:
        return publish_private_capability(con, principal, args)
    if action == "share":
        return create_share(con, principal, args)
    if action == "submit":
        return submit_promotion(con, principal, args)
    if action in {"prepare-pr", "git.pr.prepare"}:
        return prepare_capability_pr(con, principal, args)
    raise ValueError(f"Unsupported capability action: {action}")


def capability_template() -> dict[str, Any]:
    return {
        "required": ["name", "title", "description", "content"],
        "optional": ["type", "version", "plugin", "category", "keywords", "riskTier", "entrypoint", "namespaceId", "storeId"],
        "defaults": {"type": "workflow", "version": "0.1.0", "riskTier": "low", "entrypoint": "CAPABILITY.md"},
        "actions": ["draft.create", "draft.update", "draft.diff", "validate", "publish-private", "share", "submit", "prepare-pr"],
        "notes": [
            "Private/shared draft edits are stored in the capmesh state directory and audited.",
            "Org namespace promotion must go through submit/approve and Git-backed review.",
            "On the authoritative node, a superadmin create is approved immediately when every mandatory gate passes; no second approval is requested.",
        ],
    }


def create_capability_draft(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    tenant_id = principal.tenant_id or DEFAULT_TENANT
    identity_id = ensure_identity_for_principal(con, principal)
    name = slug(str(payload.get("name") or ""))
    title = str(payload.get("title") or "").strip()
    description = str(payload.get("description") or "").strip()
    content = str(payload.get("content") or "")
    capability_type = str(payload.get("type") or payload.get("capabilityType") or "workflow")
    if not name or not title or not description or not content:
        raise ValueError("name, title, description, and content are required.")
    if capability_type not in {"skill", "agent", "plugin", "command", "mcp_server", "workflow", "reference", "bundle"}:
        raise ValueError("Unsupported capability type.")
    store_id = str(payload.get("storeId") or stable_id("store", tenant_id, "user_private", identity_id))
    namespace_id = str(payload.get("namespaceId") or stable_id("ns", tenant_id, store_id, "personal"))
    store = con.execute("SELECT * FROM stores WHERE id = ? AND tenant_id = ?", (store_id, tenant_id)).fetchone()
    if store is None:
        raise ValueError("Target store not found.")
    if store["kind"] in {"org", "system"}:
        allowed, reason = evaluate_access(con, principal, right="manage", resource_uri=f"store:{store_id}")
        if not allowed:
            raise PermissionError(reason)
    draft_id = stable_id("capdraft", tenant_id, principal.subject, capability_type, name, payload.get("version") or "0.1.0")
    entrypoint = safe_entrypoint(str(payload.get("entrypoint") or "CAPABILITY.md"))
    draft_dir = state_dir() / "drafts" / draft_id
    draft_dir.mkdir(parents=True, exist_ok=True)
    draft_file = draft_dir / entrypoint
    draft_file.parent.mkdir(parents=True, exist_ok=True)
    draft_file.write_text(content, encoding="utf-8")
    namespace = con.execute("SELECT * FROM namespaces WHERE id = ? AND tenant_id = ?", (namespace_id, tenant_id)).fetchone()
    if namespace is None:
        raise ValueError("Target namespace not found.")
    version = normalize_version(str(payload.get("version") or "0.1.0"))
    uri = str(payload.get("uri") or f"{namespace['uri_prefix'].rstrip('/')}/{capability_type}/{name}@{version}")
    metadata = {
        "draft": True,
        "editable": True,
        "source": "system.capabilities",
        "validation": validate_capability_payload(payload, content),
    }
    cap = Capability(
        uri=uri,
        capability_type=capability_type,
        name=name,
        version=version,
        title=title,
        description=description,
        package_path=normalize_path(draft_dir),
        entrypoint=entrypoint,
        source_path=normalize_path(draft_file),
        source_kind="capmesh_draft",
        source_system="capmesh.system",
        canonical_key=f"{capability_type}:capmesh-draft:{tenant_id}:{principal.subject}:{name}:{version}",
        content_hash="sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
        visibility=str(payload.get("visibility") or "protected"),
        discovery_mode=str(payload.get("discoveryMode") or "hidden"),
        owner=principal.subject,
        plugin=payload.get("plugin"),
        category=payload.get("category"),
        keywords=tuple(str(item) for item in payload.get("keywords") or (name,)),
        risk_tier=str(payload.get("riskTier") or "low"),
        lifecycle="draft",
        tenant_id=tenant_id,
        store_id=store_id,
        namespace_id=namespace_id,
        created_by=principal.subject,
        approval_state="draft",
        metadata=metadata,
    )
    from .index import upsert_capability

    upsert_capability(con, cap)
    audit_event(con, event_type="capability.draft.created", actor=principal.subject, target=uri, action="draft.create", decision="allow", payload={"name": name}, tenant_id=tenant_id)
    con.commit()
    return {"capability": cap.to_record(include_paths=True), "validation": metadata["validation"]}


def update_capability_draft(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    cap = require_capability_for_edit(con, principal, payload)
    content = str(payload.get("content") or Path(cap.source_path).read_text(encoding="utf-8"))
    if payload.get("content") is not None:
        Path(cap.source_path).write_text(content, encoding="utf-8")
    metadata = dict(cap.metadata)
    validation_payload = {
        "name": payload.get("name") or cap.name,
        "title": payload.get("title") or cap.title,
        "description": payload.get("description") or cap.description,
        "riskTier": payload.get("riskTier") or cap.risk_tier,
    }
    metadata["validation"] = validate_capability_payload(validation_payload, content)
    updated = Capability(
        **{
            **cap.__dict__,
            "title": str(payload.get("title") or cap.title),
            "description": str(payload.get("description") or cap.description),
            "keywords": tuple(str(item) for item in payload.get("keywords") or cap.keywords),
            "risk_tier": str(payload.get("riskTier") or cap.risk_tier),
            "content_hash": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "metadata": metadata,
        }
    )
    from .index import upsert_capability

    upsert_capability(con, updated)
    audit_event(con, event_type="capability.draft.updated", actor=principal.subject, target=cap.uri, action="draft.update", decision="allow", tenant_id=principal.tenant_id or DEFAULT_TENANT)
    con.commit()
    return {"capability": updated.to_record(include_paths=True), "validation": metadata["validation"]}


def diff_capability_draft(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    cap = require_capability_for_edit(con, principal, payload, right="load")
    current = Path(cap.source_path).read_text(encoding="utf-8")
    proposed = str(payload.get("content") or current)
    diff = list(difflib.unified_diff(current.splitlines(), proposed.splitlines(), fromfile="current", tofile="proposed", lineterm=""))
    return {"capabilityUri": cap.uri, "changed": current != proposed, "diff": diff[:400]}


def validate_capability_draft(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    cap = require_capability_for_edit(con, principal, payload, right="load")
    content = Path(cap.source_path).read_text(encoding="utf-8")
    result = validate_capability_payload({"name": cap.name, "title": cap.title, "description": cap.description, "riskTier": cap.risk_tier}, content)
    return {"capabilityUri": cap.uri, "valid": result["valid"], "checks": result["checks"], "warnings": result["warnings"]}


def publish_private_capability(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    cap = require_capability_for_edit(con, principal, payload)
    con.execute("UPDATE capabilities SET lifecycle = 'published', approval_state = 'draft', updated_at = CURRENT_TIMESTAMP WHERE uri = ?", (cap.uri,))
    audit_event(con, event_type="capability.private.published", actor=principal.subject, target=cap.uri, action="publish-private", decision="allow", tenant_id=principal.tenant_id or DEFAULT_TENANT)
    con.commit()
    return {"capabilityUri": cap.uri, "lifecycle": "published", "approvalState": "draft"}


def prepare_capability_pr(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
    cap = require_capability_for_edit(con, principal, payload, right="submit")
    out_dir = state_dir() / "pr-prep"
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = out_dir / f"{stable_id('prprep', cap.uri)}.json"
    data = {
        "capabilityUri": cap.uri,
        "title": str(payload.get("title") or f"Promote {cap.name}"),
        "branch": str(payload.get("branch") or f"capmesh/{slug(cap.name)}"),
        "sourcePath": cap.source_path,
        "packagePath": cap.package_path,
        "requestedBy": principal.subject,
        "checks": validate_capability_payload({"name": cap.name, "title": cap.title, "description": cap.description, "riskTier": cap.risk_tier}, Path(cap.source_path).read_text(encoding="utf-8")),
        "nextCommands": [
            "Create a git branch from this artifact.",
            "Add/update the source capability files.",
            "Run capmesh ingest, tests, retrieval evals, and submit the PR for governed review.",
        ],
    }
    artifact.write_text(json_dumps(data), encoding="utf-8")
    audit_event(con, event_type="capability.pr.prepared", actor=principal.subject, target=cap.uri, action="prepare-pr", decision="allow", payload={"artifact": str(artifact)}, tenant_id=principal.tenant_id or DEFAULT_TENANT)
    con.commit()
    return {"artifact": str(artifact), **data}


def require_capability_for_edit(con: sqlite3.Connection, principal: Principal, payload: dict[str, Any], *, right: str = "manage") -> Capability:
    identifier = str(payload.get("capabilityUri") or payload.get("uri") or payload.get("name") or "")
    if not identifier:
        raise ValueError("capabilityUri is required.")
    from .index import get_capability

    cap = get_capability(con, identifier)
    if cap is None:
        raise ValueError("Capability not found.")
    allowed, reason = evaluate_access(con, principal, right=right, capability=cap)
    if not allowed:
        raise PermissionError(reason)
    if right == "manage" and cap.approval_state == "approved" and not cap.store_id:
        raise PermissionError("Approved capabilities must be edited through prepare-pr.")
    return cap


def validate_capability_payload(payload: dict[str, Any], content: str) -> dict[str, Any]:
    warnings: list[str] = []
    checks = {
        "hasName": bool(str(payload.get("name") or "").strip()),
        "hasTitle": bool(str(payload.get("title") or "").strip()),
        "hasDescription": bool(str(payload.get("description") or "").strip()),
        "hasContent": bool(content.strip()),
        "riskTierKnown": str(payload.get("riskTier") or "low") in {"low", "medium", "high", "critical"},
    }
    found = scan_prompt_injection(content)
    if found:
        warnings.append("Potential prompt-injection wording found: " + ", ".join(found))
    checks["promptInjectionScan"] = not found
    return {"valid": all(checks.values()), "checks": checks, "warnings": warnings}


def safe_entrypoint(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("entrypoint must be a relative path inside the draft package.")
    return str(path)


def normalize_version(value: str) -> str:
    version = "".join(ch.lower() if ch.isalnum() or ch in ".-" else "-" for ch in value).strip(".-")
    return version or "0.1.0"


def dispatch_system_capability(con: sqlite3.Connection, capability: Capability, args: dict[str, Any], principal: Principal) -> dict[str, Any]:
    action = str(args.get("action") or "list")
    name = capability.name
    if name == "system.help":
        return help_payload(str(args.get("topic") or "overview"), base_url=str(args.get("baseUrl") or os.environ.get("CAPMESH_BASE_URL", "http://127.0.0.1:8000")))
    if name == "system.onboard":
        return onboarding_payload(
            base_url=str(args.get("baseUrl") or os.environ.get("CAPMESH_BASE_URL", "http://127.0.0.1:8000")),
            client=str(args.get("client") or "all"),
            direct=bool(args.get("direct", False)),
            tenant=principal.tenant_id or DEFAULT_TENANT,
        )
    if name == "system.auth":
        if action == "logout":
            return revoke_capmesh_session(con, principal, session_id=args.get("sessionId"))
        return auth_status(con, principal)
    if name == "system.capabilities":
        result = manage_capability(con, principal, args)
        if action in {"draft.create", "create"}:
            from .install_policy import configured_superadmin_auto_approval
            from .lifecycle import approve_catalog

            actor = configured_superadmin_auto_approval(principal.subject)
            if actor:
                approval = approve_catalog(
                    con,
                    Principal(subject=actor, tenant_id=principal.tenant_id or DEFAULT_TENANT, roles=("org_admin",)),
                )
                result["autoApproval"] = {
                    "policy": "superadmin-immediate-after-gates",
                    "actor": actor,
                    **approval,
                }
        return result
    if name == "system.me":
        return current_user(con, principal)
    if name == "system.stores":
        return create_store(con, principal, args) if action == "create" else {"items": list_stores(con, principal, args.get("kind"))}
    if name == "system.namespaces":
        return create_namespace(con, principal, args) if action == "create" else {"items": list_namespaces(con, principal, args.get("storeId"))}
    if name == "system.share":
        if action == "create":
            return create_share(con, principal, args)
        if action == "revoke":
            return revoke_share(con, principal, str(args.get("shareId") or args.get("id") or ""))
        return {"items": list_shares(con, principal, args.get("capabilityUri"))}
    if name == "system.submit":
        return submit_promotion(con, principal, args)
    if name == "system.requests":
        return {"items": list_requests(con, principal, args.get("state"))}
    if name == "system.gates":
        from .lifecycle import dispatch_gate_action

        return dispatch_gate_action(con, principal, args)
    if name == "system.approve":
        return approve_request(con, principal, args)
    if name == "system.roles":
        if action == "assign":
            return assign_role(con, principal, args)
        if action == "revoke":
            return revoke_role(con, principal, str(args.get("assignmentId") or args.get("id") or ""))
        return {"items": list_roles(con, principal)}
    if name == "system.audit":
        return {"items": list_audit_events(con, principal, int(args.get("limit") or 50))}
    if name == "system.sync":
        if action == "graph-subscription":
            return plan_graph_subscription(con, principal, args)
        if action == "teams-bind":
            return create_teams_binding(con, principal, args)
        if action == "teams-list":
            return {"items": list_teams_bindings(con, principal)}
        return sync_summary(con, principal)
    raise ValueError(f"Unknown system capability: {name}")
