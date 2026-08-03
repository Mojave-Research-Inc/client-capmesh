"""Tenant / store / namespace identity and provisioning helpers.

Extracted verbatim from ``governance.py`` (CM-12 decomposition) as a cohesive,
behavior-preserving seam: the deterministic id/uri-prefix derivations for the
default user, org, all-users and system namespaces, the default-tenant
provisioner, and the canonical-uri/default-namespace rewrite helpers.

``governance.py`` re-exports every public name defined here, so all existing
``capmesh.governance.X`` imports keep working unchanged. Pure move — no behavior
change.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import Capability

DEFAULT_TENANT = "asg"
DEFAULT_USER_SUBJECT = "jason@asgroup.ai"
DEFAULT_ORG_SLUG = "agentic-secure-group-inc"
DEFAULT_ORG_DISPLAY_NAME = "Agentic Secure Group Inc"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def expires_in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "\x1f".join(str(part) for part in parts if part is not None)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[capmesh] warning: failed to parse JSON: {exc}\n")
        return default


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


def ensure_default_tenant(con: sqlite3.Connection) -> str:
    tenant_id = DEFAULT_TENANT
    con.execute(
        """
        INSERT OR IGNORE INTO tenants(id, slug, display_name, status)
        VALUES (?, ?, ?, 'active')
        """,
        (tenant_id, DEFAULT_TENANT, DEFAULT_ORG_DISPLAY_NAME),
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
    org_store_id_value = stable_id("store", tenant_id, "org", DEFAULT_ORG_SLUG)
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, metadata_json)
        VALUES (?, ?, 'org', ?, ?, ?)
        """,
        (
            org_store_id_value,
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
            org_store_id_value,
            json_dumps({"defaultOrg": True}),
        ),
    )
    system_store_id = stable_id("store", tenant_id, "system", "system")
    con.execute(
        """
        INSERT OR IGNORE INTO stores(id, tenant_id, kind, name, uri_prefix, metadata_json)
        VALUES (?, ?, 'system', 'System Governance', 'cap://system/asg', ?)
        """,
        (system_store_id, tenant_id, json_dumps({"managed": True})),
    )
    system_namespace_id = stable_id("ns", tenant_id, system_store_id, "system")
    con.execute(
        """
        INSERT OR IGNORE INTO namespaces(id, tenant_id, store_id, name, uri_prefix, visibility, owner, description, metadata_json)
        VALUES (?, ?, ?, 'system', 'cap://system/asg', 'protected', 'asg-platform', 'Built-in governance capabilities.', ?)
        """,
        (system_namespace_id, tenant_id, system_store_id, json_dumps({"managed": True})),
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


def ensure_org_shared_namespace(con: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT) -> str:
    """Ensure the org-shared namespace (and its org store) exist; return its id.

    ``ensure_default_tenant`` already creates the org store + organization row, so
    this only has to backfill the ``shared`` namespace used as the org vault target.
    """
    ensure_default_tenant(con)
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
    ensure_default_tenant(con)
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
