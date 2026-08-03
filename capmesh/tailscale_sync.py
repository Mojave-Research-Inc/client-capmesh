"""Design (C) — Tailscale user/group mapping sync.

Maps verified tailnet users and their Tailscale ACL groups onto capmesh
identities and groups so that org membership (design B) and role grants can be
keyed on tailnet identity.

Sources, in preference order:
  1. Tailscale v2 API (OAuth client, scope ``users:read``) reading
     ``GET /api/v2/tailnet/<tailnet>/users`` and the tailnet ACL
     (``GET /api/v2/tailnet/<tailnet>/acl``) to enumerate ``group:*`` -> members.
     The OAuth client credentials are read at runtime from OpenBao path
     ``asg/services/tailscale-user-sync`` via ``bao-client`` — never embedded.
  2. Local ``tailscale status --json`` as a credential-free fallback (peer
     LoginName -> identity; no ACL groups available this way).

The sync is additive + prune and idempotent: it upserts every tailnet user as a
capmesh identity (``identities``), upserts each ACL group as a capmesh group
(``groups`` / ``group_members``), deactivates identities for suspended/removed
tailnet users (reusing the existing ``identities.active = 0`` deactivation path
so ``is_disabled()`` denies them), and prunes ``group_members`` rows whose
identity is no longer in the tailnet group. Progress is recorded in
``scim_sync_state`` with ``resource_type`` ``tailscale_user`` / ``tailscale_group``
so the existing ``sync_summary()`` surface reports tailscale counts with no
schema change.

Tags grant *groups* (for convenient bulk org membership) but never capmesh
roles/rights directly — privilege still flows only through audited
role_assignments (least privilege).
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import urllib.parse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import governance
from .governance import (
    DEFAULT_TENANT,
    audit_event,
    tag_to_group,
    upsert_group_from_tailnet,
    upsert_identity_from_tailnet,
)

VAULT_PATH = os.environ.get("CAPMESH_TAILSCALE_VAULT_PATH", "asg/services/tailscale-user-sync")
TAILSCALE_API_BASE = os.environ.get("CAPMESH_TAILSCALE_API_BASE", "https://api.tailscale.com")
TAILSCALE_OAUTH_TOKEN_URL = f"{TAILSCALE_API_BASE.rstrip('/')}/api/v2/oauth/token"
_HTTP_TIMEOUT = int(os.environ.get("CAPMESH_TAILSCALE_HTTP_TIMEOUT", "30"))


class TailscaleSyncError(RuntimeError):
    """Raised when the tailnet sync cannot proceed (no source reachable)."""


# --------------------------------------------------------------------------
# Secret + token acquisition
# --------------------------------------------------------------------------


def _bao_get(path: str, key: str) -> str | None:
    """Read a single secret value from OpenBao via bao-client. Never logged."""
    try:
        result = subprocess.run(
            ["bao-client", "get", path, key],
            capture_output=True,
            text=True,
            timeout=_HTTP_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = (result.stdout or "").strip()
    return value or None


def _oauth_credentials() -> tuple[str, str] | None:
    """Return (client_id, client_secret) from vault, or env override, or None."""
    client_id = os.environ.get("CAPMESH_TAILSCALE_CLIENT_ID") or _bao_get(VAULT_PATH, "client_id")
    client_secret = os.environ.get("CAPMESH_TAILSCALE_CLIENT_SECRET") or _bao_get(VAULT_PATH, "client_secret")
    if client_id and client_secret:
        return client_id, client_secret
    return None


def _acquire_token(client_id: str, client_secret: str) -> str:
    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }
    ).encode("utf-8")
    request = Request(
        TAILSCALE_OAUTH_TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=_HTTP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError) as exc:
        raise TailscaleSyncError(f"Tailscale OAuth token request failed: {exc}") from exc
    token = str(payload.get("access_token") or "")
    if not token:
        raise TailscaleSyncError("Tailscale OAuth response did not include an access_token.")
    return token


def _api_get(token: str, path: str) -> Any:
    url = f"{TAILSCALE_API_BASE.rstrip('/')}{path}"
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError) as exc:
        raise TailscaleSyncError(f"Tailscale API GET {path} failed: {exc}") from exc


# --------------------------------------------------------------------------
# Source fetchers
# --------------------------------------------------------------------------


def _resolve_tailnet(token: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    env_tailnet = os.environ.get("CAPMESH_TAILSCALE_TAILNET")
    if env_tailnet:
        return env_tailnet
    return "-"  # Tailscale API alias for "the default tailnet of the credential".


def _fetch_users(token: str, tailnet: str) -> list[dict[str, Any]]:
    data = _api_get(token, f"/api/v2/tailnet/{urllib.parse.quote(tailnet)}/users")
    users = data.get("users") if isinstance(data, dict) else data
    return [u for u in (users or []) if isinstance(u, dict)]


def _fetch_acl_groups(token: str, tailnet: str) -> dict[str, list[str]]:
    """Return {group_name: [member_login, ...]} from the tailnet ACL groups block."""
    try:
        acl = _api_get(token, f"/api/v2/tailnet/{urllib.parse.quote(tailnet)}/acl")
    except TailscaleSyncError:
        return {}
    groups = acl.get("groups") if isinstance(acl, dict) else None
    if not isinstance(groups, dict):
        return {}
    result: dict[str, list[str]] = {}
    for name, members in groups.items():
        if not isinstance(members, list):
            continue
        result[str(name)] = [str(m) for m in members if isinstance(m, str)]
    return result


def _fallback_status_users() -> list[dict[str, Any]]:
    """Credential-free fallback: derive users from `tailscale status --json`."""
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=_HTTP_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if result.returncode != 0 or not result.stdout:
        return []
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    seen: dict[str, dict[str, Any]] = {}
    for section in ("Self", "Peer"):
        block = status.get(section)
        if isinstance(block, dict) and section == "Self":
            block = {"self": block}
        if not isinstance(block, dict):
            continue
        for node in block.values():
            if not isinstance(node, dict):
                continue
            # status.json maps users by numeric id under "User"; resolve the login.
            user_map = status.get("User") or {}
            profile = user_map.get(str(node.get("UserID"))) if isinstance(user_map, dict) else None
            if isinstance(profile, dict):
                login_name = str(profile.get("LoginName") or "")
                if login_name:
                    seen[login_name] = {
                        "id": str(profile.get("ID") or login_name),
                        "loginName": login_name,
                        "displayName": profile.get("DisplayName") or login_name,
                        "type": "member",
                        "status": "active",
                        "_source": "tailscale-status",
                    }
    return list(seen.values())


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def run(
    con: sqlite3.Connection,
    *,
    tenant_id: str = DEFAULT_TENANT,
    tailnet: str | None = None,
    actor: str = "tailscale-sync",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the tailnet -> capmesh identity/group sync. Idempotent.

    Returns a JSON-serializable summary of users/groups processed and pruned.
    """
    audit_event(
        con,
        tenant_id=tenant_id,
        event_type="tailscale.sync.started",
        actor=actor,
        actor_type="system",
        target=f"tenant:{tenant_id}",
        action="sync",
        decision="allow",
        payload={"dryRun": dry_run, "source": "pending"},
    )

    creds = _oauth_credentials()
    source = "tailscale-api"
    users: list[dict[str, Any]] = []
    acl_groups: dict[str, list[str]] = {}

    if creds is not None:
        token = _acquire_token(*creds)
        resolved_tailnet = _resolve_tailnet(token, tailnet)
        users = _fetch_users(token, resolved_tailnet)
        acl_groups = _fetch_acl_groups(token, resolved_tailnet)
    else:
        source = "tailscale-status"
        users = _fallback_status_users()
        if not users:
            raise TailscaleSyncError(
                "No tailnet source available: vault OAuth creds at "
                f"'{VAULT_PATH}' are unreadable and `tailscale status --json` returned nothing."
            )

    summary: dict[str, Any] = {
        "tenantId": tenant_id,
        "source": source,
        "dryRun": dry_run,
        "usersSeen": len(users),
        "usersUpserted": 0,
        "usersDeactivated": 0,
        "groupsSeen": len(acl_groups),
        "groupsUpserted": 0,
        "groupMembersAdded": 0,
        "groupMembersPruned": 0,
    }

    # ---- Users -> identities -------------------------------------------
    login_to_identity: dict[str, str] = {}
    for user in users:
        login = str(user.get("loginName") or user.get("login") or "").strip().lower()
        if not login:
            continue
        external_id = str(user.get("id") or login)
        display_name = user.get("displayName") or login
        ts_type = str(user.get("type") or "member")
        ts_status = str(user.get("status") or "active").lower()
        active = ts_status not in {"suspended", "removed", "deactivated", "disabled"}
        if not dry_run:
            identity_id, was_deactivated = upsert_identity_from_tailnet(
                con,
                tenant_id=tenant_id,
                external_id=external_id,
                login_name=login,
                display_name=display_name,
                ts_type=ts_type,
                active=active,
                actor=actor,
            )
            login_to_identity[login] = identity_id
            if was_deactivated:
                summary["usersDeactivated"] += 1
        else:
            login_to_identity[login] = governance.stable_id("idn", tenant_id, external_id)
            if not active:
                summary["usersDeactivated"] += 1
        summary["usersUpserted"] += 1

    # ---- ACL groups -> groups / group_members --------------------------
    for group_name, member_logins in acl_groups.items():
        display_name = tag_to_group(group_name)
        member_identity_ids: list[str] = []
        for member in member_logins:
            login = member.strip().lower()
            if login.startswith("group:"):
                # Nested group references are skipped (flattened by Tailscale at
                # enforcement time; capmesh keys membership on concrete logins).
                continue
            ident = login_to_identity.get(login)
            if ident is None:
                # Materialize a thin identity so membership can be keyed on it
                # even if the user did not appear in the users list (e.g. ACL
                # references a login that status omitted).
                if not dry_run:
                    ident, _ = upsert_identity_from_tailnet(
                        con,
                        tenant_id=tenant_id,
                        external_id=login,
                        login_name=login,
                        display_name=login,
                        ts_type="member",
                        active=True,
                        actor=actor,
                    )
                else:
                    ident = governance.stable_id("idn", tenant_id, login)
                login_to_identity[login] = ident
            member_identity_ids.append(ident)
        if dry_run:
            summary["groupsUpserted"] += 1
            summary["groupMembersAdded"] += len(member_identity_ids)
            continue
        result = upsert_group_from_tailnet(
            con,
            tenant_id=tenant_id,
            external_id=group_name,
            display_name=display_name,
            member_identity_ids=member_identity_ids,
            actor=actor,
        )
        summary["groupsUpserted"] += 1
        summary["groupMembersAdded"] += result.get("added", 0)
        summary["groupMembersPruned"] += result.get("pruned", 0)

    if not dry_run:
        con.commit()

    audit_event(
        con,
        tenant_id=tenant_id,
        event_type="tailscale.sync.completed",
        actor=actor,
        actor_type="system",
        target=f"tenant:{tenant_id}",
        action="sync",
        decision="allow",
        payload={k: v for k, v in summary.items() if k != "tenantId"},
    )
    if not dry_run:
        con.commit()
    return summary
