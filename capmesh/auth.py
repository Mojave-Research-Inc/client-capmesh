from __future__ import annotations

import sqlite3

from .models import Capability, Principal


def can_discover(capability: Capability, principal: Principal, con: sqlite3.Connection | None = None, audit: bool = True) -> tuple[bool, bool]:
    """Return (visible_in_search, locked_stub).

    `audit=False` skips the policy-decision write for bulk discovery/visibility
    checks (called per-candidate on every cap.search). Auditing each discovery
    filter is both wrong-by-design and the cause of an uncommitted-write lock that
    serialized concurrent searches under the threaded HTTP server.
    """

    if capability.discovery_mode == "hidden" and not can_load(capability, principal, con=con, audit=audit)[0]:
        return False, False
    allowed, _ = can_load(capability, principal, con=con, audit=audit)
    if allowed:
        return True, False
    if capability.discovery_mode == "locked":
        return True, True
    return False, False


def can_load(capability: Capability, principal: Principal, con: sqlite3.Connection | None = None, right: str = "load", audit: bool = True) -> tuple[bool, str | None]:
    if con is not None:
        from .governance import evaluate_access

        return evaluate_access(con, principal, right=right, capability=capability, audit=audit)

    if capability.visibility == "public":
        return True, None
    if not principal.authenticated:
        return False, "Authentication required."
    if capability.visibility == "internal":
        return True, None

    if capability.allow_users and principal.subject in capability.allow_users:
        return True, None
    if capability.allow_groups and set(principal.groups).intersection(capability.allow_groups):
        return True, None
    if capability.required_scopes and set(capability.required_scopes).issubset(principal.scopes):
        return True, None

    if capability.visibility == "secret":
        return False, "Capability is secret and hidden without explicit entitlement."
    return False, "Capability requires a protected entitlement."


def require_scope(principal: Principal, scope: str) -> tuple[bool, str | None]:
    equivalents = {
        "cap:search": {"cap.discover", "cap.discover:*"},
        "cap:load": {"cap.load", "cap.load:*"},
        "cap:delegate": {"cap.delegate", "cap.delegate:*"},
        "cap:report": {"cap.audit", "cap.audit:*"},
        "cap:call": {"cap.call", "cap.call:*"},
    }
    scopes = set(principal.scopes)
    if scope in scopes or "cap:*" in scopes or scopes.intersection(equivalents.get(scope, set())):
        return True, None
    return False, f"Missing required scope: {scope}"
