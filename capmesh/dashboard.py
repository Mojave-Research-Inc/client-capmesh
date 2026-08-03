"""Dashboard for search/load/delegate volume and operational metrics.

Aggregates operational metrics from the registry: search/load/delegate
volume by capability, top capabilities by access, error rates, and
lifecycle distribution. Returns a structured dashboard payload suitable
for rendering in any metrics visualization tool.
"""

from __future__ import annotations

import sqlite3
from typing import Any


def capability_volume_dashboard(con: sqlite3.Connection, *, tenant_id: str = "asg") -> dict[str, Any]:
    """Return a dashboard payload with operational metrics for the registry."""
    # Lifecycle distribution
    lifecycle_rows = con.execute(
        "SELECT lifecycle, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY lifecycle ORDER BY count DESC",
        (tenant_id,),
    ).fetchall()
    lifecycle_dist = {str(row["lifecycle"]): int(row["count"]) for row in lifecycle_rows}

    # Type distribution
    type_rows = con.execute(
        "SELECT type, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY type ORDER BY count DESC",
        (tenant_id,),
    ).fetchall()
    type_dist = {str(row["type"]): int(row["count"]) for row in type_rows}

    # Approval state distribution
    approval_rows = con.execute(
        "SELECT approval_state, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY approval_state ORDER BY count DESC",
        (tenant_id,),
    ).fetchall()
    approval_dist = {str(row["approval_state"]): int(row["count"]) for row in approval_rows}

    # Visibility distribution
    vis_rows = con.execute(
        "SELECT visibility, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY visibility",
        (tenant_id,),
    ).fetchall()
    vis_dist = {str(row["visibility"]): int(row["count"]) for row in vis_rows}

    # Risk tier distribution
    risk_rows = con.execute(
        "SELECT risk_tier, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY risk_tier",
        (tenant_id,),
    ).fetchall()
    risk_dist = {str(row["risk_tier"]): int(row["count"]) for row in risk_rows}

    # Top capabilities by source system
    source_rows = con.execute(
        "SELECT source_system, COUNT(*) as count FROM capabilities WHERE tenant_id = ? GROUP BY source_system ORDER BY count DESC LIMIT 10",
        (tenant_id,),
    ).fetchall()
    top_sources = [{"source": str(row["source_system"]), "count": int(row["count"])} for row in source_rows]

    # Policy decision distribution (from audit_events)
    policy_rows = con.execute(
        "SELECT action, decision, COUNT(*) as count FROM policy_decisions WHERE tenant_id = ? GROUP BY action, decision ORDER BY count DESC LIMIT 20",
        (tenant_id,),
    ).fetchall()
    policy_decisions = [
        {"action": str(row["action"]), "decision": str(row["decision"]), "count": int(row["count"])}
        for row in policy_rows
    ]

    # Total counts
    total_caps = con.execute(
        "SELECT COUNT(*) FROM capabilities WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()[0]
    total_stores = con.execute(
        "SELECT COUNT(*) FROM stores WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()[0]
    total_namespaces = con.execute(
        "SELECT COUNT(*) FROM namespaces WHERE tenant_id = ?", (tenant_id,)
    ).fetchone()[0]

    # Recent audit events
    recent_events = con.execute(
        "SELECT event_type, COUNT(*) as count FROM audit_events WHERE tenant_id = ? GROUP BY event_type ORDER BY count DESC LIMIT 15",
        (tenant_id,),
    ).fetchall()
    event_summary = {str(row["event_type"]): int(row["count"]) for row in recent_events}

    return {
        "tenantId": tenant_id,
        "totals": {
            "capabilities": total_caps,
            "stores": total_stores,
            "namespaces": total_namespaces,
        },
        "distributions": {
            "lifecycle": lifecycle_dist,
            "type": type_dist,
            "approvalState": approval_dist,
            "visibility": vis_dist,
            "riskTier": risk_dist,
        },
        "topSources": top_sources,
        "policyDecisions": policy_decisions,
        "auditEventSummary": event_summary,
    }


def capability_detail(con: sqlite3.Connection, uri: str, *, tenant_id: str = "asg") -> dict[str, Any]:
    """Return detailed metrics for a single capability."""
    row = con.execute(
        "SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?",
        (uri, tenant_id),
    ).fetchone()
    if row is None:
        return {"found": False, "uri": uri}
    # Get policy decisions for this capability
    policy_rows = con.execute(
        "SELECT action, decision, COUNT(*) as count FROM policy_decisions WHERE resource_uri = ? GROUP BY action, decision ORDER BY count DESC",
        (uri,),
    ).fetchall()
    decisions = [
        {"action": str(r["action"]), "decision": str(r["decision"]), "count": int(r["count"])}
        for r in policy_rows
    ]
    # Get audit events for this capability
    event_rows = con.execute(
        "SELECT event_type, COUNT(*) as count FROM audit_events WHERE target = ? GROUP BY event_type ORDER BY count DESC",
        (uri,),
    ).fetchall()
    events = {str(r["event_type"]): int(r["count"]) for r in event_rows}
    return {
        "found": True,
        "uri": uri,
        "name": str(row["name"]),
        "type": str(row["type"]),
        "lifecycle": str(row["lifecycle"]),
        "approvalState": str(row["approval_state"]),
        "riskTier": str(row["risk_tier"]),
        "policyDecisions": decisions,
        "auditEvents": events,
    }
