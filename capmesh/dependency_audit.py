"""Dependency audit job for the capability mesh registry.

Scans all capabilities for known vulnerability patterns in their
dependencies, checks for outdated versions, and produces an audit
report with actionable findings.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from .utils import json_dumps, new_id, utc_now

# Known vulnerability patterns in dependency metadata
VULNERABILITY_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"eval\(", "severity": "critical", "description": "Use of eval() in dependency"},
    {"pattern": r"exec\(", "severity": "critical", "description": "Use of exec() in dependency"},
    {"pattern": r"subprocess\.call.*shell=True", "severity": "high", "description": "Shell injection risk"},
    {"pattern": r"os\.system\(", "severity": "high", "description": "OS command injection risk"},
    {"pattern": r"pickle\.loads?", "severity": "high", "description": "Deserialization vulnerability"},
    {"pattern": r"yaml\.load\(", "severity": "medium", "description": "Unsafe YAML loading (use yaml.safe_load)"},
    {"pattern": r"http://(?!localhost|127\.0\.0\.1)", "severity": "medium", "description": "Insecure HTTP URL (should use HTTPS)"},
    {"pattern": r"\bpassword\b.*=.*[\"\']", "severity": "medium", "description": "Hardcoded password reference"},
]

# Deprecated/blocked packages
BLOCKED_PACKAGES = {"python-eclipse", "pycrypto", "nose", "distutils"}


def ensure_audit_table(con: sqlite3.Connection) -> None:
    """Create the dependency_audit_results table."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS dependency_audit_results (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            capability_uri TEXT NOT NULL,
            severity TEXT NOT NULL,
            finding TEXT NOT NULL,
            detail TEXT,
            run_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_audit_results_uri ON dependency_audit_results(capability_uri);
        CREATE INDEX IF NOT EXISTS idx_audit_results_severity ON dependency_audit_results(severity);
        """
    )


def scan_capability(con: sqlite3.Connection, uri: str, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """Scan a single capability for dependency issues."""
    row = con.execute(
        "SELECT * FROM capabilities WHERE uri = ? AND tenant_id = ?",
        (uri, tenant_id),
    ).fetchone()
    if row is None:
        return []
    findings: list[dict[str, Any]] = []
    metadata = json.loads(str(row["metadata_json"])) if row["metadata_json"] else {}
    # Check metadata for vulnerability patterns
    metadata_str = json_dumps(metadata)
    for pattern_info in VULNERABILITY_PATTERNS:
        if re.search(pattern_info["pattern"], metadata_str, re.IGNORECASE):
            findings.append({
                "capabilityUri": uri,
                "severity": pattern_info["severity"],
                "finding": pattern_info["description"],
            })
    # Check for blocked packages in metadata
    deps = metadata.get("dependencies", [])
    if isinstance(deps, list):
        for dep in deps:
            dep_name = str(dep).split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
            if dep_name in BLOCKED_PACKAGES:
                findings.append({
                    "capabilityUri": uri,
                    "severity": "high",
                    "finding": f"Blocked/deprecated package: {dep_name}",
                })
    # Check license field
    license_val = str(row["license"]) if "license" in row else None
    if license_val and license_val.lower() in {"gpl", "gpl-3.0", "agpl", "agpl-3.0"}:
        findings.append({
            "capabilityUri": uri,
            "severity": "medium",
            "finding": f"Copyleft license may restrict distribution: {license_val}",
        })
    return findings


def run_dependency_audit(
    con: sqlite3.Connection,
    *,
    tenant_id: str = "asg",
    limit: int = 1000,
    commit: bool = True,
) -> dict[str, Any]:
    """Run a full dependency audit across all capabilities in the registry."""
    ensure_audit_table(con)
    run_id = new_id("aud")
    rows = con.execute(
        "SELECT uri FROM capabilities WHERE tenant_id = ? AND source_kind != ? ORDER BY uri LIMIT ?",
        (tenant_id, "system_capability", min(max(limit, 1), 10000)),
    ).fetchall()
    all_findings: list[dict[str, Any]] = []
    for row in rows:
        uri = str(row["uri"])
        cap_findings = scan_capability(con, uri, tenant_id=tenant_id)
        for finding in cap_findings:
            finding_id = new_id("audf")
            con.execute(
                """INSERT INTO dependency_audit_results(id, tenant_id, capability_uri, severity, finding, detail, run_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, tenant_id, finding["capabilityUri"], finding["severity"], finding["finding"], json_dumps(finding), run_id, utc_now()),
            )
            all_findings.append(finding)
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    if commit:
        con.commit()
    return {
        "runId": run_id,
        "scannedCapabilities": len(rows),
        "totalFindings": len(all_findings),
        "severityBreakdown": severity_counts,
        "findings": all_findings[:100],
        "findingsTruncated": len(all_findings) > 100,
    }


def get_audit_results(con: sqlite3.Connection, run_id: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    """Get dependency audit results, optionally filtered by run_id."""
    ensure_audit_table(con)
    query = "SELECT * FROM dependency_audit_results"
    params: list[Any] = []
    if run_id:
        query += " WHERE run_id = ?"
        params.append(run_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(min(max(limit, 1), 500))
    rows = con.execute(query, tuple(params)).fetchall()
    return [
        {
            "id": str(row["id"]),
            "capabilityUri": str(row["capability_uri"]),
            "severity": str(row["severity"]),
            "finding": str(row["finding"]),
            "detail": json.loads(str(row["detail"])) if row["detail"] else {},
            "runId": str(row["run_id"]),
            "createdAt": str(row["created_at"]),
        }
        for row in rows
    ]
