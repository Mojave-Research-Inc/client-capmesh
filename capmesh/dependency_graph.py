"""Package dependency graph and compatibility constraints.

Tracks dependencies between capabilities and validates compatibility
constraints (version ranges, capability type requirements). Provides
cycle detection and topological ordering for safe deployment ordering.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict, deque
from typing import Any

from .utils import new_id


def ensure_dependency_table(con: sqlite3.Connection) -> None:
    """Create the capability_dependencies table if it does not exist."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS capability_dependencies (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            capability_uri TEXT NOT NULL,
            depends_on_uri TEXT NOT NULL,
            version_constraint TEXT NOT NULL DEFAULT '*',
            required_type TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, capability_uri, depends_on_uri)
        );
        CREATE INDEX IF NOT EXISTS idx_deps_capability ON capability_dependencies(capability_uri);
        CREATE INDEX IF NOT EXISTS idx_deps_depends_on ON capability_dependencies(depends_on_uri);
        """
    )


def add_dependency(
    con: sqlite3.Connection,
    capability_uri: str,
    depends_on_uri: str,
    *,
    version_constraint: str = "*",
    required_type: str | None = None,
    tenant_id: str = "asg",
    commit: bool = True,
) -> dict[str, Any]:
    """Add a dependency relationship between two capabilities."""
    ensure_dependency_table(con)
    if capability_uri == depends_on_uri:
        raise ValueError("A capability cannot depend on itself")
    dep_id = new_id("dep")
    con.execute(
        """INSERT INTO capability_dependencies(id, tenant_id, capability_uri, depends_on_uri, version_constraint, required_type)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, capability_uri, depends_on_uri) DO UPDATE SET
               version_constraint=excluded.version_constraint,
               required_type=excluded.required_type""",
        (dep_id, tenant_id, capability_uri, depends_on_uri, version_constraint, required_type),
    )
    if commit:
        con.commit()
    return {
        "capabilityUri": capability_uri,
        "dependsOnUri": depends_on_uri,
        "versionConstraint": version_constraint,
        "requiredType": required_type,
    }


def remove_dependency(con: sqlite3.Connection, capability_uri: str, depends_on_uri: str, *, tenant_id: str = "asg", commit: bool = True) -> dict[str, Any]:
    """Remove a dependency relationship."""
    ensure_dependency_table(con)
    cur = con.execute(
        "DELETE FROM capability_dependencies WHERE capability_uri = ? AND depends_on_uri = ? AND tenant_id = ?",
        (capability_uri, depends_on_uri, tenant_id),
    )
    if commit:
        con.commit()
    return {"removed": cur.rowcount > 0, "capabilityUri": capability_uri, "dependsOnUri": depends_on_uri}


def list_dependencies(con: sqlite3.Connection, capability_uri: str, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """List all dependencies of a capability."""
    ensure_dependency_table(con)
    rows = con.execute(
        """SELECT d.depends_on_uri, d.version_constraint, d.required_type, c.name, c.version, c.type
           FROM capability_dependencies d
           LEFT JOIN capabilities c ON c.uri = d.depends_on_uri AND c.tenant_id = d.tenant_id
           WHERE d.capability_uri = ? AND d.tenant_id = ?
           ORDER BY d.depends_on_uri""",
        (capability_uri, tenant_id),
    ).fetchall()
    return [
        {
            "dependsOnUri": str(row["depends_on_uri"]),
            "versionConstraint": str(row["version_constraint"]),
            "requiredType": str(row["required_type"]) if row["required_type"] else None,
            "resolvedName": str(row["name"]) if row["name"] else None,
            "resolvedVersion": str(row["version"]) if row["version"] else None,
            "resolvedType": str(row["type"]) if row["type"] else None,
            "resolved": row["name"] is not None,
        }
        for row in rows
    ]


def list_dependents(con: sqlite3.Connection, depends_on_uri: str, *, tenant_id: str = "asg") -> list[dict[str, Any]]:
    """List all capabilities that depend on the given capability (reverse dependencies)."""
    ensure_dependency_table(con)
    rows = con.execute(
        """SELECT d.capability_uri, d.version_constraint, c.name, c.version
           FROM capability_dependencies d
           LEFT JOIN capabilities c ON c.uri = d.capability_uri AND c.tenant_id = d.tenant_id
           WHERE d.depends_on_uri = ? AND d.tenant_id = ?
           ORDER BY d.capability_uri""",
        (depends_on_uri, tenant_id),
    ).fetchall()
    return [
        {
            "capabilityUri": str(row["capability_uri"]),
            "versionConstraint": str(row["version_constraint"]),
            "name": str(row["name"]) if row["name"] else None,
            "version": str(row["version"]) if row["version"] else None,
        }
        for row in rows
    ]


def detect_cycles(con: sqlite3.Connection, *, tenant_id: str = "asg") -> list[list[str]]:
    """Detect circular dependencies in the dependency graph using DFS."""
    ensure_dependency_table(con)
    rows = con.execute(
        "SELECT capability_uri, depends_on_uri FROM capability_dependencies WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    graph: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        graph[str(row["capability_uri"])].append(str(row["depends_on_uri"]))
    cycles: list[list[str]] = []
    visited: set[str] = set()
    rec_stack: set[str] = set()
    path: list[str] = []

    def dfs(node: str) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in rec_stack:
                cycle_start = path.index(neighbor)
                cycles.append(path[cycle_start:] + [neighbor])
        path.pop()
        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node)
    return cycles


def topological_sort(con: sqlite3.Connection, *, tenant_id: str = "asg") -> list[str]:
    """Return capabilities in dependency-safe deployment order (dependencies first)."""
    ensure_dependency_table(con)
    rows = con.execute(
        "SELECT capability_uri, depends_on_uri FROM capability_dependencies WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    graph: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)
    all_nodes: set[str] = set()
    for row in rows:
        cap = str(row["capability_uri"])
        dep = str(row["depends_on_uri"])
        graph[dep].append(cap)
        in_degree[cap] += 1
        all_nodes.add(cap)
        all_nodes.add(dep)
    for node in all_nodes:
        if node not in in_degree:
            in_degree[node] = 0
    queue = deque(sorted(n for n in all_nodes if in_degree[n] == 0))
    result: list[str] = []
    while queue:
        node = queue.popleft()
        result.append(node)
        for neighbor in sorted(graph.get(node, [])):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    return result


def check_compatibility(
    con: sqlite3.Connection,
    capability_uri: str,
    *,
    tenant_id: str = "asg",
) -> dict[str, Any]:
    """Check whether all dependencies of a capability are satisfied and compatible."""
    deps = list_dependencies(con, capability_uri, tenant_id=tenant_id)
    issues: list[dict[str, Any]] = []
    for dep in deps:
        if not dep["resolved"]:
            issues.append({
                "dependsOnUri": dep["dependsOnUri"],
                "issue": "unresolved",
                "detail": "Dependency capability not found in registry",
            })
            continue
        if dep["requiredType"] and dep["resolvedType"] != dep["requiredType"]:
            issues.append({
                "dependsOnUri": dep["dependsOnUri"],
                "issue": "type_mismatch",
                "expected": dep["requiredType"],
                "actual": dep["resolvedType"],
            })
        if dep["versionConstraint"] != "*":
            constraint = dep["versionConstraint"]
            actual = dep["resolvedVersion"] or "0.0.0"
            if not _satisfies_constraint(actual, constraint):
                issues.append({
                    "dependsOnUri": dep["dependsOnUri"],
                    "issue": "version_mismatch",
                    "constraint": constraint,
                    "actual": actual,
                })
    return {
        "capabilityUri": capability_uri,
        "dependencies": len(deps),
        "issues": issues,
        "compatible": len(issues) == 0,
    }


def _satisfies_constraint(version: str, constraint: str) -> bool:
    """Check if a version satisfies a constraint (supports >=, >, <=, <, ==, ^, ~, *)."""
    from .semver_policy import compare_semver
    constraint = constraint.strip()
    if constraint == "*":
        return True
    if constraint.startswith("^"):
        base = constraint[1:].strip()
        parts = base.split(".")
        if len(parts) >= 2:
            major = int(parts[0]) if parts[0].isdigit() else 0
            return compare_semver(version, f"{major}.0.0") >= 0 and compare_semver(version, f"{major + 1}.0.0") < 0
        return compare_semver(version, base) >= 0
    if constraint.startswith("~"):
        base = constraint[1:].strip()
        parts = base.split(".")
        if len(parts) >= 3:
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if parts[1].isdigit() else 0
            return compare_semver(version, f"{major}.{minor}.0") >= 0 and compare_semver(version, f"{major}.{minor + 1}.0") < 0
        return compare_semver(version, base) >= 0
    for op in [">=", "<=", "==", ">", "<"]:
        if constraint.startswith(op):
            target = constraint[len(op):].strip()
            cmp = compare_semver(version, target)
            if op == ">=": return cmp >= 0
            if op == "<=": return cmp <= 0
            if op == "==": return cmp == 0
            if op == ">": return cmp > 0
            if op == "<": return cmp < 0
    return compare_semver(version, constraint) == 0
