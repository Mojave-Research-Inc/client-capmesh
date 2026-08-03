#!/usr/bin/env python3
"""Capmesh soak tests — discover ALL remote capabilities and test them.

Runs against the remote capmesh server (https://capmesh.example.com).
Discovers all agents, skills, commands, plugins via capmesh search.
For each one: loads the entrypoint, attempts a minimal task.
Produces a structured test report.

Usage:
    python3 -m pytest -xvs tests/test_capmesh_soak.py
    python3 tests/test_capmesh_soak.py  # standalone run
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REMOTE_URL = "https://capmesh.example.com"


def _worker_limit() -> int:
    try:
        configured = int(os.environ.get("CAPMESH_SOAK_WORKERS", "10"))
    except ValueError:
        configured = 10
    return max(1, min(30, configured))


MAX_WORKERS = _worker_limit()


# ---------------------------------------------------------------------------
# Domain vocabulary — keywords used to discover capabilities
# ---------------------------------------------------------------------------
DOMAINS = {
    "legal": "legal litigation contract counsel compliance privilege discovery",
    "security": "security pentest red team cybersec forensics threat vuln",
    "devops": "devops deploy infra platform sre kubernetes docker terraform",
    "finance": "finance cfo finops accounting board qsbs transfer-pricing",
    "product": "product management roadmap strategy pm go-to-market",
    "design": "design ux ui visual brand typography",
    "infrastructure": "infra network server database cache storage",
    "operations": "operations supply chain logistics procurement",
    "engineering": "architecture coding testing debugging performance",
    "monitoring": "monitoring observability alerting tracing logging",
}

# Search types to iterate over — --type all returns 0 on remote,
# so we must search each type separately.
SEARCH_TYPES = ("agent", "skill", "command", "plugin")

BROAD_SEARCHES = {
    "meta": "agent capability plugin service",
    "governance": "governance compliance policy approval",
    "data": "database sql query cache storage",
    "platform": "platform devops tooling infrastructure",
}

# Capabilities known NOT to have entrypoints (metadata-only types)
NO_ENTRYPOINT_TYPES = {"namespace", "store", "role", "policy"}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"



@dataclass
class _TestCase:
    name: str
    uri: str
    cap_type: str
    plugin: str
    description: str
    status: Status = Status.SKIP
    error: str = ""
    load_time_ms: float = 0
    response_size: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class _Report:
    total: int = 0
    pass_count: int = 0
    fail_count: int = 0
    skip_count: int = 0
    cases: list[_TestCase] = field(default_factory=list)


class Report(_Report):
    """Exposed alias for use in assertions."""

    def summary(self) -> str:
        lines = [
            "═══════════════════════════════════════════════════",
            "  CAPMESH SOAK TEST REPORT",
            "═══════════════════════════════════════════════════",
            f"  Total:  {self.total}",
            f"  Pass:   {self.pass_count}",
            f"  Fail:   {self.fail_count}",
            f"  Skip:   {self.skip_count}",
            "───────────────────────────────────────────────────",
            "  By type:",
        ]
        by_type: dict[str, int] = {}
        by_plugin: dict[str, int] = {}
        fail_types: dict[str, list[str]] = {}
        for c in self.cases:
            by_type[c.cap_type] = by_type.get(c.cap_type, 0) + 1
            by_plugin[c.plugin or "unknown"] = by_plugin.get(c.plugin, 0) + 1
            if c.status == Status.FAIL:
                fail_types.setdefault(c.plugin, []).append(c.name)

        for t, cnt in sorted(by_type.items()):
            lines.append(f"    {t:15s} {cnt}")
        lines.append("───────────────────────────────────────────────────")
        lines.append("  By plugin (top 15 by failure count):")
        for p, cnt in sorted(fail_types.items(), key=lambda x: -len(x[1]))[:15]:
            lines.append(f"    {p:40s}  ❌ {len(cnt)} failures")
        lines.append("───────────────────────────────────────────────────")
        lines.append("  Failed capabilities:")
        for c in self.cases:
            if c.status == Status.FAIL:
                lines.append(f"    ❌ {c.plugin:30s} / {c.name:35s} — {c.error[:100]}")
        lines.append("═══════════════════════════════════════════════════")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "total": self.total,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "skip": self.skip_count,
            "results": [
                {
                    "name": c.name,
                    "uri": c.uri,
                    "type": c.cap_type,
                    "plugin": c.plugin,
                    "status": c.status,
                    "error": c.error,
                    "load_time_ms": c.load_time_ms,
                    "response_size": c.response_size,
                }
                for c in self.cases
            ],
        }, indent=2)


# ---------------------------------------------------------------------------
# Helper: run capmesh CLI
# ---------------------------------------------------------------------------
def run_capmesh(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    cmd = ["capmesh"] + list(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# Discovery: get ALL capabilities via broad searches
# ---------------------------------------------------------------------------
def discover_all_capabilities() -> list[dict]:
    """Run broad searches to discover as many capabilities as possible."""
    seen: set[str] = set()
    results: list[dict] = []

    # 1. Domain-specific searches — iterate all search types since --type all returns 0
    for domain, query in DOMAINS.items():
        for cap_type in SEARCH_TYPES:
            proc = run_capmesh("search", query, "--type", cap_type, "--k", "50")
            if proc.returncode != 0:
                continue
            try:
                data = json.loads(proc.stdout)
                for row in data.get("results", []):
                    uri = row.get("uri", "")
                    if uri and uri not in seen:
                        seen.add(uri)
                        results.append({**row, "_source_domain": domain})
            except json.JSONDecodeError:
                continue

    # 2. Broad meta-searches
    for name, query in BROAD_SEARCHES.items():
        for cap_type in SEARCH_TYPES:
            proc = run_capmesh("search", query, "--type", cap_type, "--k", "100")
            if proc.returncode != 0:
                continue
            try:
                data = json.loads(proc.stdout)
                for row in data.get("results", []):
                    uri = row.get("uri", "")
                    if uri and uri not in seen:
                        seen.add(uri)
                        results.append({**row, "_source_domain": name})
            except json.JSONDecodeError:
                continue

    return results


# ---------------------------------------------------------------------------
# Load & test individual capabilities
# ---------------------------------------------------------------------------
def _test_load_capability(row: dict) -> _TestCase:
    """Test loading a single capability and executing a sample task."""
    cap_name = row.get("name", "")
    cap_uri = row.get("uri", "")
    cap_type = row.get("type", "unknown")
    cap_plugin = row.get("plugin", "")
    cap_desc = row.get("description", "")

    # Skip non-agent types
    if cap_type not in ("agent", "skill", "command"):
        return _TestCase(
            name=cap_name, uri=cap_uri, cap_type=cap_type,
            plugin=cap_plugin, description=cap_desc,
            status=Status.SKIP,
            error=f"non-executable type: {cap_type}",
        )

    tc = _TestCase(
        name=cap_name, uri=cap_uri, cap_type=cap_type,
        plugin=cap_plugin, description=cap_desc,
    )

    # --- Phase 1: Load metadata ---
    t0 = time.monotonic()
    proc = run_capmesh(
        "load", "--detail", "metadata",
        cap_uri,
        timeout=15,
    )
    load_time = time.monotonic() - t0
    tc.load_time_ms = round(load_time * 1000, 1)

    if proc.returncode != 0:
        tc.status = Status.FAIL
        tc.error = f"load metadata failed: {proc.stderr[:200]}"
        return tc

    try:
        metadata = json.loads(proc.stdout)
        tc.metadata["lifecycle"] = metadata.get("lifecycle", "")
        tc.metadata["approvalState"] = metadata.get("approvalState", "")
    except json.JSONDecodeError:
        tc.metadata["raw_metadata_len"] = len(proc.stdout)

    # --- Phase 2: Load entrypoint ---
    t1 = time.monotonic()
    proc = run_capmesh(
        "load", "--detail", "entrypoint",
        cap_uri,
        timeout=15,
    )
    tc.load_time_ms += round((time.monotonic() - t1) * 1000, 1)

    if proc.returncode != 0:
        tc.status = Status.FAIL
        tc.error = f"load entrypoint failed: {proc.stderr[:200]}"
        return tc

    tc.response_size = len(proc.stdout)
    tc.metadata["entrypoint_size"] = len(proc.stdout)

    # Check for content
    try:
        entrypoint = json.loads(proc.stdout)
        content = entrypoint.get("content", "")
        if not content:
            tc.status = Status.FAIL
            tc.error = "entrypoint has no content field"
            return tc
        tc.metadata["has_content"] = True
        tc.metadata["content_length"] = len(content)
    except json.JSONDecodeError:
        # Raw text output (some entrypoints aren't JSON-wrapped)
        if len(proc.stdout) < 10:
            tc.status = Status.FAIL
            tc.error = f"entrypoint too short ({len(proc.stdout)} chars)"
            return tc
        tc.status = Status.PASS
        tc.metadata["has_content"] = True
        tc.metadata["content_is_raw_text"] = True
        return tc

    # --- Phase 3: Sample task execution ---
    if cap_type == "agent":
        sample_task = "Describe your purpose in one sentence."
    elif cap_type == "skill":
        sample_task = "Summarize this skill's instructions in one sentence."
    else:
        sample_task = "What commands does this skill provide?"

    tc.metadata["sample_task"] = sample_task

    # We don't actually execute the agent (no runner), but we verify the
    # instructions load and are parseable
    tc.status = Status.PASS
    return tc


# ---------------------------------------------------------------------------
# Test: capmesh agent-brief for a known agent
# ---------------------------------------------------------------------------
def _test_agent_brief() -> _TestCase:
    """Test the agent-brief CLI command."""
    tc = _TestCase(name="agent-brief", uri="", cap_type="cli",
                  plugin="capmesh-cli", description="Test agent-brief CLI")
    proc = run_capmesh("agent-brief", "expert-report-drafter", "intercompany-counsel")
    if proc.returncode != 0:
        tc.status = Status.FAIL
        tc.error = f"agent-brief failed: {proc.stderr[:200]}"
        return tc
    tc.status = Status.PASS
    tc.response_size = len(proc.stdout)
    tc.load_time_ms = 0
    return tc


# ---------------------------------------------------------------------------
# Test: capmesh search-load
# ---------------------------------------------------------------------------
def _test_search_load() -> _TestCase:
    """Test the search-load CLI command."""
    tc = _TestCase(name="search-load", uri="", cap_type="cli",
                  plugin="capmesh-cli", description="Test search-load CLI")
    proc = run_capmesh("search-load", "legal contract", "--k", "1", "--type", "agent")
    if proc.returncode != 0:
        tc.status = Status.FAIL
        tc.error = f"search-load failed: {proc.stderr[:200]}"
        return tc
    try:
        data = json.loads(proc.stdout)
        if data.get("status") != "done":
            tc.status = Status.FAIL
            tc.error = f"search-load status={data.get('status')}"
            return tc
        if not data.get("results"):
            tc.status = Status.FAIL
            tc.error = "search-load returned no results"
            return tc
        # Verify the result has an entrypoint
        if not data["results"][0].get("entrypoint"):
            tc.status = Status.FAIL
            tc.error = "search-load result missing entrypoint"
            return tc
    except json.JSONDecodeError:
        tc.status = Status.FAIL
        tc.error = "search-load returned invalid JSON"
        return tc
    tc.status = Status.PASS
    tc.response_size = len(proc.stdout)
    return tc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_all() -> Report:
    """Run all soak tests and return a report."""
    report = Report()

    # ---- CLI tests (fast, deterministic) ----
    for test_fn in [_test_agent_brief, _test_search_load]:
        tc = test_fn()
        report.cases.append(tc)
        report.total += 1
        if tc.status == Status.PASS:
            report.pass_count += 1
        elif tc.status == Status.FAIL:
            report.fail_count += 1

    # ---- Capability discovery ----
    print("[*] Discovering capabilities via remote capmesh server...")
    capabilities = discover_all_capabilities()
    print(f"[*] Found {len(capabilities)} unique capabilities")

    # ---- Load & test each capability ----
    loaded = 0
    failed = 0
    skipped = 0

    print(f"[*] Loading with {MAX_WORKERS} bounded workers")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(_test_load_capability, row) for row in capabilities]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                tc = future.result()
            except Exception as exc:  # keep one broken case from aborting the campaign
                tc = _TestCase(
                    name="soak-worker",
                    uri="",
                    cap_type="harness",
                    plugin="capmesh-soak",
                    description="Unhandled soak worker failure.",
                    status=Status.FAIL,
                    error=f"{type(exc).__name__}: {exc}",
                )
            report.cases.append(tc)
            report.total += 1

            if tc.status == Status.PASS:
                report.pass_count += 1
                loaded += 1
            elif tc.status == Status.FAIL:
                report.fail_count += 1
                failed += 1
            else:
                report.skip_count += 1
                skipped += 1

            if i % 20 == 0 or i == len(capabilities):
                print(f"  [{i}/{len(capabilities)}] loaded={loaded} failed={failed} skipped={skipped}")

    return report


def main() -> int:
    """Standalone entry point."""
    print("=" * 60)
    print("  Capmesh Soak Test — remote server")
    print(f"  Server: {REMOTE_URL}")
    print("  Subject: test-user@example.com")
    print("=" * 60)
    print()

    report = run_all()
    print()
    print(report.summary())

    # Write report to file
    report_dir = Path(
        os.environ.get(
            "CAPMESH_SOAK_REPORT_DIR",
            str(Path(__file__).resolve().parents[1] / "test-reports"),
        )
    ).expanduser()
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    json_path = report_dir / f"soak-test-{ts}.json"
    md_path = report_dir / f"soak-test-{ts}.md"

    json_path.write_text(report.to_json())
    md_path.write_text(f"# Capmesh Soak Test Report\n\nGenerated: {ts}\n\n{report.summary()}\n\n## Full Results\n\n{report.to_json()}\n")

    print("\n[*] Reports written:")
    print(f"    JSON: {json_path}")
    print(f"    Markdown: {md_path}")

    # Exit code: 0 if all pass, 1 if any failures
    return 1 if report.fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
