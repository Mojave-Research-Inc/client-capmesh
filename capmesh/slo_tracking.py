"""Latency SLO tracking for search and load operations.

Records operation latencies in an in-memory ring buffer and computes
percentiles (p50, p90, p95, p99) for SLO evaluation. SLO thresholds
are configurable per operation type.
"""

from __future__ import annotations

import sqlite3
import threading
from collections import deque
from typing import Any

from .utils import json_dumps, new_id, utc_now

# Default SLO targets in milliseconds
DEFAULT_SLO_TARGETS: dict[str, dict[str, float]] = {
    "search": {"p50": 50, "p90": 200, "p99": 500},
    "load": {"p50": 20, "p90": 100, "p99": 300},
    "delegate": {"p50": 30, "p90": 150, "p99": 500},
    "call": {"p50": 100, "p90": 500, "p99": 2000},
    "list": {"p50": 30, "p90": 100, "p99": 300},
    "describe": {"p50": 20, "p90": 80, "p99": 200},
}

RING_BUFFER_SIZE = 10000


class SLOTracker:
    """In-memory latency tracker with percentile computation and SLO evaluation."""

    def __init__(self, buffer_size: int = RING_BUFFER_SIZE, slo_targets: dict[str, dict[str, float]] | None = None) -> None:
        self._buffer_size = buffer_size
        self._latencies: dict[str, deque] = {}
        self._slo_targets = slo_targets or DEFAULT_SLO_TARGETS
        self._lock = threading.Lock()

    def record(self, operation: str, latency_ms: float) -> None:
        """Record a latency measurement for an operation."""
        with self._lock:
            if operation not in self._latencies:
                self._latencies[operation] = deque(maxlen=self._buffer_size)
            self._latencies[operation].append(latency_ms)

    def percentiles(self, operation: str) -> dict[str, float]:
        """Compute p50, p90, p95, p99 for an operation."""
        with self._lock:
            samples = list(self._latencies.get(operation, []))
        if not samples:
            return {"p50": 0, "p90": 0, "p95": 0, "p99": 0, "count": 0}
        samples.sort()
        n = len(samples)
        return {
            "p50": samples[int(n * 0.50)],
            "p90": samples[int(n * 0.90)] if n >= 10 else samples[-1],
            "p95": samples[int(n * 0.95)] if n >= 20 else samples[-1],
            "p99": samples[int(n * 0.99)] if n >= 100 else samples[-1],
            "count": n,
            "min": samples[0],
            "max": samples[-1],
        }

    def slo_status(self, operation: str | None = None) -> dict[str, Any]:
        """Evaluate SLO compliance for one or all operations."""
        ops = [operation] if operation else list(self._latencies.keys())
        results: dict[str, Any] = {}
        for op in ops:
            pcts = self.percentiles(op)
            targets = self._slo_targets.get(op, {})
            violations: list[dict[str, Any]] = []
            for percentile, target_ms in targets.items():
                actual = pcts.get(percentile, 0)
                if actual > target_ms and pcts.get("count", 0) > 0:
                    violations.append({
                        "percentile": percentile,
                        "targetMs": target_ms,
                        "actualMs": actual,
                    })
            results[op] = {
                "percentiles": pcts,
                "targets": targets,
                "violations": violations,
                "sloMet": len(violations) == 0,
            }
        return results

    def summary(self) -> dict[str, Any]:
        """Return a summary of all tracked operations and their SLO status."""
        status = self.slo_status()
        total_violations = sum(len(v.get("violations", [])) for v in status.values())
        return {
            "operations": list(status.keys()),
            "totalOperations": len(status),
            "totalViolations": total_violations,
            "allSloMet": total_violations == 0,
            "details": status,
        }

    def reset(self, operation: str | None = None) -> None:
        """Reset latency data for one or all operations."""
        with self._lock:
            if operation:
                self._latencies.pop(operation, None)
            else:
                self._latencies.clear()


# Global singleton tracker
_TRACKER = SLOTracker()


def get_tracker() -> SLOTracker:
    """Return the global SLO tracker singleton."""
    return _TRACKER


def record_latency(operation: str, latency_ms: float) -> None:
    """Convenience: record a latency on the global tracker."""
    _TRACKER.record(operation, latency_ms)


def slo_summary() -> dict[str, Any]:
    """Convenience: get SLO summary from the global tracker."""
    return _TRACKER.summary()


def ensure_slo_table(con: sqlite3.Connection) -> None:
    """Create the slo_snapshots table for periodic SLO persistence."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS slo_snapshots (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            operation TEXT NOT NULL,
            p50 REAL, p90 REAL, p95 REAL, p99 REAL,
            sample_count INTEGER,
            slo_met INTEGER NOT NULL DEFAULT 1,
            violations_json TEXT NOT NULL DEFAULT '[]',
            captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_slo_operation ON slo_snapshots(operation, captured_at);
        """
    )


def persist_slo_snapshot(con: sqlite3.Connection, *, tenant_id: str = "asg", commit: bool = True) -> dict[str, Any]:
    """Persist current SLO measurements to the database."""
    ensure_slo_table(con)
    summary = _TRACKER.summary()
    for op, details in summary.get("details", {}).items():
        pcts = details.get("percentiles", {})
        con.execute(
            """INSERT INTO slo_snapshots(id, tenant_id, operation, p50, p90, p95, p99, sample_count, slo_met, violations_json, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new_id("slo"), tenant_id, op,
                pcts.get("p50", 0), pcts.get("p90", 0), pcts.get("p95", 0), pcts.get("p99", 0),
                pcts.get("count", 0),
                1 if details.get("sloMet", True) else 0,
                json_dumps(details.get("violations", [])),
                utc_now(),
            ),
        )
    if commit:
        con.commit()
    return summary
