"""Client Capability Mesh (client-capmesh).

Baseline capability router for customer distribution, derived from ASG
Capability Mesh. Ships with a bundled capability set for customer installs.



The mesh indexes capability packages and exposes a fixed lazy-loading router
surface: cap.search, cap.load, cap.call, cap.list, cap.describe, cap.delegate,
and cap.report.
"""

from .models import Capability, Principal

# CapGuard authoritative domain surface — types, policy, and exports. Re-exported
# here so callers may ``from capmesh import CapGuardPolicy, evaluate_cap_guard_policy``
# without depending on the internal module path. See ``capmesh/cap_guard.py``.
from .cap_guard import (
    CHECK_STATES,
    DEFAULT_CHECKS,
    GUARD_ACTIONS,
    ISOLATION_MODES,
    QUARANTINE_RECORD_STATUSES,
    RISK_TIERS,
    SCAN_OUTCOMES,
    SEVERITIES,
    CapGuardCheckResult,
    CapGuardPolicy,
    CapGuardVerdict,
    QuarantineRecord,
    decide_isolation_mode,
    default_policy,
    evaluate_cap_guard_policy,
    fail_closed_scan,
    quarantine_required,
)

__all__ = [
    "CHECK_STATES",
    "DEFAULT_CHECKS",
    "GUARD_ACTIONS",
    "ISOLATION_MODES",
    "QUARANTINE_RECORD_STATUSES",
    "RISK_TIERS",
    "SCAN_OUTCOMES",
    "SEVERITIES",
    "CapGuardCheckResult",
    "CapGuardPolicy",
    "CapGuardVerdict",
    "Capability",
    "Principal",
    "QuarantineRecord",
    "decide_isolation_mode",
    "default_policy",
    "evaluate_cap_guard_policy",
    "fail_closed_scan",
    "quarantine_required",
]

