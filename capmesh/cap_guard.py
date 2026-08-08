"""CapGuard — authoritative capability security guard domain (client-capmesh).

CapGuard is the model-agnostic runtime enforcement layer that decides whether
a capability may be indexed as callable, must be held in quarantine pending
controls, or must be denied outright. This module is the authoritative home
for the CapGuard types, policy, and exports consumed by the client-capmesh server
and the embedded client-mcp-gateway. The persistence/integration layer
(quarantine store tables, server wiring, gateway embedding) lives in companion
lanes; the authoritative types and policy live here.

Design mandates (from the CapGuard production-ready workflow):

* quarantine-before-indexing — a capability is never indexed as callable until
  every blocking control reports ``passed``. Anything short of that is held in
  quarantine (``action == "quarantine"``) or denied (``action == "deny"``),
  never ``allow``. Pending (not-yet-run) controls quarantine; failed controls
  quarantine or deny depending on severity.
* fail-closed scanning — an absent, errored, or inconclusive malware scan is
  treated as a failed control that drives a ``deny``, never as a pass. The
  default is deny. A scan that simply has not been run yet quarantines (so the
  operator can run it); a scan that *ran and errored* denies (fail-closed).
* model-agnostic runtime enforcement — verdicts are derived purely from
  capability metadata, signature/provenance state, and scan results. They
  never reference a specific model or runtime backend, so the same policy
  governs every caller regardless of which LLM ultimately executes the
  capability.
* Camber/CIRE isolation — high and critical risk tiers require Camber (the
  strongest sandboxed) isolation before any execution; medium tiers run under
  CIRE (the Capability Isolation Runtime Environment, a lighter isolation);
  low/none tiers run without isolation. The runtime may downgrade Camber to
  CIRE only when the policy explicitly permits it (``allow_cire_downgrade``).

This module is intentionally dependency-free (stdlib only) and pure: it holds
no SQLite handles, performs no I/O, and imports nothing from ``capmesh`` except
``models.Capability`` for typing. That keeps the domain layer testable in
isolation and safe to embed in the client-mcp-gateway without dragging the
full server stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Capability

# --- Vocabularies -------------------------------------------------------

# Isolation modes the runtime may impose on a capability before execution.
#   none   — no isolation (trusted, low-risk capabilities)
#   cire   — Capability Isolation Runtime Environment (baseline isolation)
#   camber — strongest sandboxed isolation (required for high/critical tiers)
ISOLATION_MODES: tuple[str, ...] = ("none", "cire", "camber")

# Raw malware-scan outcomes as understood by CapGuard. A scan that has not been
# run is handled separately (it quarantines, it does not "inconclusive-deny").
SCAN_OUTCOMES: tuple[str, ...] = ("passed", "failed", "inconclusive")

# Per-control states. These match the promotion-gate vocabulary in
# ``governance.py`` / ``risk_policy.py`` so CapGuard verdicts compose cleanly
# with the existing promotion-gate machinery.
CHECK_STATES: tuple[str, ...] = ("pending", "passed", "failed")

# CapGuard verdict actions.
GUARD_ACTIONS: tuple[str, ...] = ("allow", "deny", "quarantine")

# Risk tiers, aligned with ``models.Capability.risk_tier``.
RISK_TIERS: tuple[str, ...] = ("low", "medium", "high", "critical")

# Severity scale for failed controls, aligned with ``malware_scan.py``.
SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

# The controls CapGuard evaluates by default. Names mirror the canonical
# 7-gate promotion set (see ``risk_policy.default_promotion_gates``) minus the
# gates that are not pre-index concerns (sourceIntegrity/tests/retrievalEvals
# are promotion-time concerns, not runtime guard concerns).
DEFAULT_CHECKS: tuple[str, ...] = (
    "malwareScan",
    "signature",
    "provenance",
    "promptInjectionScan",
    "riskTierPolicy",
)

# Quarantine status lifecycle for the domain ``QuarantineRecord`` row shape.
# This is the *runtime policy* lifecycle (a held item becomes released/rejected
# by a CapGuard decision) and is deliberately distinct from the persistence
# vocabulary in :mod:`capmesh.capguard` (``quarantined``/``released``/
# ``rejected``/``superseded``), which is the on-disk store lifecycle. The two
# are separate concerns on separate constants so a caller cannot import the
# wrong one by accident: import ``QUARANTINE_RECORD_STATUSES`` for the policy
# row, ``capguard.QUARANTINE_STATUSES`` for the store.
QUARANTINE_RECORD_STATUSES: tuple[str, ...] = ("held", "released", "rejected")


# --- Types --------------------------------------------------------------


@dataclass(frozen=True)
class CapGuardCheckResult:
    """Outcome of a single CapGuard control for one capability.

    Attributes:
        name: Control name (one of ``DEFAULT_CHECKS``).
        state: ``"pending"`` (not yet evaluated), ``"passed"``, or ``"failed"``.
        severity: Highest severity of the failure, when ``state == "failed"``.
            Meaningless for non-failed states; defaults to ``"low"``.
        message: Human-readable detail. Empty for clean passes.
        fail_closed: True when this failure was produced by a fail-closed
            control (absent/errored/inconclusive scan). Such failures always
            drive a ``deny`` verdict, never a mere quarantine.
        evidence: Structured evidence blob (finding counts, status strings,
            etc.). Never contains secrets.
    """

    name: str
    state: str
    severity: str = "low"
    message: str = ""
    fail_closed: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in CHECK_STATES:
            raise ValueError(f"Unsupported CapGuard check state: {self.state!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unsupported CapGuard severity: {self.severity!r}")
        if self.name not in DEFAULT_CHECKS:
            raise ValueError(f"Unknown CapGuard check: {self.name!r}")
        # A non-failed control cannot carry a fail-closed flag meaningfully.
        if self.fail_closed and self.state != "failed":
            raise ValueError(
                f"CapGuard check {self.name!r} marked fail_closed but state is {self.state!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "severity": self.severity,
            "message": self.message,
            "failClosed": self.fail_closed,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class CapGuardVerdict:
    """Authoritative CapGuard decision for one capability.

    Attributes:
        action: ``"allow"``, ``"deny"``, or ``"quarantine"``.
        isolation_mode: Runtime isolation the capability must run under. For
            ``allow`` verdicts this is always the tier-required mode; for
            ``deny``/``quarantine`` it records what the mode *would* be.
        capability_uri: The capability under evaluation.
        risk_tier: Snapshot of the capability's risk tier at evaluation time.
        reason: Single human-readable sentence explaining the action.
        checks: Tuple of per-control results CapGuard considered.
        fail_closed: True when the action was driven by a fail-closed control
            (absent/errored/inconclusive scan). Distinguishes "needs a scan"
            from "scan broke and we denied".
    """

    action: str
    isolation_mode: str
    capability_uri: str
    risk_tier: str
    reason: str
    checks: tuple[CapGuardCheckResult, ...] = ()
    fail_closed: bool = False

    def __post_init__(self) -> None:
        if self.action not in GUARD_ACTIONS:
            raise ValueError(f"Unsupported CapGuard action: {self.action!r}")
        if self.isolation_mode not in ISOLATION_MODES:
            raise ValueError(f"Unsupported isolation mode: {self.isolation_mode!r}")
        # Invariant: a high/critical capability is never *allowed* to run
        # without sandboxed isolation. Camber is required; CIRE is the only
        # permitted downgrade and only when the policy allows it (enforced by
        # the policy function before construction, but defended here too).
        if (
            self.action == "allow"
            and self.risk_tier in ("high", "critical")
            and self.isolation_mode == "none"
        ):
            raise ValueError(
                f"CapGuard invariant violated: {self.risk_tier}-tier capability "
                f"{self.capability_uri!r} allowed with no isolation"
            )

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def denied(self) -> bool:
        return self.action == "deny"

    @property
    def quarantined(self) -> bool:
        return self.action == "quarantine"

    def check(self, name: str) -> CapGuardCheckResult | None:
        """Return the result for ``name`` or ``None`` if not evaluated."""
        for c in self.checks:
            if c.name == name:
                return c
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "isolationMode": self.isolation_mode,
            "capabilityUri": self.capability_uri,
            "riskTier": self.risk_tier,
            "reason": self.reason,
            "failClosed": self.fail_closed,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass(frozen=True)
class CapGuardPolicy:
    """Authoritative CapGuard policy configuration.

    All fields default to the production fail-closed posture. Construct with
    ``CapGuardPolicy.from_dict(...)`` to load an operator-supplied config;
    unknown keys are rejected so a typo cannot silently relax a control.

    Attributes:
        enabled_checks: Controls CapGuard evaluates. Must be a subset of
            ``DEFAULT_CHECKS``.
        blocking_checks: Controls that block indexing until ``passed``. Must be
            a subset of ``enabled_checks``; every blocking check is enforced.
        fail_closed: When True (default), absent/errored/inconclusive scans
            drive a ``deny``. When False, they only quarantine. Production
            must leave this True.
        camber_tiers: Risk tiers that require Camber (strongest) isolation.
        cire_tiers: Risk tiers that require CIRE (baseline) isolation.
        allow_cire_downgrade: Permit the runtime to downgrade a Camber
            requirement to CIRE. Off by default; enable only when the
            deployment actually runs a CIRE capable of high-tier containment.
        deny_on_high_findings: When True (default), high/critical malware
            findings produce a ``deny``. When False, they quarantine.
        quarantine_on_medium_findings: When True (default), a scan that
            technically passed but surfaced medium-severity findings is
            treated as a failed control and quarantined for review.
        max_scan_age_seconds: When set, a scan older than this (seconds) is
            treated as stale and fail-closed (re-scan required). ``None``
            disables staleness enforcement.
    """

    enabled_checks: tuple[str, ...] = DEFAULT_CHECKS
    blocking_checks: tuple[str, ...] = DEFAULT_CHECKS
    fail_closed: bool = True
    camber_tiers: tuple[str, ...] = ("high", "critical")
    cire_tiers: tuple[str, ...] = ("medium",)
    allow_cire_downgrade: bool = False
    deny_on_high_findings: bool = True
    quarantine_on_medium_findings: bool = True
    max_scan_age_seconds: int | None = None

    def __post_init__(self) -> None:
        for c in self.enabled_checks:
            if c not in DEFAULT_CHECKS:
                raise ValueError(f"Unknown CapGuard check: {c!r}")
        unknown = set(self.blocking_checks) - set(self.enabled_checks)
        if unknown:
            raise ValueError(
                f"Blocking checks not enabled: {sorted(unknown)!r}"
            )
        for tier in self.camber_tiers:
            if tier not in RISK_TIERS:
                raise ValueError(f"Unknown risk tier in camber_tiers: {tier!r}")
        for tier in self.cire_tiers:
            if tier not in RISK_TIERS:
                raise ValueError(f"Unknown risk tier in cire_tiers: {tier!r}")
        overlap = set(self.camber_tiers) & set(self.cire_tiers)
        if overlap:
            raise ValueError(
                f"Risk tiers cannot require both Camber and CIRE: {sorted(overlap)!r}"
            )
        if self.max_scan_age_seconds is not None and self.max_scan_age_seconds <= 0:
            raise ValueError("max_scan_age_seconds must be positive or None")

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> CapGuardPolicy:
        """Build a policy from an operator config, rejecting unknown keys."""
        if not raw:
            return cls()
        known = {
            "enabled_checks",
            "blocking_checks",
            "fail_closed",
            "camber_tiers",
            "cire_tiers",
            "allow_cire_downgrade",
            "deny_on_high_findings",
            "quarantine_on_medium_findings",
            "max_scan_age_seconds",
        }
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"Unknown CapGuard policy keys: {sorted(unknown)!r}")

        def _tuple(key: str) -> tuple[str, ...] | None:
            val = raw.get(key)
            if val is None:
                return None
            return tuple(str(x) for x in val)

        return cls(
            enabled_checks=_tuple("enabled_checks") or cls().enabled_checks,
            blocking_checks=_tuple("blocking_checks") or cls().blocking_checks,
            fail_closed=bool(raw.get("fail_closed", True)),
            camber_tiers=_tuple("camber_tiers") or cls().camber_tiers,
            cire_tiers=_tuple("cire_tiers") or cls().cire_tiers,
            allow_cire_downgrade=bool(raw.get("allow_cire_downgrade", False)),
            deny_on_high_findings=bool(raw.get("deny_on_high_findings", True)),
            quarantine_on_medium_findings=bool(raw.get("quarantine_on_medium_findings", True)),
            max_scan_age_seconds=(
                int(raw["max_scan_age_seconds"]) if raw.get("max_scan_age_seconds") is not None else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabledChecks": list(self.enabled_checks),
            "blockingChecks": list(self.blocking_checks),
            "failClosed": self.fail_closed,
            "camberTiers": list(self.camber_tiers),
            "cireTiers": list(self.cire_tiers),
            "allowCireDowngrade": self.allow_cire_downgrade,
            "denyOnHighFindings": self.deny_on_high_findings,
            "quarantineOnMediumFindings": self.quarantine_on_medium_findings,
            "maxScanAgeSeconds": self.max_scan_age_seconds,
        }


@dataclass(frozen=True)
class QuarantineRecord:
    """A capability held in quarantine pending CapGuard controls.

    The authoritative store is a SQLite table owned by the integration lane;
    this dataclass is the typed row shape those lanes persist and return.

    Attributes:
        id: Stable quarantine record identifier (e.g. ``qtn_...``).
        capability_uri: The capability held.
        tenant_id: Tenant scope (matches ``utils.DEFAULT_TENANT``).
        quarantined_at: ISO-8601 UTC timestamp the hold started.
        reason: Why the hold was placed (copied from the verdict reason).
        isolation_mode: Isolation the capability must run under if released.
        status: ``"held"``, ``"released"``, or ``"rejected"``.
        checks: Per-control results snapshot at quarantine time.
        released_at: ISO-8601 UTC timestamp the hold ended, or ``None``.
    """

    id: str
    capability_uri: str
    tenant_id: str = "asg"
    quarantined_at: str = ""
    reason: str = ""
    isolation_mode: str = "camber"
    status: str = "held"
    checks: tuple[CapGuardCheckResult, ...] = ()
    released_at: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("QuarantineRecord requires a non-empty id")
        if not self.capability_uri:
            raise ValueError("QuarantineRecord requires a capability_uri")
        if self.status not in QUARANTINE_RECORD_STATUSES:
            raise ValueError(f"Unsupported quarantine status: {self.status!r}")
        if self.isolation_mode not in ISOLATION_MODES:
            raise ValueError(f"Unsupported isolation mode: {self.isolation_mode!r}")
        # A released/rejected record must record when the hold ended; a held
        # record must not. This keeps the lifecycle monotonic.
        if self.status in ("released", "rejected") and not self.released_at:
            raise ValueError(
                f"QuarantineRecord status {self.status!r} requires released_at"
            )
        if self.status == "held" and self.released_at is not None:
            raise ValueError("Held QuarantineRecord must not set released_at")

    @property
    def held(self) -> bool:
        return self.status == "held"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "capabilityUri": self.capability_uri,
            "tenantId": self.tenant_id,
            "quarantinedAt": self.quarantined_at,
            "reason": self.reason,
            "isolationMode": self.isolation_mode,
            "status": self.status,
            "checks": [c.to_dict() for c in self.checks],
            "releasedAt": self.released_at,
        }


# --- Policy functions (pure, model-agnostic) ----------------------------


def default_policy() -> CapGuardPolicy:
    """Return the production-default CapGuard policy (fail-closed)."""
    return CapGuardPolicy()


def decide_isolation_mode(risk_tier: str, *, policy: CapGuardPolicy | None = None) -> str:
    """Pick the isolation mode a capability must run under.

    Model-agnostic: the decision depends only on the risk tier and the policy,
    never on the model that will execute the capability. High/critical tiers
    get Camber; tiers listed in ``cire_tiers`` get CIRE; everything else gets
    no isolation. Unknown risk tiers get Camber (defensive: assume dangerous).
    """
    pol = policy or CapGuardPolicy()
    if risk_tier in pol.camber_tiers:
        return "camber"
    if risk_tier in pol.cire_tiers:
        return "cire"
    if risk_tier not in RISK_TIERS:
        # Unknown tier: fail safe toward the strongest isolation.
        return "camber"
    return "none"


def _scan_check(
    scan_result: dict[str, Any] | None,
    *,
    policy: CapGuardPolicy,
) -> CapGuardCheckResult:
    """Build the ``malwareScan`` control result from a raw scan dict.

    The dict shape is compatible with both ``malware_scan.scan_file`` and
    ``malware_scan.scan_capability`` (and the persisted row shape returned by
    ``get_scan_results``). Recognized keys: ``passed``, ``error``,
    ``findings`` (list of ``{severity, ...}``), ``criticalCount``, ``highCount``.
    """
    if scan_result is None:
        # Not scanned yet: quarantine (pending), do not fail-closed deny.
        return CapGuardCheckResult(
            name="malwareScan",
            state="pending",
            severity="low",
            message="malware scan has not been run",
            evidence={"ran": False},
        )

    error = scan_result.get("error")
    if error:
        # Ran and errored/inconclusive -> fail-closed.
        return CapGuardCheckResult(
            name="malwareScan",
            state="failed",
            severity="critical",
            message=f"scan inconclusive: {error}",
            fail_closed=True,
            evidence={"ran": True, "error": str(error)},
        )

    findings = scan_result.get("findings") or []
    crit = scan_result.get("criticalCount")
    high = scan_result.get("highCount")
    crit = sum(1 for f in findings if f.get("severity") == "critical") if crit is None else int(crit)
    high = sum(1 for f in findings if f.get("severity") == "high") if high is None else int(high)
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    passed = bool(scan_result.get("passed"))

    evidence = {
        "ran": True,
        "passed": passed,
        "criticalCount": crit,
        "highCount": high,
        "mediumCount": medium,
    }

    if not passed and (crit or high):
        sev = "critical" if crit else "high"
        return CapGuardCheckResult(
            name="malwareScan",
            state="failed",
            severity=sev,
            message=f"scan blocked: {crit} critical, {high} high findings",
            evidence=evidence,
        )
    if not passed:
        # Failed without severity findings (e.g. file too large) -> fail-closed.
        return CapGuardCheckResult(
            name="malwareScan",
            state="failed",
            severity="critical",
            message="scan failed without enumerated findings",
            fail_closed=True,
            evidence=evidence,
        )
    # passed == True. CapGuard overlays medium-finding review on top of the
    # raw scan verdict: a "passed" scan with medium findings still quarantines.
    if medium and policy.quarantine_on_medium_findings:
        return CapGuardCheckResult(
            name="malwareScan",
            state="failed",
            severity="medium",
            message=f"scan passed but {medium} medium findings require review",
            evidence=evidence,
        )
    return CapGuardCheckResult(
        name="malwareScan",
        state="passed",
        severity="low",
        message="scan passed",
        evidence=evidence,
    )


def _status_check(name: str, status: str | None) -> CapGuardCheckResult:
    """Map a capability ``*_status`` field to a control result.

    Used for ``signature`` (from ``Capability.signature_status``) and
    ``provenance`` (from ``Capability.provenance_status``). Recognized passing
    value is ``"verified"``; recognized failing values are any containing
    ``"fail"``/``"invalid"``/``"reject"``; everything else (including the
    default ``"unchecked"``) is pending, which quarantines before indexing.
    """
    if status is None:
        status = ""
    norm = status.strip().lower()
    if norm == "verified":
        return CapGuardCheckResult(name=name, state="passed", message=f"{name} verified")
    if any(tok in norm for tok in ("fail", "invalid", "reject")):
        return CapGuardCheckResult(
            name=name, state="failed", severity="high",
            message=f"{name} failed: {status!r}", evidence={"status": status},
        )
    return CapGuardCheckResult(
        name=name, state="pending", message=f"{name} not verified (status={status!r})",
        evidence={"status": status},
    )


def _injection_check(injection_result: bool | None) -> CapGuardCheckResult:
    """Build the ``promptInjectionScan`` control result.

    ``injection_result`` is True (clean), False (blocked), or None (not run).
    A blocked injection scan is critical: prompt-injection payloads in a
    callable capability are a direct execution-safety risk.
    """
    if injection_result is None:
        return CapGuardCheckResult(
            name="promptInjectionScan", state="pending",
            message="prompt-injection scan has not been run",
        )
    if injection_result:
        return CapGuardCheckResult(
            name="promptInjectionScan", state="passed",
            message="prompt-injection scan passed",
        )
    return CapGuardCheckResult(
        name="promptInjectionScan", state="failed", severity="critical",
        message="prompt-injection scan blocked the capability",
        evidence={"blocked": True},
    )


def _risk_tier_check(risk_tier: str) -> CapGuardCheckResult:
    """Build the ``riskTierPolicy`` control result.

    Pre-index, a recognized risk tier always passes this control — the
    isolation *requirement* for high/critical tiers is enforced separately by
    ``decide_isolation_mode`` and the verdict invariant. Only an *unknown*
    risk tier fails: CapGuard refuses to index a capability whose risk it
    cannot classify. This deliberately differs from the promotion-time
    ``risk_policy.evaluate_risk_tier_policy`` gate, which is vault-target
    oriented; CapGuard is runtime-isolation oriented.
    """
    if risk_tier in RISK_TIERS:
        return CapGuardCheckResult(
            name="riskTierPolicy", state="passed",
            message=f"risk tier {risk_tier!r} recognized; isolation enforced separately",
            evidence={"riskTier": risk_tier},
        )
    return CapGuardCheckResult(
        name="riskTierPolicy", state="failed", severity="high",
        message=f"unknown risk tier {risk_tier!r}; cannot index unclassified capability",
        evidence={"riskTier": risk_tier},
    )


def evaluate_cap_guard_policy(
    capability: Capability,
    scan_result: dict[str, Any] | None = None,
    *,
    policy: CapGuardPolicy | None = None,
    injection_result: bool | None = None,
) -> CapGuardVerdict:
    """Evaluate CapGuard policy for a capability and return the verdict.

    This is the single authoritative entry point. It is pure and
    model-agnostic: given the same capability, scan result, injection result,
    and policy, it always returns the same verdict with no I/O or model
    reference.

    Decision rule (quarantine-before-indexing + fail-closed scanning):

    1. Any blocking control that is ``failed`` with severity ``high``/``critical``
       OR flagged ``fail_closed`` -> ``action = "deny"``.
    2. Otherwise, any blocking control that is ``failed`` (medium/low) -> if
       ``policy.deny_on_high_findings`` and the failure is high-severity it was
       already caught by rule 1; medium/low failures quarantine.
    3. Otherwise, any blocking control that is ``pending`` -> ``"quarantine"``
       (hold before indexing until the control runs).
    4. Otherwise (all blocking controls ``passed``) -> ``"allow"`` with the
       tier-required isolation mode.

    ``injection_result`` overrides the ``promptInjectionScan`` control only when
    provided; when ``None`` the control is pending (quarantine).
    """
    pol = policy or CapGuardPolicy()
    isolation = decide_isolation_mode(capability.risk_tier, policy=pol)

    # Build only the enabled controls, in canonical order.
    enabled = [c for c in DEFAULT_CHECKS if c in pol.enabled_checks]
    results: list[CapGuardCheckResult] = []
    for name in enabled:
        if name == "malwareScan":
            results.append(_scan_check(scan_result, policy=pol))
        elif name == "signature":
            results.append(_status_check("signature", capability.signature_status))
        elif name == "provenance":
            results.append(_status_check("provenance", capability.provenance_status))
        elif name == "promptInjectionScan":
            results.append(_injection_check(injection_result))
        elif name == "riskTierPolicy":
            results.append(_risk_tier_check(capability.risk_tier))

    blocking = [c for c in results if c.name in pol.blocking_checks]
    failed = [c for c in blocking if c.state == "failed"]
    pending = [c for c in blocking if c.state == "pending"]

    fail_closed_triggered = any(c.fail_closed for c in failed)

    # Rule 1: hard failure (high/critical severity or fail-closed) -> deny.
    hard = [c for c in failed if c.severity in ("high", "critical") or c.fail_closed]
    if hard:
        worst = max(hard, key=lambda c: ("low", "medium", "high", "critical").index(c.severity))
        reason = (
            f"CapGuard denied {capability.uri}: control {worst.name!r} failed "
            f"({worst.severity})"
        )
        return CapGuardVerdict(
            action="deny",
            isolation_mode=isolation,
            capability_uri=capability.uri,
            risk_tier=capability.risk_tier,
            reason=reason,
            checks=tuple(results),
            fail_closed=fail_closed_triggered,
        )

    # Rule 2: soft failure (medium/low) -> deny if configured, else quarantine.
    if failed:
        if pol.deny_on_high_findings and any(c.severity == "high" for c in failed):
            # high-severity soft failures only reachable here if not flagged
            # fail_closed; treat as deny per policy.
            worst = max(failed, key=lambda c: ("low", "medium", "high", "critical").index(c.severity))
            return CapGuardVerdict(
                action="deny",
                isolation_mode=isolation,
                capability_uri=capability.uri,
                risk_tier=capability.risk_tier,
                reason=f"CapGuard denied {capability.uri}: control {worst.name!r} failed ({worst.severity})",
                checks=tuple(results),
                fail_closed=fail_closed_triggered,
            )
        names = ", ".join(sorted({c.name for c in failed}))
        return CapGuardVerdict(
            action="quarantine",
            isolation_mode=isolation,
            capability_uri=capability.uri,
            risk_tier=capability.risk_tier,
            reason=f"CapGuard quarantined {capability.uri}: failed controls [{names}]",
            checks=tuple(results),
            fail_closed=fail_closed_triggered,
        )

    # Rule 3: pending controls -> quarantine before indexing.
    if pending:
        names = ", ".join(sorted({c.name for c in pending}))
        return CapGuardVerdict(
            action="quarantine",
            isolation_mode=isolation,
            capability_uri=capability.uri,
            risk_tier=capability.risk_tier,
            reason=f"CapGuard quarantined {capability.uri}: pending controls [{names}]",
            checks=tuple(results),
            fail_closed=False,
        )

    # Rule 4: all blocking controls passed -> allow with tier-required isolation.
    iso_note = f" under {isolation} isolation" if isolation != "none" else " (no isolation)"
    return CapGuardVerdict(
        action="allow",
        isolation_mode=isolation,
        capability_uri=capability.uri,
        risk_tier=capability.risk_tier,
        reason=f"CapGuard allowed {capability.uri}{iso_note}",
        checks=tuple(results),
        fail_closed=False,
    )


def quarantine_required(verdict: CapGuardVerdict) -> bool:
    """True when a verdict requires the capability to be held in quarantine."""
    return verdict.action == "quarantine"


def fail_closed_scan(verdict: CapGuardVerdict) -> bool:
    """True when the verdict was driven by a fail-closed (absent/errored) scan.

    Callers use this to distinguish "scan needs to run" (quarantine, retry)
    from "scan ran and broke" (deny, investigate) when surfacing guidance.
    """
    return verdict.fail_closed


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
    "QuarantineRecord",
    "decide_isolation_mode",
    "default_policy",
    "evaluate_cap_guard_policy",
    "fail_closed_scan",
    "quarantine_required",
]
