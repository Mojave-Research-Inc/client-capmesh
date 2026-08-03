"""Risk-tier policy subsystem (CM-12 slice-3 of ``governance.py``).

This module holds the self-contained risk-tier policy helpers extracted from
``capmesh.governance`` as part of the governance.py decomposition (plan item
CM-12, slice-3, following slice-1 ``vault_placement`` and slice-2
``prompt_injection``). The public surface of ``governance.py`` is unchanged:
every name moved here is re-imported by ``governance.py`` so existing
``from capmesh.governance import evaluate_risk_tier_policy`` (or
``default_promotion_gates``) call sites and tests continue to work.

Moved names:
    - ``evaluate_risk_tier_policy`` -- CM-04 ``riskTierPolicy`` promotion gate
      that decides whether a capability of a given risk tier may target a given
      vault/namespace.
    - ``default_promotion_gates`` -- the canonical 7-gate promotion gate set
      (``sourceIntegrity``, ``tests``, ``retrievalEvals``, ``signature``,
      ``provenance``, ``promptInjectionScan``, ``riskTierPolicy``) used to seed
      every promotion request.

Both functions are pure: they reference only string literals and no
``governance`` helpers or module-level constants. This module does NOT import
``governance`` (no circular import).
"""

from __future__ import annotations


def evaluate_risk_tier_policy(risk_tier: str, target_vault: str, visibility: str) -> tuple[bool, str]:
    """Evaluate the riskTierPolicy gate for a promotion request.

    Policy rules:
    - target_vault in {"org", "private"} -> ALLOW for ALL tiers (allowlisted vaults).
    - risk_tier in {"low", "none"} -> ALLOW.
    - risk_tier == "medium" AND target_vault == "all" -> ALLOW with warning.
    - risk_tier in {"high", "critical"} AND target_vault == "all" -> DENY.
    - unknown risk_tier AND target_vault == "all" -> DENY.
    """
    if target_vault in {"org", "private"}:
        return True, "org/private vaults are allowlisted for all risk tiers"
    if risk_tier in {"low", "none"}:
        return True, f"{risk_tier}-tier capability is allowlisted"
    if risk_tier == "medium":
        return True, "medium-tier capability allowed with warning for all-user namespace"
    if risk_tier in {"high", "critical"}:
        tier_label = risk_tier if risk_tier == "high" else risk_tier  # noqa: RUF034
        return (
            False,
            f"{tier_label}-tier capability is blocked from the all-user namespace",
        )
    # Unknown risk tier targeting all-user namespace
    return False, "unknown risk tier is denied for all-user namespace"


def default_promotion_gates() -> dict[str, str]:
    return {
        "sourceIntegrity": "pending",
        "tests": "pending",
        "retrievalEvals": "pending",
        "signature": "pending",
        "provenance": "pending",
        "promptInjectionScan": "pending",
        "riskTierPolicy": "pending",
    }
