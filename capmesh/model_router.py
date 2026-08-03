"""Model routing for cap.delegate task envelopes.

Maps capability risk tier and task complexity to a model tier, enabling
the capability mesh to route delegated tasks to the cheapest capable model:

- qwen-worker    -- free, local Qwen 3.6 9B Worker (mechanical/atomic/parallel)
- qwen-director  -- free, local Qwen 3.6 35B Director (reasoning/synthesis/verify)
- glm            -- free, local GLM-5.2 on B200 (frontier reasoning, 300K context)
- opus           -- cloud, paid (critical/irreversible/security artifacts)

The routing is advisory: the caller can always override by passing an
explicit modelTier in the delegation params.  The task_runner uses the
routed tier to select the appropriate handler backend.
"""

from __future__ import annotations

from typing import Any

# Model tiers, cheapest first
MODEL_TIERS = ("qwen-worker", "qwen-director", "glm", "opus")

# Map risk_tier -> default model tier
RISK_TIER_TO_MODEL: dict[str, str] = {
    "low": "qwen-worker",
    "medium": "qwen-director",
    "high": "glm",
    "critical": "opus",
}

# Task keywords that bump the model tier up
COMPLEXITY_KEYWORDS: dict[str, list[str]] = {
    "qwen-director": ["synthesize", "review", "verify", "validate", "audit", "analyze", "summarize"],
    "glm": ["refactor", "architecture", "design", "security", "adversarial", "migrate", "optimize"],
    "opus": ["legal", "financial", "irreversible", "compliance", "board", "investor"],
}


def route_model(
    *,
    risk_tier: str = "low",
    capability_type: str = "agent",
    mutating: bool = False,
    task: str = "",
    metadata: dict[str, Any] | None = None,
    override: str | None = None,
) -> dict[str, Any]:
    """Route a delegated task to the cheapest capable model tier.

    Returns a dict with modelTier, rationale, and the backend to use.
    """
    if override and override in MODEL_TIERS:
        return {
            "modelTier": override,
            "rationale": f"explicit override: {override}",
            "backend": _backend_for(override),
        }

    tier = RISK_TIER_TO_MODEL.get(risk_tier, "qwen-worker")
    rationale = f"risk_tier={risk_tier} -> {tier}"

    # Bump tier based on task keywords
    task_lower = (task or "").lower()
    for bump_tier, keywords in COMPLEXITY_KEYWORDS.items():
        if any(kw in task_lower for kw in keywords) and MODEL_TIERS.index(bump_tier) > MODEL_TIERS.index(tier):
            tier = bump_tier
            rationale += f"; keyword bump -> {tier}"

    # Mutating capabilities always need at least qwen-director
    if mutating and MODEL_TIERS.index(tier) < MODEL_TIERS.index("qwen-director"):
        tier = "qwen-director"
        rationale += "; mutating -> qwen-director"

    # Check metadata for explicit hints
    meta = metadata or {}
    if meta.get("requiresFrontier"):
        tier = "glm" if MODEL_TIERS.index(tier) < MODEL_TIERS.index("glm") else tier
        rationale += "; requiresFrontier -> glm"
    if meta.get("requiresCloud"):
        tier = "opus" if MODEL_TIERS.index(tier) < MODEL_TIERS.index("opus") else tier
        rationale += "; requiresCloud -> opus"

    return {
        "modelTier": tier,
        "rationale": rationale,
        "backend": _backend_for(tier),
    }


def _backend_for(tier: str) -> str:
    """Map model tier to the gateway backend name."""
    return {
        "qwen-worker": "asgcode-build",
        "qwen-director": "asgcode-build",
        "glm": "bolde-exec",
        "opus": "codex-exec",
    }.get(tier, "asgcode-build")
