"""Tests for the model_router module."""

from __future__ import annotations

import unittest

from capmesh.model_router import MODEL_TIERS, route_model


class TestModelRouter(unittest.TestCase):
    def test_low_risk_defaults_to_qwen_worker(self) -> None:
        result = route_model(risk_tier="low", task="build this module")
        self.assertEqual(result["modelTier"], "qwen-worker")
        self.assertEqual(result["backend"], "asgcode-build")

    def test_medium_risk_defaults_to_qwen_director(self) -> None:
        result = route_model(risk_tier="medium", task="summarize the results")
        self.assertEqual(result["modelTier"], "qwen-director")
        self.assertEqual(result["backend"], "asgcode-build")

    def test_high_risk_defaults_to_glm(self) -> None:
        result = route_model(risk_tier="high", task="refactor the architecture")
        self.assertEqual(result["modelTier"], "glm")
        self.assertEqual(result["backend"], "bolde-exec")

    def test_critical_risk_defaults_to_opus(self) -> None:
        result = route_model(risk_tier="critical", task="review legal compliance")
        self.assertEqual(result["modelTier"], "opus")
        self.assertEqual(result["backend"], "codex-exec")

    def test_explicit_override(self) -> None:
        result = route_model(risk_tier="low", task="simple task", override="glm")
        self.assertEqual(result["modelTier"], "glm")
        self.assertIn("override", result["rationale"])

    def test_invalid_override_ignored(self) -> None:
        result = route_model(risk_tier="low", task="simple task", override="invalid-model")
        self.assertEqual(result["modelTier"], "qwen-worker")

    def test_keyword_bumps_tier_up(self) -> None:
        result = route_model(risk_tier="low", task="please review and verify this code")
        self.assertEqual(result["modelTier"], "qwen-director")

    def test_keyword_bumps_to_glm(self) -> None:
        result = route_model(risk_tier="low", task="refactor the security architecture")
        self.assertEqual(result["modelTier"], "glm")

    def test_keyword_bumps_to_opus(self) -> None:
        result = route_model(risk_tier="low", task="review legal financial compliance")
        self.assertEqual(result["modelTier"], "opus")

    def test_mutating_bumps_to_director(self) -> None:
        result = route_model(risk_tier="low", task="simple write", mutating=True)
        self.assertEqual(result["modelTier"], "qwen-director")

    def test_metadata_requires_frontier(self) -> None:
        result = route_model(risk_tier="low", task="simple", metadata={"requiresFrontier": True})
        self.assertEqual(result["modelTier"], "glm")

    def test_metadata_requires_cloud(self) -> None:
        result = route_model(risk_tier="low", task="simple", metadata={"requiresCloud": True})
        self.assertEqual(result["modelTier"], "opus")

    def test_rationale_is_informative(self) -> None:
        result = route_model(risk_tier="high", task="refactor architecture", mutating=True)
        self.assertIn("risk_tier=high", result["rationale"])
        self.assertIn("backend", result)

    def test_all_tiers_have_backends(self) -> None:
        for tier in MODEL_TIERS:
            result = route_model(risk_tier="critical", task="test", override=tier)
            self.assertTrue(result["backend"])

    def test_capability_type_does_not_affect_routing(self) -> None:
        r1 = route_model(risk_tier="low", task="test", capability_type="agent")
        r2 = route_model(risk_tier="low", task="test", capability_type="skill")
        self.assertEqual(r1["modelTier"], r2["modelTier"])


if __name__ == "__main__":
    unittest.main()
