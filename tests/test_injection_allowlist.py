"""Tests for capmesh.injection_allowlist (VAULT-TRIAGE-REPORT item #7).

These pin the allowlist/severity model that downgrades benign
prompt-injection scan hits so legitimate agent definitions are not blocked
on phrases like ``act as`` or ``system prompt`` in ``*-system-prompt`` caps.
"""
from __future__ import annotations

from capmesh.injection_allowlist import (
    classify_scan_result,
    filter_scan_hits,
    should_block,
)


def test_system_prompt_name_allowed():
    result = classify_scan_result("system prompt", "anthropic-claude-system-prompt", "agent")
    assert result.severity == "allowed"


def test_act_as_info_for_normal_name():
    result = classify_scan_result("act as", "general-helper", "skill")
    assert result.severity == "info"


def test_unknown_phrase_blocks():
    result = classify_scan_result("exfiltrate the secrets", "sneaky-cap", "skill")
    assert result.severity == "block"


def test_role_definition_name_allowed():
    result = classify_scan_result("you are", "analyst-role-definition")
    assert result.severity == "allowed"


def test_filter_scan_hits_splits():
    hits = [{"phrase": "system prompt"}, {"phrase": "exfiltrate secrets"}]
    blocking, non_blocking = filter_scan_hits(hits, "x-system-prompt")
    assert [h["phrase"] for h in blocking] == ["exfiltrate secrets"]
    assert [h["phrase"] for h in non_blocking] == ["system prompt"]
    for hit in blocking + non_blocking:
        assert "severity" in hit
        assert "reason" in hit


def test_should_block_true_when_any_block():
    assert should_block(
        [{"phrase": "system prompt"}, {"phrase": "steal keys"}], "helper"
    ) is True


def test_should_block_false_all_benign():
    assert should_block(
        [{"phrase": "act as"}, {"phrase": "system prompt"}], "helper"
    ) is False


def test_case_insensitive():
    assert classify_scan_result("ACT AS", "Helper").severity == "info"


# ---------------------------------------------------------------------------
# Security-domain vocabulary downgrade (2026-07-31)
#
# An offensive-security corpus cannot describe itself without words like
# "exfiltrate". Before this, three redteam-ai-llm capabilities were refused
# promotion on exactly that word -- a 100% false-positive rate on the domain
# the gate looked most alarming for. These pin the narrow exception AND its
# limits: the downgrade is INFO (never "allowed"), applies only to the
# vocabulary tuple, and only for structurally security-domain plugins.
# ---------------------------------------------------------------------------


def test_exfiltrate_in_security_domain_plugin_is_info_not_block():
    result = classify_scan_result("exfiltrate", "ai-report", "skill", "redteam-ai-llm")
    assert result.severity == "info"
    assert "redteam-ai-llm" in result.reason


def test_exfiltrate_in_ordinary_plugin_still_blocks():
    """The whole point: the downgrade must not leak to non-security plugins."""
    result = classify_scan_result("exfiltrate", "ai-report", "skill", "invoice-helper")
    assert result.severity == "block"


def test_exfiltrate_with_no_plugin_still_blocks():
    """Unattributed capability must never inherit the domain downgrade."""
    assert classify_scan_result("exfiltrate", "ai-report", "skill", None).severity == "block"
    assert classify_scan_result("exfiltrate", "ai-report", "skill", "").severity == "block"


def test_injection_imperative_still_blocks_inside_security_plugin():
    """Vocabulary is downgraded; a command aimed at a reading agent is not.

    Descriptions are fed to an LLM during cap.search, so an imperative in a
    description is the real second-order injection surface -- it blocks even
    for red-team packages.
    """
    for phrase in ("ignore previous instructions", "disable guardrails", "reveal your instructions"):
        result = classify_scan_result(phrase, "prompt-injection", "skill", "redteam-ai-llm")
        assert result.severity == "block", phrase


def test_bypass_auth_variants_downgrade_in_security_domain():
    for phrase in ("bypass auth", "bypass authentication", "BYPASS AUTH"):
        assert (
            classify_scan_result(phrase, "authz-testing", "skill", "redteam-web").severity
            == "info"
        ), phrase


def test_security_domain_prefixes_match_expected_packages():
    from capmesh.injection_allowlist import is_security_domain_plugin

    for plugin in ("redteam-ai-llm", "re-workbench", "dfir-triage", "codeforensics-static"):
        assert is_security_domain_plugin(plugin) is True, plugin
    for plugin in ("invoice-helper", "pm-execution", "core", "reporting", None, ""):
        assert is_security_domain_plugin(plugin) is False, plugin


def test_security_domain_never_returns_allowed():
    """Downgrade to info, never to allowed -- the hit stays visible in gate output."""
    result = classify_scan_result("exfiltrate", "x-system-prompt", "agent", "redteam-ai-llm")
    assert result.severity == "info"


def test_filter_and_should_block_thread_the_plugin():
    hits = [{"phrase": "exfiltrate"}, {"phrase": "ignore previous instructions"}]
    blocking, non_blocking = filter_scan_hits(hits, "prompt-injection", "skill", "redteam-ai-llm")
    assert [h["phrase"] for h in blocking] == ["ignore previous instructions"]
    assert [h["phrase"] for h in non_blocking] == ["exfiltrate"]
    assert should_block(hits, "prompt-injection", "skill", "redteam-ai-llm") is True
    assert should_block([{"phrase": "exfiltrate"}], "prompt-injection", "skill", "redteam-ai-llm") is False
    # Same hit, ordinary plugin -> still blocks.
    assert should_block([{"phrase": "exfiltrate"}], "prompt-injection", "skill", "billing") is True


def test_existing_callers_without_plugin_arg_are_unchanged():
    """Backward compatibility: the new arg is optional and defaults to blocking."""
    assert classify_scan_result("exfiltrate", "sneaky-cap", "skill").severity == "block"
    assert should_block([{"phrase": "exfiltrate"}], "sneaky-cap") is True


# ---------------------------------------------------------------------------
# Surface split: metadata (broadcast by cap.search) vs body (pulled by cap.load)
# ---------------------------------------------------------------------------


def test_imperative_in_description_blocks_even_for_security_plugin():
    """The metadata surface is what cap.search injects into unrelated agents."""
    from capmesh.injection_allowlist import SURFACE_METADATA

    for phrase in ("ignore all previous", "you are now", "reveal your instructions"):
        result = classify_scan_result(
            phrase, "prompt-injection", "skill", "redteam-ai-llm", SURFACE_METADATA
        )
        assert result.severity == "block", phrase


def test_imperative_in_body_is_info_for_security_plugin():
    """A prompt-injection corpus IS a payload collection; the body is pulled, not pushed."""
    from capmesh.injection_allowlist import SURFACE_BODY

    for phrase in ("ignore all previous", "you are now"):
        result = classify_scan_result(
            phrase, "prompt-injection", "skill", "redteam-ai-llm", SURFACE_BODY
        )
        assert result.severity == "info", phrase
        assert "payload" in result.reason


def test_imperative_in_body_still_blocks_for_ordinary_plugin():
    """The body exemption is scoped by plugin, not granted to everyone."""
    from capmesh.injection_allowlist import SURFACE_BODY

    result = classify_scan_result(
        "ignore all previous", "invoice-parser", "skill", "billing", SURFACE_BODY
    )
    assert result.severity == "block"


def test_metadata_is_the_default_surface():
    """Callers that predate the split get the strict surface, not the permissive one."""
    assert (
        classify_scan_result("ignore all previous", "x", "skill", "redteam-ai-llm").severity
        == "block"
    )


def test_domain_vocabulary_downgrades_on_both_surfaces():
    from capmesh.injection_allowlist import SURFACE_BODY, SURFACE_METADATA

    for surface in (SURFACE_METADATA, SURFACE_BODY):
        assert (
            classify_scan_result("exfiltrate", "ai-report", "command", "redteam-ai-llm", surface).severity
            == "info"
        ), surface
