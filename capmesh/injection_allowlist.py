"""Allowlist / severity model for prompt-injection scan hits.

WHY THIS EXISTS
---------------
``scan_prompt_injection`` (governance.py) flags 27/507 promoted caps on
benign authoring phrases like ``act as`` and ``system prompt`` -- phrases
that are *expected* inside agent/skill definitions (e.g. a cap literally
named ``*-system-prompt``). With no allowlist/severity model, legitimate
agent definitions get blocked as false positives.

This module is a self-contained classifier. A later wave calls it AFTER
``scan_prompt_injection`` to downgrade benign hits to ``allowed``/``info``
instead of ``block``. It imports only the standard library and does NOT
import or copy ``scan_prompt_injection`` (refactored concurrently).

SEVERITY MODEL
--------------
- ``allowed``: benign phrase AND the capability name matches the design
  allowlist (e.g. ``system prompt`` inside ``anthropic-claude-system-prompt``)
  -- expected by design.
- ``info``: benign phrase but the capability name does NOT match the
  allowlist -- flagged, but not blocking.
- ``block``: not a recognized benign authoring phrase -- a genuine injection
  indicator that blocks regardless of name. This is why ``exfiltrate secrets``
  blocks even inside a cap named ``x-system-prompt``: the name allowlist only
  downgrades *benign* phrases; it never silences a real injection indicator.
"""
from __future__ import annotations

from dataclasses import dataclass

# Severity values returned by ``classify_scan_result`` and attached to each
# hit by ``filter_scan_hits``. A later gate reads ``should_block`` (severity
# == "block") as its single boolean.
SEVERITY_BLOCK: str = "block"
SEVERITY_INFO: str = "info"
SEVERITY_ALLOWED: str = "allowed"

# Benign authoring phrases that ``scan_prompt_injection`` flags but that are
# expected inside agent/skill definitions. Lowercased; matched against the
# lowercased scan hit phrase.
ALLOWED_PHRASES: tuple[str, ...] = (
    "act as",
    "system prompt",
    "you are",
    "your role",
    "your task",
    "ignore previous",
    "disregard the above",
    "pretend you are",
)

# Capability-name patterns (plain suffixes/prefixes checked with
# ``str.endswith``/``str.startswith``) where the benign authoring phrases above
# are expected BY DESIGN. Lowercased. A name match downgrades a benign phrase
# from ``info`` to ``allowed``; it never downgrades a non-benign phrase.
CAPABILITY_NAME_ALLOWLIST: tuple[str, ...] = (
    "-system-prompt",
    "-role-definition",
    "-persona",
    "system-prompt-",
    "role-",
)

# Offensive-security / DFIR domain vocabulary. These words are the SUBJECT MATTER
# of the plugins below, not an attempt to steer a reading agent: a red-team
# reporting skill cannot describe itself without "exfiltrate", and a malware
# sandbox skill cannot without "c2"/"beacon".
#
# Deliberately NOT added to ALLOWED_PHRASES: that tuple is global, and making
# "exfiltrate" universally benign would silence the exact indicator the gate
# exists to catch on an ordinary capability. These downgrade to INFO (still
# reported, still auditable) and only for capabilities structurally owned by a
# security-domain plugin.
SECURITY_DOMAIN_VOCABULARY: tuple[str, ...] = (
    "exfiltrate",
    "bypass auth",
    "bypass authentication",
)

# Plugin-name prefixes that mark a capability as offensive-security/DFIR tooling.
# `plugin` is STRUCTURAL metadata derived from the package directory at ingest --
# an author cannot set it by wording a description persuasively, which is exactly
# why it is a safer signal than the free-text name allowlist above.
SECURITY_DOMAIN_PLUGIN_PREFIXES: tuple[str, ...] = (
    "redteam-",
    "re-",          # reverse-engineering packs: re-workbench, re-malware, re-dynamic
    "dfir-",
    "codeforensics-",
)


# Scan surfaces. These are NOT equally dangerous and must not be gated identically.
#
#   SURFACE_METADATA -- name/title/description. ``cap.search`` feeds these into
#     OTHER agents' context unbidden, so an imperative here is a live
#     second-order injection against a reader who never asked for it. Gated
#     strictly: only the benign authoring phrases and security-domain
#     vocabulary are ever downgraded.
#
#   SURFACE_BODY -- the capability body, returned only by ``cap.load``, i.e.
#     when an agent deliberately loads that specific capability. A red-team
#     prompt-injection corpus cannot exist without carrying attack strings as
#     example payloads, and the loader asked for exactly that.
#
# Measured 2026-07-31 on redteam-ai-llm.prompt-injection@1.1.0: the description
# is clean; every blocking imperative is in the body, and each is a payload
# literal (a Python string assignment at L119, an f-string at L140, a bracketed
# example at L161) rather than an instruction aimed at the reader.
SURFACE_METADATA: str = "metadata"
SURFACE_BODY: str = "body"


def is_security_domain_plugin(plugin: str | None) -> bool:
    """True when ``plugin`` is an offensive-security / DFIR package.

    Prefix match on the ingest-derived package name. Returns False for a missing
    plugin so an unattributed capability never inherits the domain downgrade.
    """
    if not plugin:
        return False
    return plugin.strip().lower().startswith(SECURITY_DOMAIN_PLUGIN_PREFIXES)


@dataclass(frozen=True)
class ClassificationResult:
    """Outcome of classifying a single prompt-injection scan hit.

    ``severity`` is one of the ``SEVERITY_*`` constants; ``reason`` is a
    human-readable explanation suitable for surfacing in gate warnings.
    """

    severity: str
    reason: str


def classify_scan_result(
    scan_hit_phrase: str,
    capability_name: str,
    capability_kind: str | None = None,
    capability_plugin: str | None = None,
    surface: str = SURFACE_METADATA,
) -> ClassificationResult:
    """Classify one scan hit as ``allowed``/``info``/``block``.

    The name allowlist only downgrades *benign* authoring phrases. A
    non-benign indicator (e.g. ``exfiltrate secrets``) blocks even when the
    capability name matches the allowlist, so real injection wording is never
    silenced by a benign-looking name.

    ``capability_plugin`` adds one narrow exception: security-domain vocabulary
    (``SECURITY_DOMAIN_VOCABULARY``) inside a capability owned by a
    security-domain plugin (``SECURITY_DOMAIN_PLUGIN_PREFIXES``) is downgraded to
    ``info`` rather than ``block``. Measured 2026-07-31: this was blocking
    ``redteam-ai-llm.prompt-injection`` and ``redteam-ai-llm.ai-report`` -- an
    offensive-security corpus cannot describe itself without the word
    ``exfiltrate``, so the gate produced a 100% false-positive rate on exactly
    the capabilities it looked most alarming for. A gate that only ever cries
    wolf trains its operators to ignore it.

    ``surface`` decides how far that exception reaches, because the two scan
    surfaces carry very different risk:

      * ``SURFACE_METADATA`` (name/title/description) -- only the vocabulary in
        ``SECURITY_DOMAIN_VOCABULARY`` is downgraded. An imperative such as
        ``ignore all previous instructions`` still BLOCKS even for a red-team
        package, because ``cap.search`` feeds descriptions to an LLM: an
        imperative here reaches agents that never asked for this capability,
        which is the real second-order injection surface.

      * ``SURFACE_BODY`` -- attack strings are also downgraded, because a
        prompt-injection testing corpus IS a payload collection and the body is
        returned only by an explicit ``cap.load`` of that specific capability.

    Both exceptions are scoped by ``plugin``, which is derived from the package
    directory at ingest and therefore cannot be spoofed by wording a description
    persuasively -- unlike the free-text name allowlist. Both downgrade to
    ``info``, never ``allowed``, so every phrase stays recorded and visible in
    the gate reason.
    """
    phrase_l = scan_hit_phrase.lower()
    name_l = capability_name.lower()
    name_allowlisted = name_l.endswith(CAPABILITY_NAME_ALLOWLIST) or name_l.startswith(
        CAPABILITY_NAME_ALLOWLIST
    )
    security_domain = is_security_domain_plugin(capability_plugin)
    if phrase_l in SECURITY_DOMAIN_VOCABULARY and security_domain:
        return ClassificationResult(
            SEVERITY_INFO,
            f"security-domain vocabulary {scan_hit_phrase!r} expected in "
            f"{capability_kind or 'capability'} from plugin {capability_plugin!r}; "
            "flagged but not blocking",
        )
    if security_domain and surface == SURFACE_BODY:  # noqa: SIM102
        # Body of a security-domain capability: attack strings are the payload
        # corpus, not an instruction to the reader. Downgraded to info so the
        # gate still names every phrase in its warnings. NOT applied to
        # SURFACE_METADATA -- an imperative in a description is broadcast into
        # unrelated agents by cap.search and always blocks.
        if phrase_l not in ALLOWED_PHRASES:
            return ClassificationResult(
                SEVERITY_INFO,
                f"attack payload {scan_hit_phrase!r} in the body of "
                f"{capability_plugin!r} (offensive-security corpus); readable only "
                "via an explicit cap.load, flagged but not blocking",
            )
    if phrase_l in ALLOWED_PHRASES:
        if name_allowlisted:
            return ClassificationResult(
                SEVERITY_ALLOWED,
                f"flagged phrase {scan_hit_phrase!r} expected in "
                f"{capability_kind or 'capability'} named {capability_name!r}",
            )
        return ClassificationResult(
            SEVERITY_INFO,
            f"benign authoring phrase {scan_hit_phrase!r}; flagged but not blocking",
        )
    return ClassificationResult(
        SEVERITY_BLOCK,
        f"unrecognized injection indicator {scan_hit_phrase!r} in {capability_name!r}",
    )


def filter_scan_hits(
    hits: list[dict],
    capability_name: str,
    capability_kind: str | None = None,
    capability_plugin: str | None = None,
    surface: str = SURFACE_METADATA,
) -> tuple[list[dict], list[dict]]:
    """Split raw scan hits into ``(blocking, non_blocking)``.

    Each returned hit is a shallow copy of the input hit augmented with
    ``severity`` and ``reason`` keys from :func:`classify_scan_result` (the
    caller's dicts are not mutated). ``blocking`` holds hits whose severity is
    ``block``; ``non_blocking`` holds hits whose severity is ``info`` or
    ``allowed``.
    """
    blocking: list[dict] = []
    non_blocking: list[dict] = []
    for hit in hits:
        phrase = hit.get("phrase", "")
        result = classify_scan_result(
            phrase, capability_name, capability_kind, capability_plugin, surface
        )
        augmented = {**hit, "severity": result.severity, "reason": result.reason}
        if result.severity == SEVERITY_BLOCK:
            blocking.append(augmented)
        else:
            non_blocking.append(augmented)
    return blocking, non_blocking


def should_block(
    hits: list[dict],
    capability_name: str,
    capability_kind: str | None = None,
    capability_plugin: str | None = None,
    surface: str = SURFACE_METADATA,
) -> bool:
    """Return ``True`` iff any hit classifies as ``block``.

    This is the single boolean the gate calls. Fails closed: a hit missing the
    ``phrase`` key is treated as an empty phrase, which classifies as ``block``.
    """
    for hit in hits:
        phrase = hit.get("phrase", "")
        result = classify_scan_result(
            phrase, capability_name, capability_kind, capability_plugin, surface
        )
        if result.severity == SEVERITY_BLOCK:
            return True
    return False
