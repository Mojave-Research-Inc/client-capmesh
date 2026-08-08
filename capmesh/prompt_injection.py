"""Prompt-injection scan subsystem (CM-12 slice-2 of ``governance.py``).

This module holds the self-contained prompt-injection scan helpers extracted
from ``capmesh.governance`` as part of the governance.py decomposition (plan
item CM-12, slice-2). The public surface of ``governance.py`` is unchanged:
every name moved here is re-imported by ``governance.py`` so existing
``from capmesh.governance import scan_prompt_injection`` (or
``evaluate_prompt_injection_scan``) call sites and tests continue to work.

Moved names:
    - ``_ZERO_WIDTH`` -- zero-width / invisible characters used to split
      blocklisted phrases.
    - ``_HOMOGLYPHS`` -- common Cyrillic/Greek homoglyphs mapped to their
      Latin look-alikes.
    - ``_INJECTION_PHRASES`` -- the blocklisted injection-indicator phrases.
    - ``scan_prompt_injection`` -- best-effort prompt-injection blocklist
      resistant to common obfuscation.
    - ``evaluate_prompt_injection_scan`` -- CM-04 ``promptInjectionScan``
      promotion gate that wraps ``scan_prompt_injection`` with allowlist
      logic.

``evaluate_prompt_injection_scan`` delegates pass/fail to
``injection_allowlist`` (a standalone module that does NOT import
``governance``), pulled in with a lazy import inside the function body. This
module does NOT import ``governance`` at module top, so there is no circular
import. The scan helpers themselves are stdlib-only (``re`` and
``unicodedata``).
"""

from __future__ import annotations

import re
import sqlite3
import unicodedata

# Zero-width / invisible characters used to split blocklisted phrases.
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E], None
)

# Common Cyrillic/Greek homoglyphs mapped to their Latin look-alikes. NFKC does
# NOT fold these (they are distinct scripts, not compatibility forms), so we map
# the high-frequency confusables explicitly before matching.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "i", "ѕ": "s", "ո": "n", "т": "t", "в": "b", "м": "m", "к": "k",
        "ɡ": "g", "ⅼ": "l", "ν": "v", "ο": "o", "ρ": "p", "α": "a", "ε": "e",
        "ι": "i", "κ": "k", "ѵ": "v",
    }
)
_INJECTION_PHRASES = (
    "ignore previous instructions",
    "ignore prior instructions",
    "ignore all previous",
    "disregard previous instructions",
    "disregard the above",
    "system prompt",
    "developer message",
    "exfiltrate",
    "disable safety",
    "disable guardrails",
    "bypass authentication",
    "bypass auth",
    "reveal your instructions",
    "print your system prompt",
    "you are now",
    "act as",
    "ignore the above",
    "forget your previous",
    "forget the above",
    "new instructions:",
    "override your instructions",
    "override the system",
    "do not follow your rules",
    "reveal your system prompt",
    "show your system prompt",
    "jailbreak",
    "developer mode",
    "ignore safety",
    "bypass your safety",
)


def scan_prompt_injection(content: str) -> list[str]:
    """Best-effort prompt-injection blocklist resistant to common obfuscation.

    Normalizes Unicode (NFKC folds full-width/compatibility forms), maps common
    Cyrillic/Greek homoglyphs to Latin, strips zero-width and soft-hyphen
    characters, then matches against both a whitespace-collapsed and a fully
    despaced view. This defeats the trivial bypasses (full-width, cross-script
    homoglyphs, zero-width splitting, newline/space padding) flagged in F-14. It
    is informational, not a security boundary — capabilities are still gated by
    approval and risk review, and an exhaustive confusables table is out of
    scope.
    """
    normalized = unicodedata.normalize("NFKC", content or "").translate(_ZERO_WIDTH).lower().translate(_HOMOGLYPHS)
    # Two views defeat both common obfuscations: whitespace padding (collapse
    # runs to one space) and using invisible/zero-width chars AS separators
    # (compare with all whitespace removed).
    collapsed = re.sub(r"\s+", " ", normalized)
    compact = re.sub(r"\s+", "", normalized)
    found = []
    for phrase in _INJECTION_PHRASES:
        if phrase in collapsed or phrase.replace(" ", "") in compact:
            found.append(phrase)
    return found


def evaluate_prompt_injection_scan(
    con: sqlite3.Connection,
    capability_uri: str,
    target_namespace_id: str,
) -> tuple[str, str]:
    """Evaluate the CM-04 ``promptInjectionScan`` promotion gate.

    Runs ``scan_prompt_injection`` over the capability's name, title,
    description and metadata text, wraps each flagged phrase into the
    ``{"phrase": ...}`` hit shape that ``injection_allowlist.filter_scan_hits``
    expects, and delegates pass/fail to ``injection_allowlist.should_block``.
    Real injection indicators (e.g. ``exfiltrate``) block the promotion; benign
    authoring phrases (``act as``, ``system prompt``, ...) are downgraded to
    ``info``/``allowed`` by the allowlist so legitimate agent/skill
    definitions -- e.g. a cap named ``*-system-prompt`` -- are not blocked as
    false positives.

    CM-04 scope: the gate is enforced only for everyone/org promotion targets
    (store kind ``all_users`` or ``org`` -- ``cap://all/...`` and
    ``cap://org/...``). Private/author promotions are confined to the author's
    own namespace, so the blast radius of any injection wording is bounded;
    the gate is ``skipped`` (not enforced) there by design.

    Returns ``(gate_state, reason)`` where ``gate_state`` is ``"passed"``,
    ``"failed"`` or ``"skipped"``.
    """
    from . import injection_allowlist

    ns_row = con.execute(
        "SELECT store_id FROM namespaces WHERE id = ?",
        (target_namespace_id,),
    ).fetchone()
    if ns_row is None:
        return "skipped", "target namespace not found; injection scan not enforced"
    store_row = con.execute(
        "SELECT kind FROM stores WHERE id = ?",
        (ns_row["store_id"],),
    ).fetchone()
    if store_row is None:
        return "skipped", "target store not found; injection scan not enforced"
    store_kind = str(store_row["kind"] or "")
    if store_kind not in {"all_users", "org"}:
        return "skipped", f"injection scan not enforced for {store_kind or 'unknown'} promotion targets"
    cap_row = con.execute(
        "SELECT name, title, description, type, plugin, metadata_json FROM capabilities WHERE uri = ?",
        (capability_uri,),
    ).fetchone()
    if cap_row is None:
        return "skipped", "source capability not found; injection scan not enforced"
    capability_name = str(cap_row["name"] or "")
    capability_kind = str(cap_row["type"] or "")
    content = "\n".join(
        [
            capability_name,
            str(cap_row["title"] or ""),
            str(cap_row["description"] or ""),
            str(cap_row["metadata_json"] or ""),
        ]
    )
    flagged = scan_prompt_injection(content)
    hits = [{"phrase": phrase} for phrase in flagged]
    capability_plugin = str(cap_row["plugin"] or "")
    if injection_allowlist.should_block(hits, capability_name, capability_kind, capability_plugin):
        blocking, _non_blocking = injection_allowlist.filter_scan_hits(
            hits, capability_name, capability_kind, capability_plugin
        )
        phrases = ", ".join(sorted({str(hit.get("phrase", "")) for hit in blocking}))
        return "failed", f"blocking prompt-injection indicators: {phrases}"
    return "passed", "no blocking prompt-injection indicators (benign hits downgraded to info/allowed)"
