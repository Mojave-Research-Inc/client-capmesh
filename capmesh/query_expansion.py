"""Query expansion using capability taxonomy.

Expands search queries using synonyms, category terms, and the
capability type taxonomy to improve retrieval recall without
requiring an embedding model.
"""

from __future__ import annotations

import re
from typing import Any

# Taxonomy: capability type -> related terms that should also match
TYPE_TAXONOMY: dict[str, list[str]] = {
    "skill": ["instruction", "guide", "howto", "procedure", "playbook", "runbook"],
    "agent": ["assistant", "bot", "specialist", "worker", "delegate"],
    "plugin": ["extension", "addon", "module", "bundle", "package"],
    "command": ["action", "operation", "invoke", "trigger", "shortcut"],
    "mcp_server": ["mcp", "server", "connector", "tool", "service", "endpoint"],
    "workflow": ["pipeline", "process", "flow", "orchestration", "sequence"],
    "reference": ["doc", "documentation", "spec", "specification", "manual", "guide"],
    "bundle": ["collection", "pack", "group", "set"],
}

# Reverse taxonomy: term -> capability type(s)
REVERSE_TAXONOMY: dict[str, list[str]] = {}
for cap_type, terms in TYPE_TAXONOMY.items():
    for term in terms:
        REVERSE_TAXONOMY.setdefault(term.lower(), []).append(cap_type)

# Common synonyms for capability-related queries
SYNONYMS: dict[str, list[str]] = {
    "search": ["find", "lookup", "query", "discover"],
    "create": ["make", "build", "generate", "scaffold", "init"],
    "deploy": ["publish", "release", "ship", "install", "setup"],
    "test": ["verify", "validate", "check", "assert"],
    "debug": ["troubleshoot", "diagnose", "investigate", "trace"],
    "config": ["configuration", "settings", "options", "env"],
    "auth": ["authentication", "login", "sso", "oauth", "token"],
    "api": ["endpoint", "route", "interface", "contract"],
    "db": ["database", "storage", "sqlite", "store"],
    "mcp": ["model context protocol", "tool server", "connector"],
}

# Build reverse synonym map
REVERSE_SYNONYMS: dict[str, list[str]] = {}
for canonical, syns in SYNONYMS.items():
    REVERSE_SYNONYMS.setdefault(canonical.lower(), []).append(canonical)
    for syn in syns:
        REVERSE_SYNONYMS.setdefault(syn.lower(), []).append(canonical)


def expand_query(query: str) -> dict[str, Any]:
    """Expand a search query with taxonomy and synonym terms.

    Returns the original query plus expanded terms, inferred types,
    and suggested FTS query modifications.
    """
    query_lower = query.lower().strip()
    words = re.findall(r"\w+", query_lower)
    expanded_terms: list[str] = []
    inferred_types: list[str] = []

    for word in words:
        # Check reverse taxonomy
        if word in REVERSE_TAXONOMY:
            inferred_types.extend(REVERSE_TAXONOMY[word])
        # Check reverse synonyms
        if word in REVERSE_SYNONYMS:
            for syn in REVERSE_SYNONYMS[word]:
                if syn not in expanded_terms and syn.lower() != word.lower():
                    expanded_terms.append(syn)
        # Check forward synonyms: if this word IS a canonical term, add its synonyms
        if word in SYNONYMS:
            for syn in SYNONYMS[word]:
                if syn not in expanded_terms and syn.lower() != word.lower():
                    expanded_terms.append(syn)
        # Check type taxonomy forward
        for cap_type, terms in TYPE_TAXONOMY.items():
            if word in terms and cap_type not in inferred_types:
                inferred_types.append(cap_type)

    # Build expanded FTS query
    all_terms = list(set(words + expanded_terms))
    fts_terms = [term for term in all_terms if len(term) > 1]
    expanded_fts = " OR ".join(fts_terms) if fts_terms else query

    return {
        "originalQuery": query,
        "expandedTerms": sorted(set(expanded_terms)),
        "inferredTypes": sorted(set(inferred_types)),
        "expandedFtsQuery": expanded_fts,
        "termCount": len(fts_terms),
    }


def expand_search_terms(query: str) -> str:
    """Return just the expanded FTS query string for use in search."""
    return expand_query(query)["expandedFtsQuery"]
