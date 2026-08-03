"""Semver conflict policy for capability version resolution."""

from __future__ import annotations

import re
from typing import Any

_SEMVER_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$')


def parse_semver(version: str) -> tuple[int, int, int, str | None, str | None] | None:
    """Parse a semver string into (major, minor, patch, prerelease, build)."""
    match = _SEMVER_RE.match(version.strip().lstrip("v"))
    if not match:
        return None
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    prerelease = match.group(4)
    build = match.group(5)
    return (major, minor, patch, prerelease, build)


def compare_semver(a: str, b: str) -> int:
    """Compare two semver strings. Returns -1 if a < b, 0 if equal, 1 if a > b."""
    pa = parse_semver(a)
    pb = parse_semver(b)
    if pa is None and pb is None:
        return 0 if a == b else (-1 if a < b else 1)
    if pa is None:
        return 1
    if pb is None:
        return -1
    for i in range(3):
        if pa[i] < pb[i]:
            return -1
        if pa[i] > pb[i]:
            return 1
    pa_pre, pb_pre = pa[3], pb[3]
    if pa_pre is None and pb_pre is None:
        return 0
    if pa_pre is None:
        return 1
    if pb_pre is None:
        return -1
    pa_ids = pa_pre.split(".")
    pb_ids = pb_pre.split(".")
    for i in range(min(len(pa_ids), len(pb_ids))):
        pai, pbi = pa_ids[i], pb_ids[i]
        pai_num = pai.isdigit()
        pbi_num = pbi.isdigit()
        if pai_num and pbi_num:
            ia, ib = int(pai), int(pbi)
            if ia < ib:
                return -1
            if ia > ib:
                return 1
        elif pai_num and not pbi_num:
            return -1
        elif not pai_num and pbi_num:
            return 1
        else:
            if pai < pbi:
                return -1
            if pai > pbi:
                return 1
    if len(pa_ids) < len(pb_ids):
        return -1
    if len(pa_ids) > len(pb_ids):
        return 1
    return 0


def _semver_sort_key(version: str) -> tuple:
    """Return a sort key for semver comparison."""
    parsed = parse_semver(version)
    if parsed is None:
        return (0, 0, 0, 0, "")
    major, minor, patch, pre, _build = parsed
    pre_key = (1, "") if pre is None else (0, pre)
    return (major, minor, patch, pre_key[0], pre_key[1])


def resolve_version_conflict(versions: list[str]) -> dict[str, Any]:
    """Given multiple versions for the same canonical key, resolve the winner."""
    if not versions:
        return {"winner": None, "conflict": False, "allValid": True, "versions": []}
    unique = sorted(set(versions))
    if len(unique) == 1:
        return {"winner": unique[0], "conflict": False, "allValid": parse_semver(unique[0]) is not None, "versions": unique}
    valid = [v for v in unique if parse_semver(v) is not None]
    all_valid = len(valid) == len(unique)
    if not valid:
        winner = max(unique)
    else:
        winner = max(unique, key=lambda v: (parse_semver(v) is not None, _semver_sort_key(v)))
    return {
        "winner": winner,
        "conflict": True,
        "allValid": all_valid,
        "versions": unique,
        "invalidVersions": [v for v in unique if parse_semver(v) is None],
    }


def check_version_conflicts(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check a list of capabilities for version conflicts on the same canonical key."""
    by_key: dict[str, list[str]] = {}
    for cap in capabilities:
        key = str(cap.get("canonicalKey") or cap.get("canonical_key") or "")
        version = str(cap.get("version") or "")
        if key and version:
            by_key.setdefault(key, []).append(version)
    conflicts = []
    for key, versions in by_key.items():
        result = resolve_version_conflict(versions)
        if result["conflict"]:
            conflicts.append({
                "canonicalKey": key,
                "versions": result["versions"],
                "winner": result["winner"],
                "allValid": result["allValid"],
                "invalidVersions": result.get("invalidVersions", []),
            })
    return conflicts
