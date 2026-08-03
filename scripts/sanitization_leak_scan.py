#!/usr/bin/env python3
"""Sanitization leak scanner — company-agnostic CapMesh productionization gate.

Asserts that a target tree (the sanitized repo / corpus) contains ZERO ASG-private
identifiers, per the cire-apps sanitization contract (cire-apps/CLAUDE.md +
docs/security/ai-agent-security.md): "Never include internal ASG identifiers,
hostnames, domains, IPs, personal paths, private secret-store paths, credentials,
cookies, raw tokens, or customer secrets."

Exit codes:
  0 = clean (no leaks) — gate passes
  1 = leaks found — gate fails (print hit table)
  2 = usage / scan error

This is the negative-acceptance gate from the capmesh workstream
("signature/provenance negatives, policy-conflict tests"). Wire it into CI so a
leak fails the build.

Usage:
  sanitization_leak_scan.py [--root PATH] [--allowlist FILE] [--json]
  --root       directory to scan (default: CWD)
  --allowlist  newline-delimited file of substrings to permit (e.g. provenance
               stubs that legitimately mention "anthropic-official"); matched by
               substring against the hit's full line, case-sensitive
  --json       emit machine-readable JSON instead of a human table
  --baseline   path to a "before" snapshot of allowed-hit counts (JSON); used
               during sanitization to assert counts only DECREASE. Optional.

The scanner is intentionally conservative: it over-matches (regex, no AST) and
relies on the human sanitizer to confirm each hit is a real ASG identifier vs. a
false positive. A green run is necessary, not sufficient — pair with the
leak-negative pytest suite (tests/test_sanitization_leak.py).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# ASG-private token catalog. Add patterns here; the scanner is the single
# source of truth for what "ASG-private" means. Keep this list in sync with
# cire-apps/CLAUDE.md sanitization rule.
# ---------------------------------------------------------------------------
# Each entry: (label, compiled regex, is_regex). Plain substrings compile as
# fixed strings (fast, no metachar surprises); true regexes flagged is_regex.
ASG_PRIVATE_PATTERNS: list[tuple[str, str, bool]] = [
    # Domains / hostnames
    ("asg-domain", r"asgroup\.ai", True),
    ("asg-tailnet", r"asg\.ts\.net", True),
    ("capmesh-host", r"capmesh\.asg\.ts\.net", True),
    # Entra / identity tenant
    ("entra-tenant-id", r"7cc4e405[-0-9a-fA-F]*", True),
    # Entity / org names (case-sensitive to avoid false hits on common words)
    ("entity-asi", "Agentic Secure Inc", False),
    ("entity-agentic-secure", "Agentic Secure", False),
    ("entity-mojave", "Mojave Research", False),
    ("entity-mojave-research-inc", "Mojave-Research-Inc", False),
    ("entity-ipsa", "IPSA Intelligent Systems", False),
    ("entity-xero-llc", "Agent Xero", False),
    ("entity-trace-llc", "Agentic Trace", False),
    ("entity-asgroup", "ASGroup", False),
    ("org-asgroup-main-project", "asgroup-main-project", False),
    # Entity-abbreviation + color tokens (R1-P0-01). Leaks like "mriblue",
    # "asiblue", "ipsared", "xeroblue", "tracegray" are entity-abbreviation-
    # derived color names forbidden by the sanitization contract. The
    # inline (?i) flag compiles this single entry case-insensitive without
    # changing the shared _compile() loop (existing regex entries stay
    # case-sensitive as authored). Verified FP-free across the tree.
    ("entity-abbrev-color", r"(?i)\b(mri|asi|ipsa|xero|trace)[a-z]*(blue|red|green|gray|grey)\b", True),
    # Entity-abbreviation hyphenated slug leaks (R6-BP-07). The color-suffix regex
    # above is blind to hyphenated capability slugs like
    # "global.consolidating-xero-group-financials" or
    # "global.building-trace-engagement-letters" — both use a banned entity
    # abbreviation (Xero, Trace) as a hyphenated token, not a color suffix.
    # Anchored on the global.<slug>@ capability-pin form so it catches the
    # internal-name reuse without flagging the legitimate public words xero/trace
    # in prose. Case-insensitive to catch Xero/Trace too.
    ("entity-abbrev-slug", r"(?i)global\.[a-z0-9-]*(mri|asi|ipsa|xero|trace)[a-z0-9-]*@", True),
    # ASG-internal fleet agent pin (R6-BP-07). "bolde" is an ASG-internal fleet
    # name. Deliberately SCOPED to the global.bolde-<slug>@ capability-pin form
    # (NOT a bare case-insensitive "bolde" substring) because a bare (?i)bolde
    # would false-positive the legitimate public "Bolde" brand that appears
    # elsewhere in the broader repo (README "Bolde Apps for CIRE", cireapps.bolde.ai,
    # BOLDE_* env vars) and break the build — a tier-collapse hazard. The
    # global.bolde-...@ anchor is load-bearing: it catches the internal-fleet
    # agent-pin reuse (e.g. global.bolde-large-specialist@0.1.0) with zero FP.
    ("fleet-bolde-agent-pin", r"\bglobal\.bolde-[a-z0-9-]+@", True),
    # Node / host names
    ("node-cpubox", "cpubox", False),
    ("node-jwgpu", "jwgpu", False),
    ("host-asgcode-packet-gpu", "asgcode-packet-gpu", False),
    # Personal paths / deploy roots
    # "/Users/jason" is a substring of "/Users/jasonw", so it catches both
    # bare /Users/jason and /Users/jasonw personal paths.
    ("path-users-jason", "/Users/jason", False),
    ("path-home-jason", "/home/jason", False),
    ("path-capmesh-registry-gitdir", ".local/state/capmesh-registry.gitdir", False),
    # Personal GitHub org (MRIHub) — catches bare org + "MRIHub/<repo>" refs.
    ("org-mrihub", "MRIHub", False),
    # Superadmin emails (case-insensitive: catches Jason@/jason@, Manbir@/manbir@)
    ("email-jason", r"[Jj]ason@", True),
    ("email-manbir", r"[Mm]anbir@", True),
    # Capmesh-tier local-subject placeholder — the neutral default is admin@example.com;
    # any <localpart>@capmesh.local is an un-neutralized leak (uses the capmesh
    # product-tier name in a user-facing subject). Catch ANY localpart so a
    # non-admin subject (e.g. deployer@) cannot be reintroduced silently.
    ("local-subject-capmesh", r"[\w.+-]+@capmesh\.local", True),
    # Personal name (persona owner) — only flag in corpus context, see allowlist
    ("person-jason-wareham", "Jason Wareham", False),
    ("person-manbir", "Manbir", False),
    # Personal unix user "jason" baked into deployment/ops scripts as a
    # systemd unit owner or chown/setfacl target (FP-free: these forms only
    # appear as a real unix-user name, never as prose/code).
    ("unix-user-jason-unit", "User=jason", False),
    ("unix-user-jason-group", "Group=jason", False),
    ("unix-user-jason-chown", "jason:jason", False),
    ("unix-user-jason-acl", "u:jason:", False),
    ("person-gulati", "Gulati", False),
    ("person-wareham", "Wareham", False),
    # Personal email / overlay-name leaks (fixed-string: each token is FP-free
    # across the tree — only ever appeared at the now-removed leak sites).
    ("email-michel", "michel", False),
    ("email-paradis", "paradis", False),
    ("overlay-atrace", "atrace", False),
    ("entity-ivc-trust", "IVC-Trust", False),
    # Real instance hashes — hex-anchored + 8+ hex chars. "idn_REDACTED"/"ns_REDACTED"
    # don't match (R not hex); code vars ns_root/ns_id don't match (not 8+ pure hex).
    ("instance-hash-idn", r"\bidn_[0-9a-fA-F]{8,}", True),
    ("instance-hash-ns", r"\bns_[0-9a-fA-F]{8,}", True),
    # Excluded ASG-OS plugin packs / ASG-internal system names — explicit
    # alternation (FP-safe: does NOT match KEEP asg-os / asg-os-plugins /
    # asg-capability-mesh* units, none of which are listed here).
    ("asg-excluded-pack",
     r"\basg-(?:finance-govcon-controls|pricing-strategy|strategic-planning|"
     r"operating-model|program-management|chairman-office|communications|"
     r"local-agent-roster|intercompany-governance|entity-strategy|mcp-gateway|"
     r"hardened-profile|supply-chain-policy|people-operations|contract-lifecycle|"
     r"document-forge|external-docs|internal-docs|client-delivery|"
     r"delivery-pmo-and-sops|small-business|govcon-capture|regulatory-radar|"
     r"financial-consolidation|visual-intelligence|board-governance|"
     r"subcontractor-network|overlay-asi|overlay-ipsa|overlay-mri|"
     r"overlay-agentic-trace|overlay-agent-xero|overlay-aisf|agent-governance|"
     r"training-and-visuals)\b", True),
]

# File globs to skip (caches, build artifacts, VCS, provenance stubs that are
# *expected* to name "anthropic-official" as a marketplace name — those are not
# ASG-private). Provenance stubs are allowlisted per-file below.
SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules", "build", "dist", ".turbo", ".next",
    "asg_capability_mesh.egg-info", ".eggs", ".cache",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".so", ".o", ".a", ".lock", ".png", ".jpg",
                 ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".zip",
                 ".gz", ".tgz", ".db", ".sqlite", ".sqlite3", ".bin"}


# Files to skip entirely from scanning (known self-references).
SKIP_FILES = {
    "scripts/sanitization_leak_scan.py",
    "sanitization_leak_scan.py",  # bare basename so self-skip works from any CWD
    # Contract-guard test that asserts the mac installer never leaks the
    # forbidden identifiers (michel/paradis/atrace/IVC-Trust/mriblue). It names
    # those tokens as test fixtures, not as leaked production identifiers — the
    # guarded installer itself is clean. Same self-referential rationale as
    # the scanner self-skip above; verified the guard test passes and the
    # installer has zero hits for every token.
    "tests/test_mac_installer_settings_comment.py",
    "test_mac_installer_settings_comment.py",
}

# Files that are allowed to reference "anthropic-official" as a marketplace
# name in provenance stubs (third-party cap provenance, not ASG-private). The
# scanner still checks these for *other* ASG tokens; only the marketplace name
# is exempted via the per-line allowlist mechanism.
PROVENANCE_FILES = {".upstream-source"}


@dataclass
class Hit:
    file: str
    line_no: int
    label: str
    pattern: str
    line: str

    def to_json(self) -> dict:
        return asdict(self)


def _compile(patterns: list[tuple[str, str, bool]]) -> list[tuple[str, "re.Pattern[str]", bool]]:
    out = []
    for label, pat, is_re in patterns:
        if is_re:
            out.append((label, re.compile(pat), True))
        else:
            out.append((label, re.compile(re.escape(pat)), False))
    return out


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in SKIP_SUFFIXES:
            continue
        rel = str(p.relative_to(root))
        if rel in SKIP_FILES or os.path.basename(rel) in SKIP_FILES:
            continue
        yield p


def _line_allowed(line: str, allowlist: list[str]) -> bool:
    return any(allow in line for allow in allowlist)


def scan(root: Path, allowlist: list[str]) -> list[Hit]:
    compiled = _compile(ASG_PRIVATE_PATTERNS)
    hits: list[Hit] = []
    for fpath in _iter_files(root):
        rel = str(fpath.relative_to(root))
        is_provenance = fpath.name in PROVENANCE_FILES
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            # Provenance stubs may legitimately contain "anthropic-official"
            # marketplace naming — extend allowlist dynamically for that file.
            line_allow = allowlist + (["anthropic-official"] if is_provenance else [])
            if _line_allowed(line, line_allow):
                continue
            for label, rx, _ in compiled:
                if rx.search(line):
                    hits.append(Hit(rel, i, label, rx.pattern, line.strip()[:200]))
                    break  # one hit per line is enough; the sanitizer reads the line
    return hits


# Install-readiness gate: a README shell command line that references a script
# under scripts/ or ops/ must point at a real file. Only fenced code blocks are
# scanned — a runnable command — not prose mentions of scripts that may
# legitimately live in a sibling repo (e.g. the asg-os autoupdate script).
# Candidates cover both resolution conventions README uses: scripts/ is
# repo-root-relative (resolved against root.parent) and ops/ is
# service-relative (resolved against root).
_INSTALL_SCRIPT_REF = re.compile(r"(scripts|ops)/[A-Za-z0-9_./-]+\.sh")


def scan_readme_install_paths(root: Path) -> list[Hit]:
    """Append an install-readiness Hit for every README shell-command-line
    reference to a script under scripts/ or ops/ that does not exist on disk.

    A documented install path that does not exist is an install-readiness error:
    a reader who copies the command fails at a path that was never shipped.
    severity is implicit-error (any scanner Hit fails the gate, exit 1).
    """
    readme = root / "README.md"
    if not readme.is_file():
        return []
    # README resolves install scripts two ways: scripts/ is repo-root-relative
    # (resolved against root.parent.parent, i.e. <repo>/scripts/) and ops/ is
    # service-relative (resolved against root, i.e. services/capability-mesh/ops/).
    # root.parent (<repo>/services) is included for completeness.
    candidates = [root, root.parent, root.parent.parent]
    hits: list[Hit] = []
    in_fence = False
    try:
        text = readme.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for i, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        for m in _INSTALL_SCRIPT_REF.finditer(line):
            ref = m.group(0)
            if not any((base / ref).is_file() for base in candidates):
                hits.append(Hit(
                    file="README.md",
                    line_no=i,
                    label="install-readiness",
                    pattern=f"README references missing install script {ref}",
                    line=line.strip()[:200],
                ))
    return hits


def _format_table(hits: list[Hit]) -> str:
    if not hits:
        return "no ASG-private leaks found"
    out = [f"{'FILE':60} {'LN':>5}  {'LABEL':22} LINE"]
    for h in hits:
        out.append(f"{h.file:60} {h.line_no:>5}  {h.label:22} {h.line}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ASG-private leak scanner for CapMesh sanitization")
    ap.add_argument("--root", default=".", help="directory to scan")
    ap.add_argument("--allowlist", help="newline-delimited file of permitted substrings")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--baseline", help="JSON baseline of prior hit counts (assert non-increase)")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 2

    allowlist: list[str] = []
    if args.allowlist:
        allowlist = Path(args.allowlist).read_text(encoding="utf-8").splitlines()
        allowlist = [a for a in (a.strip() for a in allowlist) if a and not a.startswith("#")]

    hits = scan(root, allowlist)
    # Install-readiness gate: README install commands must reference files that
    # exist. Runs as part of the normal scan and contributes to nonzero-exit.
    hits.extend(scan_readme_install_paths(root))

    if args.baseline:
        try:
            prior = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            prior_count = prior.get("count", prior.get("total", 0)) if isinstance(prior, dict) else 0
            if len(hits) > prior_count:
                print(f"error: leak count increased vs baseline ({len(hits)} > {prior_count})",
                      file=sys.stderr)
                if args.json:
                    print(json.dumps({"hits": [h.to_json() for h in hits], "count": len(hits),
                                       "baseline": prior_count, "increased": True}))
                else:
                    print(_format_table(hits), file=sys.stderr)
                return 1
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: cannot read baseline {args.baseline}: {e}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"hits": [h.to_json() for h in hits], "count": len(hits)}))
    else:
        print(_format_table(hits))

    return 0 if not hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
