from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from .models import Capability, normalize_path

DEFAULT_ROOTS = (
    str(Path(__file__).resolve().parent.parent / "caps"),  # bundled caps shipped with client-capmesh
    "~/.agents/skill-registry",
    "~/.codex/skills",
    "~/.codex/plugins/cache",
)


def configured_default_roots() -> tuple[str, ...]:
    raw = os.environ.get("CAPMESH_ROOTS")
    if raw:
        return tuple(item for item in raw.split(os.pathsep) if item)
    return DEFAULT_ROOTS


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    end = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end = idx
            break
    if end is None:
        return {}, text

    raw = lines[1:end]
    data: dict[str, Any] = {}
    idx = 0
    while idx < len(raw):
        line = raw[idx]
        if not line.strip() or line.lstrip().startswith("#"):
            idx += 1
            continue
        if ":" not in line:
            idx += 1
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not value:
            # Valid YAML permits a quoted scalar to wrap onto indented lines
            # after an empty ``key:``. Preserve that common skill-manifest
            # form without taking a dependency on a full YAML loader.
            idx += 1
            continuation: list[str] = []
            while idx < len(raw) and (raw[idx].startswith(" ") or raw[idx].startswith("\t")):
                continuation.append(raw[idx].strip())
                idx += 1
            if continuation:
                data[key] = " ".join(continuation).strip().strip('"').strip("'")
                continue
            data[key] = ""
            continue
        if value in {"|", "|-", ">", ">-"}:
            idx += 1
            block: list[str] = []
            while idx < len(raw) and (raw[idx].startswith(" ") or raw[idx].startswith("\t") or not raw[idx].strip()):
                block.append(raw[idx].strip())
                idx += 1
            data[key] = "\n".join(block).strip()
            continue
        if value.lower() in {"true", "false"}:
            data[key] = value.lower() == "true"
        else:
            data[key] = value
        idx += 1
    return data, "\n".join(lines[end + 1 :])


def read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^\w\.\-]+", "-", value, flags=re.UNICODE)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value or "unnamed"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return {}


# Component directories a capability package may contain. Kept in one place because both
# package attribution (package_name_for) and package-root detection (package_path_for)
# must agree on what counts as "inside a package".
PACKAGE_COMPONENT_DIRS = ("skills", "agents", "commands", "references")

# Runtime projections occasionally end up nested inside an authored plugin tree
# (for example ``plugins/foo/.codex/skills/...``).  They are mirrors, not source,
# and ingesting them at the authored root's authority creates false equal-rank
# collisions.  Only ignore these names when they occur *below* a configured
# root; a configured root such as ``~/.codex/skills`` must still be scanned.
NESTED_RUNTIME_MIRROR_DIRS = {
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".git",
    "__pycache__",
    "node_modules",
}


def package_name_for(path: Path, root: Path) -> str | None:
    # Plugin caches are themselves below a directory named ``plugins``.  Handle
    # them before the authored-plugin rule so ``~/.codex/plugins/cache`` does
    # not incorrectly attribute every cached capability to a plugin named
    # ``cache``.  Cache layouts are ``<channel>/<plugin>/<release>/<kind>/...``
    # (or ``<plugin>/<release>/<kind>/...`` when the root already selects a
    # channel), so the owning plugin is two components before the kind marker.
    if "cache" in root.parts:
        rel = path.relative_to(root).parts
        if path.name in {".mcp.json", "cap.json"} and len(rel) >= 3:
            return rel[-3]
        component_positions = [
            rel.index(marker) for marker in PACKAGE_COMPONENT_DIRS if marker in rel
        ]
        if component_positions:
            marker_index = min(component_positions)
            if marker_index >= 2:
                return rel[marker_index - 2]
            if marker_index >= 1:
                return rel[marker_index - 1]
        return rel[0] if rel else None
    if "plugins" in root.parts or (
        root.name == "asg-os-plugins" and root.parent.name == "capability-roots"
    ):
        rel = path.relative_to(root).parts
        # A scoped ingest may point at one package rather than the parent plugins/
        # directory. Preserve the same package identity in both discovery shapes.
        if root.parent.name == "plugins" and (root / ".claude-plugin" / "plugin.json").is_file():
            return root.name
        if path.name in {".mcp.json", "cap.json"} and len(rel) >= 2:
            package_parts = list(rel[:-1])
            if root.parent.name == "plugins" and root.name != "plugins":
                package_parts.insert(0, root.name)
            return "-".join(package_parts)
        # The authoring tree may group plugins below a bundle directory, e.g.
        # ``plugins/anthropic-code/feature-dev/agents/...``.  Attribute the
        # capability to the package immediately owning its component directory,
        # not to the top-level bundle, or same-named agents from sibling plugins
        # collapse onto one canonical key.
        for marker in (*PACKAGE_COMPONENT_DIRS, ".claude-plugin"):
            if marker in rel:
                marker_index = rel.index(marker)
                if marker_index >= 1:
                    package_parts = list(rel[:marker_index])
                    if root.parent.name == "plugins" and root.name != "plugins":
                        package_parts.insert(0, root.name)
                    return "-".join(package_parts)
        return rel[0] if rel else None
    if root.parent.name == "skill-registry":
        rel = path.relative_to(root).parts
        if rel and rel[0] in PACKAGE_COMPONENT_DIRS:
            return root.name
    if root.name == "skill-registry":
        rel = path.relative_to(root).parts
        # Every packaged component dir attributes to its owning package — not just skills/.
        # Attributing ONLY skills/ was a real defect: agents/ and commands/ fell through to
        # None, which capability_uri() renders as the `global` namespace. Measured on this
        # host 2026-07-18: 601 caps (308 agents + 293 commands) across 120 packages were
        # filed as `global.<name>`, and 68 of those URIs COLLIDED — two packages sharing one
        # cap URI, where the second ingested silently overwrote the first (e.g.
        # global.treasurer claimed by both cfo-cash and cfo-treasury-and-cash). Package
        # attribution is what makes those distinct, and makes a plugin's agents/commands
        # discoverable alongside its own skills instead of orphaned in `global`.
        if len(rel) >= 3 and rel[1] in PACKAGE_COMPONENT_DIRS:
            return rel[0]
        return None
    return None


def package_path_for(path: Path) -> Path:
    parts = path.parts
    for marker in PACKAGE_COMPONENT_DIRS:
        if marker in parts:
            idx = parts.index(marker)
            return Path(*parts[:idx])
    if ".claude-plugin" in parts:
        idx = parts.index(".claude-plugin")
        return Path(*parts[:idx])
    return path.parent


def source_kind_for(path: Path) -> str:
    parts = set(path.parts)
    if path.name == "SKILL.md":
        return "skill"
    if "agents" in parts and path.suffix == ".md":
        return "agent"
    if "commands" in parts and path.suffix == ".md":
        return "command"
    if path.name == "plugin.json":
        return "plugin_manifest"
    if path.name == ".mcp.json":
        return "mcp_manifest"
    if path.name == "cap.json":
        return "cap_manifest"
    return "reference"


def source_system_for(path: Path) -> str:
    s = str(path)
    if "/GitHub/asg-os/plugins/" in s or "/capability-roots/asg-os-plugins/" in s:
        return "asg-os.plugins"
    if "/.agents/skill-registry/" in s:
        return "agents.skill-registry"
    if "/.codex/plugins/cache/" in s:
        return "codex.plugin-cache"
    if "/.codex/skills/" in s:
        return "codex.skills"
    if "/.claude/plugins/cache/" in s:
        return "claude.plugin-cache"
    return "local"


def source_authority_rank(source_system: str, source_path: str) -> int:
    """Return the deterministic authority tier for mirrored ecosystem sources.

    ASG OS is the authoring source. The shared registry is authoritative over ordinary
    projected Codex skills, while Codex's own ``.system`` bundle is authoritative for those
    vendor-managed built-ins. Cache copies are intentionally lower than authored/projected
    sources. Equal-rank content conflicts remain ambiguous and must fail closed at merge time.
    """
    normalized = normalize_path(source_path)
    if source_system == "asg-os.plugins":
        # Nested editor MIRRORS inside the authoring tree are NOT authoring sources.
        # Sync tooling has written copies such as
        #   plugins/<p>/.codex/skills/<p>/Users/<user>/GitHub/asg-os/plugins/<p>/skills/...
        # i.e. another machine's absolute path baked inside this repo. Ranked at 500
        # they tie with the real file, so merge_duplicate_capabilities correctly fails
        # closed on "equal-authority sources contain different content" — which blocked
        # ingest of 6 plugins outright (anthropic-code, anthropic-knowledge-work,
        # anthropic-official, asgcode-mkt, gtm-warroom, vossian) and, because only a
        # FULL reingest generates vector embeddings, left every incrementally-added
        # capability present-but-unsearchable.
        # Demote mirrors below the authored file so the real one wins cleanly. This
        # fixes the class rather than deleting 114 git-tracked mirror files.
        if "/.codex/" in normalized or "/.cursor/" in normalized:
            return 250
        return 500
    if source_system == "codex.skills" and "/.codex/skills/.system/" in normalized:
        return 450
    if source_system == "agents.skill-registry":
        return 400
    if source_system == "codex.skills":
        return 300
    if source_system == "codex.plugin-cache":
        # Prefer the current signed/remote OpenAI channel over the retired
        # local curated cache when both retain the same logical capability.
        # Content still fails closed for conflicts within one authority tier.
        if "/.codex/plugins/cache/openai-curated-remote/" in normalized:
            return 260
        if "/.codex/plugins/cache/openai-bundled/" in normalized:
            return 250
        if "/.codex/plugins/cache/openai-curated/" in normalized:
            return 220
        return 200
    if source_system == "claude.plugin-cache":
        return 100
    return 0


def capability_uri(cap_type: str, plugin: str | None, name: str, version: str, fallback: str) -> tuple[str, str]:
    plug = slugify(plugin or "global")
    slug = slugify(name)
    version = slugify(version or "0.1.0")
    canonical_key = f"{cap_type}:{plug}:{slug}:{version}"
    uri = f"cap://asg.local/{cap_type}/{plug}.{slug}@{version}"
    if plug == "global" and fallback:
        canonical_key = f"{cap_type}:{plug}:{slug}:{version}:{short_hash(fallback)}"
        uri = f"cap://asg.local/{cap_type}/{plug}.{slug}-{short_hash(fallback)}@{version}"
    return uri, canonical_key


def from_cap_manifest(path: Path, root: Path) -> Capability | None:
    data = load_json(path)
    if not data:
        return None
    cap_type = str(data.get("type") or data.get("capabilityType") or "workflow")
    name = str(data.get("name") or path.parent.name)
    version = str(data.get("version") or "0.1.0")
    plugin = data.get("plugin") or package_name_for(path, root)
    uri = str(data.get("uri") or capability_uri(cap_type, plugin, name, version, str(path))[0])
    canonical = str(data.get("canonicalKey") or capability_uri(cap_type, plugin, name, version, str(path))[1])
    entrypoint = str(data.get("entrypoint") or path.name)
    return Capability(
        uri=uri,
        capability_type=cap_type,
        name=name,
        version=version,
        title=str(data.get("title") or name),
        description=str(data.get("description") or ""),
        package_path=normalize_path(path.parent),
        entrypoint=entrypoint,
        source_path=normalize_path(path),
        source_kind="cap_manifest",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility=str(data.get("visibility") or "internal"),
        discovery_mode=str(data.get("discoveryMode") or "public"),
        owner=str(data.get("owner") or "asg"),
        plugin=str(plugin) if plugin else None,
        category=data.get("category"),
        keywords=tuple(str(x) for x in data.get("keywords", ())),
        required_scopes=tuple(str(x) for x in data.get("requiredScopes", ())),
        allow_groups=tuple(str(x) for x in data.get("allowGroups", ())),
        allow_users=tuple(str(x) for x in data.get("allowUsers", ())),
        risk_tier=str(data.get("riskTier") or "low"),
        mutating=bool(data.get("mutating", False)),
        metadata=data,
    )


def from_skill(path: Path, root: Path) -> Capability:
    text = read_text(path)
    fm, body = parse_frontmatter(text)
    name = str(fm.get("name") or path.parent.name)
    plugin = package_name_for(path, root)
    version = str(fm.get("version") or "0.1.0")
    uri, canonical = capability_uri("skill", plugin, name, version, str(path))
    desc = str(fm.get("description") or first_paragraph(body))
    title = str(fm.get("title") or name.replace("-", " ").title())
    package_path = package_path_for(path)
    return Capability(
        uri=uri,
        capability_type="skill",
        name=name,
        version=version,
        title=title,
        description=desc[:4000],
        package_path=normalize_path(package_path),
        entrypoint=str(path.relative_to(package_path)),
        source_path=normalize_path(path),
        source_kind="skill",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility=str(fm.get("visibility") or "internal"),
        discovery_mode=str(fm.get("discoveryMode") or "public"),
        owner=str(fm.get("owner") or "asg"),
        plugin=plugin,
        category=fm.get("category"),
        keywords=tuple(split_keywords(str(fm.get("keywords") or ""))),
        required_scopes=tuple(split_keywords(str(fm.get("requiredScopes") or ""))),
        metadata={"frontmatter": fm, "bodyPreview": body[:2000]},
    )


def from_agent(path: Path, root: Path) -> Capability:
    text = read_text(path)
    fm, body = parse_frontmatter(text)
    name = str(fm.get("name") or path.stem)
    plugin = package_name_for(path, root)
    version = str(fm.get("version") or "0.1.0")
    uri, canonical = capability_uri("agent", plugin, name, version, str(path))
    package_path = package_path_for(path)
    return Capability(
        uri=uri,
        capability_type="agent",
        name=name,
        version=version,
        title=str(fm.get("title") or name.replace("-", " ").title()),
        description=str(fm.get("description") or first_paragraph(body))[:4000],
        package_path=normalize_path(package_path),
        entrypoint=str(path.relative_to(package_path)),
        source_path=normalize_path(path),
        source_kind="agent",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility=str(fm.get("visibility") or "internal"),
        discovery_mode=str(fm.get("discoveryMode") or "public"),
        owner=str(fm.get("owner") or "asg"),
        plugin=plugin,
        category=fm.get("category"),
        keywords=tuple(split_keywords(str(fm.get("keywords") or ""))),
        required_scopes=tuple(split_keywords(str(fm.get("requiredScopes") or ""))),
        risk_tier=str(fm.get("riskTier") or "medium"),
        metadata={"frontmatter": fm, "bodyPreview": body[:2000]},
    )


def from_command(path: Path, root: Path) -> Capability:
    text = read_text(path)
    fm, body = parse_frontmatter(text)
    name = str(fm.get("name") or path.stem)
    plugin = package_name_for(path, root)
    version = str(fm.get("version") or "0.1.0")
    uri, canonical = capability_uri("command", plugin, name, version, str(path))
    package_path = package_path_for(path)
    return Capability(
        uri=uri,
        capability_type="command",
        name=name,
        version=version,
        title=str(fm.get("title") or name.replace("-", " ").title()),
        description=str(fm.get("description") or first_paragraph(body))[:4000],
        package_path=normalize_path(package_path),
        entrypoint=str(path.relative_to(package_path)),
        source_path=normalize_path(path),
        source_kind="command",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility=str(fm.get("visibility") or "internal"),
        discovery_mode=str(fm.get("discoveryMode") or "public"),
        owner=str(fm.get("owner") or "asg"),
        plugin=plugin,
        risk_tier="medium",
        metadata={"frontmatter": fm, "bodyPreview": body[:2000]},
    )


def from_plugin_manifest(path: Path, root: Path) -> Capability:
    data = load_json(path)
    plugin = package_name_for(path, root) or path.parent.parent.name
    name = str(data.get("name") or plugin)
    version = str(data.get("version") or "0.1.0")
    uri, canonical = capability_uri("plugin", plugin, name, version, str(path))
    return Capability(
        uri=uri,
        capability_type="plugin",
        name=name,
        version=version,
        title=str(data.get("displayName") or data.get("title") or name.replace("-", " ").title()),
        description=str(data.get("description") or ""),
        package_path=normalize_path(package_path_for(path)),
        entrypoint=str(path.relative_to(package_path_for(path))),
        source_path=normalize_path(path),
        source_kind="plugin_manifest",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility=str(data.get("visibility") or "internal"),
        discovery_mode=str(data.get("discoveryMode") or "public"),
        owner=str(data.get("author") or "asg"),
        plugin=plugin,
        keywords=tuple(str(x) for x in data.get("keywords", ())),
        metadata=data,
    )


def from_mcp_manifest(path: Path, root: Path) -> Capability:
    data = load_json(path)
    plugin = package_name_for(path, root) or path.parent.name
    name = str(data.get("name") or f"{plugin}-mcp")
    version = str(data.get("version") or "0.1.0")
    uri, canonical = capability_uri("mcp_server", plugin, name, version, str(path))
    package_path = package_path_for(path)
    return Capability(
        uri=uri,
        capability_type="mcp_server",
        name=name,
        version=version,
        title=name.replace("-", " ").title(),
        description="MCP server manifest packaged with plugin.",
        package_path=normalize_path(package_path),
        entrypoint=str(path.relative_to(package_path)),
        source_path=normalize_path(path),
        source_kind="mcp_manifest",
        source_system=source_system_for(path),
        canonical_key=canonical,
        content_hash=sha256_file(path),
        visibility="protected",
        discovery_mode="locked",
        owner="asg",
        plugin=plugin,
        risk_tier="high",
        metadata=data,
    )


def first_paragraph(text: str) -> str:
    for block in re.split(r"\n\s*\n", text.strip()):
        cleaned = re.sub(r"\s+", " ", block).strip(" #")
        if cleaned:
            return cleaned
    return ""


def split_keywords(raw: str) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in re.split(r"[,;\n]", raw) if x.strip()]


def source_files(roots: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for raw_root in roots:
        root = Path(raw_root).expanduser()
        if not root.exists():
            continue
        patterns = [
            "**/cap.json",
            "**/SKILL.md",
            "**/agents/*.md",
            "**/commands/*.md",
            "**/.claude-plugin/plugin.json",
            "**/.mcp.json",
        ]
        for pattern in patterns:
            for path in root.glob(pattern):
                if not path.is_file():
                    continue
                try:
                    relative_parts = path.relative_to(root).parts[:-1]
                except ValueError:
                    continue
                if any(part in NESTED_RUNTIME_MIRROR_DIRS for part in relative_parts):
                    continue
                if path.name.startswith(".") and path.name not in {".mcp.json"}:
                    continue
                norm = normalize_path(path)
                if norm in seen:
                    continue
                seen.add(norm)
                files.append(path)
    return sorted(files, key=lambda p: str(p))


def discover_capabilities(roots: Iterable[str | Path]) -> list[Capability]:
    capabilities: list[Capability] = []
    root_paths = [Path(x).expanduser().resolve() for x in roots if Path(x).expanduser().exists()]
    for path in source_files(root_paths):
        if not path.exists():
            continue
        root = next((r for r in root_paths if path.is_relative_to(r)), path.parent)
        try:
            if path.name == "cap.json":
                cap = from_cap_manifest(path, root)
                if cap:
                    capabilities.append(cap)
            elif path.name == "SKILL.md":
                capabilities.append(from_skill(path, root))
            elif "agents" in path.parts and path.suffix == ".md":
                capabilities.append(from_agent(path, root))
            elif "commands" in path.parts and path.suffix == ".md":
                capabilities.append(from_command(path, root))
            elif path.name == "plugin.json" and ".claude-plugin" in path.parts:
                capabilities.append(from_plugin_manifest(path, root))
            elif path.name == ".mcp.json":
                capabilities.append(from_mcp_manifest(path, root))
        except FileNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001
            if not path.exists():
                continue
            fallback_uri, fallback_key = capability_uri("reference", None, path.stem, "0.1.0", str(path))
            capabilities.append(
                Capability(
                    uri=fallback_uri,
                    capability_type="reference",
                    name=path.stem,
                    version="0.1.0",
                    title=path.stem,
                    description=f"Failed to parse as structured capability: {exc}",
                    package_path=normalize_path(path.parent),
                    entrypoint=path.name,
                    source_path=normalize_path(path),
                    source_kind=source_kind_for(path),
                    source_system=source_system_for(path),
                    canonical_key=fallback_key,
                    content_hash=sha256_file(path),
                    discovery_mode="locked",
                    metadata={"parseError": str(exc)},
                )
            )
    return merge_duplicate_capabilities(capabilities)


def strict_collisions() -> bool:
    """Opt-in: turn an ambiguous equal-authority collision back into a hard failure.

    Default OFF. In production an unattended 15-minute refresh must degrade rather than stop
    ingesting 2177 capabilities over one ambiguous mirror. In CI, set
    CAPMESH_STRICT_COLLISIONS=1 so a genuinely ambiguous source layout fails the build.
    """
    return os.environ.get("CAPMESH_STRICT_COLLISIONS", "").strip().lower() in {"1", "true", "yes"}


def merge_duplicate_capabilities(capabilities: list[Capability]) -> list[Capability]:
    """Merge canonical duplicates using explicit authority and complete provenance."""

    by_key: dict[str, list[Capability]] = {}
    for cap in capabilities:
        by_key.setdefault(cap.canonical_key, []).append(cap)

    merged: list[Capability] = []
    for canonical_key, caps in by_key.items():
        ranked = sorted(
            caps,
            key=lambda cap: (
                -source_authority_rank(cap.source_system, cap.source_path),
                cap.source_system,
                normalize_path(cap.source_path),
            ),
        )
        preferred = ranked[0]
        top_rank = source_authority_rank(preferred.source_system, preferred.source_path)
        top_hashes = {
            cap.content_hash
            for cap in ranked
            if source_authority_rank(cap.source_system, cap.source_path) == top_rank
        }
        ambiguous_sources: list[str] = []
        if len(top_hashes) > 1:
            # DEGRADE, DO NOT ABORT.
            #
            # This used to `raise ValueError`, which aborts the WHOLE ingest — all 2177
            # capabilities — because ONE of them has two equal-authority sources whose content
            # differs. That is a data-quality problem in a single capability being escalated
            # into a total outage of the refresh job, which runs unattended every 15 minutes.
            # The mesh would simply stop updating and the only signal would be a traceback in a
            # journal nobody reads. Verified 2026-07-19: a root set including
            # ~/GitHub/asg-os/plugins/vossian (where one SKILL.md is mirrored under
            # .codex/skills, .cursor/skills, and the real skills/ path) raises here and no
            # capability is ingested at all. Production's narrower CAPMESH_ROOTS happens not to
            # hit it today — so this is a live landmine, not a theoretical one.
            #
            # `ranked` is already sorted by (-authority, source_system, normalized path), so
            # ranked[0] is a DETERMINISTIC winner even among equal-authority peers: the same
            # input always selects the same source, independent of filesystem walk order.
            # Choosing deterministically and recording the conflict beats refusing to run.
            ambiguous_sources = sorted(
                normalize_path(cap.source_path)
                for cap in ranked
                if source_authority_rank(cap.source_system, cap.source_path) == top_rank
            )
            message = (
                f"capmesh: ambiguous canonical-key collision for {canonical_key}: "
                f"equal-authority sources contain different content: {ambiguous_sources}; "
                f"selected {normalize_path(preferred.source_path)} deterministically. "
                f"Recorded as ambiguousAuthorityCollision in capability metadata."
            )
            if strict_collisions():
                # Opt-in for CI and tests, where an ambiguous mirror SHOULD fail the build
                # rather than be silently resolved.
                raise ValueError(message)
            print(message, file=sys.stderr)

        provenance = sorted(
            {
                (
                    normalize_path(cap.source_path),
                    cap.source_kind,
                    cap.source_system,
                    cap.content_hash,
                )
                for cap in caps
            }
        )
        metadata = dict(preferred.metadata)
        metadata["sourcePaths"] = sorted({item[0] for item in provenance})
        metadata["sourceProvenance"] = [
            {
                "sourcePath": source_path,
                "sourceKind": source_kind,
                "sourceSystem": source_system,
                "contentHash": content_hash,
            }
            for source_path, source_kind, source_system, content_hash in provenance
        ]
        conflicts = [
            item for item in metadata["sourceProvenance"] if item["contentHash"] != preferred.content_hash
        ]
        if conflicts:
            metadata["staleMirrorDetected"] = True
            metadata["sourceConflicts"] = conflicts
            metadata["sourceAuthority"] = {
                "selectedSourcePath": normalize_path(preferred.source_path),
                "selectedSourceSystem": preferred.source_system,
                "rank": top_rank,
            }
        if ambiguous_sources:
            # Distinct from staleMirrorDetected: that means a LOWER-authority mirror disagreed,
            # which the authority order resolves cleanly. This means two sources of EQUAL
            # authority disagreed, so the winner was picked by tie-break rather than by rank.
            # Surfaced separately so it stays queryable:
            #   SELECT uri FROM capabilities
            #   WHERE json_extract(metadata_json,'$.ambiguousAuthorityCollision') = 1;
            metadata["ambiguousAuthorityCollision"] = True
            metadata["ambiguousSources"] = ambiguous_sources
            metadata["sourceAuthority"] = {
                "selectedSourcePath": normalize_path(preferred.source_path),
                "selectedSourceSystem": preferred.source_system,
                "rank": top_rank,
                "resolvedBy": "deterministic-tiebreak",
            }
        merged.append(replace(preferred, metadata=metadata))
    return sorted(merged, key=lambda cap: cap.uri)
