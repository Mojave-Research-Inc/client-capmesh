"""Plugin authoring hook that emits cap.json automatically for new assets.

When a new capability package is created (e.g. by a scaffold or init tool),
this hook generates a cap.json manifest file with the correct schema,
derived from the package structure. This ensures every new asset has
a valid capability manifest without requiring manual authoring.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .utils import utc_now

CAPABILITY_TYPES = {"skill", "agent", "plugin", "command", "mcp_server", "workflow", "reference", "bundle"}


def detect_capability_type(pkg_path: Path) -> str:
    """Detect the capability type from the package structure."""
    # Check for plugin manifest
    plugin_json = pkg_path / ".claude-plugin" / "plugin.json"
    if plugin_json.exists():
        return "plugin"
    # Check for skill files
    skills_dir = pkg_path / "skills"
    if skills_dir.is_dir() and any(skills_dir.glob("*/SKILL.md")):
        return "skill"
    # Check for agent files
    agents_dir = pkg_path / "agents"
    if agents_dir.is_dir() and any(agents_dir.glob("*.md")):
        return "agent"
    # Check for MCP server config
    mcp_file = pkg_path / ".mcp.json"
    if mcp_file.exists():
        return "mcp_server"
    # Check for commands
    commands_dir = pkg_path / "commands"
    if commands_dir.is_dir() and any(commands_dir.glob("*.md")):
        return "command"
    # Check for workflow files
    workflows_dir = pkg_path / "workflows"
    if workflows_dir.is_dir() and any(workflows_dir.glob("*.json")):
        return "workflow"
    # Check for reference docs
    refs_dir = pkg_path / "references"
    if refs_dir.is_dir() and any(refs_dir.glob("*.md")):
        return "reference"
    return "reference"  # default to reference for unknown packages


def detect_name(pkg_path: Path) -> str:
    """Detect the package name from structure."""
    # Try plugin.json first
    plugin_json = pkg_path / ".claude-plugin" / "plugin.json"
    if plugin_json.exists():
        try:
            data = json.loads(plugin_json.read_text())
            return str(data.get("name", pkg_path.name))
        except (json.JSONDecodeError, KeyError):
            pass
    return pkg_path.name


def detect_version(pkg_path: Path) -> str:
    """Detect the package version from structure."""
    plugin_json = pkg_path / ".claude-plugin" / "plugin.json"
    if plugin_json.exists():
        try:
            data = json.loads(plugin_json.read_text())
            return str(data.get("version", "0.1.0"))
        except (json.JSONDecodeError, KeyError):
            pass
    return "0.1.0"


def compute_content_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def generate_cap_json(
    pkg_path: str | Path,
    *,
    name: str | None = None,
    version: str | None = None,
    capability_type: str | None = None,
    description: str = "",
    owner: str = "asg",
    license: str | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """Generate a cap.json manifest for a package.

    If write=True, writes the cap.json file to the package root.
    Returns the manifest dict regardless.
    """
    pkg = Path(pkg_path)
    if not pkg.is_dir():
        raise ValueError(f"Package path is not a directory: {pkg}")
    cap_type = capability_type or detect_capability_type(pkg)
    if cap_type not in CAPABILITY_TYPES:
        raise ValueError(f"Invalid capability type: {cap_type}")
    cap_name = name or detect_name(pkg)
    cap_version = version or detect_version(pkg)
    # Find the entrypoint
    entrypoint = _find_entrypoint(pkg, cap_type)
    # Compute content hash of the entrypoint
    content_hash = compute_content_hash(entrypoint) if entrypoint.exists() else "sha256:unknown"
    manifest: dict[str, Any] = {
        "schema": "capmesh.capability.v1",
        "name": cap_name,
        "version": cap_version,
        "type": cap_type,
        "title": cap_name.replace("-", " ").replace("_", " ").title(),
        "description": description or f"{cap_name} {cap_type}",
        "owner": owner,
        "sourcePath": str(entrypoint),
        "sourceKind": "local",
        "sourceSystem": "capmesh.plugin-hook",
        "contentHash": content_hash,
        "visibility": "internal",
        "discoveryMode": "public",
        "riskTier": "low",
        "mutating": False,
        "lifecycle": "draft",
        "generatedAt": utc_now(),
    }
    if license:
        manifest["license"] = license
    if write:
        cap_json_path = pkg / "cap.json"
        cap_json_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _find_entrypoint(pkg: Path, cap_type: str) -> Path:
    """Find the primary entrypoint file for a capability type."""
    if cap_type == "plugin":
        return pkg / ".claude-plugin" / "plugin.json"
    if cap_type == "skill":
        skills = list((pkg / "skills").glob("*/SKILL.md"))
        return skills[0] if skills else pkg / "SKILL.md"
    if cap_type == "agent":
        agents = list((pkg / "agents").glob("*.md"))
        return agents[0] if agents else pkg / "agent.md"
    if cap_type == "mcp_server":
        return pkg / ".mcp.json"
    if cap_type == "command":
        commands = list((pkg / "commands").glob("*.md"))
        return commands[0] if commands else pkg / "command.md"
    if cap_type == "workflow":
        workflows = list((pkg / "workflows").glob("*.json"))
        return workflows[0] if workflows else pkg / "workflow.json"
    if cap_type == "reference":
        refs = list((pkg / "references").glob("*.md"))
        return refs[0] if refs else pkg / "README.md"
    return pkg / "README.md"


def scan_and_emit(pkg_path: str | Path, *, write: bool = True) -> list[dict[str, Any]]:
    """Scan a directory tree for capability packages and emit cap.json for each.

    Returns a list of generated manifests.
    """
    root = Path(pkg_path)
    manifests: list[dict[str, Any]] = []
    # Find all directories that look like capability packages
    candidates: list[Path] = []
    for plugin_json in root.rglob("plugin.json"):
        if ".claude-plugin" in plugin_json.parent.name:
            candidates.append(plugin_json.parent.parent)
    for skill_md in root.rglob("SKILL.md"):
        # The package root is typically the parent of the skills/ directory
        pkg_root = skill_md.parent.parent.parent
        if pkg_root not in candidates:
            candidates.append(pkg_root)
    for pkg in candidates:
        cap_json = pkg / "cap.json"
        if not cap_json.exists():
            manifest = generate_cap_json(pkg, write=write)
            manifests.append(manifest)
    return manifests
