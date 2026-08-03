"""Idempotent production-state provisioning for immutable releases."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .install_policy import (
    SUPERADMIN_ACTOR_ENV,
    SUPERADMIN_AUTO_APPROVE_ENV,
    superadmin_actor,
)
from .node_role import (
    AUTHORITATIVE_ROLE,
    AUTHORITY_URL_ENV,
    NODE_ROLE_ENV,
    VALID_NODE_ROLES,
    default_authority_url,
)
from .signing import provision_production_signing_key

CATALOG_HEALTH_FLOOR = 3000
READY_MIN_CAPABILITIES_ENV = "CAPMESH_READY_MIN_CAPABILITIES"
MIN_HEALTHY_ENV = "CAPMESH_MIN_HEALTHY"


def configure_canonical_root(
    state: str | Path,
    env_file: str | Path,
    canonical_root: str | Path,
    *,
    require_secure_state: bool = True,
    node_role: str = AUTHORITATIVE_ROLE,
) -> dict[str, str]:
    state_path = Path(os.path.abspath(Path(state).expanduser()))
    env_path = Path(os.path.abspath(Path(env_file).expanduser()))
    root_path = Path(os.path.abspath(Path(canonical_root).expanduser()))
    if require_secure_state and not state_path.is_relative_to("/secure"):
        raise ValueError("Production state must be below /secure.")
    expected_root = state_path / "current" / "capability-roots" / "asg-os-plugins"
    if root_path != expected_root:
        raise ValueError(f"Canonical production root must be {expected_root}.")
    if env_path.parent != state_path or env_path.is_symlink() or not env_path.is_file():
        raise PermissionError("Production env must be a regular file directly inside the state directory.")
    if node_role not in VALID_NODE_ROLES:
        raise ValueError(f"Invalid Capmesh node role: {node_role}.")
    lines = env_path.read_text(encoding="utf-8").splitlines()
    existing = next((line.split("=", 1)[1] for line in lines if line.startswith("CAPMESH_ROOTS=")), "")
    auxiliary = [
        item
        for item in existing.split(os.pathsep)
        if item
        and item != "/opt/asg-os/plugins"
        and not item.endswith("/current/capability-roots/asg-os-plugins")
        and item != str(root_path)
    ]
    roots = os.pathsep.join((str(root_path), *auxiliary))
    managed = (
        "CAPMESH_ROOTS=",
        f"{SUPERADMIN_AUTO_APPROVE_ENV}=",
        f"{SUPERADMIN_ACTOR_ENV}=",
        f"{NODE_ROLE_ENV}=",
        f"{AUTHORITY_URL_ENV}=",
        f"{READY_MIN_CAPABILITIES_ENV}=",
        f"{MIN_HEALTHY_ENV}=",
    )
    rendered = [line for line in lines if not line.startswith(managed)]
    rendered.extend(
        (
            f"CAPMESH_ROOTS={roots}",
            f"{SUPERADMIN_AUTO_APPROVE_ENV}=1",
            f"{SUPERADMIN_ACTOR_ENV}={superadmin_actor()}",
            f"{NODE_ROLE_ENV}={node_role}",
            # Call-time, like superadmin_actor() above: this renders into a real
            # env file, so it must reflect the authority configured now, not
            # whatever was set when the module first imported.
            f"{AUTHORITY_URL_ENV}={default_authority_url()}",
            f"{READY_MIN_CAPABILITIES_ENV}={CATALOG_HEALTH_FLOOR}",
            f"{MIN_HEALTHY_ENV}={CATALOG_HEALTH_FLOOR}",
        )
    )
    temporary = env_path.with_name(f".{env_path.name}.roots.{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(rendered) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, env_path)
        os.chmod(env_path, 0o600)
        directory_fd = os.open(env_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "canonicalRoot": str(root_path),
        "roots": roots,
        "superadminAutoApprove": "enabled",
        "superadminActor": superadmin_actor(),
        "nodeRole": node_role,
        "authorityUrl": default_authority_url(),
        "catalogHealthFloor": str(CATALOG_HEALTH_FLOOR),
    }


def provision_production_state(
    state: str | Path,
    env_file: str | Path,
    canonical_root: str | Path,
    *,
    node_role: str = AUTHORITATIVE_ROLE,
) -> dict[str, str]:
    signing = provision_production_signing_key(state, env_file)
    roots = configure_canonical_root(state, env_file, canonical_root, node_role=node_role)
    return {**signing, **roots}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Provision Capability Mesh production signing and canonical roots.")
    parser.add_argument("--state", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--canonical-root", required=True)
    parser.add_argument("--node-role", choices=sorted(VALID_NODE_ROLES), default=AUTHORITATIVE_ROLE)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            provision_production_state(
                args.state,
                args.env_file,
                args.canonical_root,
                node_role=args.node_role,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
