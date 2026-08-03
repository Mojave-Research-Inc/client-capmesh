"""Capability provenance signing and production key provisioning.

This module implements an ASG-internal Ed25519 trust anchor.  It does not
claim Sigstore, SLSA, or transparency-log provenance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .audit import state_dir


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _production() -> bool:
    return os.environ.get("CAPMESH_ENVIRONMENT", "").strip().lower() in {"prod", "production"}


def signing_key_path() -> Path:
    configured = os.environ.get("CAPMESH_SIGNING_KEY_FILE", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    if _production():
        raise RuntimeError("Production requires CAPMESH_SIGNING_KEY_FILE to reference an existing 0600 key.")
    return (state_dir() / "signing" / "capmesh-ed25519.pem").resolve()


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(public_key: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise PermissionError(f"Capmesh signing key must be a regular file with mode 0600: {path}")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            pem = handle.read(64 * 1024)
    finally:
        os.close(fd)
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("CAPMESH_SIGNING_KEY_FILE is not an Ed25519 private key.")
    return key


def _write_new_key(path: Path) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_info = path.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise PermissionError(f"Capmesh signing directory must be a real directory: {path.parent}")
    os.chmod(path.parent, 0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return _read_private_key(path)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    return key


def load_or_create_signing_key(*, persist: bool) -> Ed25519PrivateKey:
    path = signing_key_path()
    if path.exists() or path.is_symlink():
        return _read_private_key(path)
    if _production():
        raise FileNotFoundError(f"Production signing key does not exist: {path}")
    if not persist:
        return Ed25519PrivateKey.generate()
    return _write_new_key(path)


def trusted_signing_key_id() -> str:
    return key_id(_public_key_bytes(_read_private_key(signing_key_path())))


def sign_attestation(envelope: dict[str, Any], *, persist: bool) -> dict[str, Any]:
    private_key = load_or_create_signing_key(persist=persist)
    payload = _canonical_json(envelope)
    public_key = _public_key_bytes(private_key)
    result = {
        "algorithm": "Ed25519",
        "keyId": key_id(public_key),
        "envelope": envelope,
        "publicKey": base64.b64encode(public_key).decode("ascii"),
        "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }
    if not verify_attestation(result, trusted_key_id=result["keyId"]):
        raise RuntimeError("Newly signed provenance attestation did not verify.")
    return result


def verify_attestation(attestation: dict[str, Any], *, trusted_key_id: str | None = None) -> bool:
    try:
        if attestation.get("algorithm") != "Ed25519":
            return False
        public_key_bytes = base64.b64decode(attestation["publicKey"], validate=True)
        embedded_key_id = str(attestation["keyId"])
        if embedded_key_id != key_id(public_key_bytes):
            return False
        if trusted_key_id is not None and embedded_key_id != trusted_key_id:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature = base64.b64decode(attestation["signature"], validate=True)
        public_key.verify(signature, _canonical_json(attestation["envelope"]))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def _rewrite_env(env_path: Path, signing_path: Path) -> None:
    if env_path.is_symlink():
        raise PermissionError(f"Refusing symlinked production env file: {env_path}")
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    rendered = [line for line in lines if not line.startswith("CAPMESH_SIGNING_KEY_FILE=")]
    rendered.append(f"CAPMESH_SIGNING_KEY_FILE={signing_path}")
    temporary = env_path.with_name(f".{env_path.name}.signing.{os.getpid()}")
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


def provision_production_signing_key(
    state: str | Path,
    env_file: str | Path,
    *,
    require_secure_state: bool = True,
) -> dict[str, str]:
    state_path = Path(state).expanduser().resolve()
    env_path = Path(env_file).expanduser().resolve()
    if require_secure_state and not state_path.is_relative_to("/secure"):
        raise ValueError("Production signing state must be below /secure.")
    if env_path.parent != state_path:
        raise ValueError("Production env file must be directly inside the asg-capmesh state directory.")
    state_path.mkdir(parents=True, exist_ok=True)
    signing_path = state_path / "signing" / "capmesh-ed25519.pem"
    private_key = _read_private_key(signing_path) if signing_path.exists() or signing_path.is_symlink() else _write_new_key(signing_path)
    _rewrite_env(env_path, signing_path)
    return {"keyId": key_id(_public_key_bytes(private_key)), "keyPath": str(signing_path), "envPath": str(env_path)}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Provision the Capability Mesh production signing trust anchor.")
    parser.add_argument("--state", required=True)
    parser.add_argument("--env-file", required=True)
    args = parser.parse_args(argv)
    result = provision_production_signing_key(args.state, args.env_file)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
