"""Fail-closed bootstrap and client pinning for the CapMesh receipt authority."""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import secrets
import socket
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TRUST_SCHEMA = "capmesh.authority-trust.v1"
ROTATION_SCHEMA = "capmesh.authority-rotation.v1"
ROTATION_DOMAIN = b"ASGCODE:capmesh-authority-rotation.v1\x00"


class AuthorityTrustError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:sha256:" + hashlib.sha256(raw).hexdigest()


def _assert_parent(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise AuthorityTrustError("authority key directory is not owner-controlled")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise AuthorityTrustError("authority key directory must be mode 0700")


def _read_regular(path: Path, *, exact_mode: int) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise AuthorityTrustError(f"required trust file is missing: {path}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise AuthorityTrustError(f"trust file is not an owner-controlled regular file: {path}")
    if stat.S_IMODE(info.st_mode) != exact_mode:
        raise AuthorityTrustError(f"trust file mode must be {exact_mode:04o}: {path}")
    return path.read_bytes()


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    _assert_parent(path.parent)
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()


def _public_from_pem(data: bytes) -> Ed25519PublicKey:
    try:
        value = serialization.load_pem_public_key(data)
    except Exception as exc:
        raise AuthorityTrustError("authority public key PEM is invalid") from exc
    if not isinstance(value, Ed25519PublicKey):
        raise AuthorityTrustError("authority public key is not Ed25519")
    return value


def _trust_record(public_pem: bytes) -> dict[str, Any]:
    public = _public_from_pem(public_pem)
    return {
        "schema": TRUST_SCHEMA,
        "key_id": key_id(public),
        "public_sha256": "sha256:" + hashlib.sha256(public_pem).hexdigest(),
    }


def ensure_authority_keypair(
    private_path: Path, public_path: Path, record_path: Path, *,
    node_role: str | None = None, hostname: str | None = None,
) -> dict[str, Any]:
    """Create once on cpubox; existing keys are verified and never rotated."""
    role = (node_role or os.environ.get("CAPMESH_NODE_ROLE", "")).strip().lower()
    actual_host = (hostname or socket.gethostname()).split(".", 1)[0].lower()
    expected_host = os.environ.get("CAPMESH_AUTHORITY_HOSTNAME", "cpubox").strip().lower()
    test_override = (
        bool(os.environ.get("PYTEST_CURRENT_TEST"))
        and os.environ.get("CAPMESH_ALLOW_TEST_AUTHORITY_KEYGEN") == "1"
        and hostname is None
    )
    if test_override and not role:
        role = "authoritative"
    if role != "authoritative" or (actual_host != expected_host and not test_override):
        raise AuthorityTrustError("authority private keys may be generated only by authoritative cpubox")
    private_path, public_path, record_path = (
        p.expanduser().absolute() for p in (private_path, public_path, record_path)
    )
    if len({private_path.parent, public_path.parent, record_path.parent}) != 1:
        raise AuthorityTrustError("authority keypair and trust record must share one protected directory")
    _assert_parent(private_path.parent)
    lock_path = private_path.with_suffix(private_path.suffix + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.chmod(lock_path, 0o600)
    with os.fdopen(lock_fd, "rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if private_path.exists() or private_path.is_symlink():
            private_pem = _read_regular(private_path, exact_mode=0o600)
            try:
                private = serialization.load_pem_private_key(private_pem, password=None)
            except Exception as exc:
                raise AuthorityTrustError("authority private key PEM is invalid") from exc
            if not isinstance(private, Ed25519PrivateKey):
                raise AuthorityTrustError("authority private key is not Ed25519")
        else:
            private = Ed25519PrivateKey.generate()
            private_pem = private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            _atomic_write(private_path, private_pem, 0o600)
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        record = _trust_record(public_pem)
        if public_path.exists() or public_path.is_symlink():
            if _read_regular(public_path, exact_mode=0o644) != public_pem:
                raise AuthorityTrustError("authority public key mismatch; rotation ceremony required")
        else:
            _atomic_write(public_path, public_pem, 0o644)
        encoded_record = canonical(record) + b"\n"
        if record_path.exists() or record_path.is_symlink():
            if _read_regular(record_path, exact_mode=0o644) != encoded_record:
                raise AuthorityTrustError("authority trust record mismatch; rotation ceremony required")
        else:
            _atomic_write(record_path, encoded_record, 0o644)
        return record


def _verify_rotation(
    ceremony_path: Path, operator_public_path: Path, *, old_key_id: str,
    new_key_id: str, now: int | None = None,
) -> None:
    ceremony = json.loads(_read_regular(ceremony_path, exact_mode=0o600))
    required = {
        "schema", "old_key_id", "new_key_id", "issued_at", "expires_at",
        "nonce", "approved_by", "signature",
    }
    if not isinstance(ceremony, dict) or set(ceremony) != required:
        raise AuthorityTrustError("rotation ceremony document is malformed")
    current = int(time.time()) if now is None else int(now)
    if any((
        ceremony["schema"] != ROTATION_SCHEMA,
        ceremony["old_key_id"] != old_key_id,
        ceremony["new_key_id"] != new_key_id,
        ceremony["approved_by"] != "operator",
        not isinstance(ceremony["issued_at"], int),
        not isinstance(ceremony["expires_at"], int),
        ceremony["issued_at"] > current + 30,
        ceremony["expires_at"] <= current,
        ceremony["expires_at"] - ceremony["issued_at"] > 900,
    )):
        raise AuthorityTrustError("rotation ceremony is not current or correctly bound")
    operator = _public_from_pem(_read_regular(operator_public_path, exact_mode=0o644))
    try:
        signature_text = ceremony["signature"]
        signature = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
        operator.verify(signature, ROTATION_DOMAIN + canonical({k: v for k, v in ceremony.items() if k != "signature"}))
    except Exception as exc:
        raise AuthorityTrustError("rotation ceremony signature is invalid") from exc


def install_client_trust(
    source_public: Path, source_record: Path, expected_key_id: str,
    destination_public: Path, destination_pin: Path, *,
    rotation_ceremony: Path | None = None,
    operator_public_key: Path | None = None,
) -> dict[str, Any]:
    public_pem = _read_regular(source_public.expanduser().absolute(), exact_mode=0o644)
    source = json.loads(_read_regular(source_record.expanduser().absolute(), exact_mode=0o644))
    actual = _trust_record(public_pem)
    if source != actual or expected_key_id != actual["key_id"]:
        raise AuthorityTrustError("authority public key does not match the expected pinned fingerprint")
    destination_public = destination_public.expanduser().absolute()
    destination_pin = destination_pin.expanduser().absolute()
    _assert_parent(destination_public.parent)
    if destination_pin.parent != destination_public.parent:
        raise AuthorityTrustError("client public key and pin must share one protected directory")
    existing: dict[str, Any] | None = None
    if destination_pin.exists() or destination_pin.is_symlink():
        existing = json.loads(_read_regular(destination_pin, exact_mode=0o644))
    if existing is not None and existing != actual:
        if rotation_ceremony is None or operator_public_key is None:
            raise AuthorityTrustError("authority key rotation requires an operator-signed ceremony")
        _verify_rotation(
            rotation_ceremony, operator_public_key,
            old_key_id=str(existing.get("key_id") or ""), new_key_id=actual["key_id"],
        )
    if destination_public.exists() or destination_public.is_symlink():
        current_pem = _read_regular(destination_public, exact_mode=0o644)
        if existing == actual and current_pem != public_pem:
            raise AuthorityTrustError("pinned client public key bytes do not match its trust record")
    _atomic_write(destination_public, public_pem, 0o644)
    _atomic_write(destination_pin, canonical(actual) + b"\n", 0o644)
    return actual


def export_client_trust(source_public: Path, source_record: Path, output_dir: Path) -> dict[str, Any]:
    """Create a transport bundle containing only the public key and its hash pin."""
    public_pem = _read_regular(source_public.expanduser().absolute(), exact_mode=0o644)
    record = json.loads(_read_regular(source_record.expanduser().absolute(), exact_mode=0o644))
    actual = _trust_record(public_pem)
    if record != actual:
        raise AuthorityTrustError("authority export record does not match public key")
    output_dir = output_dir.expanduser().absolute()
    _assert_parent(output_dir)
    _atomic_write(output_dir / "capmesh-authority-ed25519.pub.pem", public_pem, 0o644)
    _atomic_write(output_dir / "capmesh-authority-trust.v1.json", canonical(actual) + b"\n", 0o644)
    _atomic_write(output_dir / "expected-key-id.txt", (actual["key_id"] + "\n").encode(), 0o644)
    expected = {
        "capmesh-authority-ed25519.pub.pem",
        "capmesh-authority-trust.v1.json",
        "expected-key-id.txt",
    }
    if {path.name for path in output_dir.iterdir()} != expected:
        raise AuthorityTrustError("authority client export contains unexpected material")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.add_argument("--private", required=True); bootstrap.add_argument("--public", required=True)
    bootstrap.add_argument("--record", required=True)
    export = sub.add_parser("export-client")
    export.add_argument("--public", required=True); export.add_argument("--record", required=True)
    export.add_argument("--output-dir", required=True)
    install = sub.add_parser("install-client")
    for name in ("source-public", "source-record", "expected-key-id", "destination-public", "destination-pin"):
        install.add_argument("--" + name, required=True)
    install.add_argument("--rotation-ceremony"); install.add_argument("--operator-public-key")
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            result = ensure_authority_keypair(Path(args.private), Path(args.public), Path(args.record))
        elif args.command == "export-client":
            result = export_client_trust(Path(args.public), Path(args.record), Path(args.output_dir))
        else:
            result = install_client_trust(
                Path(args.source_public), Path(args.source_record), args.expected_key_id,
                Path(args.destination_public), Path(args.destination_pin),
                rotation_ceremony=Path(args.rotation_ceremony) if args.rotation_ceremony else None,
                operator_public_key=Path(args.operator_public_key) if args.operator_public_key else None,
            )
    except (AuthorityTrustError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
