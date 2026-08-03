from __future__ import annotations

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capmesh.authority_keys import (
    ROTATION_DOMAIN,
    AuthorityTrustError,
    canonical,
    ensure_authority_keypair,
    export_client_trust,
    install_client_trust,
)


def protected(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(mode=0o700)
    return path


def pair(root: Path, name: str = "authority") -> tuple[Path, Path, Path, dict]:
    directory = protected(root, name)
    private = directory / "authority.pem"
    public = directory / "authority.pub.pem"
    record = directory / "trust.json"
    result = ensure_authority_keypair(
        private, public, record, node_role="authoritative", hostname="cpubox",
    )
    return private, public, record, result


def test_bootstrap_is_cpubox_authoritative_only_and_missing_is_created(tmp_path: Path) -> None:
    directory = protected(tmp_path, "keys")
    paths = (directory / "private.pem", directory / "public.pem", directory / "trust.json")
    with pytest.raises(AuthorityTrustError, match="only by authoritative cpubox"):
        ensure_authority_keypair(*paths, node_role="client", hostname="cpubox")
    with pytest.raises(AuthorityTrustError, match="only by authoritative cpubox"):
        ensure_authority_keypair(*paths, node_role="authoritative", hostname="workerbox")
    result = ensure_authority_keypair(*paths, node_role="authoritative", hostname="cpubox")
    assert result["key_id"].startswith("ed25519:sha256:")
    assert paths[0].stat().st_mode & 0o777 == 0o600
    assert paths[1].stat().st_mode & 0o777 == 0o644
    assert paths[2].stat().st_mode & 0o777 == 0o644


def test_bootstrap_rejects_private_mode_symlink_and_public_mismatch(tmp_path: Path) -> None:
    private, public, record, _ = pair(tmp_path)
    private.chmod(0o644)
    with pytest.raises(AuthorityTrustError, match="0600"):
        ensure_authority_keypair(private, public, record, node_role="authoritative", hostname="cpubox")
    private.chmod(0o600)
    private.unlink()
    private.symlink_to(public)
    with pytest.raises(AuthorityTrustError, match="owner-controlled regular"):
        ensure_authority_keypair(private, public, record, node_role="authoritative", hostname="cpubox")

    other = protected(tmp_path, "other")
    private2, public2, record2 = other / "p", other / "u", other / "r"
    ensure_authority_keypair(private2, public2, record2, node_role="authoritative", hostname="cpubox")
    public2.write_bytes(public.read_bytes())
    public2.chmod(0o644)
    with pytest.raises(AuthorityTrustError, match="public key mismatch"):
        ensure_authority_keypair(private2, public2, record2, node_role="authoritative", hostname="cpubox")


def test_bootstrap_concurrency_returns_one_key_identity(tmp_path: Path) -> None:
    directory = protected(tmp_path, "keys")
    args = (directory / "private.pem", directory / "public.pem", directory / "trust.json")
    def run() -> str:
        return ensure_authority_keypair(
            *args, node_role="authoritative", hostname="cpubox",
        )["key_id"]
    with ThreadPoolExecutor(max_workers=12) as pool:
        identities = list(pool.map(lambda _n: run(), range(24)))
    assert len(set(identities)) == 1


def test_client_install_rejects_missing_symlink_mode_and_fingerprint_mismatch(tmp_path: Path) -> None:
    _private, public, record, trust = pair(tmp_path)
    client = protected(tmp_path, "client")
    with pytest.raises(AuthorityTrustError, match="missing"):
        install_client_trust(
            tmp_path / "missing", record, trust["key_id"],
            client / "public.pem", client / "pin.json",
        )
    link = tmp_path / "source-link"
    link.symlink_to(public)
    with pytest.raises(AuthorityTrustError, match="owner-controlled regular"):
        install_client_trust(link, record, trust["key_id"], client / "public.pem", client / "pin.json")
    public.chmod(0o600)
    with pytest.raises(AuthorityTrustError, match="0644"):
        install_client_trust(public, record, trust["key_id"], client / "public.pem", client / "pin.json")
    public.chmod(0o644)
    with pytest.raises(AuthorityTrustError, match="expected pinned fingerprint"):
        install_client_trust(public, record, "ed25519:sha256:" + "0" * 64, client / "public.pem", client / "pin.json")


def test_client_export_contains_only_public_material_and_hash(tmp_path: Path) -> None:
    private, public, record, trust = pair(tmp_path)
    export = protected(tmp_path, "export")
    assert export_client_trust(public, record, export) == trust
    assert sorted(path.name for path in export.iterdir()) == [
        "capmesh-authority-ed25519.pub.pem",
        "capmesh-authority-trust.v1.json",
        "expected-key-id.txt",
    ]
    assert private.read_bytes() not in b"".join(path.read_bytes() for path in export.iterdir())
    assert (export / "expected-key-id.txt").read_text().strip() == trust["key_id"]
    (export / "unexpected-private-copy.pem").write_bytes(private.read_bytes())
    (export / "unexpected-private-copy.pem").chmod(0o600)
    with pytest.raises(AuthorityTrustError, match="unexpected material"):
        export_client_trust(public, record, export)


def test_client_rotation_requires_current_operator_signed_ceremony(tmp_path: Path) -> None:
    _old_private, old_public, old_record, old = pair(tmp_path, "old")
    _new_private, new_public, new_record, new = pair(tmp_path, "new")
    client = protected(tmp_path, "client")
    destination_public, destination_pin = client / "public.pem", client / "pin.json"
    install_client_trust(old_public, old_record, old["key_id"], destination_public, destination_pin)
    with pytest.raises(AuthorityTrustError, match="operator-signed ceremony"):
        install_client_trust(new_public, new_record, new["key_id"], destination_public, destination_pin)

    operator = Ed25519PrivateKey.generate()
    operator_public = tmp_path / "operator.pub.pem"
    operator_public.write_bytes(operator.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    operator_public.chmod(0o644)
    now = int(time.time())
    ceremony = {
        "schema": "capmesh.authority-rotation.v1", "old_key_id": old["key_id"],
        "new_key_id": new["key_id"], "issued_at": now - 1, "expires_at": now + 300,
        "nonce": "operator-rotation-1234", "approved_by": "operator",
    }
    signature = operator.sign(ROTATION_DOMAIN + canonical(ceremony))
    ceremony["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    ceremony_path = tmp_path / "ceremony.json"
    ceremony_path.write_text(json.dumps(ceremony))
    ceremony_path.chmod(0o600)
    result = install_client_trust(
        new_public, new_record, new["key_id"], destination_public, destination_pin,
        rotation_ceremony=ceremony_path, operator_public_key=operator_public,
    )
    assert result == new
    assert json.loads(destination_pin.read_text()) == new
    assert destination_public.read_bytes() == new_public.read_bytes()
