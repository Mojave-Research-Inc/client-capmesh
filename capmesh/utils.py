from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

# Must match the tenant the SCHEMA itself defaults to. Both governance.py and
# index.py declare `tenant_id TEXT NOT NULL DEFAULT 'asg'`, and lifecycle.py
# falls back to `principal.tenant_id or "asg"` in ~10 places.
# Still env-overridable, so this is a default that agrees with the schema.
DEFAULT_TENANT = os.environ.get("CAPMESH_DEFAULT_TENANT", "asg")

# Capmesh session TTL.  Defaults to 10 years so users stay logged in
# (intentional product requirement: minted bearer tokens persist; revocation is
# via revoke_capmesh_session / revoked_at, not expiry).
# Override on the service host with CAPMESH_SESSION_TTL_SECONDS.
_CAPMESH_SESSION_TTL: int = int(os.environ.get("CAPMESH_SESSION_TTL_SECONDS", str(10 * 365 * 24 * 3600)))

# How long a completed OAuth session will hand back its one-time bearer/refresh
# tokens to the polling client before they are purged from the row at rest.
# The CLI/wait flow polls within seconds; 10 minutes is a generous ceiling.
_OAUTH_TOKEN_DELIVERY_TTL: int = int(os.environ.get("CAPMESH_TOKEN_DELIVERY_TTL_SECONDS", "600"))


def _oauth_verify_signature_enabled() -> bool:
    return os.environ.get("CAPMESH_OAUTH_VERIFY_SIGNATURE", "1") not in {"0", "false", "False", ""}


def _production_environment() -> bool:
    return os.environ.get("CAPMESH_ENVIRONMENT", "").strip().lower() in {"production", "prod"}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def expires_in(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "\x1f".join(str(part) for part in parts if part is not None)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[capmesh] warning: failed to parse JSON: {exc}\n")
        return default

