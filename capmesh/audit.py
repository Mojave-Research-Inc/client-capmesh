from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Principal

SENSITIVE_KEYS = {"token", "access_token", "refresh_token", "password", "secret", "api_key", "authorization"}


def state_dir() -> Path:
    return Path(os.environ.get("CAPMESH_STATE_DIR", "~/.capmesh")).expanduser()


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_KEYS:
                out[key] = "[REDACTED]"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(x) for x in value]
    return value


def audit(event: str, principal: Principal, payload: dict[str, Any]) -> None:
    root = state_dir()
    root.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": utc_now(),
        "event": event,
        "principal": {
            "subject": principal.subject,
            "groups": list(principal.groups),
            "scopes": list(principal.scopes),
            "authenticated": principal.authenticated,
        },
        "payload": redact(payload),
    }
    with (root / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")

