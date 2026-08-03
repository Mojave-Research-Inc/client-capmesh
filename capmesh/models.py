from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CAPABILITY_TYPES = {
    "skill",
    "agent",
    "plugin",
    "command",
    "mcp_server",
    "workflow",
    "reference",
    "bundle",
}

VISIBILITIES = {"public", "internal", "protected", "secret"}
DISCOVERY_MODES = {"public", "locked", "hidden"}
DEFAULT_LOCAL_SUBJECT = os.environ.get("CAPMESH_DEFAULT_LOCAL_SUBJECT", "admin@example.com")
DEFAULT_BASIC_SCOPES = (
    "cap:search",
    "cap:load",
    "cap:delegate",
    "cap:report",
    "cap:call",
)


@dataclass(frozen=True)
class Principal:
    """Authorization subject used by the local router.

    The stdio deployment defaults to an authenticated local principal. Remote
    HTTP deployments must populate this from OAuth token claims.
    """

    subject: str = DEFAULT_LOCAL_SUBJECT
    tenant_id: str = "asg"
    identity_id: str | None = None
    email: str | None = None
    display_name: str | None = None
    app_id: str | None = None
    groups: tuple[str, ...] = ("asg:local",)
    roles: tuple[str, ...] = ("member",)
    scopes: tuple[str, ...] = DEFAULT_BASIC_SCOPES
    authenticated: bool = True
    disabled: bool = False
    step_up_authenticated: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> Principal:
        if not raw:
            return cls()
        subject = str(raw.get("subject") or raw.get("sub") or DEFAULT_LOCAL_SUBJECT)
        app_id = raw.get("app_id") or raw.get("appId") or raw.get("azp")
        roles_raw = raw.get("roles")
        scopes_raw = raw.get("scopes")
        groups_raw = raw.get("groups")
        is_default_local = subject == DEFAULT_LOCAL_SUBJECT and not app_id
        if roles_raw is None:
            roles = cls().roles if is_default_local else (("app_service",) if app_id else ("member",))
        else:
            roles = tuple(str(x) for x in roles_raw)
        if scopes_raw is None:
            scopes = cls().scopes if is_default_local else DEFAULT_BASIC_SCOPES
        else:
            scopes = tuple(str(x) for x in scopes_raw)
        if groups_raw is None:
            groups = cls().groups if is_default_local else ()
        else:
            groups = tuple(str(x) for x in groups_raw)
        return cls(
            subject=subject,
            tenant_id=str(raw.get("tenant_id") or raw.get("tenantId") or raw.get("tenant") or "asg"),
            identity_id=raw.get("identity_id") or raw.get("identityId"),
            email=raw.get("email"),
            display_name=raw.get("display_name") or raw.get("displayName") or raw.get("name"),
            app_id=app_id,
            groups=groups,
            roles=roles,
            scopes=scopes,
            authenticated=bool(raw.get("authenticated", True)),
            disabled=bool(raw.get("disabled", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "tenantId": self.tenant_id,
            "identityId": self.identity_id,
            "email": self.email,
            "displayName": self.display_name,
            "appId": self.app_id,
            "groups": list(self.groups),
            "roles": list(self.roles),
            "scopes": list(self.scopes),
            "authenticated": self.authenticated,
            "disabled": self.disabled,
        }


@dataclass(frozen=True)
class Capability:
    uri: str
    capability_type: str
    name: str
    version: str
    title: str
    description: str
    package_path: str
    entrypoint: str
    source_path: str
    source_kind: str
    source_system: str
    canonical_key: str
    content_hash: str
    visibility: str = "internal"
    discovery_mode: str = "public"
    owner: str = "asg"
    plugin: str | None = None
    category: str | None = None
    keywords: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ()
    allow_groups: tuple[str, ...] = ()
    allow_users: tuple[str, ...] = ()
    risk_tier: str = "low"
    mutating: bool = False
    lifecycle: str = "active"
    tenant_id: str = "asg"
    store_id: str | None = None
    namespace_id: str | None = None
    created_by: str | None = None
    submitted_by: str | None = None
    promoted_from_uri: str | None = None
    approval_state: str = "published"
    share_state: str = "not_shared"
    signature_status: str = "unchecked"
    provenance_status: str = "unchecked"
    risk_review_status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)
    source_commit: str | None = None
    license: str | None = None

    def __post_init__(self) -> None:
        if self.capability_type not in CAPABILITY_TYPES:
            raise ValueError(f"Unsupported capability type: {self.capability_type}")
        if self.visibility not in VISIBILITIES:
            raise ValueError(f"Unsupported visibility: {self.visibility}")
        if self.discovery_mode not in DISCOVERY_MODES:
            raise ValueError(f"Unsupported discovery mode: {self.discovery_mode}")
        risk_tiers = {"low", "medium", "high", "critical"}
        if self.risk_tier and self.risk_tier not in risk_tiers:
            raise ValueError(f"Unsupported risk tier: {self.risk_tier}")

    def index_text(self) -> str:
        fields = [
            self.name,
            self.title,
            self.description,
            self.capability_type,
            self.plugin or "",
            self.category or "",
            " ".join(self.keywords),
        ]
        return "\n".join(x for x in fields if x)

    def to_record(self, *, stub: bool = False, include_paths: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "uri": self.uri,
            "type": self.capability_type,
            "name": self.name,
            "version": self.version,
            "title": self.title,
            "description": self.description if not stub else "Capability exists but requires authorization to load.",
            "visibility": self.visibility,
            "discoveryMode": self.discovery_mode,
            "owner": self.owner,
            "plugin": self.plugin,
            "category": self.category,
            "keywords": list(self.keywords),
            "riskTier": self.risk_tier,
            "mutating": self.mutating,
            "lifecycle": self.lifecycle,
            "tenantId": self.tenant_id,
            "storeId": self.store_id,
            "namespaceId": self.namespace_id,
            "createdBy": self.created_by,
            "submittedBy": self.submitted_by,
            "promotedFromUri": self.promoted_from_uri,
            "approvalState": self.approval_state,
            "shareState": self.share_state,
            "signatureStatus": self.signature_status,
            "provenanceStatus": self.provenance_status,
            "riskReviewStatus": self.risk_review_status,
            "contentHash": self.content_hash,
           "sourceSystem": self.source_system,
           "sourceKind": self.source_kind,
            "sourceCommit": self.source_commit,
            "license": self.license,
        }
        if include_paths and not stub:
            data.update(
                {
                    "packagePath": self.package_path,
                    "entrypoint": self.entrypoint,
                    "sourcePath": self.source_path,
                }
            )
        return data


@dataclass(frozen=True)
class SearchResult:
    capability: Capability
    score: float
    rank: int
    matched_by: tuple[str, ...]
    locked: bool = False


def normalize_path(path: str | Path) -> str:
    return str(Path(path).expanduser().resolve())
