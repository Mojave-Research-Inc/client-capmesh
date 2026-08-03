from __future__ import annotations

import os
from typing import Any

DEFAULT_BASE_URL = os.environ.get("CAPMESH_BASE_URL", "https://capmesh.asg.ts.net")

RUNTIME_TOOLS = ["cap.search", "cap.load", "cap.call", "cap.list", "cap.describe", "cap.delegate", "cap.process", "cap.report"]
SYSTEM_CAPABILITIES = [
    "system.help",
    "system.onboard",
    "system.auth",
    "system.capabilities",
    "system.me",
    "system.stores",
    "system.namespaces",
    "system.share",
    "system.submit",
    "system.requests",
    "system.approve",
    "system.roles",
    "system.audit",
    "system.sync",
]
CAPMESH_SCOPES = [
    "cap.discover",
    "cap.load",
    "cap.call",
    "cap.delegate",
    "cap.share",
    "cap.submit",
    "cap.publish",
    "cap.approve",
    "cap.manage",
    "cap.audit",
]


HELP_TOPICS: dict[str, dict[str, Any]] = {
    "overview": {
        "title": "Capmesh overview",
        "summary": "Use the eight cap.* tools for runtime work (cap.search, cap.load, cap.call, cap.list, cap.describe, cap.delegate, cap.process, cap.report). cap.delegate + cap.process route tasks to GLM/Qwen/Opus via model routing. Use system capabilities and JSON CLI/API commands for governance.",
        "commands": [
            "capmesh bootstrap --client all --json",
            "capmesh help onboarding",
            "capmesh onboard --client all --json",
            "capmesh auth login --m365 --tenant asg",
            "capmesh capabilities --action template",
            "capmesh delegate <agent-uri> <task> --model-tier glm",
            "capmesh task list",
            "capmesh task process <task-id> --handler glm",
        ],
        "modelRouting": {
            "tiers": ["qwen-worker", "qwen-director", "glm", "opus"],
            "processTool": "cap.process",
            "delegateTool": "cap.delegate (with modelTier param)",
        },
    },
    "onboarding": {
        "title": "Tailnet onboarding",
        "summary": (
            "Start here when a coder or LLM client is not yet configured for capmesh. "
            "TAILNET users need only point their MCP client at "
            "https://capmesh.asg.ts.net/mcp — verified Tailscale whois authenticates "
            "them, with NO OAuth and NO bearer token for reads/discovery (initialize, "
            "tools/list, cap.search, cap.load, cap.list, cap.describe). Mutating tools "
            "(cap.call/cap.delegate/cap.report) still require a service bearer supplied "
            "by the asg-mcp-gateway relay for ASG users, or a minted session for external "
            "users. capmesh auth login --m365 / --device-code is the fallback for EXTERNAL "
            "(non-tailnet) users only; tailnet users do not need it for reads."
        ),
        "commands": [
            "capmesh bootstrap --client all --json",
            "capmesh onboard --client all --json",
            "capmesh auth login --m365 --tenant asg            # EXTERNAL non-tailnet users only; tailnet users need no bearer for reads",
            "capmesh auth login --m365 --tenant asg --device-code --no-browser   # EXTERNAL, headless only",
            "capmesh auth doctor --json",
        ],
        "api": [
            "GET /bootstrap",
            "GET /.well-known/oauth-protected-resource",
            "POST /api/v1/bootstrap/start",
            "POST /api/v1/onboarding/start",
            "GET /api/v1/onboarding/status/{sessionId}",
        ],
    },
    "auth": {
        "title": "M365 authentication",
        "summary": "Browser sign-in uses Entra auth-code + PKCE. Device code is only for headless fallback sessions.",
        "commands": [
            "capmesh auth login --m365 --tenant asg",
            "capmesh auth status --json",
            "capmesh auth refresh --json",
            "capmesh auth logout --json",
        ],
        "api": [
            "POST /api/v1/auth/m365/start",
            "POST /api/v1/auth/m365/device-code",
            "POST /api/v1/auth/m365/refresh",
            "POST /api/v1/auth/logout",
        ],
    },
    "capabilities": {
        "title": "Capability lifecycle",
        "summary": "Private/shared drafts can be edited in capmesh. Org promotion requires submit, review, and approval.",
        "commands": [
            "capmesh capabilities --action template",
            "capmesh capabilities --action draft.create --json '{...}'",
            "capmesh capabilities --action draft.update --json '{...}'",
            "capmesh capabilities --action validate --json '{\"capabilityUri\":\"...\"}'",
            "capmesh capabilities --action submit --json '{\"capabilityUri\":\"...\",\"targetNamespaceId\":\"...\"}'",
            "capmesh capabilities --action prepare-pr --json '{\"capabilityUri\":\"...\"}'",
        ],
        "api": [
            "POST /api/v1/capabilities/drafts",
            "PATCH /api/v1/capabilities/drafts/{uriOrName}",
            "POST /api/v1/capabilities/{uriOrName}/validate",
            "POST /api/v1/capabilities/{uriOrName}/prepare-pr",
        ],
    },
    "org": {
        "title": "Organizations and per-user membership",
        "summary": (
            "Org stores are membership-gated (Design B): a capability with visibility "
            "'internal' in an org store is granted discover/load/call ONLY to members of "
            "THAT org. Membership is a role_assignment with scope_type='org' (role member, "
            "namespace_admin, or org_admin). Being a member of org A does not grant org B's "
            "capabilities. Non-members can still receive a single org capability via an explicit "
            "share or relationship tuple. Public-visibility org capabilities stay open to all. "
            "Add/remove/list-members require the manage right on the org store (org_admin / "
            "platform_admin); list-members also accepts the audit right."
        ),
        "commands": [
            "capmesh org list",
            "capmesh org add-member --org <slug|id|storeId> --subject-id user@asg --role member",
            "capmesh org add-member --org <slug> --subject-id lead@asg --role namespace_admin --expires-at 2027-01-01T00:00:00Z",
            "capmesh org remove-member --org <slug> --subject-id user@asg",
            "capmesh org list-members --org <slug>",
        ],
        "api": [
            "POST /api/v1/orgs/{org}/members",
            "DELETE /api/v1/orgs/{org}/members/{subjectId}",
            "GET /api/v1/orgs/{org}/members",
        ],
    },
    "tailnet": {
        "title": "Tailnet identity mapping & sync",
        "summary": (
            "TAILNET users need only point an MCP client at https://capmesh.asg.ts.net/mcp "
            "— verified Tailscale whois authenticates them, with no OAuth and no bearer "
            "for reads/discovery (initialize, tools/list, cap.search, cap.load, cap.list, "
            "cap.describe); mutating tools (cap.call/cap.delegate/cap.report) still require "
            "a service bearer. Verified tailnet users map onto capmesh identities and their Tailscale ACL "
            "groups/tags map onto capmesh groups, so org membership and role grants can be "
            "keyed on tailnet identity. Identity is established by VERIFIED whois (the reverse "
            "proxy resolves the calling peer via the Tailscale LocalAPI and injects "
            "X-Tailscale-Login / X-Tailscale-Tags ONLY after presenting the static service "
            "token) — never from spoofable client headers, and only on the already-trusted "
            "upstream path. A minted capmesh bearer (M365/Google login) still wins first; an "
            "unverified caller collapses to tailnet-guest, never the platform owner. Tags grant "
            "GROUPS (e.g. tag:eng -> asg:eng) for convenient bulk org membership but NEVER roles "
            "or rights directly — privilege flows only through audited role_assignments. The "
            "batch sync reads OAuth client creds (scope users:read) from OpenBao path "
            "asg/services/tailscale-user-sync via bao-client (never embedded), upserts tailnet "
            "users as identities and ACL groups as capmesh groups (additive + prune), and "
            "deactivates suspended/removed users. After a sync, "
            "'capmesh org add-member --subject-type group --subject-id asg:<tsgroup>' adds an "
            "entire tailnet ACL group to an org in one grant."
        ),
        "commands": [
            "capmesh sync                       # show SCIM/Graph/Teams + tailscale counts",
            "capmesh sync tailscale             # run the tailnet -> capmesh identity/group sync",
            "capmesh sync tailscale --dry-run   # compute the diff without writing",
            "capmesh sync tailscale --tailnet <name>",
            "capmesh org add-member --org <slug> --subject-type group --subject-id asg:<tsgroup> --role member",
        ],
        "vaultPath": "asg/services/tailscale-user-sync (OAuth client, scope users:read)",
    },
    "fanout": {
        "title": "Multi-agent fanout",
        "summary": "Use capmesh as the routing source of truth, then delegate to the smallest useful specialist set.",
        "commands": [
            "capmesh search '<workstream intent>' --type agent --k 8",
            "capmesh load '<agent-uri>' --detail entrypoint",
            "capmesh delegate '<agent-uri>' '<bounded task>'",
        ],
    },
}


def help_payload(topic: str | None = None, *, base_url: str = DEFAULT_BASE_URL) -> dict[str, Any]:
    selected = (topic or "overview").strip().lower()
    if selected in {"list", "topics", "all"}:
        return {"topics": sorted(HELP_TOPICS), "items": HELP_TOPICS, "baseUrl": base_url.rstrip("/")}
    item = HELP_TOPICS.get(selected)
    if item is None:
        return {
            "topic": selected,
            "error": "Unknown help topic.",
            "topics": sorted(HELP_TOPICS),
            "baseUrl": base_url.rstrip("/"),
        }
    return {
        "topic": selected,
        "baseUrl": base_url.rstrip("/"),
        "mcp": {
            "runtimeTools": RUNTIME_TOOLS,
            "systemCapabilities": SYSTEM_CAPABILITIES,
            "pattern": "Run cap.search for the intent, cap.load only the selected item, and cap.call system.* for governance.",
        },
        **item,
    }


def onboarding_payload(
    *,
    base_url: str = DEFAULT_BASE_URL,
    client: str = "all",
    direct: bool = False,
    tenant: str = "asg",
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    mode = "direct" if direct else "gateway"
    return {
        "tenant": tenant,
        "mode": mode,
        "baseUrl": base,
        "loginUrl": f"{base}/login?tenant={tenant}",
        "callbackUrl": f"{base}/oauth/callback",
        "mcpUrl": f"{base}/mcp",
        "client": client,
        "tailnetOnly": True,
        "recommendedPath": [
            f"capmesh auth login --m365 --tenant {tenant}",
            f"capmesh onboard --client {client} --json",
            "Use the gateway backend named capmesh, then call cap.search before loading or delegating.",
        ],
        "directMcpConfig": {
            "url": f"{base}/mcp",
            "authorization": "Bearer token from capmesh auth login; do not paste it into chat.",
        },
        "gatewayMcpConfig": {
            "url": "http://127.0.0.1:17777/mcp",
            "backend": "capmesh",
        },
        "doctorCommands": [
            "capmesh auth doctor --json",
            "asgcode-mcp-gateway doctor",
        ],
        "help": f"{base}/help",
    }


def authorization_server_issuer(authority: str) -> str:
    raw = authority.rstrip("/")
    if raw.endswith("/oauth2/v2.0"):
        return raw.removesuffix("/oauth2/v2.0") + "/v2.0"
    if raw.endswith("/v2.0"):
        return raw
    return raw + "/v2.0"


def protected_resource_metadata(
    *,
    base_url: str = DEFAULT_BASE_URL,
    authority: str = "https://login.microsoftonline.com/organizations/oauth2/v2.0",
    resource: str | None = None,
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    # Use the RFC 9728 module to build and validate the base metadata document,
    # then layer capmesh-specific extensions on top.  This ensures the
    # /.well-known/oauth-protected-resource endpoint is spec-compliant while
    # preserving the capmesh bootstrap/mcp/tailnet fields clients depend on.
    from .rfc9728 import build_resource_metadata

    resource_url = resource or base
    metadata = build_resource_metadata(
        resource_url=resource_url,
        authorization_servers=[authorization_server_issuer(authority)],
        scopes_supported=CAPMESH_SCOPES,
        bearer_methods=["header"],
    )
    # Override the generic documentation URL with the capmesh bootstrap endpoint.
    metadata["resource_documentation"] = f"{base}/bootstrap"
    # Capmesh-specific extensions (not part of RFC 9728 but used by clients).
    metadata["capmesh_bootstrap"] = f"{base}/bootstrap"
    metadata["capmesh_mcp"] = f"{base}/mcp"
    metadata["capmesh_tailnet_only"] = True
    return metadata


def bootstrap_payload(
    *,
    base_url: str = DEFAULT_BASE_URL,
    authority: str = "https://login.microsoftonline.com/organizations/oauth2/v2.0",
    resource: str | None = None,
    tenant: str = "asg",
    client: str = "all",
    direct: bool = False,
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    mode = "direct" if direct else "gateway"
    return {
        "schema": os.environ.get("CAPMESH_BOOTSTRAP_SCHEMA_URL", "http://127.0.0.1:8000/schemas/bootstrap.v1.json"),
        "version": "2026-06-16",
        "tailnetOnly": True,
        "service": {
            "name": "asg-capability-mesh",
            "baseUrl": base,
            "mcpUrl": f"{base}/mcp",
            "preferredGatewayUrl": "http://127.0.0.1:17777/mcp",
            "preferredGatewayBackend": "capmesh",
            "mode": mode,
        },
        "modelRouting": {
            "description": "Task delegation routes to the cheapest capable model tier",
            "tiers": {
                "qwen-worker": {"backend": "asgcode-build", "cost": "free", "use": "mechanical/atomic/parallel"},
                "qwen-director": {"backend": "asgcode-build", "cost": "free", "use": "reasoning/synthesis/verify"},
                "glm": {"backend": "bolde-exec", "cost": "free", "use": "frontier reasoning, 300K context"},
                "opus": {"backend": "codex-exec", "cost": "paid", "use": "critical/irreversible/security"},
            },
            "routing": "risk_tier + task keywords -> model tier",
            "override": "Pass modelTier in cap.delegate params",
            "processTool": "cap.process",
        },
        "discovery": {
            "bootstrap": f"{base}/bootstrap",
            "help": f"{base}/help",
            "onboarding": f"{base}/onboard",
            "login": f"{base}/login?tenant={tenant}",
            "oauthProtectedResource": f"{base}/.well-known/oauth-protected-resource",
            "protectedResourceMetadata": protected_resource_metadata(base_url=base, authority=authority, resource=resource),
        },
        "identity": {
            "tenant": tenant,
            "provider": "Microsoft Entra ID",
            "flow": "authorization_code_pkce",
            "fallbackFlow": "device_code",
            "browserStart": {
                "method": "POST",
                "url": f"{base}/api/v1/auth/m365/start",
                "json": {"tenant": tenant, "client": client},
                "result": "Open authorizationUrl for the user, then poll pollUrl by id or state.",
            },
            "deviceCodeStart": {
                "method": "POST",
                "url": f"{base}/api/v1/auth/m365/device-code",
                "json": {"tenant": tenant, "client": client},
                "result": "Show verificationUri and userCode only when no browser can be launched.",
            },
            "poll": {
                "method": "POST",
                "url": f"{base}/api/v1/auth/m365/poll",
                "json": {"sessionId": "<id-or-state>", "consumeTokens": False},
            },
            "autoProvisioning": {
                "trigger": "Successful M365 sign-in or accepted app principal.",
                "createsOrUpdates": [
                    "capmesh identity record",
                    "private user store",
                    "shared user store",
                    "tenant-wide all-user (everyone) store at cap://all/<tenant> — read-only for every authenticated tenant user; admin-managed",
                    "default private namespace",
                    "role and group derived grants from Entra/SCIM cache",
                    "short-lived capmesh bearer session",
                ],
                "authorizationSources": ["manual capmesh grants", "SCIM users/groups", "Entra app roles/groups", "app service principals"],
            },
        },
        "install": {
            "recommendedCommand": f"capmesh auth login --m365 --tenant {tenant} --base-url {base} --wait --install-env",
            "headlessCommand": f"capmesh auth login --m365 --tenant {tenant} --base-url {base} --device-code --wait --install-env --no-browser",
            "doctorCommand": f"capmesh auth doctor --base-url {base} --json",
            "localEnvFile": "~/.config/asgcode/capmesh.env",
            "tokenHandling": "Do not paste bearer, refresh, or device codes into chat. Let the CLI write local env/keychain material.",
        },
        "llmRunbook": [
            "First GET /bootstrap or /.well-known/oauth-protected-resource.",
            "Prefer the local ASG MCP gateway at http://127.0.0.1:17777/mcp with backend capmesh.",
            "If the gateway reports missing or expired capmesh auth, run the recommendedCommand or start browserStart and show/open authorizationUrl.",
            "After sign-in, retry through the gateway. The logged-in user or app role is auto-provisioned and sees all authorized user, shared, org, app, and system spaces.",
            "For work, call cap.search with the intent, cap.load only selected results, then cap.call or cap.delegate. Do not bulk-load all capabilities.",
            "For capability authoring or maintenance, use cap.call system.capabilities or the JSON CLI/API shown in help topic capabilities.",
            "The gateway keeps search/load/list/describe local when a synchronized member is available, but routes every cap.call, cap.delegate, cap.report, unknown future tool, install, update, maintenance, and third-party resync to the authoritative node.",
        ],
        "runtime": {
            "tools": RUNTIME_TOOLS,
            "systemCapabilities": SYSTEM_CAPABILITIES,
            "searchFirstPattern": "cap.search -> cap.load selected capability -> cap.call/cap.delegate",
            "fanoutPattern": "Resolve agent URIs with cap.search type=agent, then fan out bounded cap.delegate calls in waves of 10 or fewer.",
        },
        "api": {
            "help": f"{base}/api/v1/help",
            "onboarding": f"{base}/api/v1/onboarding",
            "bootstrapStart": f"{base}/api/v1/bootstrap/start",
            "authStart": f"{base}/api/v1/auth/m365/start",
            "authDeviceCode": f"{base}/api/v1/auth/m365/device-code",
            "authPoll": f"{base}/api/v1/auth/m365/poll",
        },
        "security": {
            "tailnetOnly": True,
            "publicInternet": False,
            "secrets": "Never print, store, or ask the user to paste secrets. Use keychain, OpenBao, or /secure service env only.",
            "authorizationHeader": "Protected endpoints return WWW-Authenticate with resource_metadata for OAuth/MCP-aware clients.",
        },
    }
