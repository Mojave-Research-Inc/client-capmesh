"""MCP SDK server wrapper for standardized MCP protocol compliance.

Wraps the capmesh router with the official MCP SDK server interface
when available, providing standardized JSON-RPC handling, tool
registration, and protocol negotiation.
"""

from __future__ import annotations

from typing import Any

PROTOCOL_VERSION = "2026-01-25"
SERVER_NAME = "capmesh"
SERVER_VERSION = "0.1.0"

# Tool name validation: MCP SDK requires tool names to match
# ^[a-zA-Z][a-zA-Z0-9_-]*$ (no dots). Capmesh uses dotted names like
# "cap.search". This wrapper maps dotted names to SDK-compatible names.
DOTTED_TO_SDK = {
    "cap.search": "cap_search",
    "cap.load": "cap_load",
    "cap.call": "cap_call",
    "cap.list": "cap_list",
    "cap.describe": "cap_describe",
    "cap.delegate": "cap_delegate",
    "cap.process": "cap_process",
    "cap.report": "cap_report",
}
SDK_TO_DOTTED = {v: k for k, v in DOTTED_TO_SDK.items()}


def to_sdk_name(dotted_name: str) -> str:
    """Convert a dotted tool name to SDK-compatible underscore name."""
    return DOTTED_TO_SDK.get(dotted_name, dotted_name.replace(".", "_"))


def to_dotted_name(sdk_name: str) -> str:
    """Convert an SDK-compatible name back to dotted form."""
    return SDK_TO_DOTTED.get(sdk_name, sdk_name.replace("_", "."))


def build_initialize_response() -> dict[str, Any]:
    """Build the MCP initialize response."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "capabilities": {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
        },
    }


def build_tools_list() -> list[dict[str, Any]]:
    """Build the tools list with SDK-compatible names."""
    return [
        {"name": "cap_search", "description": "Search capabilities by query", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "k": {"type": "integer", "default": 10}}, "required": ["query"]}},
        {"name": "cap_load", "description": "Load a capability by URI", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}}, "required": ["uri"]}},
        {"name": "cap_call", "description": "Call a capability with input", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "input": {"type": "object"}}, "required": ["uri"]}},
        {"name": "cap_list", "description": "List capabilities with pagination", "inputSchema": {"type": "object", "properties": {"cursor": {"type": "string"}, "pageSize": {"type": "integer", "default": 50}}}},
        {"name": "cap_describe", "description": "Describe a capability without loading it", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}}, "required": ["uri"]}},
        {"name": "cap_delegate", "description": "Delegate a task to a capability", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "task": {"type": "string"}}, "required": ["uri", "task"]}},
        {"name": "cap_report", "description": "Report telemetry or coverage", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "report": {"type": "object"}}}},
        {"name": "cap_process", "description": "Process a queued task by dispatching to GLM/Qwen/Opus backend via the ASG MCP gateway", "inputSchema": {"type": "object", "properties": {"taskId": {"type": "string"}}, "required": ["taskId"]}},
    ]


def is_sdk_available() -> bool:
    """Check if the MCP SDK is available."""
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def route_sdk_call(sdk_name: str, params: dict[str, Any], router: Any, *, principal: Any = None) -> dict[str, Any]:
    """Route an SDK-compatible tool call to the capmesh router.

    Uses the router's call() method so that authorization, SLO tracking,
    and audit logging are applied consistently with the /mcp endpoint.
    """
    dotted = to_dotted_name(sdk_name)
    if dotted not in ("cap.search", "cap.load", "cap.call", "cap.list", "cap.describe", "cap.delegate", "cap.process", "cap.report"):
        return {"error": {"code": -32601, "message": f"Unknown tool: {sdk_name}"}}
    from .models import Principal
    principal_obj = principal if isinstance(principal, Principal) else Principal()
    # Inject the principal into params so the router can extract it
    call_params = {**params, "principal": principal_obj.to_dict() if hasattr(principal_obj, "to_dict") else {}}
    result = router.call(dotted, call_params)
    return result
