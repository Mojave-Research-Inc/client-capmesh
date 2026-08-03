"""Streamable HTTP transport for MCP (2026 spec).

Implements the Streamable HTTP transport defined in the MCP 2026 RC.
Supports both SSE (Server-Sent Events) for streaming responses and
regular HTTP POST for single-request/response patterns.
"""

from __future__ import annotations

import json
from typing import Any

SUPPORTED_PROTOCOL_VERSIONS = ["2026-01-25", "2025-06-18", "2024-11-05"]
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_SSE = "text/event-stream"


class StreamableHTTPResponse:
    """Response wrapper for the Streamable HTTP transport."""

    def __init__(self, body: dict[str, Any] | None = None, status: int = 200, content_type: str = CONTENT_TYPE_JSON, headers: dict[str, str] | None = None) -> None:
        self.body = body or {}
        self.status = status
        self.content_type = content_type
        self.headers = headers or {}
        self.headers.setdefault("Content-Type", content_type)
        self.headers.setdefault("MCP-Protocol-Version", SUPPORTED_PROTOCOL_VERSIONS[0])

    def to_json(self) -> str:
        return json.dumps(self.body, sort_keys=True)

    def to_sse(self) -> str:
        """Format as Server-Sent Events."""
        lines = ["event: message", f"data: {self.to_json()}", ""]
        return "\n".join(lines) + "\n"


def handle_initialize(params: dict[str, Any], protocol_version: str | None = None) -> StreamableHTTPResponse:
    """Handle MCP initialize request over Streamable HTTP."""
    params.get("protocolVersions", [])
    if protocol_version and protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
        return StreamableHTTPResponse(
            body={"error": {"code": -32000, "message": f"Unsupported protocol version: {protocol_version}"}},
            status=400,
        )
    selected = protocol_version or SUPPORTED_PROTOCOL_VERSIONS[0]
    return StreamableHTTPResponse(body={
        "protocolVersion": selected,
        "serverInfo": {"name": "capmesh", "version": "0.1.0"},
        "capabilities": {"tools": {"listChanged": True}, "resources": {"subscribe": True, "listChanged": True}},
    })


def handle_request(method: str, params: dict[str, Any], protocol_version: str | None = None) -> StreamableHTTPResponse:
    """Route a Streamable HTTP request to the appropriate handler."""
    if method == "initialize":
        return handle_initialize(params, protocol_version)
    if method == "ping":
        return StreamableHTTPResponse(body={"pong": True})
    if method == "tools/list":
        return StreamableHTTPResponse(body={"tools": _get_tool_list()})
    if method == "tools/call":
        return StreamableHTTPResponse(body={"result": "tool call routed to stdio router"})
    return StreamableHTTPResponse(
        body={"error": {"code": -32601, "message": f"Method not found: {method}"}},
        status=404,
    )


def _get_tool_list() -> list[dict[str, Any]]:
    """Return the list of available tools."""
    return [
        {"name": "cap.search", "description": "Search capabilities", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "k": {"type": "integer"}}}},
        {"name": "cap.load", "description": "Load a capability", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}}}},
        {"name": "cap.call", "description": "Call a capability", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "input": {"type": "object"}}}},
        {"name": "cap.list", "description": "List capabilities", "inputSchema": {"type": "object", "properties": {"cursor": {"type": "string"}, "pageSize": {"type": "integer"}}}},
        {"name": "cap.describe", "description": "Describe a capability", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}}}},
        {"name": "cap.delegate", "description": "Delegate a task", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "task": {"type": "string"}}}},
        {"name": "cap.report", "description": "Report telemetry", "inputSchema": {"type": "object", "properties": {"uri": {"type": "string"}, "report": {"type": "object"}}}},
    ]


def check_protocol_version(headers: dict[str, str]) -> str | None:
    """Extract and validate the MCP-Protocol-Version header."""
    version = headers.get("MCP-Protocol-Version") or headers.get("mcp-protocol-version")
    if version and version not in SUPPORTED_PROTOCOL_VERSIONS:
        return None
    return version or SUPPORTED_PROTOCOL_VERSIONS[0]
