# Capability Mesh transport error contract

Capability Mesh exposes the same router through native MCP and REST-compatible
adapters. They intentionally use different transport status semantics while
sharing stable structured error codes.

## Native MCP (`POST /mcp`)

- Unknown tool names are protocol errors: JSON-RPC `-32602` (`Invalid params`).
- Failures produced by a known tool, including authorization denials, are
  `CallToolResult` values with `isError: true` and HTTP 200.
- Missing or invalid transport authentication is rejected before tool dispatch
  with the appropriate HTTP authentication status.

This follows the MCP rule that an unknown tool is a protocol error while a
known tool's execution failure remains visible to the model as a tool result.

## REST compatibility (`/tools/call`, `/cap/call`, `/cap/search`)

The response body retains the MCP-shaped `isError` and `structuredContent`
envelope. HTTP status is derived from `structuredContent.error.code`:

| Error code | HTTP status |
|---|---:|
| `FORBIDDEN`, `INSUFFICIENT_SCOPE` | 403 |
| `TOOL_NOT_FOUND`, `CAPABILITY_NOT_FOUND`, `RESOURCE_NOT_FOUND` | 404 |
| `NOT_AUTHORITATIVE` | 409 |
| `RATE_LIMITED` | 429 |
| `INTERNAL_ERROR` | 500 |
| validation, confirmation, and legacy errors | 400 |

Clients should branch on the stable error code and use HTTP status as the
transport-level summary. They must not parse human-readable messages.

## Governance operation names

The router tools are `cap.search`, `cap.load`, `cap.call`, `cap.list`,
`cap.describe`, `cap.delegate`, and `cap.report`. Governance operations are
system capabilities invoked through `cap.call`, for example:

```json
{
  "name": "cap.call",
  "arguments": {
    "name": "system.roles",
    "dryRun": false,
    "confirm": true,
    "args": {"action": "list"}
  }
}
```

Names such as `cap.approve`, `cap.publish`, `cap.share`, and `cap.submit` are
not router tools. A request using one of those names receives
`TOOL_NOT_FOUND`; it does not prove an authorization policy decision. To audit
least privilege, call the supported `system.approve`, `system.capabilities`,
`system.share`, `system.submit`, or `system.roles` capability through
`cap.call` and assert `FORBIDDEN` for a principal without the required right.
