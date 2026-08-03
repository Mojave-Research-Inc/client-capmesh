# MCP Client Verification Steps

> Steps to verify that the Capability Mesh MCP server is correctly registered
> and accessible from all target MCP clients (Claude Code, Codex CLI, Cursor Agent).

## Prerequisites

1. Ensure the capmesh server is running:
   ```bash
   capmesh serve --db ~/.capmesh/mesh.db
   ```
2. Or use the HTTP transport:
   ```bash
   capmesh serve-http --host 127.0.0.1 --port 17778
   ```

## Claude Code Verification

```bash
# Check that the capmesh MCP server is registered
claude mcp list

# Verify the server appears in the list with tools visible
# Expected output should show capmesh with cap.search, cap.load, etc.
```

If capmesh does not appear:
1. Add it to Claude Code MCP config:
   ```bash
   claude mcp add capmesh -- capmesh serve
   ```
2. Restart Claude Code and verify again.

## Codex CLI Verification

```bash
# Check that the capmesh MCP server is registered
codex mcp list

# The output should include capmesh as a registered server
```

If capmesh does not appear:
1. Add it to Codex MCP config:
   ```bash
   codex mcp add capmesh -- capmesh serve
   ```
2. Restart Codex and verify again.

## Cursor Agent Verification

```bash
# Check that the capmesh MCP server is registered
cursor-agent mcp list

# If Cursor reports "gateway: not loaded (needs approval)" run:
cursor-agent mcp add capmesh -- capmesh serve
```

For headless Cursor smoke tests, MCP approval may be needed:
```bash
cursor-agent --approve-mcps smoke-test
```

## Shared Gateway Verification

If using the unified ASG MCP gateway at `127.0.0.1:17777`:

```bash
# List all backends including capmesh
# (Use gateway tools: list_backends, list_tools, search_tools)
```

## Automated Verification

Run the MCP inspector smoke test:
```bash
python -m pytest tests/test_mcp_inspector_smoke.py -v
```

Expected: all tests pass, confirming the MCP protocol handshake,
tools/list, and tools/call all work correctly.

## Post-Verification Checklist

- [ ] `claude mcp list` shows capmesh with all 7 tools
- [ ] `codex mcp list` shows capmesh
- [ ] `cursor-agent mcp list` shows capmesh (or approved)
- [ ] MCP inspector smoke tests pass
- [ ] `cap.search` returns results for a known query
- [ ] `cap.list` returns a paginated list
- [ ] `cap.describe` returns details for a known URI
