# Pending test-first specs (not yet collected)

These are red-by-design specs for behavior that is **not implemented**. They live
here rather than in `tests/` so `pytest tests/` stays green and does not block
`ops/deploy-capmesh.sh` (which refuses a dirty tree).

| File | Specifies | Status |
|---|---|---|
| `test_install_served_bytes_contract.py` | `/install.sh` and `/install.ps1` must serve the canonical bytes from the repo-root `install/` directory, not the `_install_sh`/`_install_ps1` heredocs in `capmesh/server.py:2284`. | RED — `server.py:1277` still serves the heredoc; there is no on-disk preference. Also note `INSTALL_DIR` in the spec resolves relative to the test file and does not currently point at the repo-root `install/`. |
| `test_keychain_macos_argv.py` | `store_keychain_secret` must not pass a refresh token via `security add-generic-password -w <secret>` argv (process-table leak on a shared tailnet device). | Verify against current `capmesh/cli.py` before promoting. |
| `test_mcp_mutation_blocked.py` | MCP mutation routes are refused without a service token. | Verify against current route policy before promoting. |

To promote one: implement the behavior, move the file to `tests/`, and confirm the
whole suite is green.
