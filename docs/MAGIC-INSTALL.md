# Magic Tailnet Install — Capability Mesh

## One-Line Install

**macOS/Linux:**
```bash
curl the installer endpoint (CAPMESH_BASE_URL + /install.sh) | sh
```

**Windows:**
```powershell
irm the installer endpoint (CAPMESH_BASE_URL + /install.ps1) | iex
```

The installer downloads the capmesh CLI and configures Tailscale integration.
The client always uses the authoritative node's service at
`the authority URL (env CAPMESH_BASE_URL)`; a client installation does not become an
independent catalog authority.

## Identity & Auto-Provisioning

Once installed, your identity is automatic:

- **On the tailnet**, tailscaled (Tailscale Service `svc:capmesh`) resolves the calling peer via verified Tailscale whois and injects trusted `Tailscale-User-Login` / `Tailscale-Tags` headers; nginx forwards them to the worker across the authenticated loopback hop (validated by `X-Capmesh-Proxy-Token`), so the worker trusts that verified identity and direct client-supplied identity headers are ignored. Tailnet reads/discovery need no OAuth and no bearer — point an MCP client at `https://capmesh.asg.ts.net/mcp` and whois authenticates you.
- **Identity precedence:** Verified Tailscale WhoIs identity is primary. Microsoft 365 or Google OIDC is used only as a fallback when no verified Tailscale identity is present.
- **Auto-provisioned on first use:** Your private and shared namespaces (`cap://user/asg/<identity>/*`) are created automatically when you first access capmesh.
- **ASG authoring:** Verified `the corporate email domain (env CAPMESH_CORPORATE_EMAIL_DOMAIN)` users can write capabilities in their own stores and submit them for gated elevation to any active organization or everyone namespace. Submission never bypasses gates or approval.
- **Superadmins:** `jasonthe corporate email domain (env CAPMESH_CORPORATE_EMAIL_DOMAIN)` and `manbirthe corporate email domain (env CAPMESH_CORPORATE_EMAIL_DOMAIN)` have audited tenant-wide administration and immediate-after-gates install activation.
- **Pre-configured read-only store:** You immediately have access to `cap://all/asg` — the all-user shared capability store. No M365 setup or OAuth step required.
- Use `capmesh whoami` to verify your identity and current capabilities.

## Troubleshooting

- **"Not on Tailscale network"** — Verify `tailscale status` shows an active connection to the tailnet. The capmesh service is tailnet-only.
- **"Auth failed"** — Run `capmesh auth doctor` to diagnose identity resolution. Confirms tailscale user injection and permission checks.
- **"Permission denied on cap://all/asg"** — Rare; indicates your user is not in the `capmesh-readers` group. Contact the operator to add you.

---

**Questions?** Check the [README.md](../README.md) for full API reference and advanced usage.
