# ADR: Remote OAuth deployment decision — tailnet-primary Capmesh

**Entity:** ASG  
**Scope:** Capability Mesh production (`the authority URL (env CAPMESH_AUTHORITY_URL)`)  
**Status:** ACCEPTED  
**Date:** 2026-07-21  
**Owner:** the operator / Capmesh ops  

## Context

The ideal-state checklist required a recorded decision on whether Capmesh remote
HTTP must implement full OAuth 2.1 Authorization Code + PKCE as a production
exit criterion, versus remaining a Tailscale-authenticated internal service.

## Decision

**Production Capmesh remains tailnet-primary.** Access to
`the authority URL (env CAPMESH_AUTHORITY_URL)` is restricted to the tailnet. Identity is:

1. **Primary:** verified Tailscale WhoIs / Serve identity.
2. **Fallback:** Microsoft Entra ID and Google OIDC for interactive login when
   Tailscale identity is unavailable (existing `CAPMESH_ENTRA_*` /
   `CAPMESH_GOOGLE_*` wiring).
3. **Service clients:** bearer / trusted-proxy hop
   (`CAPMESH_BEARER_TOKEN`, `CAPMESH_TRUSTED_PROXY_TOKEN`) on loopback nginx →
   worker pool.

Full public-internet OAuth 2.1 + RFC 9728 protected-resource hardening for
untrusted networks is **deferred** until an explicit product requirement opens
Capmesh beyond the tailnet.

## Consequences

- Production exit item “Remote OAuth deployment decision recorded” is **done**.
- Checklist items for OAuth 2.1+PKCE / resource indicators remain **open as
  product backlog**, not as blockers for tailnet production readiness.
- Operators must not publish Capmesh on a public edge without revisiting this ADR.
- Metrics remain fail-closed without a scrape bearer; public bare `/metrics` is
  401.

## Evidence (2026-07-21)

- `ops/closure-verify.sh` RESULT: all checks passed.
- Public `/health/ready` → ready, `nodeRole=authoritative`.
- Public `/metrics` bare → 401.
- Workers bind `127.0.0.1` only; LB `127.0.0.1:17778` + Tailscale Serve.
- Replica write → `NOT_AUTHORITATIVE`.
