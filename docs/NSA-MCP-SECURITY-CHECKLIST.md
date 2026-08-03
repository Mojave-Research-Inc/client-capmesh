# NSA May 2026 MCP Security Review Checklist

> [INTERNAL] Capability Mesh security review checklist based on NSA May 2026
> MCP (Model Context Protocol) security guidance. Every production deployment
> must pass this checklist before being declared production-ready.

## 1. Authentication and Authorization

- [ ] All MCP endpoints require authentication (no anonymous access)
- [ ] OAuth 2.1 Authorization Code + PKCE for remote HTTP transport
- [ ] Token audience and issuer validation enforced
- [ ] RFC 8707 resource indicators (authorization server metadata)
- [ ] RFC 9728 protected resource metadata published
- [ ] Step-up authentication for destructive or high-risk operations
- [ ] Break-glass admin flow with mandatory reason and audit trail
- [ ] Role-based access control (RBAC) with least-privilege defaults
- [ ] No hardcoded credentials in configuration or source

## 2. Input Validation and Sanitization

- [ ] All tool inputs validated against schema before execution
- [ ] Prompt injection scanning on capability metadata and source content
- [ ] Injection allowlist with per-surface (metadata vs body) filtering
- [ ] File path validation (no path traversal, no symlinks)
- [ ] Content size limits enforced (MAX_SOURCE_BYTES, MAX_EVIDENCE_BYTES)
- [ ] SQL injection prevention (parameterized queries, identifier allowlist)

## 3. Transport Security

- [ ] TLS for all remote connections
- [ ] Tailscale SSH for admin access (session recording enabled)
- [ ] No plain HTTP for remote traffic (localhost-only stdio is exception)
- [ ] Certificate validation enforced
- [ ] Connection timeouts configured

## 4. Registry Integrity

- [ ] Tamper-evident append-only registry log with hash chain verification
- [ ] Capability content hash verification on ingest
- [ ] Source authority ranking prevents lower-authority shadowing
- [ ] Version conflict detection and resolution
- [ ] Lifecycle state transitions enforced (no invalid jumps)
- [ ] Signed allowlist for executable call bindings
- [ ] Malware scan for scripts/assets before indexing as callable

## 5. Supply Chain Security

- [ ] Dependency audit job runs regularly
- [ ] SLSA provenance statements for generated registry artifacts
- [ ] Sigstore signing for registry exports
- [ ] License capture for external/vendor-derived capabilities
- [ ] Source repo commit capture for each ingested package
- [ ] Keyless signing policy defined
- [ ] Verification summary artifact produced per build

## 6. Audit and Monitoring

- [ ] All governance decisions recorded in audit_events
- [ ] Policy decision logging with subject and resource attribution
- [ ] Structured JSON logging with sensitive field redaction
- [ ] OTel-compatible tracing for gate evaluations and HTTP requests
- [ ] Prometheus metrics endpoint for operational monitoring
- [ ] SLO tracking for search, load, and delegate latencies
- [ ] Dashboard for search/load/delegate volume

## 7. Secrets Management

- [ ] No secrets in source code or configuration files
- [ ] Secrets stored in OpenBao (never in localStorage)
- [ ] Token rotation and revocation procedures documented
- [ ] Session tokens have TTL and are invalidated on expiry
- [ ] Break-glass sessions have mandatory TTL (max 120 minutes)

## 8. Sandboxing and Isolation

- [ ] Capability execution sandboxed (no host filesystem access)
- [ ] Store/namespace isolation enforced (cross-tenant access prevented)
- [ ] Namespace membership required for org store access
- [ ] All-users store limited to read-only (discover/load/call)
- [ ] Mutating capabilities flagged and require elevated permissions

## 9. Deployment Security

- [ ] SQLite WAL mode with checkpoint timer (WAL reset fix applied)
- [ ] Write concurrency bounded (single writer, multiple readers)
- [ ] No production single-node OpenBao (HA required)
- [ ] Schema migrations are idempotent and additive-only
- [ ] Database backup and restore procedures tested

## 10. MCP-Specific Protections

- [ ] Tool descriptions do not leak sensitive configuration
- [ ] Capability stubs returned for locked capabilities (no content leak)
- [ ] Router reports are signed and nonce-protected
- [ ] Task envelopes validated against schema before processing
- [ ] Delegated task write-set enforced (no out-of-scope writes)
- [ ] Bundle receipt signing prevents repudiation

## Verification

This checklist is verified by:
1. Running `python -m pytest tests/test_mcp_security_readiness.py`
2. Running `capmesh lifecycle --action list` to verify lifecycle states
3. Running `capmesh audit` to review recent governance events
4. Running `capmesh migrate` to verify schema is current
5. Running `capmesh semver` to check for version conflicts
6. Verifying `capmesh break-glass --action active` shows no unexpired sessions
