# CM-02 Loopback Identity Spoofing Verification

Entity: the operator  
Scope: Capability Mesh HTTP authorization and trusted loopback proxy identity boundary  
Sensitivity: [CONFIDENTIAL]  
[DRAFT — REQUIRES HUMAN REVIEW — v2026-07-21]

## Result

**PASS.** A request arriving from loopback with a caller-supplied
`Tailscale-User-Login` header cannot establish an authenticated user identity,
including a configured superadmin identity, unless it also presents the configured
`CAPMESH_TRUSTED_PROXY_TOKEN` through `X-Capmesh-Proxy-Token`.

## Code-path evidence

- `capmesh/server.py:866-872` derives the socket peer and calls
  `trusted_proxy_identity_headers()` with the request's proxy authorization header
  and the configured `CAPMESH_TRUSTED_PROXY_TOKEN`.
- `capmesh/server.py:876-891` accepts Tailscale identity from only two sources:
  direct-peer LocalAPI whois or Tailscale headers on an authenticated proxy hop.
  Raw loopback identity headers fall into the empty-identity branch.
- `capmesh/server.py:937-947` converts an untrusted loopback request into the
  `tailnet-guest` principal rather than a caller-selected subject.
- `capmesh/server.py:1418-1441` authorizes only a non-guest resolved principal or a
  valid service, route, or minted session bearer; the guest path receives `401`.
- `capmesh/server.py:1682-1695` requires both a loopback peer and a configured proxy
  secret, then compares the supplied proxy credential with that secret using
  `hmac.compare_digest()`.
- `capmesh/install_policy.py:10-11` identifies `admin@example.com` as a configured
  superadmin actor, and `capmesh/governance.py:693-720` grants configured subjects
  the tenant-scoped `platform_admin` role.

## Test evidence

- Added the focused HTTP regression at
  `tests/test_http_service_auth.py:101-106`. It sends
  `Tailscale-User-Login: admin@example.com` directly over loopback with no
  proxy credential and requires `401 UNAUTHORIZED`.
- Existing helper coverage at
  `tests/test_mcp_security_readiness.py:217-245` rejects missing and forged proxy
  credentials, accepts the correct proxy credential from loopback, and rejects the
  same credential from a non-loopback peer.
- Existing positive HTTP coverage at
  `tests/test_http_service_auth.py:119-128` confirms that a Tailscale identity is
  accepted without a service bearer only when the trusted proxy credential is
  present.

Verification command:

```text
uv run --frozen --group dev pytest -q tests/test_http_service_auth.py tests/test_mcp_security_readiness.py -k "proxy or metrics or loopback or whois" --tb=short
```

Observed result on 2026-07-21:

```text
.......                                                                  [100%]
7 passed, 18 deselected in 4.35s
```

No production code or secrets were changed. `capmesh/governance.py` was not modified.
