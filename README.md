# ASG Capability Mesh

Capability Mesh is the local lazy-loading router for the ASG plugin, agent,
skill, command, and MCP package ecosystem.

The authoritative implementation and capability sources live in one repository:

- service: `services/asg-capmesh`
- authored capability packages: `plugins`

Directories under `~/.agents`, `~/.codex`, and `~/.claude` are runtime
projections or additional ingest roots, not authoring sources of truth.

It implements the seven-tool surface from `docs/design/asg-capmesh-spec.md`:

- `cap.search`
- `cap.load`
- `cap.call`
- `cap.list`
- `cap.describe`
- `cap.delegate`
- `cap.report`

## Design

The service stores canonical capability records in SQLite, uses FTS5 for lexical
retrieval, optionally creates a `sqlite-vec` table for local vector search, and
keeps a source coverage table for every source file discovered. Mirrored runtime
copies are deduplicated for routing while still counted for ingestion coverage.

Source conflicts are resolved by an explicit authority order: authored ASG OS
plugins, Codex-managed `.system` skills, the shared agent registry, ordinary
Codex skill projections, then plugin caches. Capmesh records every conflicting
hash and selected source in capability metadata. If two equal-authority sources
claim one canonical key or effective URI with different content, ingest fails
and rolls back; filesystem traversal order is never an authority mechanism.

Default roots:

- `<CAPMESH_ROOTS>/plugins (env CAPMESH_ROOTS)`
- `~/.capmesh/skill-registry`
- `~/.capmesh/skills`
- `~/.capmesh/plugins/cache`
- `~/.capmesh/plugins/cache/personal`

## Commands

```bash
cd <repo-root>/services/asg-capmesh
python3 -m capmesh ingest
python3 -m capmesh check
python3 -m capmesh search "MCP security prompt injection" --k 5
python3 -m capmesh load cap://user/asg/idn_75f310a283e0b72ebde0ee07/private/personal/skill/mcp-forge.mcp-forge@0.1.0
python3 -m capmesh me
python3 -m capmesh stores
python3 -m capmesh namespaces
python3 -m capmesh bootstrap --client all --json
python3 -m capmesh help onboarding --json
python3 -m capmesh onboard --client all --json
python3 -m capmesh auth login --m365 --tenant <tenant> --base-url https://capmesh.example.local --wait --install-env
python3 -m capmesh auth login --m365 --tenant <tenant> --base-url https://capmesh.example.local --device-code --wait --install-env --no-browser
python3 -m capmesh auth status --json
python3 -m capmesh auth doctor --json
python3 -m capmesh capabilities --action template
python3 -m capmesh.lifecycle_cli --db ~/.capmesh/asg-capmesh.db
python3 -m capmesh.lifecycle_cli --db ~/.capmesh/asg-capmesh.db --apply --actor admin@example.com (env CAPMESH_SUPERADMIN_ACTOR)
python3 -m capmesh tools
python3 -m capmesh serve
python3 -m capmesh serve-http --host 127.0.0.1 --port 17781
```

## Tailnet Onboarding

Users on the tailnet should not manually assemble MCP config. For reads and discovery, tailnet users need no OAuth and no bearer — verified Tailscale whois authenticates you; the commands below are for bootstrap metadata and mutating access (or external users). Start with:

```bash
curl -fsSL https://capmesh.example.local/bootstrap
capmesh bootstrap --client all --base-url https://capmesh.example.local --json
capmesh auth login --m365 --tenant <tenant> --base-url https://capmesh.example.local --wait --install-env
```

`/bootstrap` is the first-contact contract for a cold LLM/coder on an ASG
tailnet machine. It returns the MCP URL, preferred local gateway backend,
OAuth protected-resource metadata URL, auth-start API, exact CLI repair
commands, and the runtime rule: `cap.search` first, then `cap.load` only the
selected result, then `cap.call` or `cap.delegate`.

Verified Tailscale WhoIs identity is the primary user identity on the tailnet.
Microsoft Entra auth-code + PKCE and Google OIDC are fallback sign-in methods
when no verified Tailscale identity is available. Corporate email domain (env CAPMESH_CORPORATE_EMAIL_DOMAIN, default example.com)
identities resolve to the same Capmesh user across all three providers; external
Google invitees remain bound to Google's stable subject identifier.

The login command starts Microsoft Entra auth-code + PKCE login, opens a browser
when available, polls the tailnet control plane, stores the short-lived capmesh
bearer in `~/.config/asgcode/capmesh.env` with mode `0600`, and stores any M365
refresh credential in OS keychain when the platform supports it. Successful
sign-in auto-provisions the capmesh identity, private/shared user stores,
default namespaces, and Entra/SCIM-derived grants. For SSH or headless sessions,
use `--device-code --no-browser`.

If an LLM/coder sees a capmesh backend startup failure or timeout, it should run:

```bash
capmesh onboard --client all --base-url https://capmesh.example.local --json
capmesh auth doctor --base-url https://capmesh.example.local --json
```

The preferred client path is still the unified local gateway at
`http://127.0.0.1:17777/mcp`. Direct tailnet MCP at
`https://capmesh.example.local/mcp` authenticates tailnet users via verified whois
for reads/discovery with no bearer (mutating tools still need a service bearer);
direct mode should be used only when the local gateway is unavailable.

Protected endpoints return `WWW-Authenticate` with a
`resource_metadata="https://capmesh.example.local/.well-known/oauth-protected-resource"`
parameter and a `Link: <https://capmesh.example.local/bootstrap>` header. MCP/OAuth
aware clients should follow those links automatically when a bearer is missing
or expired.

## Fanout

Claude Code, Codex, ASGCode, Cursor, and other local clients should reach
Capability Mesh through the unified ASG MCP gateway, not as a separate client
entry. For independent mesh work, use the gateway `call_tools_parallel`
meta-tool with capmesh calls such as `cap.search`, `cap.load`, `cap.describe`,
or `cap.delegate`.

The supported maximum is 10 parallel calls per gateway request. Split larger
rosters into deterministic waves of 10 or fewer. MCP JSON-RPC batching is not a
supported fanout mechanism; the gateway handles concurrency with independent
tool calls.

Production workers bind `127.0.0.1` behind root-owned nginx and Tailscale Serve.
Nginx authenticates the proxy hop with a separate secret and strips all
caller-supplied Capmesh identity headers. Do not expose this service to the
public internet. The M365 callback,
SCIM provisioning, JSON API, Graph webhook validation endpoint, and MCP HTTP
endpoint all live on the same tailnet-only listener.

`GET /health` and `GET /health/ready` expose a `catalog` object containing the
capability count, distinct display-name count, indexed source count, latest
successful ingest timestamp, and the logical `sha256:` generation. The
generation hashes the ordered `(uri, content_hash, approval_state, share_state)`
records, so the authoritative node (env CAPMESH_AUTHORITY_HOST) and non-voting members can prove they serve the same governed
corpus even when their local SQLite files and localized source paths differ.
Consumers should require a ready response and compare `catalog.generation` for
exact parity; row-count proximity alone is not a corpus identity check.

### the authoritative node (env CAPMESH_AUTHORITY_HOST)-local service access

Services running on the authoritative node (env CAPMESH_AUTHORITY_HOST) use the same authoritative worker pool without a
tailnet round trip:

```ini
[Unit]
After=asg-capability-mesh.target
Requires=asg-capability-mesh.target

[Service]
EnvironmentFile=CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/the authoritative node (env CAPMESH_AUTHORITY_HOST)-local.env
```

That protected file supplies `CAPMESH_BASE_URL=http://127.0.0.1:17778`, the MCP
URL, the `capmesh-service` bearer, node role, and authority URL. The installer
creates it as `root:capmesh-clients` mode `0640`; systemd can read it for a
service without making it public. Non-systemd processes must be deliberately
added to `capmesh-clients`. Never copy its bearer into a repository, command
line, log, or per-project `.env` file.

The local service bearer grants application search/load/call/delegate/report
scopes, not a human superadmin identity. User requests still traverse
`https://capmesh.example.local`, where Tailscale WhoIs/Serve identity is primary.
Bearer-less loopback requests return `401`; local services must never bypass the
HTTP/MCP authorization layer by opening `asg-capmesh.db` directly.

the authoritative node (env CAPMESH_AUTHORITY_HOST) is the sole authoritative production server. macOS and the fallback node (env CAPMESH_FALLBACK_HOST) are
synchronized non-voting fallback members; local agents may use them directly
for low-latency reads, while writes remain the authoritative node (env CAPMESH_AUTHORITY_HOST)-only. Other nodes are clients. Only the authoritative node (env CAPMESH_AUTHORITY_HOST) serves
`https://capmesh.example.local` and accepts authoritative writes. See
[`docs/AUTHORITY-INVARIANT.md`](docs/AUTHORITY-INVARIANT.md). On the authoritative node (env CAPMESH_AUTHORITY_HOST) and its
replica, keep service material under encrypted `/secure`:

- immutable code: `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/releases/<release-id>`
- active code: `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/current` (atomic symlink)
- canonical plugin snapshot: `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/current/capability-roots/asg-os-plugins`
- DB, audit state, bearer/proxy env, exported registry: `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)`
- pinned SQLite: `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/runtime/sqlite` (3.53.3)
- systemd unit body: `/secure/systemd/asg-capability-mesh@.service`
- refresh unit/timer bodies: `/secure/systemd/asg-capability-mesh-refresh.*`
- `/etc/systemd/system/asg-capability-mesh*.{service,timer}`: symlinks only, no secrets

The SQLite build is configured for its immutable final release prefix and
staged with GNU `DESTDIR`; its ELF RUNPATH and `sqlite3.pc` prefix must never
reference a deleted build directory. Both installation and routine deployment
verify those embedded paths before changing the active runtime or worker pool.

Install the safe database runtime, bootstrap/migrate units once, then use the
routine immutable replica-first deployer:

```bash
sudo services/asg-capmesh/ops/install-safe-sqlite-runtime.sh
scripts/install-asg-capmesh-tailnet-service.sh
services/asg-capmesh/ops/deploy-capmesh.sh --dry-run
services/asg-capmesh/ops/deploy-capmesh.sh
```

The bootstrap installer pins the authoritative node (env CAPMESH_AUTHORITY_HOST) as `CAPMESH_NODE_ROLE=authoritative`,
preserves credentials, sets production fail-closed
security/readiness flags, migrates systemd to `current/.venv`, and enables the
15-minute transactional refresh. Routine deploys pin the fallback node (env CAPMESH_FALLBACK_HOST) as
`non-voting-raft`, preflight both hosts, reject
unsafe SQLite or insufficient CPU headroom, stage the replica first, rehearse
against a shadow DB, canary one worker, roll the pool, and restore the previous
release symlink if readiness fails.

Bootstrap and routine upgrades also provision one persistent Ed25519 signing
key at `CAPMESH_STATE_DIR (env, default ~/.capmesh/state)/signing/capmesh-ed25519.pem`, record its explicit
path in the mode-`0600` production environment file, and preserve it across
immutable code releases. The deploy rehearsal runs the entire candidate catalog
through source-integrity, metadata, retrieval, prompt-safety, risk, signature,
and provenance gates before activation. This is an internal ASG trust anchor;
it is not a Sigstore, SLSA, or transparency-log attestation.

Production provisioning also pins the standing superadmin install policy:

```bash
CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE=1
CAPMESH_SUPERADMIN_ACTOR=admin@example.com (env CAPMESH_SUPERADMIN_ACTOR)
```

`admin@example.com (env CAPMESH_SUPERADMIN_ACTOR)` and `co-admin@example.com (env CAPMESH_CO_SUPERADMIN_ACTOR)` are code-pinned, audited tenant
superadmins. The environment actor selects the identity used by unattended
catalog maintenance; either superadmin receives the same immediate-after-gates
behavior for installs made through an authenticated agent connection.

The same mode-`0600` environment records the immutable topology:

```bash
# the authoritative node (env CAPMESH_AUTHORITY_HOST)
CAPMESH_NODE_ROLE=authoritative
CAPMESH_AUTHORITY_URL=https://capmesh.example.local

# macOS and the fallback node (env CAPMESH_FALLBACK_HOST)
CAPMESH_NODE_ROLE=non-voting-raft
```

On every install or refresh, Capmesh evaluates the complete candidate catalog
and immediately publishes every passing capability under that audited identity.
This removes the second human approval step; it does not bypass a gate. Any
failure rolls back the entire ingest, so no partial or pending candidate becomes
active. The actor value is code-pinned and an unexpected value fails closed.

Every verified corporate email domain user is auto-provisioned private and shared stores
and may create, update, share, and submit capabilities they own. They may submit
to any active organization namespace or the tenant-wide everyone namespace;
publication still requires the complete promotion gate set and an authorized
approval. Users cannot publish directly merely by submitting.

Agent connections use split routing without split authority. `cap.search`,
`cap.load`, `cap.list`, and `cap.describe` may use the synchronized macOS or
the fallback node (env CAPMESH_FALLBACK_HOST) member for latency. Every `cap.call`, `cap.delegate`, and `cap.report`—the
surface used for installs, additions, approvals, upgrades, maintenance,
improvements, and third-party resync—is sent to
`https://capmesh.example.local/mcp` on the authoritative node (env CAPMESH_AUTHORITY_HOST). Unknown future tools default to
the authoritative node (env CAPMESH_AUTHORITY_HOST). If automatic routing is unavailable, `NOT_AUTHORITATIVE` includes the
machine-readable the authoritative node (env CAPMESH_AUTHORITY_HOST) MCP URL and never applies the write locally.

For durable ASGCode stages, `cap.report` returns a canonical Ed25519 receipt
under domain `ASGCODE:capmesh_report_receipt.v1\0`. The signed fields bind the
delegated task and agent, capability bundle and binding digests, exact outcome,
workflow/repository/worktree/base commit, upstream delegation, cpubox
provenance, validity interval, and nonce. Only the exact workflow receipt shape
is mutation-authoritative. Legacy titration telemetry remains a signed,
explicitly advisory audit receipt. A dedicated uniqueness table rejects a
second report for the same delegated task, including concurrent replays.

Each release also contains the exact tracked `plugins/` snapshot from the same
Git SHA as the service. Production `CAPMESH_ROOTS` begins at that immutable
snapshot, so code and canonical capabilities are rehearsed and activated
together. Runtime mirrors remain secondary roots; `/opt/asg-os/plugins` is not
a production source of truth and may be absent without losing authored caps.

Set these on both production nodes when enabling Microsoft sign-in and Entra
provisioning:

```bash
CAPMESH_TAILNET_BASE_URL=https://capmesh.example.local
CAPMESH_M365_CLIENT_ID=<Entra app client id>
CAPMESH_ENTRA_TENANT_ID=<CAPMESH_ENTRA_TENANT_ID>
CAPMESH_ENTRA_AUTHORITY=https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0
```

The redirect URI registered in Entra should be the tailnet URL:
`https://capmesh.example.local/oauth/callback`.

ASG's callback approach is nginx reverse proxy only for `/oauth/callback`.
Enable it during deployment with:

```bash
CAPMESH_INSTALL_NGINX_CALLBACK=1 \
CAPMESH_CALLBACK_SERVER_NAME=capmesh.example.local \
CAPMESH_CALLBACK_PROXY_TARGET=http://127.0.0.1:17778 \
scripts/install-asg-capmesh-tailnet-service.sh
```

The generated nginx vhost exact-matches `/oauth/callback` and returns `404` for
all other paths. Production is loopback-bound, so the callback target remains
local. It must remain reachable only through
Tailscale/Tailscale Services; do not enable Funnel or a public listener.

## Identity and Governance

The seven `cap.*` runtime tools remain the only LLM-facing tool surface. Admin
workflows are available through JSON CLI/API commands and through built-in
system capabilities discoverable via `cap.search` and callable with `cap.call`.

By default, discovered non-system capabilities are private drafts owned by
`admin@example.com (env CAPMESH_SUPERADMIN_ACTOR)` under:

```text
cap://user/asg/idn_75f310a283e0b72ebde0ee07/private/personal/...
```

The default org store is `the operator (env CAPMESH_ORG_NAME)` at
`cap://org/asg/agentic-secure-group-inc`. Additional org stores can be created
with `stores --action create --json '{"kind":"org","name":"Second Org","orgSlug":"second-org"}'`.
Capabilities move into org namespaces only through the explicit submit/approve
workflow.

### Approval lifecycle

Discovery initially creates non-system capabilities as private drafts. Outside
the production superadmin install path, an administrator must explicitly review
current content before approval. The production superadmin path performs that
same review automatically and atomically; it never waives governance. The
built-in `system.gates` capability offers:

- `verify-catalog`: read-only full-catalog gate rehearsal
- `review` and `review-batch`: approve only content that passes every gate
- `promotion.run`: execute and write back all promotion gates
- `status`: inspect current and stale review evidence

Every persisted approval records the content hash, review scope, reviewer,
evidence, and an Ed25519-signed provenance envelope. Re-ingest preserves an
approval only while the content hash is unchanged. A content change moves the
capability back to pending and invalidates signature, provenance, and risk
status until it is reviewed again.

For a controlled catalog upgrade:

1. Author or improve packages under `plugins/` and commit the reviewed change.
2. Run `capmesh ingest`, `capmesh check`, and `python -m capmesh.lifecycle_cli --db <db>`.
   Production ingest approves passing content immediately as `admin@example.com (env CAPMESH_SUPERADMIN_ACTOR)`;
   other environments require the explicit `lifecycle_cli --apply` command.
3. Confirm `remainingNonCompliant=0`, the expected catalog count, and the
   `capability.review.approved` audit actor before activation.
4. For org/all-user placement, run `submit`, `system.gates promotion.run`, then
   approve without a pending-gate override.
5. Deploy the immutable Git SHA with `ops/deploy-capmesh.sh`; the deployer
   rehearses the whole catalog and rolls back automatically on failure.

Key rotation is an explicit security event: replace the secure key, restart the
workers, and re-review affected capabilities so status is anchored to the new
key ID. Never copy the private key into Git or a runtime capability package.

CLI/API parity covers:

- `auth login --m365`
- `auth status`
- `auth refresh`
- `auth logout`
- `auth doctor`
- `help`
- `bootstrap`
- `onboard`
- `me`
- `stores`
- `namespaces`
- `share`
- `submit`
- `requests`
- `approve`
- `roles`
- `audit`
- `sync`
- `capabilities`

HTTP API endpoints mirror those commands under `/api/v1/*`. The service exposes
SCIM 2.0-compatible endpoints under `/scim/v2/*`, but those endpoints remain
tailnet-only. If Entra's cloud provisioning service cannot reach the tailnet
URL directly, use an internal relay/broker or Graph-delta reconciliation through
the ASG M365 gateway; do not make SCIM public just to satisfy push provisioning.
Graph/Teams lifecycle events use `/webhooks/graph` with stored `clientState`
hash validation. Live Microsoft Graph automation should be driven through the
ASG M365 gateway from the host, not by placing Graph credentials in capmesh.

The tailnet web console is available at `/console` on the same listener. It is
an operational console over the JSON API, not a separate public web app.

LLM/coder management path:

1. Use `cap.search "how do I add/update a capability"` or call `system.help`.
2. Use `cap.call` on `system.capabilities` with `dryRun=false` and one of:
   `template`, `draft.create`, `draft.update`, `draft.diff`, `validate`,
   `publish-private`, `share`, `submit`, or `prepare-pr`.
3. Private/shared drafts are written under the capmesh state directory and
   audited. Org namespace promotion goes through `submit` and approval, with
   `prepare-pr` producing a Git review artifact.

Automatic deployment paths:

- GitHub Actions: `.github/workflows/asg-capmesh-deploy.yml` runs on `main`
  changes to mesh, plugin, skill, agent, and ecosystem scripts. It joins the
  tailnet with a SHA-pinned Tailscale action, runs local gates, and invokes the
  replica-first immutable deployer for the fallback node (env CAPMESH_FALLBACK_HOST) then the authoritative node (env CAPMESH_AUTHORITY_HOST).
  Replica-first is a rollback-safety sequence only; the authoritative node (env CAPMESH_AUTHORITY_HOST) remains the sole
  authority before, during, and after deployment.
  Required repo secrets are either `TS_OAUTH_CLIENT_ID` plus `TS_AUDIENCE`,
  `TS_OAUTH_CLIENT_ID` plus `TS_OAUTH_SECRET`, or `TAILSCALE_AUTHKEY`.
  `TS_TAGS` selects the ephemeral runner tag.
- Local autoupdate: `scripts/asg-os-autoupdate.sh` calls
  `scripts/asg-capmesh-autodeploy.sh` when capability-affecting files
  fast-forward from `origin/main`.
- Remote refresh: `asg-capability-mesh-refresh.timer` transactionally refreshes
  installed capability roots every 15 minutes from the encrypted active release.

## Security Defaults

- Search does not load full instructions.
- Load is entitlement-aware and bounded by package path.
- Delegate writes a task envelope and does not bulk-load all agents.
- Call is dry-run by default and does not execute arbitrary package code.
- All router calls write sanitized JSONL audit records to `~/.capmesh/audit.jsonl`.
- Remote HTTP is tailnet-only, loopback-bound behind authenticated nginx and
  Tailscale Serve, and bearer-protected.
  OAuth 2.1, PKCE, resource indicators, protected resource metadata, and
  audience validation are represented in the control plane. All callbacks and
  provisioning URLs must resolve to Tailscale addresses only.
- Wildcard binds without `--interface tailscale0` are refused.
