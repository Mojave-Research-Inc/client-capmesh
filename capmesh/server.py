from __future__ import annotations

import hmac
import json
import logging
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

from . import scim
from .governance import (
    DEFAULT_TENANT,
    approve_request,
    auth_status,
    complete_google_session,
    complete_oauth_session,
    corporate_identity_id,
    create_namespace,
    create_oauth_session,
    create_share,
    create_store,
    current_user,
    email_is_allowed,
    ensure_identity_for_principal,
    evaluate_access,
    hash_secret,
    list_audit_events,
    list_namespaces,
    list_requests,
    list_roles,
    list_shares,
    list_stores,
    manage_capability,
    oauth_session_status,
    plan_graph_subscription,
    principal_from_bearer,
    revoke_capmesh_session,
    revoke_share,
    sync_summary,
    tag_to_group,
    validate_graph_client_state,
    validate_oauth_callback,
)
from .help import (
    bootstrap_payload,
    help_payload,
    onboarding_payload,
    protected_resource_metadata,
)
from .index import (
    SCHEMA_VERSION,
    ThreadLocalConnection,
    connect,
    coverage_report,
    init_db,
)
from .lifecycle import GATE_METRICS
from .manifest import configured_default_roots
from .metrics_export import render_prometheus
from .models import Principal
from .node_role import is_authoritative_node, topology_payload
from .observability import log_event
from .router import TOOL_NAMES, CapabilityRouter, tool_schemas
from .tracing import (
    SpanContext,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    parse_traceparent,
)

MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_MCP_PROTOCOL_VERSIONS = frozenset({MCP_PROTOCOL_VERSION, "2025-06-18", "2025-03-26"})

# CM-13 structured-logging slice: one redacted JSON line per handled HTTP
# request via the dependency-free observability helper. Best-effort only.
_OBS_LOGGER = logging.getLogger("capmesh.server")

# Per-boot proxy token for loopback proxy authentication.
# Only requests with the proxy token plus valid Tailscale headers (or verified_who)
# are trusted for identity assertion; raw loopback headers alone are denied.
# --interface tailscale0 with peer-IP-whois is the recommended production mode.
CAPMESH_PROXY_TOKEN: str | None = (
    os.environ.get("CAPMESH_TRUSTED_PROXY_TOKEN")
    or os.environ.get("CAPMESH_PROXY_TOKEN")
)
if CAPMESH_PROXY_TOKEN is None:
    from secrets import token_bytes
    CAPMESH_PROXY_TOKEN = token_bytes(32).hex()


def liveness_payload(con: Any, *, started_at: float, metrics: dict[str, int] | None = None) -> tuple[dict[str, Any], HTTPStatus]:
    """Return a cheap process/DB liveness signal.

    Liveness intentionally does not inspect catalog quality; a deficient index
    must remain alive long enough for operators to inspect it. Readiness below
    carries the semantic serving contract.
    """

    db_ok = False
    latency_ms = 0.0
    try:
        before = time.monotonic()
        con.execute("SELECT 1").fetchone()
        latency_ms = round((time.monotonic() - before) * 1000, 2)
        db_ok = True
    except sqlite3.Error:
        pass
    counters = metrics or {}
    payload = {
        "status": "ok" if db_ok else "failed",
        "service": "asg-capmesh",
        "check": "liveness",
        "db": {"ok": db_ok, "latencyMs": latency_ms},
        "uptimeSeconds": round(max(0.0, time.monotonic() - started_at), 1),
        "requestsTotal": int(counters.get("requests_total", 0)),
        "errorsTotal": int(counters.get("errors_total", 0)),
    }
    return payload, HTTPStatus.OK if db_ok else HTTPStatus.SERVICE_UNAVAILABLE


def _gate_runner_status() -> tuple[bool, dict[str, Any]]:
    """Return ``(ok, details)`` for the lifecycle gate runner wiring check.

    Lazy-imports :mod:`capmesh.lifecycle` so a broken gate runner never crashes
    readiness. Verifies that ``approve_catalog`` and ``review_capability`` are
    callable and that the gate set (``REQUIRED_GATES``) is non-empty.
    """
    try:
        from . import lifecycle  # local import: readiness must stay robust

        approve = getattr(lifecycle, "approve_catalog", None)
        review = getattr(lifecycle, "review_capability", None)
        gate_names = getattr(lifecycle, "REQUIRED_GATES", ())
        if not (callable(approve) and callable(review)):
            return False, {"errorType": "NotCallable"}
        if not gate_names:
            return False, {"errorType": "EmptyGateSet"}
        return True, {"gateCount": len(tuple(gate_names))}
    except Exception as exc:  # noqa: BLE001 -- readiness must never raise
        return False, {"errorType": type(exc).__name__}


def readiness_payload(con: Any, *, started_at: float, metrics: dict[str, int] | None = None) -> tuple[dict[str, Any], HTTPStatus]:
    """Validate that the catalog is safe to serve using read-only checks only."""

    checks: list[dict[str, Any]] = []
    cap_count: int | None = None
    distinct_name_count: int | None = None
    source_count: int | None = None
    generation = ""
    latest_raw = ""

    def record(name: str, ok: bool, **details: Any) -> None:
        checks.append({"name": name, "ok": bool(ok), **details})

    try:
        if os.environ.get("CAPMESH_READY_FULL_CHECK", "0").strip().lower() in {"1", "true", "yes"}:
            quick = con.execute("PRAGMA quick_check").fetchone()
            quick_value = str(quick[0] if quick is not None else "missing")
            record("sqliteQuickCheck", quick_value == "ok", value=quick_value)
        else:
            readable = con.execute("SELECT 1").fetchone()
            record("sqliteReadable", readable is not None)

        schema_row = con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        schema = int(schema_row[0]) if schema_row is not None else -1
        record("schemaVersion", schema == SCHEMA_VERSION, actual=schema, expected=SCHEMA_VERSION)

        cap_count = int(con.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0])
        distinct_name_count = int(
            con.execute("SELECT COUNT(DISTINCT name) FROM capabilities").fetchone()[0]
        )
        min_caps = _bounded_env_int("CAPMESH_READY_MIN_CAPABILITIES", 100, minimum=1, maximum=10_000_000)
        record("catalogMinimum", cap_count >= min_caps, actual=cap_count, minimum=min_caps)

        generation_row = con.execute(
            "SELECT value FROM meta WHERE key = 'last_successful_ingest_generation'"
        ).fetchone()
        generation = str(generation_row[0] or "") if generation_row is not None else ""
        record("catalogGeneration", generation.startswith("sha256:") and len(generation) == 71,
               generation=generation or None)

        fts_count = int(con.execute("SELECT COUNT(*) FROM capability_fts").fetchone()[0])
        record("ftsParity", fts_count == cap_count, capabilities=cap_count, ftsRows=fts_count)

        source_count = int(
            con.execute("SELECT COUNT(*) FROM capability_sources WHERE source_system != 'capmesh.system'").fetchone()[0]
        )
        min_sources = _bounded_env_int("CAPMESH_READY_MIN_SOURCES", 1, minimum=0, maximum=10_000_000)
        record("sourceMinimum", source_count >= min_sources, actual=source_count, minimum=min_sources)

        latest_row = con.execute(
            "SELECT value FROM meta WHERE key = 'last_successful_ingest_at'"
        ).fetchone()
        latest_raw = str(latest_row[0] or "") if latest_row is not None else ""
        max_age = _bounded_env_int("CAPMESH_READY_MAX_AGE_SECONDS", 21_600, minimum=60, maximum=31_536_000)
        age_seconds: float | None = None
        if latest_raw:
            latest = datetime.fromisoformat(latest_raw.replace("Z", "+00:00"))  # noqa: FURB162
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=UTC)
            age_seconds = max(0.0, (datetime.now(UTC) - latest).total_seconds())
        record(
            "catalogFreshness",
            age_seconds is not None and age_seconds <= max_age,
            latestSuccessfulIngest=latest_raw or None,
            ageSeconds=round(age_seconds, 1) if age_seconds is not None else None,
            maximumAgeSeconds=max_age,
        )

        canary = con.execute(
            """
            SELECT 1
            FROM capability_fts f
            JOIN capabilities c ON c.id = f.rowid AND c.uri = f.uri
            WHERE c.name = 'system.help' AND capability_fts MATCH 'help'
            LIMIT 1
            """
        ).fetchone()
        record("searchCanary", canary is not None, capability="system.help", query="help")

        vector_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'capability_vec'"
        ).fetchone()
        if vector_table is not None:
            vector_required = os.environ.get("CAPMESH_READY_REQUIRE_VECTOR", "").strip().lower() in {"1", "true", "yes"}
            # sqlite-vec may be installed even when a deployment intentionally
            # runs FTS-only. Enforce parity only when vector retrieval is an
            # explicit serving contract. Handler threads may also lack the
            # sqlite-vec module loaded on their thread-local connection, so do
            # not touch the virtual table for an FTS-only deployment.
            vector_count: int | None = None
            vector_ok = True
            if vector_required:
                try:
                    vector_count = int(con.execute("SELECT COUNT(*) FROM capability_vec").fetchone()[0])
                    vector_ok = vector_count == cap_count
                except sqlite3.Error:
                    vector_ok = False
            record(
                "vectorParity",
                vector_ok,
                capabilities=cap_count,
                vectorRows=vector_count,
                required=vector_required,
            )
    except (sqlite3.Error, TypeError, ValueError, OverflowError) as exc:
        record("readinessQuery", False, errorType=type(exc).__name__)

    # CM-13 observability: report whether the lifecycle gate runner is
    # importable and wired. This is a WARNING, not a readiness failure -- a
    # missing/broken gate runner must NOT take the server out of the load
    # balancer, because readiness is about being safe to serve the catalog
    # (read-only query surface), not about the write-side promotion path.
    # `ready` below is therefore gated only by the critical catalog checks
    # above; the gateRunner check is recorded for operator visibility but
    # excluded from the `all(check["ok"])` aggregate.
    _gr_ok, _gr_details = _gate_runner_status()
    record("gateRunner", _gr_ok, **_gr_details)

    # gateRunner is a WARNING (see comment above): exclude it from the
    # readiness aggregate so a broken gate runner does not flip overall status.
    critical = [c for c in checks if c.get("name") != "gateRunner"]
    ready = bool(critical) and all(check["ok"] for check in critical)
    counters = metrics or {}
    catalog = {
        "capabilityCount": cap_count,
        "distinctNameCount": distinct_name_count,
        "sourceCount": source_count,
        "generation": generation or None,
        "latestSuccessfulIngest": latest_raw or None,
    }
    payload = {
        "status": "ready" if ready else "not_ready",
        "service": "asg-capmesh",
        "check": "readiness",
        "checks": checks,
        "uptimeSeconds": round(max(0.0, time.monotonic() - started_at), 1),
        "requestsTotal": int(counters.get("requests_total", 0)),
        "errorsTotal": int(counters.get("errors_total", 0)),
        "topology": topology_payload(),
        "catalog": catalog,
    }
    return payload, HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE


def _prometheus_labels(**labels: str) -> str:
    parts = [f'{key}="{value}"' for key, value in sorted(labels.items()) if value]
    return "{" + ",".join(parts) + "}" if parts else ""


def prometheus_metrics_payload(
    metrics: dict[str, int],
    *,
    started_at: float,
    catalog: dict[str, Any] | None = None,
    worker_port: int | None = None,
) -> str:
    """Render in-process counters plus optional catalog gauges for multi-worker scrapes."""

    worker = str(worker_port or os.environ.get("CAPMESH_WORKER_PORT") or "")
    label = _prometheus_labels(worker=worker) if worker else ""
    lines = [
        "# HELP capmesh_uptime_seconds Seconds since this worker started.",
        "# TYPE capmesh_uptime_seconds gauge",
        f"capmesh_uptime_seconds{label} {max(0.0, time.monotonic() - started_at):.3f}",
    ]
    for name, value in sorted(metrics.items()):
        metric = f"capmesh_{name}"
        lines.extend(
            (
                f"# HELP {metric} Capmesh worker counter {name}.",
                f"# TYPE {metric} counter",
                f"{metric}{label} {int(value)}",
            )
        )
    if catalog:
        caps = int(catalog.get("capabilityCount") or 0)
        sources = int(catalog.get("sourceCount") or 0)
        ready = 1 if catalog.get("ready") else 0
        gen = str(catalog.get("generation") or "")[:16]
        gen_label = (
            _prometheus_labels(worker=worker, generation=gen)
            if worker
            else _prometheus_labels(generation=gen)
        )
        lines.extend(
            (
                "# HELP capmesh_catalog_capabilities Catalog capability row count.",
                "# TYPE capmesh_catalog_capabilities gauge",
                f"capmesh_catalog_capabilities{label} {caps}",
                "# HELP capmesh_catalog_sources Indexed source row count.",
                "# TYPE capmesh_catalog_sources gauge",
                f"capmesh_catalog_sources{label} {sources}",
                "# HELP capmesh_ready 1 when this worker's readiness checks pass.",
                "# TYPE capmesh_ready gauge",
                f"capmesh_ready{label} {ready}",
                "# HELP capmesh_catalog_generation_info Catalog generation fingerprint.",
                "# TYPE capmesh_catalog_generation_info gauge",
                f"capmesh_catalog_generation_info{gen_label} 1",
            )
        )
    return "\n".join(lines) + "\n"


def metrics_token_matches(supplied: str, *, service_token: str | None, metrics_token: str | None) -> bool:
    """True when the bearer is the service token or a dedicated scrape token."""

    if not supplied:
        return False
    if service_token and hmac.compare_digest(supplied, service_token):
        return True
    return bool(metrics_token and hmac.compare_digest(supplied, metrics_token))


def bind_transport_principal(arguments: Any, principal: Principal) -> dict[str, Any]:
    """Replace every caller-supplied principal at the HTTP trust boundary."""

    bound = dict(arguments) if isinstance(arguments, dict) else {}
    bound["principal"] = principal.to_dict()
    return bound


def stream_metrics(counters: dict[str, int], started_at: float) -> str:
    """Return a JSON object with stdio stream metrics for operator observability."""

    return json.dumps({
        "service": "asg-capmesh",
        "check": "stream_metrics",
        "requestsTotal": int(counters.get("requests_total", 0)),
        "errorsTotal": int(counters.get("errors_total", 0)),
        "routerErrorsTotal": int(counters.get("router_errors_total", 0)),
        "uptimeSeconds": round(max(0.0, time.monotonic() - started_at), 1),
    }, sort_keys=True)


def serve_stdio(db_path: str | Path, roots: tuple[str, ...] | None = None) -> None:
    """Serve a compact MCP-compatible JSON-RPC surface over newline-delimited stdio.

    This intentionally logs only to stderr. It supports initialize, tools/list,
    and tools/call, which is enough for local smoke tests and adapter clients.
    """

    con = connect(db_path)
    init_db(con)
    router = CapabilityRouter(con, roots=roots or configured_default_roots())
    started_at = time.monotonic()
    counters: dict[str, int] = {
        "requests_total": 0,
        "errors_total": 0,
        "router_errors_total": 0,
    }

    def _emit_metrics() -> None:
        sys.stderr.write("[asg-capmesh] " + stream_metrics(counters, started_at) + "\n")

    sys.stderr.write("[asg-capmesh] ready\n")

    import atexit

    atexit.register(_emit_metrics)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            counters["requests_total"] += 1
            try:
                request = json.loads(line)
                response = handle_jsonrpc(router, request)
                is_error = response.get("error") is not None
                if is_error:
                    counters["errors_total"] += 1
                    err_msg = str(response.get("error", ""))
                    if "router" in err_msg.lower():
                        counters["router_errors_total"] += 1
            except json.JSONDecodeError as exc:
                counters["errors_total"] += 1
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}
            sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        _emit_metrics()
        con.close()


def handle_jsonrpc(
    router: CapabilityRouter,
    request: dict[str, Any],
    *,
    http_request_id: str | None = None,
    traceparent: str | None = None,
) -> dict[str, Any]:
    # CM-13: ``http_request_id`` is the upstream HTTP X-Request-Id threaded from
    # the HTTP caller (server.py /mcp POST). It is distinct from ``request_id``
    # below (the JSON-RPC message id) and is passed to ``router.call`` so the
    # structured dispatch log correlates to the HTTP request. None/stdio callers
    # omit it; the router then generates a fresh uuid.
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        requested_version = str((request.get("params") or {}).get("protocolVersion") or "")
        negotiated_version = requested_version if requested_version in SUPPORTED_MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": negotiated_version,
                "serverInfo": {"name": "asg-capability-mesh", "version": "0.1.0"},
                "capabilities": {"tools": {}},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tool_schemas()}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or name not in TOOL_NAMES:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": f"Unknown tool: {name}",
                    "data": {"tool": name, "validTools": list(TOOL_NAMES)},
                },
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": router.call(str(name), arguments, request_id=http_request_id, traceparent=traceparent)}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def http_status_for_tool_result(result: dict[str, Any]) -> HTTPStatus:
    """Map the REST compatibility adapters' typed tool errors to HTTP status.

    Native MCP requests still return HTTP 200 with ``isError=true`` for tool
    execution failures.  The mapping is only for ``/tools/call``, ``/cap/call``,
    and ``/cap/search``, where callers explicitly depend on HTTP semantics.
    """

    if not result.get("isError"):
        return HTTPStatus.OK
    structured = result.get("structuredContent")
    error_payload = structured.get("error") if isinstance(structured, dict) else None
    code = str(error_payload.get("code") or "") if isinstance(error_payload, dict) else ""
    if code in {"FORBIDDEN", "INSUFFICIENT_SCOPE"}:
        return HTTPStatus.FORBIDDEN
    if code in {"TOOL_NOT_FOUND", "CAPABILITY_NOT_FOUND", "RESOURCE_NOT_FOUND"}:
        return HTTPStatus.NOT_FOUND
    if code == "NOT_AUTHORITATIVE":
        return HTTPStatus.CONFLICT
    if code == "RATE_LIMITED":
        return HTTPStatus.TOO_MANY_REQUESTS
    if code == "INTERNAL_ERROR":
        return HTTPStatus.INTERNAL_SERVER_ERROR
    return HTTPStatus.BAD_REQUEST


def _validate_scim_members_same_tenant(con: Any, members: Any, tenant_id: str) -> tuple[bool, str]:
    """Validate SCIM group member ``value`` IDs resolve to a same-tenant identity.

    IMPROVEMENT-PLAN CM-05b: a SCIM group member referencing a non-existent or
    cross-tenant identity must be rejected before insert, not silently dropped
    into ``group_members`` with a dangling foreign key. Each member ``value``
    is resolved against the identities table by ``id`` (the SCIM member value
    convention used by ``upsert_user``/``upsert_group``) OR by ``user_name``
    (login), both scoped to ``tenant_id``. Returns ``(True, "")`` when every
    member resolves; otherwise ``(False, reason)`` naming the offending values
    so the caller can return a 400 SCIM error envelope without inserting.
    """
    if not isinstance(members, list):
        return True, ""
    offenders: list[str] = []
    for member in members:
        if not isinstance(member, dict):
            continue
        value = str(member.get("value") or "").strip()
        if not value:
            continue
        row = con.execute(
            "SELECT 1 FROM identities WHERE (id = ? OR user_name = ?) AND tenant_id = ?",
            (value, value, tenant_id),
        ).fetchone()
        if row is None:
            offenders.append(value)
    if offenders:
        return (
            False,
            "SCIM Group members must resolve to an existing identity in the same tenant: "
            + ", ".join(offenders),
        )
    return True, ""


def render_metrics_endpoint() -> tuple[str, int]:
    """Render ``GATE_METRICS`` to Prometheus text, best-effort.

    Returns ``(body, status)``: the Prometheus text exposition string for the
    module-level ``GATE_METRICS`` registry (``""`` for an empty registry) with
    HTTP 200, or a minimal text body with HTTP 500 on any rendering failure so a
    scrape never crashes the server. ``GATE_METRICS`` is referenced via the
    imported symbol so tests can patch ``capmesh.server.GATE_METRICS`` or
    ``capmesh.server.render_prometheus`` to exercise the failure path.
    """

    try:
        return render_prometheus(GATE_METRICS), int(HTTPStatus.OK)
    except Exception:  # noqa: BLE001,S110
        pass
    return "capmesh_metrics_render_failed 1\n", int(HTTPStatus.INTERNAL_SERVER_ERROR)


def serve_http(
    db_path: str | Path,
    *,
    host: str,
    port: int,
    interface: str | None = None,
    roots: tuple[str, ...] | None = None,
) -> None:
    """Serve Capability Mesh over tailnet-scoped HTTP.

    This is intentionally dependency-free. Prefer `interface=tailscale0` for
    shared deployments so dynamic Tailscale IP changes do not require config
    rewrites. Bind 127.0.0.1 only when a tailnet-scoped reverse proxy is in
    front of the service.
    """

    bind_interface = validate_bind_interface(interface) if interface else None
    if host in {"0.0.0.0", "::"} and not bind_interface:
        raise SystemExit("Refusing wildcard bind. Set --interface tailscale0, --host to a Tailscale IP, or --host 127.0.0.1.")

    # Each ThreadingHTTPServer handler thread gets its own dedicated sqlite3
    # connection (lazily created on first use) rather than sharing a single
    # connection object across threads -- see ThreadLocalConnection docstring
    # in index.py for the regression this fixes.
    con = ThreadLocalConnection(db_path, check_same_thread=False)
    init_db(con)
    router = CapabilityRouter(con, roots=roots or configured_default_roots())
    state_lock = threading.RLock()
    # Dedicated lock for the shared ``metrics`` dict only. Read-only request
    # paths (read-only /mcp dispatch, GET /cap/search, health probes) no longer
    # take state_lock, so the per-request metrics increments/snapshots are
    # guarded by this short, contention-light lock instead of the global one.
    _metrics_lock = threading.Lock()
    token = os.environ.get("CAPMESH_BEARER_TOKEN")
    tailnet_base_url = os.environ.get("CAPMESH_TAILNET_BASE_URL", f"http://{host}:{port}")
    entra_authority = os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/v2.0")
    resource_id = os.environ.get("CAPMESH_RESOURCE", f"{tailnet_base_url.rstrip('/')}/mcp")
    roots_for_checks = roots or configured_default_roots()

    # Metrics counters (thread-safe via state_lock)
    metrics: dict[str, int] = {
        "requests_total": 0,
        "errors_total": 0,
        "router_errors_total": 0,
        "searches_total": 0,
        "loads_total": 0,
        "calls_total": 0,
        "auth_failures_total": 0,
    }

    start_time = time.monotonic()

    class Handler(BaseHTTPRequestHandler):
        server_version = "ASGCapabilityMesh/0.1"
        # HTTP/1.1 enables persistent (keep-alive) connections so a single
        # client TCP connection can carry many pipelined/sequential requests
        # instead of one socket per request. Prerequisite: every response must
        # send an accurate Content-Length (or close the connection). All
        # write_json/write_text/write_html/write_empty/write_unauthorized paths
        # set Content-Length via _send_common_headers, and the few hand-rolled
        # responses (405 /mcp, Graph webhook validationToken, Google redirect)
        # send Content-Length too — verified by the keepalive prerequisite
        # audit. Without this, BaseHTTPRequestHandler defaults to HTTP/1.0 and
        # forces connection: close on every response (one socket/request).
        protocol_version = "HTTP/1.1"

        def finish(self) -> None:
            try:
                super().finish()
            finally:
                # ThreadingHTTPServer creates short-lived handler threads. Do
                # not retain one SQLite connection/WAL reader per request.
                con.close_current()

        def log_request(self, *args: Any, **kwargs: Any) -> None:
            # Suppress default noisy access log; structured logging is elsewhere
            pass

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            # CM-13: structured best-effort JSON log line for the HTTP request.
            # Failure here must never break request handling or change status.
            try:
                log_event(
                    _OBS_LOGGER,
                    "http.request",
                    request_id=self._http_request_id(),
                    method="GET",
                    path=parsed.path,
                )
            except Exception:  # noqa: BLE001,S110
                pass
            if parsed.path == "/metrics":
                # CM-13: public Prometheus scrape endpoint. Renders the gate
                # runner's ``GATE_METRICS`` registry via ``render_prometheus`` so a
                # Prometheus scraper (which sends no service token) can read
                # ``capmesh_gate_*`` counters. Exempt from service-token auth and
                # from the mutating-route gate: this is a read-only GET. Rendering
                # is best-effort; a metrics failure must never crash the server.
                body, status = render_metrics_endpoint()
                self.write_text(body, status=status, content_type="text/plain; version=0.0.4")
                return
            if parsed.path in {"/health/live", "/healthz"}:
                # liveness_payload only touches the thread-local con (WAL read)
                # and the metrics dict; the metrics snapshot needs _metrics_lock,
                # not the global state_lock, so a slow health probe never
                # serializes behind (or blocks) mutating requests.
                with _metrics_lock:
                    snapshot = dict(metrics)
                payload, status = liveness_payload(con, started_at=start_time, metrics=snapshot)
                self.write_json(payload, status=status)
                return
            if parsed.path in {"/health", "/health/ready", "/readyz"}:
                # readiness_payload runs read-only checks on the thread-local
                # con (WAL + busy_timeout) and reads the metrics snapshot.
                # Neither needs state_lock; only the metrics snapshot takes the
                # short _metrics_lock. /readyz is an alias gateway/LB readiness
                # probes commonly target.
                with _metrics_lock:
                    snapshot = dict(metrics)
                payload, status = readiness_payload(con, started_at=start_time, metrics=snapshot)
                self.write_json(payload, status=status)
                return
            if parsed.path == "/.well-known/oauth-protected-resource":
                self.write_json(protected_resource_metadata(base_url=tailnet_base_url, authority=entra_authority, resource=resource_id))
                return
            if parsed.path == "/.well-known/oauth-protected-resource/mcp":
                self.write_json(protected_resource_metadata(base_url=tailnet_base_url, authority=entra_authority, resource=resource_id))
                return
            if parsed.path == "/mcp/sdk":
                # SDK-compatible MCP endpoint: uses snake_case tool names instead
                # of dotted cap.* names, for MCP SDK clients that expect
                # standard naming conventions.
                from .mcp_sdk_wrapper import build_initialize_response, build_tools_list
                if body.get("method") == "initialize":
                    self.write_json({"jsonrpc": "2.0", "id": body.get("id"), "result": build_initialize_response()})
                    return
                if body.get("method") == "tools/list":
                    self.write_json({"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": build_tools_list()}})
                    return
                # For tools/call, route through the SDK wrapper
                if body.get("method") == "tools/call":
                    from .mcp_sdk_wrapper import route_sdk_call
                    params = body.get("params", {})
                    sdk_name = str(params.get("name") or "")
                    sdk_args = params.get("arguments", {})
                    # Resolve the caller's principal for authorization
                    sdk_principal = self.principal()
                    # Check auth: read-only methods can use token auth,
                    # mutating methods need full authorization
                    sdk_dotted = None
                    try:
                        from .mcp_sdk_wrapper import to_dotted_name
                        sdk_dotted = to_dotted_name(sdk_name)
                    except Exception:  # noqa: BLE001, S110
                        pass
                    sdk_read_only = sdk_dotted in {"cap.search", "cap.load", "cap.list", "cap.describe"}
                    if sdk_read_only:
                        if not self.authorized(token):
                            return
                    elif not self.mutating_route_authorized():
                        return
                    result = route_sdk_call(sdk_name, sdk_args, router, principal=sdk_principal)
                    self.write_json({"jsonrpc": "2.0", "id": body.get("id"), "result": result})
                    return
                self.write_json({"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "Method not found"}}, status=400)
                return
            if parsed.path == "/mcp":
                header_error = validate_mcp_http_headers(
                    origin=self.headers.get("Origin"),
                    protocol_version=self.headers.get("MCP-Protocol-Version"),
                    base_url=tailnet_base_url,
                )
                if header_error:
                    status, code, message = header_error
                    self.write_json(jsonrpc_transport_error(code, message), status=status)
                    return
                self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
                self.send_header("Allow", "POST")
                self.send_header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parsed.path in {"/", "/bootstrap", "/api/v1/bootstrap", "/.well-known/capmesh"}:
                query = parse_qs(parsed.query)
                self.write_json(
                    bootstrap_payload(
                        base_url=tailnet_base_url,
                        authority=entra_authority,
                        resource=resource_id,
                        client=first(query, "client") or "all",
                        direct=(first(query, "direct") or "").lower() in {"1", "true", "yes"},
                        tenant=first(query, "tenant") or DEFAULT_TENANT,
                    )
                )
                return
            if parsed.path == "/oauth/callback":
                # NOTE: handle_oauth_callback -> complete_oauth_callback performs
                # outbound network I/O to the Microsoft Entra token endpoint
                # (exchange_authorization_code -> post_form -> urlopen, up to
                # CAPMESH_AUTH_HTTP_TIMEOUT seconds). That call must never be made
                # while holding state_lock, which also serializes every other API
                # request in this process — see the matching note on the M365
                # device-code path above. state_lock is acquired internally, only
                # around the brief DB read/write.
                self.handle_oauth_callback(parsed)
                return
            if parsed.path == "/api/v1/auth/google/start":
                with state_lock:
                    self.handle_google_start(parsed, tailnet_base_url)
                return
            if parsed.path == "/api/v1/auth/google/callback":
                # NOTE: handle_google_callback performs outbound network I/O to
                # Google's OAuth token endpoint (exchange_code_for_tokens) and to
                # Google's public-cert/JWKS endpoint (verify_google_id_token, via
                # the google-auth SDK). Same rule as /oauth/callback above: never
                # hold state_lock across that I/O. state_lock is acquired
                # internally, only around the brief DB read/write.
                self.handle_google_callback(parsed, tailnet_base_url)
                return
            if parsed.path in {"/help", "/api/v1/help"}:
                topic = first(parse_qs(parsed.query), "topic")
                self.write_json(help_payload(topic, base_url=tailnet_base_url))
                return
            if parsed.path in {"/dashboard", "/api/v1/dashboard"}:
                try:
                    from .dashboard import capability_volume_dashboard
                    ident = self.principal()
                    if ident is None:
                        self.write_json({"error": "authentication required"}, status=401)
                        return
                    with state_lock:
                        data = capability_volume_dashboard(con, tenant_id=ident.tenant_id or DEFAULT_TENANT)
                    self.write_json(data)
                except Exception as exc:  # noqa: BLE001
                    self.write_json({"error": str(exc)}, status=500)
                return
            if parsed.path in {"/onboard", "/api/v1/onboarding"}:
                query = parse_qs(parsed.query)
                self.write_json(
                    onboarding_payload(
                        base_url=tailnet_base_url,
                        client=first(query, "client") or "all",
                        direct=(first(query, "direct") or "").lower() in {"1", "true", "yes"},
                        tenant=first(query, "tenant") or DEFAULT_TENANT,
                    )
                )
                return
            if parsed.path == "/login":
                query = parse_qs(parsed.query)
                self.write_html(login_html(tailnet_base_url, first(query, "tenant") or DEFAULT_TENANT))
                return
            if parsed.path.startswith("/api/v1/onboarding/status/"):
                session_id = parsed.path.rsplit("/", 1)[-1]
                try:
                    self.write_json(oauth_session_status(con, session_id, consume_tokens=False))
                except ValueError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                return
            if parsed.path in {"/install", "/install.sh", "/install.ps1"}:
                self.handle_install(parsed, tailnet_base_url)
                return
            if parsed.path == "/api/v1/whoami":
                # Public, no-bearer: resolves the caller's tailnet identity (serve
                # identity header over loopback, or peer-IP whois) and auto-provisions
                # their namespace + all-user grant on first contact. Magic-install priming.
                # self.principal() can shell out to `tailscale whois` (subprocess,
                # up to 5s); resolve it BEFORE acquiring state_lock so a slow/stuck
                # whois never wedges every other concurrent request.
                ident = self.principal()
                # Tailscale Serve callers have a verified identity without a
                # bearer. Same-host callers do not: an authenticated proxy hop
                # only proves that nginx forwarded the request, not which local
                # service sent it. Require the authoritative node service bearer instead of
                # silently turning any loopback process into capmesh-service.
                # tailnet-guest is the unauthenticated fallback principal
                # (authenticated=True but no real identity); it must NOT pass the
                # public identity endpoint, or a spoofed loopback header leaks the
                # guest identity document. Reject it the same as unauthenticated.
                if not ident.authenticated or ident.subject == "tailnet-guest":
                    self.write_unauthorized()
                    return
                with state_lock:
                    self.write_json(current_user(con, ident))
                return
            if not self.authorized(token):
                return
            if parsed.path.startswith("/scim/v2/"):
                # Resolve principal (may shell out to `tailscale whois`) BEFORE
                # taking state_lock — see /api/v1/whoami comment above. The
                # whois subprocess must never run while holding the global lock.
                ident = self.principal()
                with state_lock:
                    self.handle_scim_get(parsed, tailnet_base_url, principal=ident)
                return
            if parsed.path.startswith("/api/v1/"):
                # Resolve principal before state_lock — see /api/v1/whoami.
                ident = self.principal()
                with state_lock:
                    self.handle_api_get(parsed, principal=ident)
                return
            if parsed.path == "/console":
                self.write_html(console_html())
                return
            if parsed.path == "/tools/list":
                self.write_json({"tools": tool_schemas()})
                return
            if parsed.path == "/cap/check":
                with state_lock:
                    self.write_json(coverage_report(con, roots_for_checks))
                return
            if parsed.path == "/cap/search":
                query = parse_qs(parsed.query)
                # Resolve principal (may shell out to `tailscale whois`) before
                # any dispatch — see /api/v1/whoami comment above.
                principal_dict = self.principal().to_dict()
                result: dict[str, Any] = {}
                try:
                    # cap.search is a lock-free router read on the thread-local
                    # connection (WAL + busy_timeout); run it UNLOCKED so 100s of
                    # concurrent searches don't serialize on the global lock.
                    # The post-call rollback is per-connection (safe).
                    result = router.call(
                        "cap.search",
                        {
                            "query": first(query, "q") or first(query, "query") or "",
                            "k": int(first(query, "k") or 10),
                            "type": first(query, "type"),
                            "principal": principal_dict,
                        },
                        request_id=self._http_request_id(),
                        traceparent=self._traceparent_str(),
                    )
                finally:
                    # Release any implicit write transaction opened by vec0
                    # KNN (temp/shadow table writes) that is never committed.
                    if con.in_transaction:
                        con.rollback()
                self.write_json(result.get("structuredContent", result), status=http_status_for_tool_result(result))
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            with _metrics_lock:
                metrics["requests_total"] += 1
            # CM-13: structured best-effort JSON log line for the HTTP request.
            # Failure here must never break request handling or change status.
            try:
                log_event(
                    _OBS_LOGGER,
                    "http.request",
                    request_id=self._http_request_id(),
                    method="POST",
                    path=urlparse(self.path).path,
                )
            except Exception:  # noqa: BLE001,S110
                pass
            body = self.read_json()
            if body is None:
                with _metrics_lock:
                    metrics["errors_total"] += 1
                return
            parsed = urlparse(self.path)
            if parsed.path == "/mcp":
                header_error = validate_mcp_http_headers(
                    origin=self.headers.get("Origin"),
                    protocol_version=self.headers.get("MCP-Protocol-Version"),
                    base_url=tailnet_base_url,
                    content_type=self.headers.get("Content-Type"),
                    accept=self.headers.get("Accept"),
                )
                if header_error:
                    status, code, message = header_error
                    with _metrics_lock:
                        metrics["errors_total"] += 1
                    self.write_json(jsonrpc_transport_error(code, message), status=status)
                    return
            if parsed.path not in {"/mcp", "/tools/call", "/cap/call"} and not is_authoritative_node():
                self.write_not_authoritative()
                return
            if parsed.path == "/oauth/callback":
                # See the GET /oauth/callback note above: never hold state_lock
                # across the Entra token-exchange network call.
                self.handle_oauth_callback(parsed)
                return
            if parsed.path in {
                "/api/v1/onboarding/start",
                "/api/v1/bootstrap/start",
                "/api/v1/auth/m365/start",
                "/api/v1/auth/m365/device-code",
                "/api/v1/auth/m365/poll",
            }:
                # NOTE: handle_public_auth_post performs outbound network I/O
                # to the Microsoft Entra token/devicecode endpoints (via
                # post_form -> urlopen). That call must never be made while
                # holding the global state_lock, since state_lock also
                # serializes every other API request in this process. A slow
                # or stuck Microsoft round trip would otherwise wedge every
                # other concurrent request behind it indefinitely. SQLite's
                # own busy_timeout (set via check_same_thread=False) already
                # protects the DB writes inside this call path.
                self.handle_public_auth_post(parsed, body, tailnet_base_url)
                return
            mcp_method = str(body.get("method") or "") if parsed.path == "/mcp" else ""
            mcp_params = body.get("params") if isinstance(body.get("params"), dict) else {}
            mcp_tool = str(mcp_params.get("name") or "") if mcp_method == "tools/call" else ""
            mcp_read_only = (
                parsed.path == "/mcp"
                and (
                    mcp_method in {"initialize", "notifications/initialized", "tools/list", "ping"}
                    or mcp_tool in {"cap.search", "cap.load", "cap.list", "cap.describe"}
                )
            )
            if mcp_read_only:
                if not self.authorized(token):
                    return
            elif not self.mutating_route_authorized():
                return
            if parsed.path.startswith("/scim/v2/"):
                # Resolve principal before state_lock — see /api/v1/whoami.
                ident = self.principal()
                with state_lock:
                    # Wire scim_sync module for group entitlement sync.
                    try:
                        from .scim_sync import ensure_scim_tables
                        ensure_scim_tables(con)
                    except Exception:  # noqa: BLE001, S110
                        pass
                    self.handle_scim_write(parsed, body, principal=ident)
                return
            if parsed.path.startswith("/api/v1/"):
                # Resolve principal before state_lock — see /api/v1/whoami.
                ident = self.principal()
                with state_lock:
                    self.handle_api_post(parsed, body, tailnet_base_url, principal=ident)
                return
            if parsed.path == "/webhooks/graph":
                # handle_graph_webhook does not resolve a principal (no whois),
                # so it can safely run under state_lock with no subprocess wedge.
                with state_lock:
                    self.handle_graph_webhook(parsed, body)
                return
            if parsed.path == "/mcp":
                if body.get("method") == "tools/call":
                    params = body.get("params")
                    if not isinstance(params, dict):
                        params = {}
                        body["params"] = params
                    params["arguments"] = bind_transport_principal(
                        params.get("arguments"), self.principal()
                    )
                response: dict[str, Any] = {}
                try:
                    # Read-only MCP methods (initialize, notifications/initialized,
                    # tools/list, ping, and tools/call of cap.search/cap.load/
                    # cap.list/cap.describe) dispatch UNLOCKED: router reads are
                    # lock-free (router.py has zero threading primitives) and run on
                    # the thread-local connection (WAL + busy_timeout), so they are
                    # safe to run concurrently. The post-call rollback is per-
                    # connection (safe). Mutating tools/call (cap.call/cap.delegate/
                    # cap.approve/...) still serializes under state_lock so the WAL
                    # write path stays correct; narrowing that is deferred.
                    if mcp_read_only:
                        response = handle_jsonrpc(
                            router,
                            body,
                            http_request_id=self._http_request_id(),
                            traceparent=self._traceparent_str(),
                        )
                    else:
                        with state_lock:
                            response = handle_jsonrpc(
                                router,
                                body,
                                http_request_id=self._http_request_id(),
                                traceparent=self._traceparent_str(),
                            )
                finally:
                    if con.in_transaction:
                        con.rollback()
                is_error = response.get("isError", False)
                with _metrics_lock:
                    if is_error:
                        metrics["errors_total"] += 1
                        if "router" in str(response.get("error", "")):
                            metrics["router_errors_total"] += 1
                    metrics["requests_total"] += 0  # already counted at entry
                if "id" not in body:
                    self.write_empty(status=HTTPStatus.ACCEPTED)
                else:
                    self.write_json(response)
                return
            if parsed.path in {"/tools/call", "/cap/call"}:
                name = str(body.get("name") or body.get("tool") or "")
                arguments = bind_transport_principal(
                    body.get("arguments") or body.get("params"), self.principal()
                )
                result: dict[str, Any] = {}
                try:
                    with state_lock:
                        result = router.call(
                            name,
                            arguments,
                            request_id=self._http_request_id(),
                            traceparent=self._traceparent_str(),
                        )
                finally:
                    if con.in_transaction:
                        con.rollback()
                is_error = result.get("isError", False)
                with _metrics_lock:
                    if is_error:
                        metrics["errors_total"] += 1
                    metrics["calls_total"] += 1  # call attempted
                self.write_json(result, status=http_status_for_tool_result(result))
                return
            with _metrics_lock:
                metrics["errors_total"] += 1
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def do_PATCH(self) -> None:
            if not self.mutating_route_authorized():
                return
            if not is_authoritative_node():
                self.write_not_authoritative()
                return
            parsed = urlparse(self.path)
            body = self.read_json()
            if parsed.path.startswith("/api/v1/capabilities/drafts/"):
                identifier = parsed.path.removeprefix("/api/v1/capabilities/drafts/").strip("/")
                payload = {**body, "action": "draft.update", "capabilityUri": identifier}
                # Resolve principal (may shell out to `tailscale whois`) before
                # taking state_lock — see /api/v1/whoami comment above.
                ident = self.principal()
                try:
                    with state_lock:
                        self.write_json(manage_capability(con, ident, payload))
                except ValueError as exc:
                    self.write_json({"error": {"code": "VALIDATION_ERROR", "message": str(exc)}}, status=HTTPStatus.BAD_REQUEST)
                except PermissionError as exc:
                    self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def do_PUT(self) -> None:
            if not self.mutating_route_authorized():
                return
            if not is_authoritative_node():
                self.write_not_authoritative()
                return
            parsed = urlparse(self.path)
            body = self.read_json()
            if parsed.path.startswith("/scim/v2/"):
                # Resolve principal before state_lock — see /api/v1/whoami.
                ident = self.principal()
                with state_lock:
                    self.handle_scim_write(parsed, body, principal=ident)
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def do_DELETE(self) -> None:
            if not self.mutating_route_authorized():
                return
            if not is_authoritative_node():
                self.write_not_authoritative()
                return
            parsed = urlparse(self.path)
            if parsed.path.startswith("/scim/v2/"):
                # Resolve principal before state_lock — see /api/v1/whoami.
                ident = self.principal()
                with state_lock:
                    self.handle_scim_delete(parsed, principal=ident)
                return
            if parsed.path.startswith("/api/v1/share/"):
                share_id = parsed.path.rsplit("/", 1)[-1]
                # Resolve principal (may shell out to `tailscale whois`) before
                # taking state_lock — see /api/v1/whoami comment above.
                ident = self.principal()
                try:
                    with state_lock:
                        self.write_json(revoke_share(con, ident, share_id))
                except ValueError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                except PermissionError as exc:
                    self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("[asg-capmesh-http] " + (fmt % args) + "\n")

        def write_not_authoritative(self) -> None:
            self.write_json(
                {
                    "error": {
                        "code": "NOT_AUTHORITATIVE",
                        "message": "Capability Mesh writes are served only by the authoritative node.",
                        "details": topology_payload(),
                    }
                },
                status=HTTPStatus.CONFLICT,
            )

        def read_json(self) -> dict[str, Any] | None:
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                self.write_json({"error": {"code": "BAD_CONTENT_LENGTH", "message": "Content-Length must be an integer."}}, status=HTTPStatus.BAD_REQUEST)
                return None
            if length > 1_000_000:
                self.write_json({"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Payload exceeds 1MB."}}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return None
            self.connection.settimeout(30)
            raw = self.rfile.read(length) if length else b"{}"
            self.connection.settimeout(None)
            try:
                value = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                self.write_json({"error": {"code": "BAD_JSON", "message": "Request body must be JSON."}}, status=HTTPStatus.BAD_REQUEST)
                return None
            if not isinstance(value, dict):
                self.write_json({"error": {"code": "BAD_JSON", "message": "Request body must be a JSON object."}}, status=HTTPStatus.BAD_REQUEST)
                return None
            return value

        def principal(self) -> Principal:
            supplied = self.supplied_bearer()
            # Identity-asserting headers are only honored from a trusted
            #    upstream: a caller presenting the static service token
            #    (the gateway / operator CLI), or pure local-dev with no token
            #    configured. Anyone else cannot inject a principal/roles (F-02).
            peer_ip = (self.client_address[0] if self.client_address else "")
            service_token_authenticated = bool(token) and bool(supplied) and hmac.compare_digest(supplied, token)
            proxy_authenticated = trusted_proxy_identity_headers(
                peer_ip=peer_ip,
                supplied_proxy_authorization=self.headers.get("X-Capmesh-Proxy-Token"),
                proxy_secret=CAPMESH_PROXY_TOKEN,
            )
            trusted_upstream = proxy_authenticated or (not token and _allow_unauthenticated())
            verified_who = _tailscale_whois(peer_ip) if not trusted_upstream and peer_ip not in {"127.0.0.1", "::1", ""} else None
            # Direct tailnet listeners can establish identity from the actual
            # socket peer through LocalAPI. They never consume caller headers.
            # 1. Tailscale identity is primary with two trusted sources:
            #    LocalAPI whois on a direct peer socket (--interface tailscale0 performs
            #    peer-IP-whois verification before trusting identity; recommended mode),
            #    or Tailscale Serve identity headers carried across the authenticated
            #    loopback proxy hop (validated by X-Capmesh-Proxy-Token). A valid
            #    M365/Google session remains a fallback and cannot override this identity.
            #    Raw loopback identity headers alone never establish identity.

            if verified_who:
                ts_login = str(verified_who.get("login") or "").strip()
                ts_display = str(verified_who.get("display_name") or "").strip()
                ts_tags_hdr = ",".join(verified_who.get("tags", []))
            elif proxy_authenticated:
                ts_login = str(self.headers.get("Tailscale-User-Login") or self.headers.get("X-Tailscale-Login") or "").strip()
                ts_display = str(self.headers.get("Tailscale-User-Name") or self.headers.get("X-Tailscale-Display-Name") or "").strip()
                ts_tags_hdr = self.headers.get("Tailscale-User-Tags") or self.headers.get("X-Tailscale-Tags")
            else:
                ts_login, ts_display, ts_tags_hdr = "", "", None
            if ts_login:
                login = ts_login.lower()
                ts_tags = split_header(ts_tags_hdr)
                # Tags/groups grant capmesh GROUPS for bulk org membership, never
                # roles/rights directly (least privilege — elevation only flows
                # through audited role_assignments).
                ts_groups = ["asg:tailnet", *(tag_to_group(tag) for tag in ts_tags)]
                principal = principal_from_tailscale_identity(
                    login=login,
                    display_name=ts_display,
                    groups=ts_groups,
                )
                # Auto-provision: identity row + private/shared stores. The all-user store
                # cap://all/<tenant> is already granted read-only (discover/load/call) to any
                # authenticated principal by all_users_store_grant(), so cap://all/asg is
                # immediately available with no extra grant. Provisioning is idempotent
                # (INSERT OR IGNORE / upsert) and cheap; guard so a DB hiccup never blocks auth.
                try:
                    with state_lock:
                        ensure_identity_for_principal(con, principal)
                except sqlite3.Error:
                    pass
                return principal

            # 2. M365 or Google sessions are the user-identity fallback when no
            # trusted Tailscale identity is available.
            if supplied:
                session_principal = principal_from_bearer(con, supplied)
                if session_principal is not None:
                    return session_principal

            # 3. The static service bearer authorizes a service identity only. It
            # must never turn caller-controlled X-Capmesh-* headers into roles
            # or scopes. Only the separate loopback proxy credential can assert
            # an end-user identity.
            if service_token_authenticated:
                return Principal(
                    subject="capmesh-service",
                    tenant_id=DEFAULT_TENANT,
                    app_id="capmesh-service",
                    groups=("asg:tailnet",),
                    roles=("app_service",),
                    scopes=("cap:search", "cap:load", "cap:call", "cap:delegate", "cap:report"),
                    authenticated=True,
                )
            if not trusted_upstream:
                # LocalAPI returned an unusable identity. Do not fall through to
                # any caller-controlled X-Capmesh-* assertions.
                return Principal(
                    subject="tailnet-guest",
                    tenant_id=DEFAULT_TENANT,
                    groups=("asg:tailnet",),
                    roles=("member",),
                    scopes=("cap:search", "cap:load"),
                    authenticated=True,
                )
            header = self.headers.get("X-Capmesh-Principal") if trusted_upstream else None
            if header:
                try:
                    raw = json.loads(header)
                    if isinstance(raw, dict):
                        return Principal.from_dict(raw)
                except json.JSONDecodeError:
                    pass
            groups = split_header(self.headers.get("X-Capmesh-Groups"))
            roles = split_header(self.headers.get("X-Capmesh-Roles"))
            scopes = split_header(self.headers.get("X-Capmesh-Scopes"))
            app_id = self.headers.get("X-Capmesh-App-Id")
            explicit_principal = any(
                self.headers.get(name)
                for name in (
                    "X-Capmesh-Subject",
                    "X-Capmesh-Identity-Id",
                    "X-Capmesh-Email",
                    "X-Capmesh-App-Id",
                    "X-Capmesh-Groups",
                    "X-Capmesh-Roles",
                    "X-Capmesh-Scopes",
                )
            )
            if proxy_authenticated and not explicit_principal:
                # The proxy credential authenticates nginx, not arbitrary
                # same-host clients. Tailscale identities returned above are
                # bearer-free by design; every other loopback service must use
                # the separately managed static service bearer.
                return Principal(
                    subject="tailnet-guest",
                    tenant_id=DEFAULT_TENANT,
                    authenticated=False,
                )
            return Principal(
                # A transport service token authorizes the hop; it never silently
                # becomes the historic platform-owner email.
                subject=self.headers.get("X-Capmesh-Subject") or (f"app:{app_id}" if app_id else "capmesh-service"),
                tenant_id=DEFAULT_TENANT,
                identity_id=self.headers.get("X-Capmesh-Identity-Id"),
                email=self.headers.get("X-Capmesh-Email"),
                display_name=self.headers.get("X-Capmesh-Display-Name"),
                app_id=app_id,
                groups=tuple(groups or (["asg:tailnet"] if not explicit_principal else [])),
                roles=tuple(roles or (["member"] if not explicit_principal else (["app_service"] if app_id else ["member"]))),
                scopes=tuple(scopes or ["cap:search", "cap:load", "cap:call", "cap:delegate", "cap:report"]),
                authenticated=True,
            )

        def handle_install(self, parsed: Any, base_url: str) -> None:
            base = base_url.rstrip("/")
            if parsed.path == "/install.ps1":
                self.write_text(_install_ps1(base), content_type="text/plain; charset=utf-8")
                return
            # /install and /install.sh both serve the POSIX bootstrap (curl|sh idiom).
            self.write_text(_install_sh(base), content_type="text/x-shellscript; charset=utf-8")

        def handle_scim_get(self, parsed: Any, base_url: str, *, principal: Principal | None = None) -> None:
            principal = principal if principal is not None else self.principal()
            if not self.require_scim_access(principal, write=False):
                return
            path = parsed.path.removeprefix("/scim/v2")
            query = parse_qs(parsed.query)
            start_index = int(first(query, "startIndex") or 1)
            count = int(first(query, "count") or 100)
            filter_query = first(query, "filter")
            if path == "/ServiceProviderConfig":
                self.write_json(scim.service_provider_config(base_url))
                return
            if path == "/Schemas":
                self.write_json(scim.schemas())
                return
            if path == "/ResourceTypes":
                self.write_json(scim.resource_types(base_url))
                return
            if path == "/Users":
                self.write_json(scim.list_users(con, tenant_id=principal.tenant_id, start_index=start_index, count=count, filter_query=filter_query, base_url=base_url))
                return
            if path.startswith("/Users/"):
                resource = scim.get_user(con, path.rsplit("/", 1)[-1], tenant_id=principal.tenant_id, base_url=base_url)
                self.write_json(resource or scim.error(404, "User not found."), status=HTTPStatus.OK if resource else HTTPStatus.NOT_FOUND)
                return
            if path == "/Groups":
                self.write_json(scim.list_groups(con, tenant_id=principal.tenant_id, start_index=start_index, count=count, filter_query=filter_query, base_url=base_url))
                return
            if path.startswith("/Groups/"):
                resource = scim.get_group(con, path.rsplit("/", 1)[-1], tenant_id=principal.tenant_id, base_url=base_url)
                self.write_json(resource or scim.error(404, "Group not found."), status=HTTPStatus.OK if resource else HTTPStatus.NOT_FOUND)
                return
            self.write_json(scim.error(404, "SCIM resource not found."), status=HTTPStatus.NOT_FOUND)

        def handle_scim_write(self, parsed: Any, body: dict[str, Any], *, principal: Principal | None = None) -> None:
            path = parsed.path.removeprefix("/scim/v2")
            principal = principal if principal is not None else self.principal()
            if not self.require_scim_access(principal, write=True):
                return
            # CM-05b: the SCIM provisioning tenant is bound to the provisioning
            # principal's tenant (principal.tenant_id), NOT a client-supplied
            # body tenant or DEFAULT_TENANT. A client cannot self-assign a
            # different tenant; a body tenant that differs from principal.tenant_id
            # is rejected with 403 before any write reaches the database. An
            # absent body tenant is fine -- the principal's tenant is used,
            # matching the pre-CM-05b behaviour.
            body_tenant = body.get("tenant")
            if body_tenant is not None and str(body_tenant) != principal.tenant_id:
                self.write_json(
                    scim.error(
                        403,
                        f"SCIM write tenant is bound to the provisioning principal's tenant "
                        f"({principal.tenant_id}); body tenant '{body_tenant}' does not match.",
                        "invalidValue",
                    ),
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            try:
                if path == "/Users" or path.startswith("/Users/"):
                    payload = self.scim_path_bound_payload(path, body, "/Users/")
                    self.write_json(scim.upsert_user(con, payload, tenant_id=principal.tenant_id, actor=principal.subject), status=HTTPStatus.CREATED if path == "/Users" else HTTPStatus.OK)
                    return
                if path == "/Groups" or path.startswith("/Groups/"):
                    payload = self.scim_path_bound_payload(path, body, "/Groups/")
                    # CM-05b: validate every member value resolves to an existing
                    # same-tenant identity BEFORE the insert. Reject 400 naming
                    # the offending member value(s) rather than silently inserting
                    # dangling group_members rows. scim.upsert_group re-checks by
                    # identity id as a defense-in-depth backstop.
                    ok, reason = _validate_scim_members_same_tenant(con, payload.get("members"), principal.tenant_id)
                    if not ok:
                        self.write_json(scim.error(400, reason, "invalidValue"), status=HTTPStatus.BAD_REQUEST)
                        return
                    self.write_json(scim.upsert_group(con, payload, tenant_id=principal.tenant_id, actor=principal.subject), status=HTTPStatus.CREATED if path == "/Groups" else HTTPStatus.OK)
                    return
            except ValueError as exc:
                self.write_json(scim.error(400, str(exc), "invalidValue"), status=HTTPStatus.BAD_REQUEST)
                return
            self.write_json(scim.error(404, "SCIM resource not found."), status=HTTPStatus.NOT_FOUND)

        def handle_scim_delete(self, parsed: Any, *, principal: Principal | None = None) -> None:
            path = parsed.path.removeprefix("/scim/v2")
            principal = principal if principal is not None else self.principal()
            if not self.require_scim_access(principal, write=True):
                return
            if path.startswith("/Users/"):
                deleted = scim.delete_user(con, path.rsplit("/", 1)[-1], tenant_id=principal.tenant_id, actor=principal.subject)
                self.write_json({}, status=HTTPStatus.NO_CONTENT if deleted else HTTPStatus.NOT_FOUND)
                return
            if path.startswith("/Groups/"):
                deleted = scim.delete_group(con, path.rsplit("/", 1)[-1], tenant_id=principal.tenant_id, actor=principal.subject)
                self.write_json({}, status=HTTPStatus.NO_CONTENT if deleted else HTTPStatus.NOT_FOUND)
                return
            self.write_json(scim.error(404, "SCIM resource not found."), status=HTTPStatus.NOT_FOUND)

        def require_scim_access(self, principal: Principal, *, write: bool) -> bool:
            rights = ("manage",) if write else ("manage", "audit")
            for right in rights:
                allowed, _ = evaluate_access(
                    con,
                    principal,
                    right=right,
                    resource_uri=f"tenant:{principal.tenant_id or DEFAULT_TENANT}",
                )
                if allowed:
                    return True
            self.write_json(
                scim.error(403, "SCIM access requires tenant manage or audit authorization."),
                status=HTTPStatus.FORBIDDEN,
            )
            return False

        @staticmethod
        def scim_path_bound_payload(path: str, body: dict[str, Any], prefix: str) -> dict[str, Any]:
            if not path.startswith(prefix):
                return dict(body)
            path_id = path.removeprefix(prefix).strip("/")
            supplied_id = str(body.get("id") or "")
            if supplied_id and supplied_id != path_id:
                raise ValueError("SCIM payload id must match the resource path id.")
            return {**body, "id": path_id}

        def handle_api_get(self, parsed: Any, *, principal: Principal | None = None) -> None:
            principal = principal if principal is not None else self.principal()
            query = parse_qs(parsed.query)
            path = parsed.path
            try:
                if path == "/api/v1/me":
                    self.write_json(current_user(con, principal))
                    return
                if path == "/api/v1/stores":
                    self.write_json({"items": list_stores(con, principal, first(query, "kind"))})
                    return
                if path == "/api/v1/namespaces":
                    self.write_json({"items": list_namespaces(con, principal, first(query, "storeId"))})
                    return
                if path == "/api/v1/shares":
                    self.write_json({"items": list_shares(con, principal, first(query, "capabilityUri"))})
                    return
                if path == "/api/v1/requests":
                    self.write_json({"items": list_requests(con, principal, first(query, "state"))})
                    return
                if path == "/api/v1/roles":
                    self.write_json({"items": list_roles(con, principal)})
                    return
                if path == "/api/v1/audit":
                    self.write_json({"items": list_audit_events(con, principal, int(first(query, "limit") or 50))})
                    return
                if path == "/api/v1/capguard/status":
                    from .capguard_api import capguard_status
                    self.write_json(capguard_status(con, principal))
                    return
                if path == "/api/v1/capguard/quarantine":
                    from .capguard_api import capguard_list_quarantine
                    self.write_json(capguard_list_quarantine(con, principal, status=first(query, "status")))
                    return
                if path.startswith("/api/v1/capguard/quarantine/") and path.endswith("/attestations"):
                    from .capguard_api import capguard_list_attestations
                    quarantine_id = parsed.path.removeprefix("/api/v1/capguard/quarantine/").removesuffix("/attestations").strip("/")
                    self.write_json(capguard_list_attestations(con, principal, quarantine_id, attestation_type=first(query, "type")))
                    return
                if path == "/api/v1/sync":
                    self.write_json(sync_summary(con, principal))
                    return
            except PermissionError as exc:
                self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown API endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def handle_api_post(self, parsed: Any, body: dict[str, Any], base_url: str, *, principal: Principal | None = None) -> None:
            principal = principal if principal is not None else self.principal()
            path = parsed.path
            try:
                if path == "/api/v1/auth/status":
                    self.write_json(auth_status(con, principal))
                    return
                if path == "/api/v1/auth/logout":
                    self.write_json(revoke_capmesh_session(con, principal, session_id=body.get("sessionId")))
                    return
                if path == "/api/v1/stores":
                    self.write_json(create_store(con, principal, body), status=HTTPStatus.CREATED)
                    return
                if path == "/api/v1/namespaces":
                    self.write_json(create_namespace(con, principal, body), status=HTTPStatus.CREATED)
                    return
                if path == "/api/v1/share":
                    self.write_json(create_share(con, principal, body), status=HTTPStatus.CREATED)
                    return
                if path == "/api/v1/submit":
                    from .governance import submit_promotion

                    self.write_json(submit_promotion(con, principal, body), status=HTTPStatus.CREATED)
                    return
                if path == "/api/v1/approve":
                    self.write_json(approve_request(con, principal, body))
                    return
                if path == "/api/v1/sync/graph-subscriptions":
                    self.write_json(plan_graph_subscription(con, principal, body), status=HTTPStatus.CREATED)
                    return
                if path == "/api/v1/capabilities":
                    self.write_json(manage_capability(con, principal, body), status=HTTPStatus.CREATED if str(body.get("action") or "").startswith("draft.create") else HTTPStatus.OK)
                    return
                if path == "/api/v1/capabilities/drafts":
                    payload = {**body, "action": "draft.create"}
                    self.write_json(manage_capability(con, principal, payload), status=HTTPStatus.CREATED)
                    return
                if path.startswith("/api/v1/capabilities/") and path.endswith("/validate"):
                    identifier = parsed.path.removeprefix("/api/v1/capabilities/").removesuffix("/validate").strip("/")
                    payload = {**body, "action": "validate", "capabilityUri": identifier}
                    self.write_json(manage_capability(con, principal, payload))
                    return
                if path.startswith("/api/v1/capabilities/") and path.endswith("/prepare-pr"):
                    identifier = parsed.path.removeprefix("/api/v1/capabilities/").removesuffix("/prepare-pr").strip("/")
                    payload = {**body, "action": "prepare-pr", "capabilityUri": identifier}
                    self.write_json(manage_capability(con, principal, payload))
                    return
            except PermissionError as exc:
                self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                return
            except ValueError as exc:
                self.write_json({"error": {"code": "VALIDATION_ERROR", "message": str(exc)}}, status=HTTPStatus.BAD_REQUEST)
                return
            # CapGuard release/reject (fail-closed). These mutate the quarantine
            # store and require the ``manage`` right. A fail-closed refusal
            # (QuarantineReleaseBlocked) maps to 409; a bad quarantine id / state
            # (QuarantineError) maps to 404/400. They live outside the try/except
            # above so the distinct error codes are handled explicitly.
            if path == "/api/v1/capguard/release":
                from .capguard import QuarantineError, QuarantineReleaseBlocked
                from .capguard_api import capguard_release
                try:
                    self.write_json(capguard_release(con, principal, body))
                except PermissionError as exc:
                    self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                except QuarantineReleaseBlocked as exc:
                    self.write_json({"error": {"code": "RELEASE_BLOCKED", "message": str(exc)}}, status=HTTPStatus.CONFLICT)
                except QuarantineError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                return
            if path == "/api/v1/capguard/reject":
                from .capguard import QuarantineError
                from .capguard_api import capguard_reject
                try:
                    self.write_json(capguard_reject(con, principal, body))
                except PermissionError as exc:
                    self.write_json({"error": {"code": "FORBIDDEN", "message": str(exc)}}, status=HTTPStatus.FORBIDDEN)
                except QuarantineError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                return
            # Task management API: list, status, cancel, process
            if path == "/api/v1/tasks":
                from .task_runner import list_queued_tasks
                self.write_json({"tasks": list_queued_tasks(con, limit=int(body.get("limit", 50)), tenant_id=principal.tenant_id or DEFAULT_TENANT)})
                return
            if path == "/api/v1/tasks/process":
                task_id = str(body.get("taskId") or "").strip()
                if not task_id:
                    self.write_json({"error": {"code": "VALIDATION_ERROR", "message": "taskId is required."}}, status=HTTPStatus.BAD_REQUEST)
                    return
                from .task_dispatcher import dispatch_queued_task
                try:
                    result = dispatch_queued_task(con, task_id, tenant_id=principal.tenant_id or DEFAULT_TENANT)
                    self.write_json(result)
                except ValueError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                return
            if path == "/api/v1/tasks/cancel":
                task_id = str(body.get("taskId") or "").strip()
                if not task_id:
                    self.write_json({"error": {"code": "VALIDATION_ERROR", "message": "taskId is required."}}, status=HTTPStatus.BAD_REQUEST)
                    return
                from .task_runner import cancel_task
                try:
                    result = cancel_task(con, task_id, tenant_id=principal.tenant_id or DEFAULT_TENANT)
                    self.write_json(result)
                except ValueError as exc:
                    self.write_json({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status=HTTPStatus.NOT_FOUND)
                return
            if path == "/api/v1/tasks/backends":
                from .task_dispatcher import list_dispatch_backends
                self.write_json({"backends": list_dispatch_backends()})
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown API endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def handle_public_auth_post(self, parsed: Any, body: dict[str, Any], base_url: str) -> None:
            path = parsed.path
            try:
                if path == "/api/v1/bootstrap/start":
                    self.write_json(
                        {
                            "bootstrap": bootstrap_payload(
                                base_url=base_url,
                                authority=entra_authority,
                                resource=resource_id,
                                client=str(body.get("client") or "all"),
                                direct=bool(body.get("direct", False)),
                                tenant=str(body.get("tenant") or DEFAULT_TENANT),
                            ),
                            "auth": start_browser_login(con, body, base_url),
                        }
                    )
                    return
                if path in {"/api/v1/onboarding/start", "/api/v1/auth/m365/start"}:
                    self.write_json(start_browser_login(con, body, base_url))
                    return
                if path == "/api/v1/auth/m365/device-code":
                    self.write_json(start_device_code_login(con, body, base_url))
                    return
                if path == "/api/v1/auth/m365/poll":
                    self.write_json(poll_oauth_session(con, body))
                    return
            except ValueError as exc:
                self.write_json({"error": {"code": "VALIDATION_ERROR", "message": str(exc)}}, status=HTTPStatus.BAD_REQUEST)
                return
            except RuntimeError as exc:
                self.write_json({"error": {"code": "AUTH_PROVIDER_ERROR", "message": str(exc)}}, status=HTTPStatus.BAD_GATEWAY)
                return
            self.write_json({"error": {"code": "NOT_FOUND", "message": "Unknown public auth endpoint."}}, status=HTTPStatus.NOT_FOUND)

        def handle_oauth_callback(self, parsed: Any) -> None:
            query = parse_qs(parsed.query)
            try:
                result = self.complete_oauth_callback(first(query, "state") or "", code=first(query, "code"), error=first(query, "error"))
                self.write_html(oauth_callback_html(result))
            except ValueError as exc:
                self.write_html(oauth_callback_html({"status": "failed", "error": str(exc)}), status=HTTPStatus.BAD_REQUEST)

        def complete_oauth_callback(self, state: str, *, code: str | None, error: str | None) -> dict[str, Any]:
            # state_lock is taken only around the brief DB reads/writes below; the
            # Entra token-exchange network call (exchange_authorization_code) runs
            # fully unlocked so a slow/stuck Microsoft round trip never wedges
            # every other concurrent request behind this one (F-HIGH-1).
            if error:
                with state_lock:
                    return validate_oauth_callback(con, state, code=code, error=error)
            if not code:
                raise ValueError("OAuth callback did not include a code.")
            client_id = os.environ.get("CAPMESH_M365_CLIENT_ID")
            if not client_id:
                with state_lock:
                    result = validate_oauth_callback(con, state, code=code, error=None)
                result["nextStep"] = "Set CAPMESH_M365_CLIENT_ID on the tailnet service host and retry login."
                return result
            with state_lock:
                row = con.execute("SELECT * FROM oauth_sessions WHERE state = ?", (state,)).fetchone()
            if row is None:
                raise ValueError("OAuth state was not found.")
            metadata = json.loads(row["metadata_json"] or "{}")
            verifier = str(metadata.get("codeVerifier") or "")
            if not verifier or hash_secret(verifier) != row["code_verifier_hash"]:
                raise ValueError("OAuth PKCE verifier is unavailable or invalid.")
            token_response = exchange_authorization_code(
                authority=os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/oauth2/v2.0"),
                client_id=client_id,
                client_secret=os.environ.get("CAPMESH_M365_CLIENT_SECRET"),
                code=code,
                redirect_uri=row["redirect_uri"],
                code_verifier=verifier,
                scope=row["scope"],
            )
            with state_lock:
                return complete_oauth_session(con, state, token_response=token_response, client_id=client_id)

        def handle_google_start(self, parsed: Any, base_url: str) -> None:
            query = parse_qs(parsed.query)
            tenant = first(query, "tenant") or DEFAULT_TENANT
            client_id = os.environ.get("CAPMESH_GOOGLE_CLIENT_ID")
            client_secret = os.environ.get("CAPMESH_GOOGLE_CLIENT_SECRET")
            redirect_uri = os.environ.get(
                "CAPMESH_GOOGLE_REDIRECT_URI",
                f"{base_url.rstrip('/')}/api/v1/auth/google/callback",
            )
            if not client_id or not client_secret:
                self.write_json(
                    {"error": {"code": "AUTH_NOT_CONFIGURED", "message": "Set CAPMESH_GOOGLE_CLIENT_ID and CAPMESH_GOOGLE_CLIENT_SECRET on the capmesh service host."}},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return
            from .auth_google import GoogleAuthError, build_google_auth_url

            # Reuse the existing OAuth session machinery to carry CSRF state. The
            # Google flow does not use the stored PKCE verifier, but create_oauth_session
            # gives us a persisted, tenant-scoped, expiring `state`.
            session = create_oauth_session(
                con,
                tenant_id=tenant,
                flow="google_authorization_code",
                redirect_uri=redirect_uri,
                scope="openid email profile",
                metadata={"google": True, "tailnetOnly": True, "baseUrl": base_url.rstrip("/")},
            )
            try:
                auth_url = build_google_auth_url(
                    state=session["state"],
                    redirect_uri=redirect_uri,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            except GoogleAuthError as exc:
                self.write_json({"error": {"code": "AUTH_PROVIDER_ERROR", "message": str(exc)}}, status=HTTPStatus.BAD_GATEWAY)
                return
            # Browser flow: redirect straight to Google consent.
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", auth_url)
            self.send_header("Cache-Control", "no-store")
            # Keepalive prerequisite: under protocol_version="HTTP/1.1" a
            # body-less response without Content-Length would leave the client
            # waiting for EOF instead of reusing the connection.
            self.send_header("Content-Length", "0")
            self.end_headers()

        def handle_google_callback(self, parsed: Any, base_url: str) -> None:
            query = parse_qs(parsed.query)
            error = first(query, "error")
            if error:
                self.write_html(oauth_callback_html({"status": "failed", "error": error}), status=HTTPStatus.BAD_REQUEST)
                return
            state = first(query, "state") or ""
            code = first(query, "code")
            if not state or not code:
                self.write_html(oauth_callback_html({"status": "failed", "error": "Google callback did not include state and code."}), status=HTTPStatus.BAD_REQUEST)
                return
            client_id = os.environ.get("CAPMESH_GOOGLE_CLIENT_ID")
            client_secret = os.environ.get("CAPMESH_GOOGLE_CLIENT_SECRET")
            redirect_uri = os.environ.get(
                "CAPMESH_GOOGLE_REDIRECT_URI",
                f"{base_url.rstrip('/')}/api/v1/auth/google/callback",
            )
            if not client_id or not client_secret:
                self.write_html(oauth_callback_html({"status": "failed", "error": "Google auth is not configured on this host."}), status=HTTPStatus.SERVICE_UNAVAILABLE)
                return
            # Verify the state is a known, pending capmesh OAuth session (CSRF binding).
            # state_lock is taken only around this brief DB read and the final DB
            # write below — never across the Google network calls that follow
            # (exchange_code_for_tokens, verify_google_id_token), so a slow/stuck
            # round trip to Google never wedges every other concurrent request
            # (F-HIGH-2).
            with state_lock:
                row = con.execute("SELECT * FROM oauth_sessions WHERE state = ?", (state,)).fetchone()
            if row is None or row["status"] != "pending":
                self.write_html(oauth_callback_html({"status": "failed", "error": "Google OAuth state was not found or already used."}), status=HTTPStatus.BAD_REQUEST)
                return
            from .auth_google import (
                GoogleAuthError,
                exchange_code_for_tokens,
                verify_google_id_token,
            )

            # Bound the outbound Google network round trips (token exchange +
            # id_token/JWKS verification) with an explicit per-call timeout
            # passed into each SDK call, instead of the prior process-global
            # socket.setdefaulttimeout(). A global setdefaulttimeout races with
            # every other thread's socket operations under concurrent load; the
            # per-call timeout scopes the bound to exactly these two calls and
            # matches CAPMESH_AUTH_HTTP_TIMEOUT used on the M365/Entra path.
            auth_http_timeout = float(os.environ.get("CAPMESH_AUTH_HTTP_TIMEOUT", "15"))
            try:
                tokens = exchange_code_for_tokens(
                    code,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    state=state,
                    timeout=auth_http_timeout,
                )
                # SECURITY: email comes ONLY from the verified id_token, never a param.
                claims = verify_google_id_token(tokens["id_token"], client_id, timeout=auth_http_timeout)
            except GoogleAuthError as exc:
                self.write_html(oauth_callback_html({"status": "failed", "error": str(exc)}), status=HTTPStatus.BAD_GATEWAY)
                return
            except (TimeoutError, OSError) as exc:
                self.write_html(oauth_callback_html({"status": "failed", "error": f"Could not reach Google's authorization server: {exc}"}), status=HTTPStatus.BAD_GATEWAY)
                return
            # SECURITY: enforce the invite allowlist server-side BEFORE minting any
            # session. A Gmail not on the allowlist gets 403 and never a session.
            if not email_is_allowed(claims["email"], claims.get("hd")):
                self.write_html(
                    oauth_callback_html({"status": "failed", "error": "This Google account is not on the capmesh invite allowlist."}),
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            try:
                with state_lock:
                    result = complete_google_session(con, state, claims=claims)
            except ValueError as exc:
                self.write_html(oauth_callback_html({"status": "failed", "error": str(exc)}), status=HTTPStatus.BAD_REQUEST)
                return
            self.write_html(oauth_callback_html(result))

        def handle_graph_webhook(self, parsed: Any, body: dict[str, Any]) -> None:
            query = parse_qs(parsed.query)
            validation_token = first(query, "validationToken")
            if validation_token:
                data = validation_token.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            values = body.get("value") or []
            for item in values:
                if not validate_graph_client_state(con, str(item.get("clientState") or "")):
                    self.write_json({"error": {"code": "INVALID_CLIENT_STATE", "message": "Graph clientState validation failed."}}, status=HTTPStatus.FORBIDDEN)
                    return
            self.write_json({"accepted": len(values)})

        def authorized(self, expected: str | None) -> bool:
            token = os.environ.get("CAPMESH_BEARER_TOKEN") or None
            supplied = self.supplied_bearer()
            # Verified tailnet identity is first-class authorization on this
            # tailnet-only service: a non-guest principal (authenticated proxy
            # identity over loopback, or peer-IP whois) is authorized to use the API. This is
            # what makes the magic install work — a tailnet user reaches /mcp with no
            # bearer. Per-capability and per-role authz still apply downstream; the
            # all-user store is read-only and private namespaces are identity-scoped.
            # Static-service-token callers resolve to the least-privileged
            # capmesh-service identity unless the trusted hop explicitly asserts
            # another principal.
            ident = self.principal()
            if ident is not None and ident.subject and ident.subject != "tailnet-guest":
                return True
            # F-01: when no static service token is configured, the gate is NOT
            # open — a valid minted session token is still required. Only the
            # explicit local-dev escape hatch opens it fully.
            if not token and not expected:
                if _allow_unauthenticated():
                    return True
                if supplied and principal_from_bearer(con, supplied):
                    return True
                self.write_unauthorized()
                return False
            # A configured static service token (constant-time compared, F-06).
            if token and supplied and hmac.compare_digest(supplied, token):
                return True
            # The per-route expected token, if any (also constant-time).
            if expected and supplied and hmac.compare_digest(supplied, expected):
                return True
            # Otherwise require a valid minted session bearer token.
            if supplied and principal_from_bearer(con, supplied):
                return True
            self.write_unauthorized()
            return False

        def mutating_route_authorized(self) -> bool:
            """Mutating-route gate: authenticated principal AND service token.

            IMPROVEMENT-PLAN CM-11: a mutating route requires BOTH (a) an
            authenticated principal (tailnet identity or service bearer) AND
            (b) the static service token (CAPMESH_BEARER_TOKEN).  A bare
            tailnet identity with no service token is rejected with 401 so
            that a plain tailnet user cannot perform SCIM writes, admin
            mutations, or any other destructive operation.

            Read-only routes (SCIM GET, /api/v1/whoami, cap.search/load) are
            unaffected; they only pass the standard ``authorized()`` check.
            """
            token = os.environ.get("CAPMESH_BEARER_TOKEN") or None
            ident = self.principal()
            # (a) Must have an authenticated principal (not tailnet-guest).
            if ident is None or not ident.authenticated or ident.subject == "tailnet-guest":
                self.write_unauthorized()
                return False
            # (b) Must present the static service token.
            if not token:
                # No service token configured: allow mutating requests from an
                # authenticated principal (local-dev / unauthenticated escape
                # hatch scenario). This preserves the existing loopback + proxy
                # token behaviour for read-only auth that callers already rely
                # on in development.
                return True
            supplied = self.supplied_bearer()
            if supplied and hmac.compare_digest(supplied, token):
                return True
            # Authenticated principal but no service token -> deny mutation.
            self.write_unauthorized()
            return False

        def authorized_for_metrics(self, expected: str | None) -> bool:
            """Metrics gate: session, service bearer, CAPMESH_METRICS_TOKEN, or proxy hop."""

            supplied = self.supplied_bearer()
            service_token = os.environ.get("CAPMESH_BEARER_TOKEN") or expected
            metrics_token = os.environ.get("CAPMESH_METRICS_TOKEN") or None
            if metrics_token_matches(supplied, service_token=service_token, metrics_token=metrics_token):
                return True
            if supplied and principal_from_bearer(con, supplied) is not None:
                return True
            peer_ip = self.client_address[0] if self.client_address else ""
            if trusted_proxy_identity_headers(
                peer_ip=peer_ip,
                supplied_proxy_authorization=self.headers.get("X-Capmesh-Proxy-Token"),
                proxy_secret=CAPMESH_PROXY_TOKEN,
            ):
                return True
            if _allow_unauthenticated() and not service_token and not metrics_token:
                return True
            self.write_unauthorized()
            return False

        def supplied_bearer(self) -> str:
            auth = self.headers.get("Authorization", "")
            token_header = self.headers.get("X-Capmesh-Token", "")
            return auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else token_header.strip()

        def _http_request_id(self) -> str:
            """Raw ``X-Request-Id`` (or ``X-Correlation-Id``) header value, or ``""`` when absent.

            CM-13: threaded into ``router.call(request_id=...)`` so the structured
            dispatch log correlates to the upstream HTTP request. The empty string
            is passed through; ``CapabilityRouter.call`` generates a fresh uuid for
            falsy/empty values (``rid = request_id or uuid.uuid4().hex``). This is
            distinct from ``request_id()`` below, which synthesizes a response-header
            id when no valid header is present -- the router must generate its own
            uuid for uncorrelated dispatches rather than reuse the synthesized one.
            """
            return (self.headers.get("X-Request-Id") or self.headers.get("X-Correlation-Id") or "").strip()

        def _inbound_trace_context(self) -> SpanContext | None:
            """Parse the inbound W3C ``traceparent`` header into a ``SpanContext``.

            CM-13-full: best-effort propagation. Returns ``None`` when the header
            is absent or malformed (``parse_traceparent`` returns None). The
            returned context is threaded into ``router.call(traceparent=...)`` so
            the request span is a child of the inbound trace, and is echoed on
            the response via ``_send_common_headers`` so downstream callers can
            continue the trace. A tracing failure must never break the request.
            """
            raw = (self.headers.get("traceparent") or "").strip()
            if not raw:
                return None
            try:
                return parse_traceparent(raw)
            except Exception:  # noqa: BLE001
                return None

        def _traceparent_str(self) -> str | None:
            """Raw inbound ``traceparent`` header value for threading into the router.

            The router parses and validates it itself; this passes the raw string
            (or ``None`` when absent) so the router can use it as the parent
            context for the request span. Distinct from ``_inbound_trace_context``
            so the router's own parse/validate path is exercised identically
            regardless of caller.
            """
            raw = (self.headers.get("traceparent") or "").strip()
            return raw or None

        def request_id(self) -> str:
            incoming = self._http_request_id()
            if incoming and re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", incoming):
                return incoming
            return f"req_{int(time.time() * 1000):x}_{threading.get_ident() & 0xFFFF:04x}"

        def write_unauthorized(self) -> None:
            metadata_url = f"{tailnet_base_url.rstrip('/')}/.well-known/oauth-protected-resource"
            bootstrap_url = f"{tailnet_base_url.rstrip('/')}/bootstrap"
            payload = {
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Bearer token required.",
                    "resourceMetadata": metadata_url,
                    "bootstrap": bootstrap_url,
                    "login": f"{tailnet_base_url.rstrip('/')}/login?tenant={DEFAULT_TENANT}",
                }
            }
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "WWW-Authenticate",
                f'Bearer realm="capmesh", resource_metadata="{metadata_url}", scope="cap.discover cap.load cap.call cap.delegate"',
            )
            self.send_header("Link", f'<{bootstrap_url}>; rel="service-desc"; type="application/json"')
            self.end_headers()
            self.wfile.write(data)

        def _send_common_headers(self, *, content_type: str | None, length: int) -> None:
            self.send_header("X-Request-Id", self.request_id())
            self.send_header("Cache-Control", "no-store")
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            if urlparse(self.path).path == "/mcp":
                self.send_header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
            # CM-13-full: echo a W3C traceparent so downstream callers can continue
            # the trace. When an inbound traceparent parsed, echo that context
            # (the request span is its child); otherwise synthesize a fresh one so
            # every response carries a traceparent. Best-effort: never break the
            # response or change status codes.
            try:
                ctx = self._inbound_trace_context()
                if ctx is None:
                    ctx = SpanContext(
                        trace_id=generate_trace_id(),
                        span_id=generate_span_id(),
                        trace_flags="01",
                        trace_state="",
                    )
                self.send_header("traceparent", format_traceparent(ctx))
            except Exception:  # noqa: BLE001,S110
                pass

        def write_json(self, payload: dict[str, Any], status: int | HTTPStatus = HTTPStatus.OK) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            try:
                self.send_response(int(status))
                self._send_common_headers(content_type="application/json", length=len(data))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                return

        def write_text(self, text: str, status: int | HTTPStatus = HTTPStatus.OK,
                       content_type: str = "text/plain; charset=utf-8") -> None:
            data = text.encode("utf-8")
            try:
                self.send_response(int(status))
                self._send_common_headers(content_type=content_type, length=len(data))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                return

        def write_empty(self, status: int | HTTPStatus = HTTPStatus.NO_CONTENT) -> None:
            try:
                self.send_response(int(status))
                self._send_common_headers(content_type=None, length=0)
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError):
                return

        def write_html(self, html: str, status: int | HTTPStatus = HTTPStatus.OK) -> None:
            data = html.encode("utf-8")
            try:
                self.send_response(int(status))
                self._send_common_headers(content_type="text/html; charset=utf-8", length=len(data))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                return

    httpd = InterfaceBoundHTTPServer((host, port), Handler, bind_interface=bind_interface)
    # `handle_request()` (used below) observes this timeout and lets the loop
    # notice shutdown_event. Calling `HTTPServer.shutdown()` from a signal
    # handler deadlocks because shutdown() is only valid with serve_forever().
    httpd.timeout = 1.0
    where = f"{host}:{port}" + (f" on {bind_interface}" if bind_interface else "")
    sys.stderr.write(f"[asg-capmesh-http] ready on {where}\n")
    # Periodic WAL checkpoint timer (audit finding #50). Runs TRUNCATE on a
    # dedicated connection every CAPMESH_WAL_CHECKPOINT_INTERVAL seconds
    # (default 180) so the WAL does not grow unbounded between rebuilds. This
    # is the dedicated checkpoint timer referenced by the shutdown handler.
    wal_checkpoint_interval = float(os.environ.get("CAPMESH_WAL_CHECKPOINT_INTERVAL", "180"))
    wal_checkpoint_event = threading.Event()

    def _wal_checkpoint_loop() -> None:
        while not wal_checkpoint_event.wait(wal_checkpoint_interval):
            try:
                ckpt_con = sqlite3.connect(str(db_path), timeout=5)
                ckpt_con.execute("PRAGMA busy_timeout=5000")
                ckpt_con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                ckpt_con.close()
            except sqlite3.Error:
                pass  # never crash the checkpoint thread

    wal_checkpoint_thread = threading.Thread(target=_wal_checkpoint_loop, name="capmesh-wal-checkpoint", daemon=True)
    wal_checkpoint_thread.start()

    shutdown_event = threading.Event()

    def _handle_signal(signum: int, _frame: Any) -> None:
        sys.stderr.write(f"[asg-capmesh-http] shutting down (signal {signum})\n")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        while not shutdown_event.is_set():
            httpd.handle_request()
    finally:
        try:
            # Never perform a blocking TRUNCATE checkpoint from each worker's
            # shutdown path. systemd stops wildcard instances sequentially;
            # sibling workers can therefore keep WAL readers open and make
            # the first worker wait for its full busy timeout, stalling the
            # entire pool. The dedicated checkpoint timer owns truncation.
            con.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass  # DB may already be closing
        wal_checkpoint_event.set()
        httpd.server_close()
        con.close()


class InterfaceBoundHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *, bind_interface: str | None = None):
        self.bind_interface = bind_interface
        super().__init__(server_address, handler)

    def server_bind(self) -> None:
        if self.bind_interface:
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise OSError("SO_BINDTODEVICE is unavailable on this platform; bind to a concrete Tailscale IP instead.")
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.bind_interface.encode("utf-8") + b"\0")
            except PermissionError as exc:
                raise PermissionError(
                    f"Could not bind socket to interface {self.bind_interface!r}. "
                    "Run on a kernel that permits unprivileged SO_BINDTODEVICE or grant only the required network capability."
                ) from exc
        super().server_bind()
        # Disable Nagle's algorithm so small response headers/JSON are not
        # delayed by the TCP coalescing timer — important for 100s of
        # concurrent short MCP/JSON-RPC round trips. Also enable TCP keepalive
        # probes so a wedged client socket is reclaimed instead of pinning a
        # handler thread forever. Best-effort: never break bind on a platform
        # (or a socket family, e.g. AF_UNIX) that lacks the option.
        try:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass


def validate_bind_interface(interface: str | None) -> str:
    if not interface:
        raise ValueError("Interface name is required.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValueError("Interface name must be 1-15 chars and contain only letters, numbers, dot, underscore, colon, or dash.")
    return interface


def first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key) or []
    return values[0] if values else None


def split_header(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


def _normalized_origin(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        return None
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def allowed_mcp_origins(base_url: str) -> frozenset[str]:
    values = [base_url, *split_header(os.environ.get("CAPMESH_ALLOWED_ORIGINS"))]
    return frozenset(origin for value in values if (origin := _normalized_origin(value)))


def validate_mcp_http_headers(
    *,
    origin: str | None,
    protocol_version: str | None,
    base_url: str,
    content_type: str | None = None,
    accept: str | None = None,
) -> tuple[HTTPStatus, str, str] | None:
    """Validate DNS-rebinding and protocol-version boundaries for `/mcp`.

    Native MCP clients commonly omit ``Origin``; when present it must match an
    exact configured origin. Missing protocol headers retain the specification's
    2025-03-26 compatibility behavior. Unknown versions fail with HTTP 400.
    """

    if origin:
        normalized = _normalized_origin(origin)
        if normalized is None or normalized not in allowed_mcp_origins(base_url):
            return HTTPStatus.FORBIDDEN, "INVALID_ORIGIN", "Origin is not allowed for this MCP resource."
    if protocol_version and protocol_version not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        # Check against the streamable_http module's supported versions.
        try:
            from .streamable_http import SUPPORTED_PROTOCOL_VERSIONS as _stream_versions
            if protocol_version in _stream_versions:
                return None  # Version is supported by the streamable_http module
        except ImportError:
            pass
        return HTTPStatus.BAD_REQUEST, "UNSUPPORTED_PROTOCOL_VERSION", "Unsupported MCP protocol version."
    if content_type is not None and content_type.split(";", 1)[0].strip().lower() != "application/json":
        return HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_CONTENT_TYPE", "MCP POST requests must use application/json."
    if accept is not None and "application/json" not in accept.lower():
        return HTTPStatus.NOT_ACCEPTABLE, "UNSUPPORTED_ACCEPT", "This stateless MCP endpoint returns application/json."
    return None


def jsonrpc_transport_error(code: str, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": message, "data": {"code": code}},
    }


def trusted_proxy_identity_headers(
    *,
    peer_ip: str,
    supplied_proxy_authorization: str | None,
    proxy_secret: str | None,
) -> bool:
    """Return true only for an authenticated loopback reverse-proxy hop.

    The loopback proxy (Tailscale Serve / local reverse proxy) must add the
    X-Capmesh-Proxy-Token (or ``Authorization: Bearer <token>``) header on
    every forwarded request.  A raw local POST with Tailscale-User-Login and
    no proxy token resolves to tailnet-guest (never the asserted identity).
    --interface tailscale0 with peer-IP-whois verification before trusting
    identity is the recommended production mode.
    """

    if peer_ip not in {"127.0.0.1", "::1", ""} or not proxy_secret:
        return False
    raw = str(supplied_proxy_authorization or "").strip()
    if not raw:
        return False
    # Accept either a bare token or an Authorization-style "Bearer <token>".
    if raw.lower().startswith("bearer ") and len(raw) > len("bearer "):
        raw = raw[len("bearer "):].strip()
    return bool(raw) and hmac.compare_digest(raw, proxy_secret)


def principal_from_tailscale_identity(
    *,
    login: str,
    display_name: str = "",
    groups: list[str] | tuple[str, ...] = (),
    tenant_id: str = DEFAULT_TENANT,
) -> Principal:
    """Create the least-privileged principal for a verified Tailscale identity."""

    normalized = login.strip().lower()
    if not normalized:
        raise ValueError("A verified Tailscale login is required.")
    merged_groups = tuple(dict.fromkeys(("asg:tailnet", *groups)))
    return Principal(
        subject=normalized,
        tenant_id=tenant_id,
        identity_id=corporate_identity_id(tenant_id, normalized, normalized),
        email=normalized if "@" in normalized else None,
        display_name=display_name.strip() or normalized,
        groups=merged_groups,
        roles=("member",),
        scopes=("cap:search", "cap:load", "cap:call", "cap:delegate", "cap:report"),
        authenticated=True,
    )


def _allow_unauthenticated() -> bool:
    """Local-dev escape hatch only.

    When no static service token is configured, the gate stays closed unless
    this is explicitly enabled. Prevents the open-by-default posture (F-01) on
    any host that forgot to set CAPMESH_BEARER_TOKEN.
    """
    if os.environ.get("CAPMESH_ENVIRONMENT", "").strip().lower() in {"production", "prod"}:
        return False
    return os.environ.get("CAPMESH_ALLOW_UNAUTHENTICATED", "") in {"1", "true", "True"}


# Bounded, thread-safe TTL cache for tailscale whois resolutions. Every
# direct-tailnet request resolves identity via `tailscale whois` (a subprocess
# with up to a 5s timeout). Without a cache, 100s of concurrent requests each
# spawn the subprocess, and one slow/stuck whois can wedge that request for 5s.
# Only UNAMBIGUOUS SUCCESSFUL resolutions are cached — errors, empty logins, and
# ambiguous results are never cached, so a transient tailscaled hiccup or a
# not-yet-provisioned peer is retried on the next request instead of pinned.
# The cache is keyed by peer IP; Tailscale node identity is stable for a given
# peer IP within a session, so a short TTL (default 15s) is safe and keeps the
# cache from masking a node re-provisioning for more than that window.
_WHOIS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_WHOIS_CACHE_LOCK = threading.Lock()
_WHOIS_CACHE_MAX = int(os.environ.get("CAPMESH_WHOIS_CACHE_MAX", "4096"))
_WHOIS_CACHE_TTL = float(os.environ.get("CAPMESH_WHOIS_CACHE_TTL", "15"))


def clear_whois_cache() -> None:
    """Drop all cached whois resolutions (e.g. after a tailnet membership change)."""
    with _WHOIS_CACHE_LOCK:
        _WHOIS_CACHE.clear()


def _tailscale_whois(peer_ip: str) -> dict[str, Any] | None:
    """Resolve a tailnet peer IP to its identity via the local tailscale whois CLI.

    Credential-free, dependency-free (mirrors tailscale_sync._fallback_status_users).
    Returns {login, display_name, tags} or None. Bounded timeout; never raises.
    Successful, unambiguous resolutions are cached per peer IP for
    ``CAPMESH_WHOIS_CACHE_TTL`` seconds (default 15s) so a burst of 100s of
    concurrent requests from the same peer resolves the subprocess at most once
    per TTL window instead of once per request.
    """
    if not re.match(r"^[0-9a-fA-F:.]+$", peer_ip or ""):  # defensive: IP-shaped only
        return None
    now = time.monotonic()
    # Fast path: a fresh cached resolution avoids the subprocess entirely. A
    # stale entry is not a hit; fall through to a fresh whois so a
    # re-provisioned node is picked up without waiting for an explicit clear.
    try:
        cached = _WHOIS_CACHE.get(peer_ip)
    except TypeError:  # unhashable peer_ip — never expected, but stay robust
        cached = None
    if cached is not None and (now - cached[0]) < _WHOIS_CACHE_TTL:
        return cached[1]
    try:
        result = subprocess.run(
            ["tailscale", "whois", "--json", peer_ip],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None  # never cache a failure
    if result.returncode != 0 or not result.stdout:
        return None  # never cache a failure
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None  # never cache a failure
    user = data.get("UserProfile") or {}
    caps = data.get("Node") or {}
    login = str(user.get("LoginName") or "").strip()
    if not login:
        return None  # ambiguous — never cache
    tags = [str(t) for t in (caps.get("Tags") or []) if isinstance(t, str)]
    resolved = {"login": login, "display_name": str(user.get("DisplayName") or ""), "tags": tags}
    # Bound the cache so a long-lived server talking to many distinct peers
    # cannot grow it without limit. A simple size cap is sufficient: the
    # active working set of tailnet peers for a asg-capmesh server is small.
    with _WHOIS_CACHE_LOCK:
        if len(_WHOIS_CACHE) >= _WHOIS_CACHE_MAX and peer_ip not in _WHOIS_CACHE:
            # Evict the single oldest entry rather than clearing all, so a
            # steady-state hot set survives a cold-peer burst.
            oldest = min(_WHOIS_CACHE, key=lambda k: _WHOIS_CACHE[k][0])
            _WHOIS_CACHE.pop(oldest, None)
        _WHOIS_CACHE[peer_ip] = (now, resolved)
    return resolved


def _install_sh(base_url: str) -> str:
    """POSIX bootstrap installer (curl|sh idiom), pinned to the tailnet base URL."""
    base = base_url.rstrip("/")
    return f"""#!/bin/sh
# capmesh POSIX installer — curl -fsSL {base}/install.sh | sh
set -eu

CAPMESH_BASE="${{CAPMESH_BASE:-{base}}}"
BIN_DIR="${{CAPMESH_BIN_DIR:-$HOME/.local/bin}}"
TARGET="$BIN_DIR/capmesh"

echo "capmesh installer -> $CAPMESH_BASE"
mkdir -p "$BIN_DIR"

cat > "$TARGET" <<CAPMESH_CLI
#!/bin/sh
# capmesh thin CLI shim. Talks to the tailnet capmesh service over its
# Tailscale-verified identity (no token needed on the tailnet).
set -eu
CAPMESH_BASE="\\${{CAPMESH_BASE:-{base}}}"
case "\\${{1:-help}}" in
  help|"")
    curl -fsSL "\\$CAPMESH_BASE/help" ;;
  bootstrap)
    curl -fsSL "\\$CAPMESH_BASE/bootstrap" ;;
  me)
    curl -fsSL "\\$CAPMESH_BASE/api/v1/me" ;;
  search)
    shift; q="\\${{*:-}}"
    curl -fsSL "\\$CAPMESH_BASE/cap/search?q=\\$q" ;;
  *)
    echo "unknown command: \\$1" >&2; exit 2 ;;
esac
CAPMESH_CLI
chmod +x "$TARGET"

echo "installed: $TARGET"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "note: add $BIN_DIR to your PATH" ;;
esac
echo "run: capmesh help"
"""


def _install_ps1(base_url: str) -> str:
    """PowerShell bootstrap installer, pinned to the tailnet base URL."""
    base = base_url.rstrip("/")
    return f"""# capmesh PowerShell installer
# irm {base}/install.ps1 | iex
$ErrorActionPreference = 'Stop'

$CapmeshBase = if ($env:CAPMESH_BASE) {{ $env:CAPMESH_BASE }} else {{ '{base}' }}
$BinDir = if ($env:CAPMESH_BIN_DIR) {{ $env:CAPMESH_BIN_DIR }} else {{ Join-Path $HOME '.local\\bin' }}
$Target = Join-Path $BinDir 'capmesh.ps1'

Write-Host "capmesh installer -> $CapmeshBase"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$cli = @'
param([Parameter(ValueFromRemainingArguments=$true)]$Args)
$ErrorActionPreference = 'Stop'
$CapmeshBase = if ($env:CAPMESH_BASE) {{ $env:CAPMESH_BASE }} else {{ '__BASE__' }}
$cmd = if ($Args.Count -ge 1) {{ $Args[0] }} else {{ 'help' }}
switch ($cmd) {{
  'help'      {{ Invoke-RestMethod "$CapmeshBase/help" }}
  ''          {{ Invoke-RestMethod "$CapmeshBase/help" }}
  'bootstrap' {{ Invoke-RestMethod "$CapmeshBase/bootstrap" }}
  'me'        {{ Invoke-RestMethod "$CapmeshBase/api/v1/me" }}
  'search'    {{ $q = ($Args[1..($Args.Count-1)] -join ' '); Invoke-RestMethod "$CapmeshBase/cap/search?q=$q" }}
  default     {{ Write-Error "unknown command: $cmd" }}
}}
'@
$cli = $cli.Replace('__BASE__', $CapmeshBase)
Set-Content -Path $Target -Value $cli -Encoding UTF8

Write-Host "installed: $Target"
Write-Host "run: powershell -File $Target help"
"""


def start_browser_login(con: Any, body: dict[str, Any], base_url: str) -> dict[str, Any]:
    tenant = str(body.get("tenant") or DEFAULT_TENANT)
    redirect_uri = str(body.get("redirectUri") or os.environ.get("CAPMESH_REDIRECT_URI") or f"{base_url.rstrip('/')}/oauth/callback")
    scope = str(body.get("scope") or "openid profile email offline_access User.Read")
    session = create_oauth_session(
        con,
        tenant_id=tenant,
        flow="authorization_code_pkce",
        redirect_uri=redirect_uri,
        scope=scope,
        metadata={"m365": True, "tailnetOnly": True, "baseUrl": base_url.rstrip("/")},
    )
    client_id = os.environ.get("CAPMESH_M365_CLIENT_ID")
    session.update(
        {
            "tenant": tenant,
            "tailnetOnly": True,
            "callbackUrl": redirect_uri,
            "pollUrl": f"{base_url.rstrip('/')}/api/v1/auth/m365/poll",
            "onboarding": onboarding_payload(base_url=base_url, tenant=tenant, client=str(body.get("client") or "all")),
        }
    )
    if not client_id:
        session["appRegistrationRequired"] = "Set CAPMESH_M365_CLIENT_ID on the capmesh service host."
        return session
    session["authorizationUrl"] = authorization_url(
        authority=os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/oauth2/v2.0"),
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=session["state"],
        nonce=session["nonce"],
        code_challenge=session["codeChallenge"],
    )
    return session


def start_device_code_login(con: Any, body: dict[str, Any], base_url: str) -> dict[str, Any]:
    tenant = str(body.get("tenant") or DEFAULT_TENANT)
    scope = str(body.get("scope") or "openid profile email offline_access User.Read")
    client_id = os.environ.get("CAPMESH_M365_CLIENT_ID")
    if not client_id:
        raise ValueError("CAPMESH_M365_CLIENT_ID is required for device code login.")
    session = create_oauth_session(
        con,
        tenant_id=tenant,
        flow="device_code",
        redirect_uri=str(body.get("redirectUri") or f"{base_url.rstrip('/')}/oauth/callback"),
        scope=scope,
        metadata={"m365": True, "tailnetOnly": True, "baseUrl": base_url.rstrip("/")},
    )
    device = post_form(
        endpoint_url(os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/oauth2/v2.0"), "devicecode"),
        {"client_id": client_id, "scope": scope},
    )
    metadata = {
        "m365": True,
        "tailnetOnly": True,
        "deviceCode": device.get("device_code"),
        "userCode": device.get("user_code"),
        "verificationUri": device.get("verification_uri") or device.get("verification_url"),
        "interval": device.get("interval", 5),
        "baseUrl": base_url.rstrip("/"),
    }
    con.execute("UPDATE oauth_sessions SET metadata_json = ? WHERE id = ?", (json.dumps(metadata, sort_keys=True), session["id"]))
    con.commit()
    return {
        **session,
        "deviceCode": None,
        "userCode": device.get("user_code"),
        "verificationUri": device.get("verification_uri") or device.get("verification_url"),
        "message": device.get("message"),
        "interval": device.get("interval", 5),
        "pollUrl": f"{base_url.rstrip('/')}/api/v1/auth/m365/poll",
    }


def poll_oauth_session(con: Any, body: dict[str, Any]) -> dict[str, Any]:
    session_id = str(body.get("sessionId") or body.get("id") or body.get("state") or "")
    if not session_id:
        raise ValueError("sessionId is required.")
    row = con.execute("SELECT * FROM oauth_sessions WHERE id = ? OR state = ?", (session_id, session_id)).fetchone()
    if row is None:
        raise ValueError("OAuth session not found.")
    metadata = json.loads(row["metadata_json"] or "{}")
    if row["flow"] == "device_code" and row["status"] == "pending" and metadata.get("deviceCode"):
        client_id = os.environ.get("CAPMESH_M365_CLIENT_ID")
        if not client_id:
            raise ValueError("CAPMESH_M365_CLIENT_ID is required for device code polling.")
        token_response = post_form(
            endpoint_url(os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/oauth2/v2.0"), "token"),
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": metadata["deviceCode"],
            },
            allow_oauth_pending=True,
        )
        if token_response.get("authorization_pending"):
            return {"id": row["id"], "status": "pending", "interval": metadata.get("interval", 5)}
        complete_oauth_session(con, row["state"], token_response=token_response, client_id=client_id)
    return oauth_session_status(con, session_id, consume_tokens=bool(body.get("consumeTokens", False)))


def authorization_url(
    *,
    authority: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{endpoint_url(authority, 'authorize')}?{query}"


def exchange_authorization_code(
    *,
    authority: str,
    client_id: str,
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    scope: str,
) -> dict[str, Any]:
    payload = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "scope": scope,
    }
    if client_secret:
        payload["client_secret"] = client_secret
    return post_form(endpoint_url(authority, "token"), payload)


def endpoint_url(authority: str, endpoint: str) -> str:
    raw = authority.rstrip("/")
    if raw.endswith("/oauth2/v2.0"):
        base = raw
    elif raw.endswith("/v2.0"):
        base = raw.removesuffix("/v2.0") + "/oauth2/v2.0"
    else:
        base = raw + "/oauth2/v2.0"
    return f"{base}/{endpoint.lstrip('/')}"


def post_form(url: str, fields: dict[str, Any], *, allow_oauth_pending: bool = False) -> dict[str, Any]:
    data = urlencode({key: str(value) for key, value in fields.items() if value is not None}).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    timeout = float(os.environ.get("CAPMESH_AUTH_HTTP_TIMEOUT", "15"))
    try:
        with urlopen(request, timeout=timeout) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": "http_error", "error_description": body}
        if allow_oauth_pending and parsed.get("error") == "authorization_pending":
            return {"authorization_pending": True}
        description = parsed.get("error_description") or parsed.get("error") or f"HTTP {exc.code}"
        raise RuntimeError(str(description))
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach authorization server: {exc}") from exc
    if not isinstance(parsed, dict):
        raise TypeError("Authorization server returned a non-object response.")
    return parsed


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def login_html(base_url: str, tenant: str) -> str:
    safe_base = _html_escape(base_url.rstrip("/"))
    safe_tenant = _html_escape(tenant)
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Capmesh Login</title></head>
<body style="font:14px/1.45 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 18px">
  <h1>Capmesh Login</h1>
  <p>This tailnet page starts Microsoft 365 sign-in for tenant <strong>{safe_tenant}</strong>.</p>
  <button id="start" style="min-height:36px">Sign in with Microsoft 365</button>
  <pre id="out" style="white-space:pre-wrap;border:1px solid #ddd;padding:12px;margin-top:16px"></pre>
  <script>
  document.querySelector('#start').onclick = async () => {{
    const out = document.querySelector('#out');
    out.textContent = 'Starting sign-in...';
    const res = await fetch('{safe_base}/api/v1/auth/m365/start', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{tenant: '{safe_tenant}'}})
    }});
    const data = await res.json();
    if (data.authorizationUrl) {{
      out.textContent = 'Redirecting to Microsoft sign-in...';
      location.href = data.authorizationUrl;
    }} else {{
      out.textContent = JSON.stringify(data, null, 2);
    }}
  }};
  </script>
</body>
</html>"""


def oauth_callback_html(result: dict[str, Any]) -> str:
    status = _html_escape(str(result.get("status") or "unknown"))
    error = _html_escape(str(result.get("error") or ""))
    session_id = _html_escape(str(result.get("id") or ""))
    next_step = _html_escape(str(result.get("nextStep") or ""))
    body = (
        f"<p>Sign-in completed. Session id: <code>{session_id}</code>.</p>"
        "<p>Return to your coder and run <code>capmesh auth status --json</code> or retry the capmesh call.</p>"
        if status == "completed"
        else f"<p>Sign-in status: <code>{status}</code>.</p><p>{error or next_step}</p>"
    )
    safe_result = json.dumps(
        {k: v for k, v in result.items() if "Token" not in k},
        indent=2,
        sort_keys=True,
    )
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Capmesh Callback</title></head>
<body style="font:14px/1.45 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 18px">
  <h1>Capmesh Microsoft 365 Sign-in</h1>
  {body}
  <pre style="white-space:pre-wrap;border:1px solid #ddd;padding:12px">{_html_escape(safe_result)}</pre>
</body>
</html>"""


def console_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Capmesh Console</title>
  <style>
    :root { color-scheme: light; --ink:#171717; --muted:#666; --line:#d9d9d9; --fill:#f7f7f7; --accent:#0f766e; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--ink); background: #fff; }
    header { border-bottom: 1px solid var(--line); padding: 14px 18px; display: flex; justify-content: space-between; gap: 16px; align-items: center; }
    h1 { font-size: 18px; margin: 0; font-weight: 650; }
    main { display: grid; grid-template-columns: 220px minmax(0, 1fr); min-height: calc(100vh - 58px); }
    nav { border-right: 1px solid var(--line); padding: 12px; background: var(--fill); }
    button { border: 1px solid var(--line); background: #fff; color: var(--ink); min-height: 34px; border-radius: 6px; padding: 0 10px; cursor: pointer; }
    button.active { border-color: var(--accent); color: var(--accent); font-weight: 650; }
    nav button { width: 100%; text-align: left; margin-bottom: 8px; }
    section { padding: 16px 18px; min-width: 0; }
    .toolbar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
    .muted { color: var(--muted); }
    pre { margin: 0; border: 1px solid var(--line); border-radius: 6px; padding: 12px; overflow: auto; background: #fbfbfb; min-height: 260px; }
    input, select, textarea { border: 1px solid var(--line); border-radius: 6px; padding: 7px 9px; min-height: 34px; font: inherit; }
    textarea { width: min(780px, 100%); min-height: 110px; display: block; margin-top: 8px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }
    th { background: var(--fill); font-weight: 650; }
  </style>
</head>
<body>
  <header>
    <h1>Capmesh Console</h1>
    <div id="identity" class="muted"></div>
  </header>
  <main>
    <nav id="nav"></nav>
    <section>
      <div class="toolbar">
        <button id="refresh">Refresh</button>
        <select id="action"></select>
        <button id="run">Run</button>
      </div>
      <div id="form"></div>
      <pre id="output">{}</pre>
    </section>
  </main>
  <script>
    const views = {
      me: { label: 'Me', method: 'GET', path: '/api/v1/me', actions: ['get'] },
      stores: { label: 'Stores', method: 'GET', path: '/api/v1/stores', actions: ['list','create'], createPath: '/api/v1/stores' },
      namespaces: { label: 'Namespaces', method: 'GET', path: '/api/v1/namespaces', actions: ['list','create'], createPath: '/api/v1/namespaces' },
      requests: { label: 'Requests', method: 'GET', path: '/api/v1/requests', actions: ['list','approve'], approvePath: '/api/v1/approve' },
      shares: { label: 'Shares', method: 'GET', path: '/api/v1/shares', actions: ['list','create'], createPath: '/api/v1/share' },
      roles: { label: 'Roles', method: 'GET', path: '/api/v1/roles', actions: ['list'] },
      audit: { label: 'Audit', method: 'GET', path: '/api/v1/audit', actions: ['list'] },
      sync: { label: 'Sync', method: 'GET', path: '/api/v1/sync', actions: ['status','graph-subscription'], graphPath: '/api/v1/sync/graph-subscriptions' },
      scimUsers: { label: 'SCIM Users', method: 'GET', path: '/scim/v2/Users', actions: ['list'] },
      scimGroups: { label: 'SCIM Groups', method: 'GET', path: '/scim/v2/Groups', actions: ['list'] }
    };
    let current = 'me';
    const nav = document.querySelector('#nav');
    const action = document.querySelector('#action');
    const form = document.querySelector('#form');
    const output = document.querySelector('#output');
    for (const [key, view] of Object.entries(views)) {
      const btn = document.createElement('button');
      btn.textContent = view.label;
      btn.onclick = () => selectView(key);
      btn.dataset.key = key;
      nav.appendChild(btn);
    }
    document.querySelector('#refresh').onclick = () => load();
    document.querySelector('#run').onclick = () => runAction();
    action.onchange = renderForm;
    async function api(path, options = {}) {
      const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
      const text = await res.text();
      const data = text ? JSON.parse(text) : {};
      if (!res.ok) throw data;
      return data;
    }
    function selectView(key) {
      current = key;
      for (const btn of nav.querySelectorAll('button')) btn.classList.toggle('active', btn.dataset.key === key);
      action.replaceChildren(...views[key].actions.map(name => Object.assign(document.createElement('option'), { value:name, textContent:name })));
      renderForm();
      load();
    }
    function renderForm() {
      const value = action.value;
      if (['create','approve','graph-subscription'].includes(value)) {
        form.innerHTML = '<label class="muted">JSON payload</label><textarea id="payload">{}</textarea>';
      } else {
        form.innerHTML = '';
      }
    }
    async function load() {
      try {
        const data = await api(views[current].path);
        output.textContent = JSON.stringify(data, null, 2);
        if (current === 'me') document.querySelector('#identity').textContent = `${data.subject || ''} · ${data.tenant || ''}`;
      } catch (err) {
        output.textContent = JSON.stringify(err, null, 2);
      }
    }
    async function runAction() {
      const view = views[current];
      const selected = action.value;
      if (selected === 'list' || selected === 'get' || selected === 'status') return load();
      const payload = JSON.parse(document.querySelector('#payload')?.value || '{}');
      const path = selected === 'approve' ? view.approvePath : selected === 'graph-subscription' ? view.graphPath : view.createPath;
      try {
        const data = await api(path, { method: 'POST', body: JSON.stringify(payload) });
        output.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        output.textContent = JSON.stringify(err, null, 2);
      }
    }
    selectView('me');
  </script>
</body>
</html>"""
