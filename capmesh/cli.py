from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import stat
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .governance import (
    DEFAULT_TENANT,
    add_org_member,
    approve_request,
    assign_role,
    auth_status,
    create_namespace,
    create_oauth_session,
    create_share,
    create_store,
    current_user,
    list_audit_events,
    list_namespaces,
    list_org_members,
    list_organizations,
    list_requests,
    list_roles,
    list_shares,
    list_stores,
    manage_capability,
    remove_org_member,
    revoke_capmesh_session,
    revoke_role,
    revoke_share,
    sync_summary,
)
from .help import bootstrap_payload, help_payload, onboarding_payload
from .index import (
    connect,
    coverage_report,
    export_jsonl,
    get_capability,
    ingest_index,
    init_db,
    promote_shadow_database,
    stage_rebuild_index,
)
from .install_policy import configured_superadmin_auto_approval
from .lifecycle import approve_catalog, review_capability
from .manifest import configured_default_roots
from .models import Capability, Principal
from .node_role import is_authoritative_node, topology_payload
from .router import CapabilityRouter, tool_schemas
from .server import serve_stdio

DEFAULT_DB = os.environ.get("CAPMESH_DB", "~/.capmesh/asg-capmesh.db")
DEFAULT_EXPORT = os.path.join("~/.capmesh", "capabilities.jsonl")
AUTHORITY_ONLY_COMMANDS = frozenset(
    {"ingest", "rebuild", "stores", "namespaces", "share", "submit", "approve", "roles", "org", "sync", "capabilities"}
)


def offline_replica_rehearsal_allowed(command: str, db_path: str) -> bool:
    """Allow only an explicitly marked, offline shadow ingest on a replica."""

    if command != "ingest" or os.environ.get("CAPMESH_OFFLINE_REHEARSAL") != "1":
        return False
    configured_live = os.environ.get("CAPMESH_DB", "").strip()
    if not configured_live:
        return False
    live_db = Path(configured_live).expanduser().resolve()
    candidate = Path(db_path).expanduser().resolve()
    return candidate != live_db and candidate.parent == live_db.parent / "rehearsal"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="capmesh", description="ASG capability mesh CLI")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    parser.add_argument("--principal-json", help="JSON principal claims for noninteractive admin operations")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Add or refresh capabilities from roots without deleting other entries")
    ingest.add_argument("--root", action="append", default=[], help="Root to scan. Defaults to ASG ecosystem roots.")
    ingest.add_argument("--no-vector", action="store_true", help="Disable sqlite-vec table creation.")
    ingest.add_argument("--export-jsonl", default=DEFAULT_EXPORT, help="Export canonical registry JSONL after ingest.")

    rebuild = sub.add_parser("rebuild", help="Build a validated full-replacement shadow database")
    rebuild.add_argument("--root", action="append", default=[], help="Authoritative roots for the replacement catalog.")
    rebuild.add_argument("--no-vector", action="store_true", help="Disable sqlite-vec table creation.")
    rebuild.add_argument("--approved-removals", help="JSON manifest containing the exact capability URIs approved for removal.")
    rebuild.add_argument("--candidate-path", help="Candidate DB path in the live DB directory.")
    rebuild.add_argument("--promote", action="store_true", help="Atomically promote the validated candidate.")
    rebuild.add_argument(
        "--workers-drained",
        action="store_true",
        help="Assert that every Capmesh worker using the DB is stopped before promotion.",
    )

    check = sub.add_parser("check", help="Run ingestion coverage check")
    diff_cmd = sub.add_parser("diff", help="Compare current mesh state against a previous JSONL export")
    sub.add_parser("compact", help="Run VACUUM and WAL checkpoint to reclaim unused SQLite space")
    diff_cmd.add_argument("--previous", required=True, help="Path to previous capabilities.jsonl export")
    diff_cmd.add_argument("--json", action="store_true")
    check.add_argument("--root", action="append", default=[], help="Root to scan. Defaults to ASG ecosystem roots.")

    search = sub.add_parser("search", help="Search capabilities")
    search.add_argument("query")
    search.add_argument("--k", type=int, default=10)
    search.add_argument("--type")

    load = sub.add_parser("load", help="Load one capability")
    load.add_argument("identifier")
    load.add_argument("--detail", choices=["metadata", "entrypoint", "full"], default="entrypoint")

    list_cmd = sub.add_parser("list", help="List capabilities")
    list_cmd.add_argument("--type")
    list_cmd.add_argument("--plugin")
    list_cmd.add_argument("--cursor")
    list_cmd.add_argument("--page-size", type=int, default=50)

    describe = sub.add_parser("describe", help="Describe one capability")
    describe.add_argument("identifier")

    call = sub.add_parser("call", help="Call one capability")
    call.add_argument("identifier")
    call.add_argument("--args", default="{}", help="JSON args")
    call.add_argument("--execute", action="store_true", help="Request non-dry-run execution where supported")
    call.add_argument("--confirm", action="store_true", help="Bypass interactive confirmations")

    delegate = sub.add_parser("delegate", help="Create a delegated task envelope for an agent")
    delegate.add_argument("identifier")
    delegate.add_argument("task")
    delegate.add_argument("--context", default="{}", help="Typed JSON context bound to the delegation")
    delegate.add_argument("--model-tier", default=None, help="Override model tier (qwen-worker, qwen-director, glm, opus)")

    # Task management commands
    task_parser = sub.add_parser("task", help="Manage delegated task envelopes")
    task_sub = task_parser.add_subparsers(dest="task_command", required=True)
    task_list = task_sub.add_parser("list", help="List queued task envelopes")
    task_list.add_argument("--limit", type=int, default=50)
    task_status = task_sub.add_parser("status", help="Get task status")
    task_status.add_argument("task_id")
    task_cancel = task_sub.add_parser("cancel", help="Cancel a task")
    task_cancel.add_argument("task_id")
    task_process = task_sub.add_parser("process", help="Process a queued task")
    task_process.add_argument("task_id")
    task_process.add_argument("--handler", default="default", help="Handler type (default, qwen, glm)")

    report = sub.add_parser("report", help="Record telemetry or coverage report")
    report.add_argument("event")
    report.add_argument("--uri")
    report.add_argument("--payload", default="{}")

    search_load = sub.add_parser(
        "search-load",
        help="Search capabilities and load full entrypoint content for top matches (LLM-optimized output)",
    )
    search_load.add_argument("query")
    search_load.add_argument("--k", type=int, default=5, help="Number of results to search and load")
    search_load.add_argument("--type", default=None, help="Filter by type: agent, skill, command, plugin")

    agent_brief = sub.add_parser(
        "agent-brief",
        help="Produce a compact brief for one or more capabilities (name, description, keywords, type, URI)",
    )
    agent_brief.add_argument("names", nargs="+", help="Capability names or URIs to brief")
    agent_brief.add_argument("--json", action="store_true", help="Output as JSON array instead of Markdown")

    eval_cmd = sub.add_parser("eval", help="Run retrieval golden evals")
    eval_cmd.add_argument("--file", default="evals/retrieval-golden.json")
    eval_cmd.add_argument("--k", type=int, default=10)
    eval_cmd.add_argument("--no-fail", action="store_true", help="Report failed thresholds without exiting non-zero.")

    auth = sub.add_parser("auth", help="Authentication helpers")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    login = auth_sub.add_parser("login", help="Start Microsoft 365 sign-in over the tailnet control plane")
    login.add_argument("--m365", action="store_true", help="Use Microsoft Entra ID")
    login.add_argument("--tenant", default=DEFAULT_TENANT)
    login.add_argument("--device-code", action="store_true", help="Prepare device-code fallback metadata for headless sessions")
    login.add_argument("--redirect-uri", default=os.environ.get("CAPMESH_REDIRECT_URI"))
    login.add_argument("--scope", default="openid profile email offline_access User.Read")
    login.add_argument("--no-browser", action="store_true")
    login.add_argument("--base-url", default=os.environ.get("CAPMESH_TAILNET_BASE_URL"), help="Tailnet capmesh base URL. If omitted, creates a local session only.")
    login.add_argument("--wait", action="store_true", help="Poll the tailnet service until login completes.")
    login.add_argument("--install-env", action="store_true", help="Write returned capmesh bearer metadata to ~/.config/asgcode/capmesh.env.")
    login.add_argument("--json", action="store_true", help="Emit JSON only.")
    status_cmd = auth_sub.add_parser("status", help="Show safe auth/session status")
    status_cmd.add_argument("--json", action="store_true")
    refresh_cmd = auth_sub.add_parser("refresh", help="Print refresh guidance or refresh when a local keychain credential exists")
    refresh_cmd.add_argument("--json", action="store_true")
    logout_cmd = auth_sub.add_parser("logout", help="Revoke local capmesh session metadata")
    logout_cmd.add_argument("--session-id")
    logout_cmd.add_argument("--json", action="store_true")
    doctor_cmd = auth_sub.add_parser("doctor", help="Check tailnet, env, gateway, and auth setup")
    doctor_cmd.add_argument("--base-url", default=os.environ.get("CAPMESH_TAILNET_BASE_URL", "https://capmesh.asg.ts.net"))
    doctor_cmd.add_argument("--json", action="store_true")

    help_cmd = sub.add_parser("help", help="Show capmesh syntax, examples, and LLM operating guidance")
    help_cmd.add_argument("topic", nargs="?", default="overview")
    help_cmd.add_argument("--base-url", default=os.environ.get("CAPMESH_TAILNET_BASE_URL", "https://capmesh.asg.ts.net"))
    help_cmd.add_argument("--json", action="store_true")

    onboard = sub.add_parser("onboard", help="Guide a user or LLM client through tailnet capmesh setup")
    onboard.add_argument("--client", default="all", choices=["all", "codex", "claude", "cursor", "asgcode", "direct"])
    onboard.add_argument("--direct", action="store_true", help="Prefer direct capmesh MCP over local gateway")
    onboard.add_argument("--tenant", default=DEFAULT_TENANT)
    onboard.add_argument("--base-url", default=os.environ.get("CAPMESH_TAILNET_BASE_URL", "https://capmesh.asg.ts.net"))
    onboard.add_argument("--json", action="store_true")

    bootstrap = sub.add_parser("bootstrap", help="Print first-contact instructions for LLM/coder clients on the ASG tailnet")
    bootstrap.add_argument("--client", default="all", choices=["all", "codex", "claude", "cursor", "asgcode", "direct"])
    bootstrap.add_argument("--direct", action="store_true", help="Prefer direct capmesh MCP over local gateway")
    bootstrap.add_argument("--tenant", default=DEFAULT_TENANT)
    bootstrap.add_argument("--base-url", default=os.environ.get("CAPMESH_TAILNET_BASE_URL", "https://capmesh.asg.ts.net"))
    bootstrap.add_argument("--json", action="store_true")

    login_cmd = sub.add_parser("login", help="Sign in to capmesh (interactive — no flags needed)")
    login_cmd.add_argument("--tenant", default=None, help=f"Tenant slug (default: {DEFAULT_TENANT})")
    login_cmd.add_argument("--base-url", default=None, dest="base_url", help="Capmesh service URL (default: auto-detect)")
    login_cmd.add_argument("--device-code", action="store_true", help="Use device code flow (works over SSH)")
    login_cmd.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    login_cmd.add_argument("--json", action="store_true", help="Emit raw JSON result")

    sub.add_parser("me", help="Show current capmesh identity")

    stores = sub.add_parser("stores", help="List or create stores")
    stores.add_argument("--action", choices=["list", "create"], default="list")
    stores.add_argument(
        "--kind",
        help="Store kind: user_private, user_shared, org, app, system, all_users "
        "(all_users = read-only tenant-wide 'everyone' store, admin-managed).",
    )
    stores.add_argument("--json", default="{}")

    namespaces = sub.add_parser("namespaces", help="List or create namespaces")
    namespaces.add_argument("--action", choices=["list", "create"], default="list")
    namespaces.add_argument("--store-id")
    namespaces.add_argument("--json", default="{}")

    share = sub.add_parser("share", help="List, create, or revoke shares")
    share.add_argument("--action", choices=["list", "create", "revoke"], default="list")
    share.add_argument("--id")
    share.add_argument("--capability-uri")
    share.add_argument("--subject-type")
    share.add_argument("--subject-id")
    share.add_argument("--rights", default="discover,load,call")
    share.add_argument("--json", default="{}")

    submit = sub.add_parser("submit", help="Submit a capability for org namespace promotion")
    submit.add_argument("--capability-uri", required=True)
    submit.add_argument("--target-namespace-id", required=True)
    submit.add_argument("--json", default="{}")

    requests = sub.add_parser("requests", help="List promotion requests")
    requests.add_argument("--state")

    approve = sub.add_parser("approve", help="Decide a promotion request")
    approve.add_argument("--request-id", required=True)
    approve.add_argument("--decision", choices=["approve", "reject", "recall", "demote", "yank"], default="approve")
    approve.add_argument("--note", default="")

    roles = sub.add_parser("roles", help="List, assign, or revoke role assignments")
    roles.add_argument("--action", choices=["list", "assign", "revoke"], default="list")
    roles.add_argument("--id")
    roles.add_argument("--subject-type")
    roles.add_argument("--subject-id")
    roles.add_argument("--role")
    roles.add_argument("--scope-type", default="tenant")
    roles.add_argument("--scope-id", default=DEFAULT_TENANT)
    roles.add_argument("--json", default="{}")

    org = sub.add_parser("org", help="List organizations and manage per-user org membership")
    org.add_argument(
        "action",
        choices=["list", "add-member", "remove-member", "list-members"],
        help="list | add-member | remove-member | list-members",
    )
    org.add_argument("--org", help="Org slug, id, or store id (required for member actions).")
    org.add_argument("--subject-type", default="user")
    org.add_argument("--subject-id", help="User email/identity for add/remove member.")
    org.add_argument("--role", choices=["member", "namespace_admin", "org_admin"], default="member")
    org.add_argument("--expires-at")
    org.add_argument("--json", default="{}")

    audit_cmd = sub.add_parser("audit", help="List governance audit events")
    audit_cmd.add_argument("--limit", type=int, default=50)

    sync_cmd = sub.add_parser("sync", help="Show SCIM/Graph/Teams sync state, or run a source sync")
    sync_cmd.add_argument(
        "source",
        nargs="?",
        choices=["tailscale"],
        help="Optional source to sync now (e.g. 'tailscale'). Omit to show sync state.",
    )
    sync_cmd.add_argument("--source", dest="source_flag", choices=["tailscale"], help="Alternative to the positional source.")
    sync_cmd.add_argument("--tailnet", help="Tailnet name (defaults to the OAuth credential's tailnet).")
    sync_cmd.add_argument("--dry-run", action="store_true", help="Compute the sync diff without writing.")
    sync_cmd.add_argument("--json", dest="sync_json", action="store_true", help="Emit machine-readable JSON (default).")

    capabilities = sub.add_parser("capabilities", help="Create, edit, diff, validate, share, submit, or prepare capability review artifacts")
    capabilities.add_argument("--action", default="template")
    capabilities.add_argument("--json", default="{}")
    capabilities.add_argument("--capability-uri")
    capabilities.add_argument("--name")
    capabilities.add_argument("--content-file")

    sub.add_parser("tools", help="Print the fixed tool inventory")
    sub.add_parser("migrate", help="Run pending schema migrations")
    lifecycle_cmd = sub.add_parser("lifecycle", help="Manage capability lifecycle transitions")
    lifecycle_cmd.add_argument("--action", default="list", help="list or transition")
    lifecycle_cmd.add_argument("--capability-uri")
    lifecycle_cmd.add_argument("--target", help="Target lifecycle state")
    lifecycle_cmd.add_argument("--reason")
    owners_cmd = sub.add_parser("owners", help="List namespace owners and capability ownership")
    owners_cmd.add_argument("--owner", help="Filter by specific owner")
    break_glass_cmd = sub.add_parser("break-glass", help="Manage break-glass admin sessions")
    break_glass_cmd.add_argument("--action", default="list", help="list, grant, or revoke")
    break_glass_cmd.add_argument("--principal")
    break_glass_cmd.add_argument("--reason")
    break_glass_cmd.add_argument("--session-id")
    sub.add_parser("semver", help="Check for version conflicts in the catalog")
    deps_cmd = sub.add_parser("deps", help="Manage capability dependencies")
    deps_cmd.add_argument("--action", default="list", help="list, add, remove, check, cycles")
    deps_cmd.add_argument("--capability-uri")
    deps_cmd.add_argument("--depends-on")
    deps_cmd.add_argument("--version-constraint", default="*")
    slo_cmd = sub.add_parser("slo", help="Show SLO status for operations")
    slo_cmd.add_argument("--operation", help="Filter to specific operation")
    reglog_cmd = sub.add_parser("reglog", help="View or verify the registry log")
    reglog_cmd.add_argument("--action", default="list", help="list, verify, head")
    reglog_cmd.add_argument("--limit", type=int, default=50)
    sub.add_parser("audit-deps", help="Run dependency audit")
    dashboard_cmd = sub.add_parser("dashboard", help="Show operational metrics dashboard")
    dashboard_cmd.add_argument("--capability-uri", help="Get detail for a specific capability")
    query_cmd = sub.add_parser("expand-query", help="Expand a search query using taxonomy")
    query_cmd.add_argument("--query", required=True)
    hook_cmd = sub.add_parser("hook", help="Plugin authoring hook for cap.json emission")
    hook_cmd.add_argument("--package-path", required=True)
    hook_cmd.add_argument("--write", action="store_true")
    sub.add_parser("serve", help="Serve the JSON-RPC stdio router")
    serve_http = sub.add_parser("serve-http", help="Serve tailnet-scoped HTTP/JSON-RPC")
    serve_http.add_argument("--host", default=os.environ.get("CAPMESH_BIND_HOST", "127.0.0.1"), help="Bind address. Use 0.0.0.0 only with --interface.")
    serve_http.add_argument("--port", type=int, default=17778)
    serve_http.add_argument("--interface", default=os.environ.get("CAPMESH_BIND_INTERFACE"), help="Linux interface name to bind with SO_BINDTODEVICE, for example tailscale0.")

    gates_cmd = sub.add_parser("gates", help="Run capability promotion gates")
    gates_sub = gates_cmd.add_subparsers(dest="gates_command", required=True)
    gates_tests = gates_sub.add_parser("tests", help="Run the per-capability tests presence gate")
    gates_tests.add_argument("identifier", help="Capability URI or name to gate-check")
    gates_run = gates_sub.add_parser(
        "run",
        help="Run the full promotion gate set on a capability and report per-gate results",
    )
    gates_run.add_argument("identifier", help="Capability URI or name to gate-check")
    gates_run.add_argument(
        "--tenant",
        default=DEFAULT_TENANT,
        help=f"Tenant slug for the gate run (default: {DEFAULT_TENANT}).",
    )
    gates_run.add_argument(
        "--write",
        action="store_true",
        help="Persist a promotion_gate_runs row per gate. Without it, the run is a dry-run (read-only).",
    )

    args = parser.parse_args(argv)
    roots = tuple(args.root or configured_default_roots()) if hasattr(args, "root") else configured_default_roots()

    if (
        args.command in AUTHORITY_ONLY_COMMANDS
        and not is_authoritative_node()
        and not offline_replica_rehearsal_allowed(args.command, args.db)
    ):
        print(
            json.dumps(
                {
                    "error": {
                        "code": "NOT_AUTHORITATIVE",
                        "message": "Run this capability install or maintenance operation through the authoritative node.",
                        "details": topology_payload(),
                    }
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(3)

    if args.command == "ingest":
        auto_approval_actor = configured_superadmin_auto_approval()

        def apply_install_policy(con: Any) -> dict[str, Any]:
            assert auto_approval_actor is not None
            approval = approve_catalog(
                con,
                Principal(subject=auto_approval_actor, tenant_id=DEFAULT_TENANT, roles=("org_admin",)),
                commit=False,
            )
            if not approval["catalogApproved"]:
                raise RuntimeError(
                    "superadmin install approval failed closed: "
                    f"failed={approval['failed']} remaining={approval['remainingNonCompliant']}"
                )
            return {
                "policy": "superadmin-immediate-after-gates",
                "actor": auto_approval_actor,
                **approval,
            }

        result = ingest_index(
            args.db,
            roots,
            enable_vector=not args.no_vector,
            post_ingest=apply_install_policy if auto_approval_actor else None,
        )
        con = connect(args.db)
        exported = export_jsonl(con, args.export_jsonl)
        con.close()
        result["exportedCapabilities"] = exported
        result["exportPath"] = str(Path(args.export_jsonl).expanduser())
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "rebuild":
        result = stage_rebuild_index(
            args.db,
            roots,
            enable_vector=not args.no_vector,
            approved_removals=args.approved_removals,
            candidate_path=args.candidate_path,
        )
        if args.promote:
            result["promotion"] = promote_shadow_database(
                args.db,
                result["candidatePath"],
                workers_drained=bool(args.workers_drained),
                expected_sha256=result["candidateSha256"],
            )
            result["operation"] = "rebuild.promoted"
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    con = connect(args.db)
    init_db(con)
    router = CapabilityRouter(con, roots=roots)
    principal = Principal.from_dict(json.loads(args.principal_json)) if args.principal_json else Principal()

    if args.command == "check":
        print(json.dumps(coverage_report(con, roots), indent=2, sort_keys=True))
    elif args.command == "compact":
        before_size = Path(args.db).expanduser().stat().st_size
        con.execute("VACUUM")
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        after_size = Path(args.db).expanduser().stat().st_size
        print(json.dumps({
            "compacted": True,
            "dbPath": str(Path(args.db).expanduser()),
            "bytesBefore": before_size,
            "bytesAfter": after_size,
            "bytesReclaimed": before_size - after_size,
        }, indent=2, sort_keys=True))
    elif args.command == "search":
        print_result(router.call("cap.search", {"query": args.query, "k": args.k, "type": args.type, "principal": principal.__dict__}))
    elif args.command == "load":
        print_result(router.call("cap.load", {"uri": args.identifier, "name": args.identifier, "detail": args.detail, "principal": principal.__dict__}))
    elif args.command == "list":
        print_result(
            router.call(
                "cap.list",
                {
                    "type": args.type,
                    "plugin": args.plugin,
                    "cursor": args.cursor,
                    "pageSize": args.page_size,
                    "principal": principal.__dict__,
                },
            )
        )
    elif args.command == "describe":
        print_result(router.call("cap.describe", {"uri": args.identifier, "name": args.identifier, "principal": principal.__dict__}))
    elif args.command == "call":
        print_result(
            router.call(
                "cap.call",
                {
                    "uri": args.identifier,
                    "name": args.identifier,
                    "args": json.loads(args.args),
                    "dryRun": not args.execute,
                    "confirm": args.confirm,
                    "principal": principal.__dict__,
                },
            )
        )
    elif args.command == "delegate":
        print_result(router.call("cap.delegate", {
            "uri": args.identifier, "name": args.identifier, "task": args.task, "modelTier": args.model_tier,
            "context": json_arg(args.context), "principal": principal.__dict__,
        }))
    elif args.command == "report":
        print_result(
            router.call(
                "cap.report",
                {"event": args.event, "uri": args.uri, "payload": json.loads(args.payload), "principal": principal.__dict__},
            )
        )
    elif args.command == "task":
        from .task_runner import cancel_task, list_queued_tasks, process_task, task_status
        con = connect(args.db)
        if args.task_command == "list":
            tasks = list_queued_tasks(con, limit=args.limit)
            print(json.dumps(tasks, indent=2, default=str))
        elif args.task_command == "status":
            try:
                result = task_status(con, args.task_id)
                print(json.dumps(result, indent=2, default=str))
            except ValueError as e:
                print(f"Error: {e}")
        elif args.task_command == "cancel":
            try:
                result = cancel_task(con, args.task_id)
                print(json.dumps(result, indent=2, default=str))
            except ValueError as e:
                print(f"Error: {e}")
        elif args.task_command == "process":
            def _default_handler(envelope):
                from .task_dispatcher import dispatch_task
                # Use the envelope's modelRouting if present, otherwise auto-route
                return dispatch_task(envelope)
            def _qwen_handler(envelope):
                from .model_router import route_model
                from .task_dispatcher import dispatch_task
                # Force Qwen backend by overriding to qwen-director tier
                routing = route_model(risk_tier="low", task=envelope.get("task", ""), override="qwen-director")
                return dispatch_task(envelope, routing=routing)
            def _glm_handler(envelope):
                from .model_router import route_model
                from .task_dispatcher import dispatch_task
                # Force GLM backend by overriding to glm tier
                routing = route_model(risk_tier="low", task=envelope.get("task", ""), override="glm")
                return dispatch_task(envelope, routing=routing)
            handler = {"default": _default_handler, "qwen": _qwen_handler, "glm": _glm_handler}.get(args.handler, _default_handler)
            try:
                result = process_task(con, args.task_id, handler)
                print(json.dumps(result, indent=2, default=str))
            except ValueError as e:
                print(f"Error: {e}")
        con.close()
    elif args.command == "search-load":
        search_result = router.call("cap.search", {"query": args.query, "k": args.k, "type": args.type, "principal": principal.__dict__})
        rows = search_result.get("structuredContent", {}).get("results", [])
        if not rows:
            print(json.dumps({"status": "no_matches", "query": args.query, "type": args.type, "results": []}, indent=2))
            return
        # Deduplicate by name (same agent may appear under multiple plugins/URIs)
        seen: dict[str, dict] = {}
        for row in rows:
            name = row.get("name", "")
            if name and name not in seen:
                seen[name] = row
        unique_rows = list(seen.values())[: args.k]
        loaded = []
        for row in unique_rows:
            identifier = row.get("name", "") or row.get("uri", "")
            try:
                load_resp = router.call(
                    "cap.load",
                    {"uri": row.get("uri", ""), "name": identifier, "detail": "entrypoint", "principal": principal.__dict__},
                )
                structured = load_resp.get("structuredContent", load_resp)
                entry = {
                    "name": structured.get("name", identifier),
                    "title": structured.get("title", ""),
                    "type": structured.get("type", ""),
                    "description": structured.get("description", ""),
                    "uri": structured.get("uri", ""),
                    "plugin": structured.get("plugin", ""),
                    "entrypoint": structured.get("content", ""),
                }
                loaded.append(entry)
            except Exception:  # noqa: BLE001
                loaded.append({"name": identifier, "error": "load failed"})
        print(json.dumps({"status": "done", "query": args.query, "type": args.type, "loaded": len(loaded), "results": loaded}, indent=2))
    elif args.command == "agent-brief":
        briefs: list[dict] = []
        for name in args.names:
            try:
                desc_resp = router.call(
                    "cap.describe",
                    {"uri": name, "name": name, "principal": principal.__dict__},
                )
                structured = desc_resp.get("structuredContent", desc_resp)
                briefs.append({
                    "name": structured.get("name", name),
                    "title": structured.get("title", ""),
                    "type": structured.get("type", ""),
                    "description": structured.get("description", ""),
                    "uri": structured.get("uri", ""),
                    "plugin": structured.get("plugin", ""),
                    "lifecycle": structured.get("lifecycle", ""),
                    "approvalState": structured.get("approvalState", ""),
                    "mutating": structured.get("mutating", False),
                    "visibility": structured.get("visibility", ""),
                })
            except Exception:  # noqa: BLE001
                briefs.append({"name": name, "error": "describe failed"})
        if args.json:
            print(json.dumps(briefs, indent=2))
        else:
            for b in briefs:
                print(f"## {b['name']}")
                print(f"- **Title:** {b['title']}")
                print(f"- **Type:** {b['type']}")
                print(f"- **URI:** `{b['uri']}`")
                print(f"- **Plugin:** {b.get('plugin', '')}")
                print(f"- **Description:** {b['description']}")
                print(f"- **Lifecycle:** {b.get('lifecycle', 'N/A')}")
                print(f"- **Approval:** {b.get('approvalState', 'N/A')}")
                print(f"- **Mutating:** {b.get('mutating', False)}")
                print(f"- **Visibility:** {b.get('visibility', 'N/A')}")
                print()
    elif args.command == "eval":
        eval_result = run_eval(router, args.file, args.k)
        print(json.dumps(eval_result, indent=2, sort_keys=True))
        if not eval_result["passed"] and not args.no_fail:
            con.close()
            raise SystemExit(2)
    elif args.command == "login":
        con.close()
        interactive_login(args)
        return
    elif args.command == "auth":
        print(json.dumps(handle_auth_command(con, args), indent=2, sort_keys=True))
    elif args.command == "help":
        print(json.dumps(help_payload(args.topic, base_url=args.base_url), indent=2, sort_keys=True))
    elif args.command == "onboard":
        print(json.dumps(onboard_command(args), indent=2, sort_keys=True))
    elif args.command == "bootstrap":
        print(json.dumps(bootstrap_command(args), indent=2, sort_keys=True))
    elif args.command == "me":
        print(json.dumps(current_user(con, principal), indent=2, sort_keys=True))
    elif args.command == "stores":
        payload = json_arg(args.json)
        if args.action == "create":
            print(json.dumps(create_store(con, principal, payload), indent=2, sort_keys=True))
        else:
            print(json.dumps({"items": list_stores(con, principal, args.kind)}, indent=2, sort_keys=True))
    elif args.command == "namespaces":
        payload = json_arg(args.json)
        if args.store_id:
            payload.setdefault("storeId", args.store_id)
        if args.action == "create":
            print(json.dumps(create_namespace(con, principal, payload), indent=2, sort_keys=True))
        else:
            print(json.dumps({"items": list_namespaces(con, principal, args.store_id)}, indent=2, sort_keys=True))
    elif args.command == "share":
        payload = json_arg(args.json)
        if args.capability_uri:
            payload.setdefault("capabilityUri", args.capability_uri)
        if args.subject_type:
            payload.setdefault("subjectType", args.subject_type)
        if args.subject_id:
            payload.setdefault("subjectId", args.subject_id)
        payload.setdefault("rights", [item.strip() for item in args.rights.split(",") if item.strip()])
        if args.action == "create":
            print(json.dumps(create_share(con, principal, payload), indent=2, sort_keys=True))
        elif args.action == "revoke":
            print(json.dumps(revoke_share(con, principal, str(args.id or payload.get("shareId") or "")), indent=2, sort_keys=True))
        else:
            print(json.dumps({"items": list_shares(con, principal, args.capability_uri)}, indent=2, sort_keys=True))
    elif args.command == "submit":
        payload = json_arg(args.json)
        payload.setdefault("capabilityUri", args.capability_uri)
        payload.setdefault("targetNamespaceId", args.target_namespace_id)
        from .governance import submit_promotion

        print(json.dumps(submit_promotion(con, principal, payload), indent=2, sort_keys=True))
    elif args.command == "requests":
        print(json.dumps({"items": list_requests(con, principal, args.state)}, indent=2, sort_keys=True))
    elif args.command == "approve":
        print(json.dumps(approve_request(con, principal, {"requestId": args.request_id, "decision": args.decision, "note": args.note}), indent=2, sort_keys=True))
    elif args.command == "roles":
        payload = json_arg(args.json)
        if args.action == "assign":
            payload.setdefault("subjectType", args.subject_type)
            payload.setdefault("subjectId", args.subject_id)
            payload.setdefault("role", args.role)
            payload.setdefault("scopeType", args.scope_type)
            payload.setdefault("scopeId", args.scope_id)
            print(json.dumps(assign_role(con, principal, payload), indent=2, sort_keys=True))
        elif args.action == "revoke":
            print(json.dumps(revoke_role(con, principal, str(args.id or payload.get("assignmentId") or "")), indent=2, sort_keys=True))
        else:
            print(json.dumps({"items": list_roles(con, principal)}, indent=2, sort_keys=True))
    elif args.command == "org":
        payload = json_arg(args.json)
        if args.org:
            payload.setdefault("org", args.org)
        if args.subject_id:
            payload.setdefault("subjectId", args.subject_id)
        payload.setdefault("subjectType", args.subject_type)
        if args.expires_at:
            payload.setdefault("expiresAt", args.expires_at)
        if args.action == "add-member":
            payload.setdefault("role", args.role)
            print(json.dumps(add_org_member(con, principal, payload), indent=2, sort_keys=True))
        elif args.action == "remove-member":
            print(json.dumps(remove_org_member(con, principal, payload), indent=2, sort_keys=True))
        elif args.action == "list-members":
            print(json.dumps({"items": list_org_members(con, principal, str(args.org or payload.get("org") or ""))}, indent=2, sort_keys=True))
        else:
            print(json.dumps({"items": list_organizations(con, principal)}, indent=2, sort_keys=True))
    elif args.command == "audit":
        print(json.dumps({"items": list_audit_events(con, principal, args.limit)}, indent=2, sort_keys=True))
    elif args.command == "sync":
        source = getattr(args, "source", None) or getattr(args, "source_flag", None)
        if source == "tailscale":
            from . import tailscale_sync
            from .governance import evaluate_access

            allowed, reason = evaluate_access(
                con, principal, right="manage", resource_uri=f"tenant:{principal.tenant_id or DEFAULT_TENANT}"
            )
            if not allowed:
                raise PermissionError(reason or "Running the tailscale sync requires the manage right.")
            result = tailscale_sync.run(
                con,
                tenant_id=principal.tenant_id or DEFAULT_TENANT,
                tailnet=args.tailnet,
                actor=principal.subject,
                dry_run=bool(args.dry_run),
            )
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(json.dumps(sync_summary(con, principal), indent=2, sort_keys=True))
    elif args.command == "capabilities":
        payload = json_arg(args.json)
        payload.setdefault("action", args.action)
        if args.capability_uri:
            payload.setdefault("capabilityUri", args.capability_uri)
        if args.name:
            payload.setdefault("name", args.name)
        if args.content_file:
            payload.setdefault("content", Path(args.content_file).read_text(encoding="utf-8"))
        print(json.dumps(manage_capability(con, principal, payload), indent=2, sort_keys=True))
    elif args.command == "tools":
        print(json.dumps(tool_schemas(), indent=2, sort_keys=True))
    elif args.command == "migrate":
        from .migrations import register_builtin_migrations, run_migrations
        register_builtin_migrations()
        result = run_migrations(con)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "lifecycle":
        from .lifecycle_transitions import list_lifecycle_states, transition_capability
        if args.action == "list":
            print(json.dumps(list_lifecycle_states(con), indent=2, sort_keys=True))
        elif args.action == "transition":
            result = transition_capability(con, args.capability_uri, args.target, actor=principal.subject, reason=args.reason or "")
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(json.dumps(list_lifecycle_states(con), indent=2, sort_keys=True))
    elif args.command == "owners":
        from .namespace_owners import namespace_owner_map, namespaces_by_owner
        if args.owner:
            print(json.dumps(namespaces_by_owner(con, args.owner), indent=2, sort_keys=True))
        else:
            print(json.dumps(namespace_owner_map(con), indent=2, sort_keys=True))
    elif args.command == "break-glass":
        from .break_glass import grant_break_glass, list_break_glass_sessions, revoke_break_glass
        if args.action == "grant":
            result = grant_break_glass(con, args.principal, args.reason, granted_by=principal.subject)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.action == "revoke":
            result = revoke_break_glass(con, args.session_id, revoked_by=principal.subject)
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(json.dumps(list_break_glass_sessions(con, active_only=args.action == "active"), indent=2, sort_keys=True))
    elif args.command == "semver":
        from .semver_policy import check_version_conflicts
        caps = []
        for row in con.execute("SELECT canonical_key, version FROM capabilities WHERE tenant_id = ?", (principal.tenant_id or "asg",)).fetchall():
            caps.append({"canonicalKey": str(row["canonical_key"]), "version": str(row["version"])})
        print(json.dumps(check_version_conflicts(caps), indent=2, sort_keys=True))
    elif args.command == "deps":
        from .dependency_graph import (
            add_dependency,
            check_compatibility,
            detect_cycles,
            list_dependencies,
            remove_dependency,
            topological_sort,
        )
        if args.action == "add":
            result = add_dependency(con, args.capability_uri, args.depends_on, version_constraint=args.version_constraint)
        elif args.action == "remove":
            result = remove_dependency(con, args.capability_uri, args.depends_on)
        elif args.action == "check":
            result = check_compatibility(con, args.capability_uri)
        elif args.action == "cycles":
            result = {"cycles": detect_cycles(con)}
        elif args.action == "topo":
            result = {"order": topological_sort(con)}
        else:
            result = {"dependencies": list_dependencies(con, args.capability_uri)} if args.capability_uri else {"cycles": detect_cycles(con)}
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "slo":
        from .slo_tracking import get_tracker, slo_summary
        tracker = get_tracker()
        result = tracker.slo_status(args.operation) if args.operation else slo_summary()
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "reglog":
        from .registry_log import get_log_head, list_log_entries, verify_log_chain
        if args.action == "verify":
            result = verify_log_chain(con)
        elif args.action == "head":
            result = get_log_head(con)
        else:
            result = list_log_entries(con, limit=args.limit)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "audit-deps":
        from .dependency_audit import run_dependency_audit
        result = run_dependency_audit(con)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "dashboard":
        from .dashboard import capability_detail, capability_volume_dashboard
        if args.capability_uri:
            result = capability_detail(con, args.capability_uri)
        else:
            result = capability_volume_dashboard(con)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "expand-query":
        from .query_expansion import expand_query
        result = expand_query(args.query)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "hook":
        from .plugin_hook import generate_cap_json
        result = generate_cap_json(args.package_path, write=args.write)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "serve":
        con.close()
        serve_stdio(args.db, roots=roots)
        return
    elif args.command == "serve-http":
        from .server import serve_http as run_http

        con.close()
        run_http(args.db, host=args.host, port=args.port, interface=args.interface, roots=roots)
        return
    elif args.command == "gates":
        if args.gates_command == "run":
            print(json.dumps(gates_run_handler(con, args), indent=2, sort_keys=True))
        else:
            print(json.dumps(gates_tests_handler(con, args), indent=2, sort_keys=True))
        con.close()
        return
    con.close()


def print_result(result: dict[str, Any]) -> None:
    print(json.dumps(result.get("structuredContent", result), indent=2, sort_keys=True))


def json_arg(raw: str) -> dict[str, Any]:
    data = json.loads(raw or "{}")
    if not isinstance(data, dict):
        raise SystemExit("JSON argument must decode to an object.")
    return data


def handle_auth_command(con, args: argparse.Namespace) -> dict[str, Any]:
    if args.auth_command == "status":
        principal = Principal()
        return {"localEnv": local_capmesh_env_status(), "sessionStatus": auth_status(con, principal)}
    if args.auth_command == "doctor":
        return auth_doctor(args.base_url)
    if args.auth_command == "refresh":
        return {
            "refreshed": False,
            "message": "Automatic M365 refresh uses the local keychain-backed gateway session when installed. Run capmesh auth login --m365 --tenant asg --install-env if this host is not configured.",
            "localEnv": local_capmesh_env_status(),
        }
    if args.auth_command == "logout":
        return revoke_capmesh_session(con, Principal(), session_id=args.session_id)
    if args.auth_command != "login" or not args.m365:
        raise SystemExit("Supported auth commands: login --m365, status, refresh, logout, doctor.")
    if args.base_url:
        return remote_auth_login(args)
    redirect_uri = args.redirect_uri or os.environ.get("CAPMESH_TAILNET_BASE_URL", "http://127.0.0.1:17778").rstrip("/") + "/oauth/callback"
    session = create_oauth_session(
        con,
        tenant_id=args.tenant,
        flow="device_code" if args.device_code else "authorization_code_pkce",
        redirect_uri=redirect_uri,
        scope=args.scope,
        metadata={"m365": True, "tailnetOnly": True},
    )
    client_id = os.environ.get("CAPMESH_M365_CLIENT_ID")
    authority = os.environ.get("CAPMESH_ENTRA_AUTHORITY", "https://login.microsoftonline.com/organizations/oauth2/v2.0")
    session["tenant"] = args.tenant
    session["tailnetOnly"] = True
    if client_id and not args.device_code:
        auth_url = (
            f"{authority.rstrip('/')}/authorize"
            f"?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&response_mode=query"
            f"&scope={args.scope.replace(' ', '%20')}"
            f"&state={session['state']}"
            f"&nonce={session['nonce']}"
            f"&code_challenge={session['codeChallenge']}"
            f"&code_challenge_method=S256"
        )
        session["authorizationUrl"] = auth_url
        if not args.no_browser:
            webbrowser.open(auth_url)
    elif not client_id:
        session["appRegistrationRequired"] = "Set CAPMESH_M365_CLIENT_ID on the authoritative node to build the Entra authorization URL."
    if args.device_code:
        session["deviceCodeRequired"] = "Use the M365 gateway or Entra app registration on the authoritative node to request a device code; this CLI does not store raw refresh tokens."
    return session


def interactive_login(args: argparse.Namespace) -> None:
    """Interactive login — just type 'capmesh login' and follow the prompts."""
    import sys

    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    emit_json = getattr(args, "json", False)

    def say(msg: str = "", end: str = "\n") -> None:
        if not emit_json:
            print(msg, end=end, flush=True)

    say("capmesh login")
    say("─" * 42)

    # Auto-detect base URL: arg > env > probe default
    base_url: str | None = (
        getattr(args, "base_url", None)
        or os.environ.get("CAPMESH_TAILNET_BASE_URL")
        or os.environ.get("CAPMESH_BASE_URL")
    )
    if not base_url:
        candidate = os.environ.get("CAPMESH_BASE_URL", "http://127.0.0.1:8000")
        say(f"  Reaching {candidate} ... ", end="")
        try:
            http_json("GET", f"{candidate}/health", None, timeout=5)
            base_url = candidate
            say("✓")
        except RuntimeError:
            say("✗")
            say("")
            say("  Could not reach the capmesh tailnet service.")
            say("  Is Tailscale connected?  (tailscale status)")
            raise SystemExit(1)
    else:
        say(f"  Service: {base_url}")

    # Already logged in?
    env_status = local_capmesh_env_status()
    if env_status["hasBearerToken"]:
        say(f"\n  Already logged in → {env_status['path']}")
        if is_tty and not emit_json:
            try:
                choice = input("  Sign in again to replace token? [y/N]: ").strip().lower()
            except EOFError:
                choice = ""
            if choice not in ("y", "yes"):
                say("  No change.")
                return
        else:
            say("  Run 'capmesh auth logout' first, then 'capmesh login' to replace.")
            return

    tenant = getattr(args, "tenant", None) or os.environ.get("CAPMESH_DEFAULT_TENANT") or DEFAULT_TENANT
    say(f"  Tenant:  {tenant}")

    # Auth method: prompt if interactive terminal, else default to browser
    device_code = getattr(args, "device_code", False)
    no_browser = getattr(args, "no_browser", False)
    if not device_code and is_tty and not no_browser and not emit_json:
        say("")
        say("  How would you like to sign in?\n")
        say("    [1]  Browser       (Microsoft 365 sign-in page)")
        say("    [2]  Device code   (paste a one-time code — works over SSH)")
        say("")
        try:
            choice = input("  Select [1]: ").strip() or "1"
        except EOFError:
            choice = "1"
        device_code = (choice == "2")
    say("")

    # Start the auth session on the server
    path = "/api/v1/auth/m365/device-code" if device_code else "/api/v1/auth/m365/start"
    scope = "openid profile email offline_access User.Read"
    payload = {
        "tenant": tenant,
        "scope": scope,
        "redirectUri": f"{base_url.rstrip('/')}/oauth/callback",
        "client": "cli",
    }
    try:
        session = http_json("POST", f"{base_url.rstrip('/')}{path}", payload)
    except RuntimeError as exc:
        say(f"  ✗ Could not start sign-in: {exc}")
        raise SystemExit(1)

    if device_code:
        user_code = session.get("userCode") or ""
        verify_uri = session.get("verificationUri") or "https://microsoft.com/devicelogin"
        say(f"  Go to:    {verify_uri}")
        say(f"  Code:     {user_code}")
        say("")
        say("  Waiting for sign-in (up to 10 minutes)...")
    else:
        auth_url = session.get("authorizationUrl") or ""
        if auth_url and not no_browser:
            say("  Opening browser...")
            webbrowser.open(auth_url)
        elif auth_url:
            say(f"  Open this URL to sign in:\n    {auth_url}")
        say("  Waiting for sign-in (up to 10 minutes)...")

    session_id = str(session.get("id") or "")
    if not session_id:
        say("  ✗ Server returned no session ID.")
        raise SystemExit(1)

    try:
        result = poll_remote_login(base_url.rstrip("/"), session_id, install_env=True, timeout_seconds=600)
    except RuntimeError as exc:
        say(f"  ✗ {exc}")
        raise SystemExit(1)

    if emit_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if result.get("timedOut"):
        say("\n  ✗ Timed out — sign-in was not completed within 10 minutes.")
        raise SystemExit(1)

    if result.get("status") == "completed" or result.get("installedEnv"):
        say("\n  ✓ Signed in!")
        if result.get("installedEnv"):
            say(f"  Token saved: {result['installedEnv']}")
        sub_info = result.get("principal", {})
        if sub_info.get("subject"):
            say(f"  Identity:  {sub_info['subject']}")
        say("")
        say("  All AI coding tools on this tailnet will pick up the token automatically.")
    else:
        say(f"\n  ✗ Sign-in did not complete (status: {result.get('status', 'unknown')}). Try again.")
        raise SystemExit(1)


def remote_auth_login(args: argparse.Namespace) -> dict[str, Any]:
    base_url = str(args.base_url).rstrip("/")
    path = "/api/v1/auth/m365/device-code" if args.device_code else "/api/v1/auth/m365/start"
    payload = {
        "tenant": args.tenant,
        "scope": args.scope,
        "redirectUri": args.redirect_uri or f"{base_url}/oauth/callback",
        "client": "cli",
    }
    session = http_json("POST", f"{base_url}{path}", payload)
    if session.get("authorizationUrl") and not args.no_browser:
        webbrowser.open(str(session["authorizationUrl"]))
    if args.wait:
        session = poll_remote_login(base_url, str(session["id"]), install_env=bool(args.install_env), timeout_seconds=600)
    elif args.install_env and session.get("bearerToken"):
        install_capmesh_env(base_url, str(session["bearerToken"]), str(session.get("expiresAt") or ""))
    return session


def poll_remote_login(base_url: str, session_id: str, *, install_env: bool, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last: dict[str, Any] = {"id": session_id, "status": "pending"}
    while time.time() < deadline:
        last = http_json("POST", f"{base_url.rstrip('/')}/api/v1/auth/m365/poll", {"sessionId": session_id, "consumeTokens": install_env})
        if last.get("status") == "completed":
            token = last.get("bearerToken")
            if install_env and token:
                install_capmesh_env(base_url, str(token), str((last.get("capmeshSession") or {}).get("expiresAt") or ""))
                last["installedEnv"] = str(capmesh_env_path())
                last["bearerToken"] = "[stored]"
                if last.get("m365RefreshToken"):
                    store_keychain_secret("asg-capmesh-m365-refresh", session_id, str(last["m365RefreshToken"]))
                    last["m365RefreshToken"] = "[stored-in-keychain]"
            return last
        time.sleep(int(last.get("interval") or 3))
    last["timedOut"] = True
    return last


def onboard_command(args: argparse.Namespace) -> dict[str, Any]:
    payload = onboarding_payload(base_url=args.base_url, client=args.client, direct=args.direct, tenant=args.tenant)
    payload["localEnv"] = local_capmesh_env_status()
    payload["doctor"] = auth_doctor(args.base_url)
    return payload


def bootstrap_command(args: argparse.Namespace) -> dict[str, Any]:
    payload = bootstrap_payload(base_url=args.base_url, client=args.client, direct=args.direct, tenant=args.tenant)
    payload["localEnv"] = local_capmesh_env_status()
    payload["doctor"] = auth_doctor(args.base_url)
    return payload


def auth_doctor(base_url: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    env_status = local_capmesh_env_status()
    checks.append({"name": "capmesh env", "ok": env_status["exists"] and env_status["hasBearerToken"], "details": env_status})
    checks.append({"name": "tailscale command", "ok": command_exists("tailscale")})
    checks.append({"name": "gateway helper", "ok": command_exists("asgcode-mcp-gateway")})
    try:
        health = http_json("GET", f"{base_url.rstrip('/')}/health", None, timeout=5)
        checks.append({"name": "tailnet capmesh health", "ok": health.get("status") == "ok", "details": health})
    except RuntimeError as exc:
        checks.append({"name": "tailnet capmesh health", "ok": False, "details": str(exc)})
    return {
        "ok": all(bool(item["ok"]) for item in checks),
        "baseUrl": base_url.rstrip("/"),
        "checks": checks,
        "repair": [
            f"capmesh auth login --m365 --tenant {DEFAULT_TENANT} --base-url {base_url.rstrip('/')} --wait --install-env",
            "asgcode-mcp-gateway doctor",
        ],
    }


def http_json(method: str, url: str, payload: dict[str, Any] | None, *, timeout: int = 30) -> dict[str, Any]:
    data = json.dumps(payload or {}).encode("utf-8") if method.upper() != "GET" else None
    request = Request(url, data=data, method=method.upper(), headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{url} returned HTTP {exc.code}: {body[:400]}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach {url}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise TypeError(f"{url} returned a non-object JSON response.")
    return parsed


def capmesh_env_path() -> Path:
    return Path(os.environ.get("ASGCODE_CAPMESH_ENV", "~/.config/asgcode/capmesh.env")).expanduser()


def local_capmesh_env_status() -> dict[str, Any]:
    path = capmesh_env_path()
    status = {"path": str(path), "exists": path.exists(), "readable": os.access(path, os.R_OK), "hasBearerToken": False, "baseUrl": None}
    if path.exists() and os.access(path, os.R_OK):
        text = path.read_text(encoding="utf-8", errors="replace")
        status["hasBearerToken"] = "CAPMESH_BEARER_TOKEN=" in text and "CAPMESH_BEARER_TOKEN=\n" not in text
        for line in text.splitlines():
            if line.startswith(("CAPMESH_BASE_URL=", "CAPMESH_TAILNET_BASE_URL=")):
                status["baseUrl"] = line.partition("=")[2]
                break
        mode = stat.S_IMODE(path.stat().st_mode)
        status["mode"] = oct(mode)
        status["modeOk"] = mode & 0o077 == 0
    return status


def install_capmesh_env(base_url: str, bearer_token: str, expires_at: str) -> None:
    path = capmesh_env_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        [
            f"CAPMESH_BASE_URL={base_url.rstrip('/')}",
            f"CAPMESH_TAILNET_BASE_URL={base_url.rstrip('/')}",
            f"CAPMESH_BEARER_TOKEN={bearer_token}",
            f"CAPMESH_TOKEN_EXPIRES_AT={expires_at}",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def store_keychain_secret(service: str, account: str, secret: str) -> bool:
    if command_exists("asgcode-keychain"):
        result = subprocess.run(
            ["asgcode-keychain", "set", "--service", service, "--account", account, "--value", secret],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return True
    # The macOS `security add-generic-password -w <secret>` CLI has no stdin mode
    # for -w, so passing the secret places the refresh token in argv (visible via
    # ps/ps auxe on a shared tailnet device). With asgcode-keychain absent we
    # therefore skip the keychain `security` call by default: the bearer token
    # the client actually uses is already persisted in the 0600 capmesh.env file
    # (install_capmesh_env), and the refresh token is a write-only cache that is
    # never read back from the keychain here. Operators who require the legacy
    # keychain write can opt in with CAPMESH_KEYCHAIN_ARGV_FALLBACK=1, accepting
    # that the token is still exposed via argv.
    if not command_exists("security"):
        return False
    if os.environ.get("CAPMESH_KEYCHAIN_ARGV_FALLBACK") != "1":
        print(
            "WARNING: macOS keychain store skipped (asgcode-keychain absent; the "
            "`security` CLI has no stdin mode for -w and would leak the refresh "
            "token via argv on a shared device). The bearer token remains in the "
            "0600 capmesh.env file. Install asgcode-keychain for the stdin path.",
            file=sys.stderr,
        )
        return True
    print(
        "WARNING: macOS keychain fallback passes the refresh token via argv "
        "(visible in the process table on a shared device); install "
        "asgcode-keychain for the stdin path.",
        file=sys.stderr,
    )
    subprocess.run(["security", "delete-generic-password", "-s", service, "-a", account], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    result = subprocess.run(
        ["security", "add-generic-password", "-U", "-s", service, "-a", account, "-w", secret],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def command_exists(name: str) -> bool:
    return any(
        (Path(part) / name).exists() and (Path(part) / name).is_file() and os.access(Path(part) / name, os.X_OK)
        for part in os.environ.get("PATH", "").split(os.pathsep)
        if part
    )


def run_eval(router: CapabilityRouter, eval_path: str, k: int) -> dict[str, Any]:
    path = Path(eval_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        cases = raw.get("cases", [])
        thresholds = raw.get("thresholds", {})
    else:
        cases = raw
        thresholds = {}
    required_recall = float(thresholds.get("recallAtK", 0.90))
    required_mrr = float(thresholds.get("mrrAtK", 0.75))
    required_ndcg = float(thresholds.get("ndcgAtK", 0.80))
    required_critical = float(thresholds.get("criticalRecallAtK", 1.0))
    results = []
    hits = 0
    reciprocal_rank_total = 0.0
    ndcg_total = 0.0
    critical_total = 0
    critical_hits = 0
    for case in cases:
        response = router.call(
            "cap.search",
            {
                "query": case["query"],
                "k": k,
                "type": case.get("type"),
                "principal": Principal().__dict__,
            },
        )
        rows = response["structuredContent"]["results"] if not response.get("isError") else []
        expected = [str(x).lower() for x in case.get("expectedAny", [])]
        relevant_ranks: list[int] = []
        matched: set[str] = set()
        for rank, row in enumerate(rows, start=1):
            row_text = " ".join(
                str(row.get(field, "")) for field in ("uri", "name", "title", "description")
            ).lower()
            row_matches = {item for item in expected if item in row_text}
            if row_matches:
                relevant_ranks.append(rank)
                matched.update(row_matches)
        hit = bool(relevant_ranks)
        first_rank = relevant_ranks[0] if relevant_ranks else None
        reciprocal_rank = 1.0 / first_rank if first_rank else 0.0
        ndcg = 1.0 / math.log2(first_rank + 1) if first_rank else 0.0
        hits += 1 if hit else 0
        reciprocal_rank_total += reciprocal_rank
        ndcg_total += ndcg
        if bool(case.get("critical", False)):
            critical_total += 1
            critical_hits += 1 if hit else 0
        results.append(
            {
                "query": case["query"],
                "hit": hit,
                "critical": bool(case.get("critical", False)),
                "firstRelevantRank": first_rank,
                "reciprocalRank": round(reciprocal_rank, 6),
                "ndcg": round(ndcg, 6),
                "matched": sorted(matched),
                "expectedAny": case.get("expectedAny", []),
                "topResults": [row["uri"] for row in rows[:5]],
            }
        )
    total = len(cases)
    recall = hits / total if total else 0.0
    mrr = reciprocal_rank_total / total if total else 0.0
    ndcg = ndcg_total / total if total else 0.0
    critical_recall = critical_hits / critical_total if critical_total else 1.0
    failed_thresholds = []
    for name, actual, required in (
        ("recallAtK", recall, required_recall),
        ("mrrAtK", mrr, required_mrr),
        ("ndcgAtK", ndcg, required_ndcg),
        ("criticalRecallAtK", critical_recall, required_critical),
    ):
        if actual < required:
            failed_thresholds.append({"metric": name, "actual": round(actual, 4), "required": required})
    return {
        "file": str(path),
        "k": k,
        "total": total,
        "hits": hits,
        "misses": total - hits,
        "recallAtK": round(recall, 4),
        "mrrAtK": round(mrr, 4),
        "ndcgAtK": round(ndcg, 4),
        "criticalRecallAtK": round(critical_recall, 4),
        "thresholds": {
            "recallAtK": required_recall,
            "mrrAtK": required_mrr,
            "ndcgAtK": required_ndcg,
            "criticalRecallAtK": required_critical,
        },
        "failedThresholds": failed_thresholds,
        "failedQueries": [item["query"] for item in results if not item["hit"]],
        "passed": not failed_thresholds,
        "results": results,
    }


def run_per_cap_tests_gate(capability: Capability, repo_root: str) -> tuple[bool, str]:
    """Check whether a capability has its per-cap test artifact.

    Test-path convention:

    1. If ``capability.metadata.get("testPath")`` is set, that exact path is
       treated as a DECLARED requirement — it MUST exist on disk, otherwise the
       gate fails.
    2. Otherwise the gate falls back to the default convention
       ``tests/<plugin>.<name>_test.py`` relative to ``repo_root``.  If that
       file exists the gate passes; if it does not exist the gate also passes
       (presence is OPTIONAL when no testPath is declared).

    This gate is a *presence* check only — actually executing the test is out
    of scope for this slice.  A declared-but-missing testPath is a failure
    because the cap author explicitly committed to a test contract.

    Returns ``(True, "per-cap test file present: <path>")`` or
    ``(False, "declared testPath missing: <path>")`` or
    ``(True, "no per-cap test declared (optional)")``.
    """
    metadata = capability.metadata if capability.metadata else {}
    declared_path: str | None = metadata.get("testPath")

    if declared_path:
        # declared testPath is a contract — must exist
        candidate = Path(repo_root) / declared_path
        if candidate.is_file():
            return (True, f"per-cap test file present: {declared_path}")
        return (False, f"declared testPath missing: {declared_path}")

    # No declared testPath — fall back to default convention.
    plugin = capability.plugin or "global"
    name = capability.name
    convention_path = f"tests/{plugin}.{name}_test.py"
    candidate = Path(repo_root) / convention_path
    if candidate.is_file():
        return (True, f"per-cap test file present: {convention_path}")

    # Optional: no test file and no declaration — gate passes.
    return (True, "no per-cap test declared (optional)")


def gates_tests_handler(con: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    """Handle the ``gates tests <capability-uri-or-name>`` subcommand.

    Loads the capability from the database, runs the per-cap test gate,
    and returns the result as JSON.  Accepts the caller's connection so
    main() can reuse its own handle.
    """
    identifier = args.identifier
    # Resolve the capability by URI or name via the router's describe endpoint
    router = CapabilityRouter(con, roots=tuple(configured_default_roots()))
    desc_resp = router.call(
        "cap.describe",
        {"uri": identifier, "name": identifier, "principal": Principal().__dict__},
    )
    if desc_resp.get("isError"):
        return {"status": "error", "message": desc_resp.get("error", "capability not found")}
    structured = desc_resp.get("structuredContent", desc_resp)
    if not structured:
        return {"status": "error", "message": "capability not found"}

    # The describe endpoint does not serialize the metadata column, so
    # read it directly from the database to get the full metadata dict.
    metadata_row = con.execute(
        "SELECT metadata_json FROM capabilities WHERE uri = ?",
        (structured.get("uri", identifier),),
    ).fetchone()
    metadata = json.loads(metadata_row["metadata_json"]) if metadata_row else {}

    # Build a Capability dataclass from the describe response so the gate
    # function receives the type it expects.
    cap = Capability(
        uri=structured.get("uri", identifier),
        capability_type=structured.get("type", "skill"),
        name=structured.get("name", identifier),
        version=structured.get("version", "0.1.0"),
        title=structured.get("title", ""),
        description=structured.get("description", ""),
        package_path=structured.get("packagePath", str(Path(__file__).resolve().parents[1])),
        entrypoint=structured.get("entrypoint", ""),
        source_path=structured.get("sourcePath", ""),
        source_kind=structured.get("sourceKind", "cap_manifest"),
        source_system=structured.get("sourceSystem", "capmesh"),
        canonical_key=structured.get("canonicalKey", ""),
        content_hash=structured.get("contentHash", ""),
        visibility=structured.get("visibility", "internal"),
        discovery_mode=structured.get("discoveryMode", "public"),
        owner=structured.get("owner", "asg"),
        plugin=structured.get("plugin"),
        category=structured.get("category"),
        keywords=tuple(structured.get("keywords", [])),
        risk_tier=structured.get("riskTier", "low"),
        mutating=structured.get("mutating", False),
        lifecycle=structured.get("lifecycle", "active"),
        tenant_id=structured.get("tenantId", "asg"),
        store_id=structured.get("storeId"),
        namespace_id=structured.get("namespaceId"),
        created_by=structured.get("createdBy"),
        metadata=metadata,
    )
    repo_root = str(Path(__file__).resolve().parents[1])
    passed, reason = run_per_cap_tests_gate(cap, repo_root)
    return {
        "capability": cap.uri,
        "gate": "tests",
        "passed": passed,
        "reason": reason,
    }


def gates_run_handler(con: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    """Handle the ``gates run <capability-uri-or-name> [--write]`` subcommand.

    Runs the lifecycle gate set (signature, provenance, sourceIntegrity, tests,
    retrievalEvals, promptInjectionScan, riskTierPolicy) on a single capability
    and returns a per-gate result table.

    Contract:

    * Capability resolution uses ``index.get_capability`` (URI, then name/title).
      An unknown identifier returns ``{"status": "error", "message": ...}`` and
      writes nothing.
    * Without ``--write`` the run is a dry-run: ``lifecycle.review_capability``
      is invoked with ``dryRun=True`` and the database is left untouched (no
      ``promotion_gate_runs`` rows, no audit event).
    * With ``--write`` the run persists one ``promotion_gate_runs`` row per gate.
      ``promotion_gate_runs.request_id`` has a FK to ``promotion_requests(id)``,
      so the handler first inserts a minimal ``promotion_requests`` anchor row
      (state ``'gate_run'``, no target namespace) to satisfy the FK and record
      the run, then inserts one row per gate keyed by
      ``(request_id, gate_name, content_hash)``.  This is a *gate-run record*,
      not a full namespace promotion: it does not mutate the capability's
      approval/lifecycle state and does not create approval steps.
    """
    identifier = args.identifier
    tenant_id = getattr(args, "tenant", DEFAULT_TENANT) or DEFAULT_TENANT
    cap = get_capability(con, identifier)
    if cap is None or cap.tenant_id != tenant_id:
        return {
            "status": "error",
            "message": f"capability not found in tenant '{tenant_id}': {identifier}",
        }

    principal = Principal(subject="capmesh-gates-run", tenant_id=tenant_id, roles=("org_admin",))
    write = bool(getattr(args, "write", False))
    review = review_capability(con, principal, {"capabilityUri": cap.uri, "dryRun": not write}, commit=write)
    gates = review.get("gates", {})
    per_gate: list[dict[str, Any]] = []
    for name, gate in gates.items():
        evidence = gate.get("evidence", {}) if isinstance(gate, dict) else {}
        per_gate.append(
            {
                "gate": name,
                "state": gate.get("state", "skipped") if isinstance(gate, dict) else "skipped",
                "code": evidence.get("code", ""),
                "reason": _gate_reason(evidence),
            }
        )

    result: dict[str, Any] = {
        "status": "ok",
        "capability": cap.uri,
        "tenantId": tenant_id,
        "write": write,
        "passed": bool(review.get("passed", False)),
        "reviewScope": review.get("reviewScope", "private"),
        "gates": per_gate,
    }

    if not write:
        return result

    # Persist one promotion_gate_runs row per gate.  The table requires a FK
    # parent in promotion_requests; create a lightweight gate-run anchor row so
    # the run is recorded without triggering a full namespace promotion.
    from .governance import audit_event, json_dumps, new_id, utc_now

    run_id = new_id("pgrun")
    con.execute(
        """INSERT INTO promotion_requests(
               id, tenant_id, capability_uri, source_store_id, target_namespace_id,
               requested_by, state, title, rationale, version, gates_json
           ) VALUES (?, ?, ?, ?, NULL, ?, 'gate_run', 'capmesh gates run', '', ?, ?)""",
        (
            run_id,
            cap.tenant_id,
            cap.uri,
            cap.store_id,
            principal.subject,
            cap.version,
            json_dumps({name: gate.get("state") for name, gate in gates.items()}),
        ),
    )
    run_at = utc_now()
    for name, gate in gates.items():
        con.execute(
            """INSERT INTO promotion_gate_runs(
                   id, request_id, gate_name, content_hash, state, evidence_json,
                   runner, run_at, attestation_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}')""",
            (
                new_id("pgr"),
                run_id,
                name,
                cap.content_hash,
                gate.get("state", "skipped"),
                json_dumps(gate.get("evidence", {})),
                principal.subject,
                run_at,
            ),
        )
    audit_event(
        con,
        tenant_id=cap.tenant_id,
        event_type="capability.gates.run",
        actor=principal.subject,
        target=cap.uri,
        action="gates.run",
        decision="allow" if result["passed"] else "deny",
        payload={"requestId": run_id, "write": True, "gates": {n: g.get("state") for n, g in gates.items()}},
    )
    con.commit()
    result["requestId"] = run_id
    result["rowsWritten"] = len(gates)
    return result


def _gate_reason(evidence: dict[str, Any]) -> str:
    """Reduce a gate evidence dict to a single human-readable reason string."""
    if not isinstance(evidence, dict) or not evidence:
        return ""
    code = evidence.get("code")
    if code:
        missing = evidence.get("missing")
        if missing:
            return f"{code}: missing {missing}"
        warnings = evidence.get("warnings")
        if warnings:
            return f"{code}: {warnings[0]}"
        indicators = evidence.get("indicators")
        if indicators:
            return f"{code}: {indicators}"
        error = evidence.get("error")
        if error:
            return f"{code}: {error}"
        return str(code)
    return json.dumps(evidence, sort_keys=True)


def router_for_db(db: str) -> CapabilityRouter:
    """Create a CapabilityRouter for the given database path.

    Opens its own connection — used only by standalone callers (e.g. unit tests)
    that need a router without going through main().
    """
    con = connect(db)
    init_db(con)
    roots = tuple(configured_default_roots())
    return CapabilityRouter(con, roots=roots)


if __name__ == "__main__":
    main()
