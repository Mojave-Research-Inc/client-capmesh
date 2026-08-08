from __future__ import annotations

import dataclasses
import datetime
import getpass
import hashlib
import hmac
import json
import math
import os
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .auth import can_discover
from .governance import (
    apply_default_user_namespace,
    apply_vault_placement,
    builtin_system_capabilities,
    ensure_default_tenant,
    init_governance_schema,
    load_vault_placement_index,
)
from .install_policy import (
    InstallPolicyError,
    SupersededCapability,
    assert_body_resolvable,
    assert_not_duplicate,
)
from .manifest import (
    discover_capabilities,
    source_authority_rank,
    source_files,
    strict_collisions,
)
from .models import (
    CAPABILITY_TYPES,
    DISCOVERY_MODES,
    VISIBILITIES,
    Capability,
    Principal,
    SearchResult,
    normalize_path,
)

SCHEMA_VERSION = 2
DEFAULT_LEXICAL_EMBED_DIMS = 256

# Vault-placement manifest: maps capability target URIs to a durable vault
# ("org" -> org shared namespace, "all" -> all-user everyone namespace) so the
# placement survives every re-ingest/redeploy. Resolved relative to the service
# directory (the repo dir that contains the `capmesh` package). Absent = no-op.
VAULT_PLACEMENT_FILENAME = "vault-placement.json"


def sqlite_wal_safety(version: str | None = None) -> dict[str, Any]:
    """Report whether the SQLite runtime contains the WAL-reset corruption fix.

    SQLite fixed the issue in 3.51.3 and backported it to 3.50.7 and 3.44.6.
    Other releases in the affected 3.7.0--3.51.2 range are unsafe for Capmesh's
    multi-process WAL workload.  The optional argument keeps this check directly
    testable without monkeypatching the interpreter's sqlite module.
    """

    raw = version or sqlite3.sqlite_version
    try:
        parts = tuple(int(part) for part in raw.split(".")[:3])
        parsed = parts + (0,) * (3 - len(parts))
    except (TypeError, ValueError):
        return {
            "version": raw,
            "walResetSafe": False,
            "reason": "unparseable SQLite runtime version",
        }

    safe = (
        parsed >= (3, 51, 3)
        or parsed[:2] == (3, 50) and parsed >= (3, 50, 7)
        or parsed[:2] == (3, 44) and parsed >= (3, 44, 6)
    )
    return {
        "version": raw,
        "walResetSafe": safe,
        "reason": (
            "runtime contains the WAL-reset fix"
            if safe
            else "runtime is vulnerable to the SQLite WAL-reset corruption bug; require 3.51.3, 3.50.7, or 3.44.6"
        ),
    }


def embedding_config() -> dict[str, Any]:
    provider = os.environ.get("CAPMESH_EMBEDDING_PROVIDER", "lexical").strip().lower()
    if provider not in {"lexical", "ollama", "tei", "openai-compatible", "sentence-transformers"}:
        provider = "lexical"
    default_dims = {
        "lexical": DEFAULT_LEXICAL_EMBED_DIMS,
        "ollama": 768,
        "tei": 384,
        "openai-compatible": 1024,
        "sentence-transformers": 384,
    }[provider]
    try:
        dims = int(os.environ.get("CAPMESH_EMBEDDING_DIMS", str(default_dims)))
    except ValueError:
        dims = default_dims
    dims = min(max(dims, 32), 4096)
    try:
        timeout = float(os.environ.get("CAPMESH_EMBEDDING_TIMEOUT_SECONDS", "2.0"))
    except ValueError:
        timeout = 2.0
    timeout = min(max(timeout, 0.1), 10.0)
    if provider == "ollama":
        url = os.environ.get("CAPMESH_OLLAMA_EMBED_URL", "http://127.0.0.1:11434/api/embeddings")
        model = os.environ.get("CAPMESH_EMBEDDING_MODEL", "nomic-embed-text")
    elif provider == "tei":
        url = os.environ.get("CAPMESH_TEI_EMBED_URL", "http://127.0.0.1:8080/embed")
        model = os.environ.get("CAPMESH_EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    elif provider == "openai-compatible":
        # Tailnet LiteLLM / Nebius OpenAI-compatible embeddings (e.g. bge-m3).
        url = os.environ.get(
            "CAPMESH_OPENAI_EMBED_URL",
            os.environ.get("CAPMESH_EMBEDDING_ENDPOINT", "http://127.0.0.1:8000/v1/embeddings"),
        )
        model = os.environ.get("CAPMESH_EMBEDDING_MODEL", "bge-m3")
    elif provider == "sentence-transformers":
        # Local sentence-transformers model (e.g. all-MiniLM-L6-v2, bge-m3).
        # No network: runs in-process via the sentence_transformers library.
        from .local_embedding import get_embedding_config
        st_config = get_embedding_config(os.environ.get("CAPMESH_EMBEDDING_MODEL"))
        url = None  # in-process, no HTTP endpoint
        model = st_config.get("model", "all-MiniLM-L6-v2")
    else:
        url = None
        model = "deterministic-lexical-hash"
    return {
        "provider": provider,
        "dims": dims,
        "timeoutSeconds": timeout,
        "url": url,
        "model": model,
        "fallback": "deterministic lexical retrieval",
    }


def _embedding_host_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    default_hosts = os.environ.get("CAPMESH_EMBEDDING_HOSTS", "127.0.0.1,localhost,::1")
    configured = {
        item.strip().lower()
        for item in os.environ.get("CAPMESH_EMBEDDING_ALLOW_HOSTS", default_hosts).split(",")
        if item.strip()
    }
    return host in configured


def load_sqlite_vec(con: sqlite3.Connection) -> tuple[bool, str]:
    """Load sqlite-vec on this connection; extensions are connection-local."""

    try:
        import sqlite_vec  # type: ignore

        try:
            con.enable_load_extension(True)
        except (AttributeError, sqlite3.Error):
            pass
        sqlite_vec.load(con)
        try:
            con.enable_load_extension(False)
        except (AttributeError, sqlite3.Error):
            pass
        return True, "sqlite_vec loaded"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def vault_placement_path() -> Path:
    return Path(__file__).resolve().parent.parent / VAULT_PLACEMENT_FILENAME


def connect(db_path: str | Path, *, check_same_thread: bool = True) -> sqlite3.Connection:
    path = Path(db_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, check_same_thread=check_same_thread)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    sqlite_status = sqlite_wal_safety()
    require_safe_sqlite = os.environ.get("CAPMESH_REQUIRE_SAFE_SQLITE", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    test_bypass = os.environ.get("CAPMESH_ALLOW_UNSAFE_SQLITE_FOR_TESTS", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if require_safe_sqlite and not sqlite_status["walResetSafe"] and not test_bypass:
        con.close()
        raise RuntimeError(
            f"Unsafe SQLite runtime {sqlite_status['version']} for Capmesh WAL: {sqlite_status['reason']}"
        )
    # Multi-LLM gateways may open several capmesh processes against one DB.
    # Default 60s (was 5s/30s); override with CAPMESH_BUSY_TIMEOUT_MS.
    try:
        busy_ms = int(os.environ.get("CAPMESH_BUSY_TIMEOUT_MS", "60000"))
    except ValueError:
        busy_ms = 60_000
    busy_ms = max(1_000, min(busy_ms, 300_000))
    con.execute(f"PRAGMA busy_timeout={busy_ms}")

    # Read-throughput pragmas for high-concurrency workloads.
    # Each is overridable via environment variable; invalid/missing values
    # fall back to the defaults documented below.

    # PRAGMA synchronous — validate against allowlist (default NORMAL).
    _synch_raw = os.environ.get("CAPMESH_SYNCHRONOUS", "NORMAL").upper()
    if _synch_raw not in ("OFF", "NORMAL", "FULL", "EXTRA"):
        _synch_raw = "NORMAL"
    con.execute(f"PRAGMA synchronous={_synch_raw}")

    # PRAGMA cache_size — integer env, fallback to default (default -131072, i.e. ~64 MiB).
    try:
        _cache_size = int(os.environ.get("CAPMESH_CACHE_SIZE", "-131072"))
    except ValueError:
        _cache_size = -131072
    con.execute(f"PRAGMA cache_size={_cache_size}")

    # PRAGMA mmap_size — integer env, fallback to default (default 1 GiB).
    try:
        _mmap_size = int(os.environ.get("CAPMESH_MMAP_SIZE", "1073741824"))
    except ValueError:
        _mmap_size = 1073741824
    con.execute(f"PRAGMA mmap_size={_mmap_size}")

    # PRAGMA temp_store=MEMORY — keep temp tables/indexes in RAM.
    con.execute("PRAGMA temp_store=MEMORY")
    # sqlite extensions are registered per connection. Loading here ensures
    # request-scoped HTTP connections can read an existing vec0 table instead
    # of silently degrading every network search to FTS-only.
    load_sqlite_vec(con)

    return con


class ThreadLocalConnection:
    """Hands each calling thread its own dedicated sqlite3.Connection.

    Regression context (2026-06-30): capmesh's HTTP server is a
    ThreadingHTTPServer, so concurrent requests run on separate Python
    threads. A single sqlite3.Connection created with
    check_same_thread=False is NOT safe for concurrent use from multiple
    threads -- check_same_thread=False only disables the interpreter's
    same-thread assertion, it does not make the connection's internal
    cursor/statement state thread-safe. Under concurrent load this
    produced `sqlite3.InterfaceError: bad parameter or other API misuse`
    on writes (e.g. POST /api/v1/auth/m365/device-code).

    The fix: this wrapper transparently proxies attribute access
    (.execute, .cursor, .commit, .executescript, etc.) to a real
    sqlite3.Connection that is created lazily, once per thread, the
    first time that thread touches the connection. All connections point
    at the same on-disk database file and inherit the same pragmas
    (WAL + busy_timeout via CAPMESH_BUSY_TIMEOUT_MS) via `connect()`, so
    concurrent writers serialize safely at the SQLite/file level instead of
    corrupting a shared Connection object's in-process state.
    """

    def __init__(self, db_path: str | Path, *, check_same_thread: bool = False) -> None:
        self._db_path = Path(db_path).expanduser()
        self._check_same_thread = check_same_thread
        self._local = threading.local()
        self._all_connections: list[sqlite3.Connection] = []
        self._registry_lock = threading.Lock()

    def _get(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = connect(self._db_path, check_same_thread=self._check_same_thread)
            self._local.con = con
            with self._registry_lock:
                self._all_connections.append(con)
        return con

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not defined on this wrapper itself
        # (e.g. execute, cursor, commit, rollback, executescript, row_factory).
        return getattr(self._get(), name)

    def close(self) -> None:
        """Close every connection this wrapper has ever handed out.

        Safe to call from any thread (typically the main thread during
        shutdown). Connections belonging to already-exited request
        threads are closed here too; sqlite3 connections may only be
        closed from a thread that is not actively using them, which
        holds true once handler threads have completed and returned.
        """
        with self._registry_lock:
            connections = list(self._all_connections)
            self._all_connections.clear()
        for con in connections:
            try:
                con.close()
            except sqlite3.Error:
                pass
        if hasattr(self._local, "con"):
            del self._local.con

    def close_current(self) -> None:
        """Close and forget the connection owned by the current request thread."""

        con = getattr(self._local, "con", None)
        if con is None:
            return
        try:
            con.close()
        finally:
            self._local.con = None
            with self._registry_lock:
                try:
                    self._all_connections.remove(con)
                except ValueError:
                    pass


def init_db(con: sqlite3.Connection, *, enable_vector: bool = True) -> dict[str, Any]:
    # NOTE: init_db runs the schema (CREATE IF NOT EXISTS), idempotent column migrations
    # (init_governance_schema -> ensure_columns, read-first), namespace normalization, and the
    # builtin-capability + default-tenant bootstrap. These are safe to run on every startup:
    # when the DB is already current they perform NO writes (so no write-lock contention across
    # worker processes). Do NOT re-add a schema_version early-return here — it skips required
    # migrations/normalization for already-versioned DBs (regressed the legacy-namespace
    # migration). The real per-request concurrency fix lives in auth.can_discover(audit=False)
    # and ensure_default_tenant()'s read-first guard.
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capabilities (
            id INTEGER PRIMARY KEY,
            uri TEXT NOT NULL UNIQUE,
            canonical_key TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL DEFAULT 'asg',
            store_id TEXT,
            namespace_id TEXT,
            type TEXT NOT NULL CHECK(type IN ('skill','agent','plugin','command','mcp_server','workflow','reference','bundle')),
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            package_path TEXT NOT NULL,
            entrypoint TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_system TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN ('public','internal','protected','secret')),
            discovery_mode TEXT NOT NULL CHECK(discovery_mode IN ('public','locked','hidden')),
            owner TEXT NOT NULL,
            plugin TEXT,
            category TEXT,
            keywords_json TEXT NOT NULL,
            required_scopes_json TEXT NOT NULL,
            allow_groups_json TEXT NOT NULL,
            allow_users_json TEXT NOT NULL,
            risk_tier TEXT NOT NULL CHECK(risk_tier IN ('low','medium','high','critical')),
            mutating INTEGER NOT NULL DEFAULT 0,
            lifecycle TEXT NOT NULL,
            created_by TEXT,
            submitted_by TEXT,
            promoted_from_uri TEXT,
            approval_state TEXT NOT NULL DEFAULT 'published',
            share_state TEXT NOT NULL DEFAULT 'not_shared',
            signature_status TEXT NOT NULL DEFAULT 'unchecked',
            provenance_status TEXT NOT NULL DEFAULT 'unchecked',
            risk_review_status TEXT NOT NULL DEFAULT 'pending',
            metadata_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS capability_sources (
            source_path TEXT PRIMARY KEY,
            uri TEXT NOT NULL REFERENCES capabilities(uri) ON DELETE CASCADE,
            source_kind TEXT NOT NULL,
            source_system TEXT NOT NULL,
            content_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS router_reports (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            event TEXT NOT NULL,
            uri TEXT,
            principal TEXT,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS authoritative_router_reports (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            event TEXT NOT NULL,
            task_id TEXT NOT NULL UNIQUE,
            report_id TEXT NOT NULL UNIQUE,
            nonce TEXT NOT NULL UNIQUE,
            principal TEXT NOT NULL,
            report_digest TEXT NOT NULL,
            receipt_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_capabilities_type ON capabilities(type);
        CREATE INDEX IF NOT EXISTS idx_capabilities_plugin ON capabilities(plugin);
        CREATE INDEX IF NOT EXISTS idx_capabilities_visibility ON capabilities(visibility, discovery_mode);
        CREATE INDEX IF NOT EXISTS idx_authoritative_router_reports_event
            ON authoritative_router_reports(event, ts);
        """
   )
    init_governance_schema(con)
    # CapGuard quarantine store + signed attestation tables.  Created here so a
    # fresh DB always has the quarantine store available for quarantine-before-
    # indexing; migration v3 also creates them idempotently for upgrading DBs.
    from .capguard import ensure_quarantine_tables
    ensure_quarantine_tables(con)
    # Register and run versioned migrations. The migration runner tracks
    # schema_version in the meta table. Each migration is idempotent.
    from .migrations import register_builtin_migrations, run_migrations
    register_builtin_migrations()
    run_migrations(con, commit=False)
    # Performance indexes
    con.execute("CREATE INDEX IF NOT EXISTS idx_capabilities_name ON capabilities(name)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_capabilities_title ON capabilities(title)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_capabilities_type ON capabilities(type)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_capabilities_visibility ON capabilities(visibility)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_capabilities_namespace ON capabilities(namespace_id)")

    con.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS capability_fts USING fts5(
            uri UNINDEXED,
            name,
            title,
            description,
            keywords,
            plugin,
            category,
            content
        )
        """
    )
    normalize_existing_capability_namespaces(con)
    embed_config = embedding_config()
    vector_status: dict[str, Any] = {
        "enabled": False,
        "reason": "disabled",
        "embedding": embed_config,
        "recreated": False,
    }
    if enable_vector:
        try:
            loaded, load_reason = load_sqlite_vec(con)
            if not loaded:
                raise RuntimeError(load_reason)
            signature = f"{embed_config['provider']}:{embed_config['model']}:{embed_config['dims']}"
            stored = con.execute("SELECT value FROM meta WHERE key = 'embedding_signature'").fetchone()
            table_exists = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='capability_vec'"
            ).fetchone()
            recreated = bool(table_exists and (stored is None or stored[0] != signature))
            if recreated:
                con.execute("DROP TABLE capability_vec")
            con.execute(
                f"CREATE VIRTUAL TABLE IF NOT EXISTS capability_vec USING vec0(embedding float[{int(embed_config['dims'])}])"
            )
            con.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('embedding_signature', ?)",
                (signature,),
            )
            vector_status = {
                "enabled": True,
                "reason": "sqlite_vec loaded",
                "embedding": embed_config,
                "recreated": recreated,
            }
        except Exception as exc:  # noqa: BLE001
            vector_status = {
                "enabled": False,
                "reason": str(exc),
                "embedding": embed_config,
                "recreated": False,
            }
    ensure_default_tenant(con)
    for cap in builtin_system_capabilities():
        upsert_capability(con, cap)
    con.commit()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "vector": vector_status,
        "sqlite": sqlite_wal_safety(),
    }


def capability_from_row(row: sqlite3.Row) -> Capability:
    # Defensive coercion: a single legacy/foreign row with an out-of-vocabulary
    # enum (e.g. a pre-existing discovery_mode="listed") must NOT crash the whole
    # rebuild_index/normalize pass and take the service down. Unknown values fall
    # back to a safe, least-surprising default.
    _dmode = row["discovery_mode"] if row["discovery_mode"] in DISCOVERY_MODES else "public"
    _vis = row["visibility"] if row["visibility"] in VISIBILITIES else "internal"
    _ctype = row["type"] if row["type"] in CAPABILITY_TYPES else "reference"
    _rtier = row["risk_tier"] if row["risk_tier"] in {"low", "medium", "high", "critical"} else "low"
    return Capability(
        uri=row["uri"],
        capability_type=_ctype,
        name=row["name"],
        version=row["version"],
        title=row["title"],
        description=row["description"],
        package_path=row["package_path"],
        entrypoint=row["entrypoint"],
        source_path=row["source_path"],
        source_kind=row["source_kind"],
        source_system=row["source_system"],
        canonical_key=row["canonical_key"],
        content_hash=row["content_hash"],
        visibility=_vis,
        discovery_mode=_dmode,
        owner=row["owner"],
        plugin=row["plugin"],
        category=row["category"],
        keywords=tuple(json.loads(row["keywords_json"])),
        required_scopes=tuple(json.loads(row["required_scopes_json"])),
        allow_groups=tuple(json.loads(row["allow_groups_json"])),
        allow_users=tuple(json.loads(row["allow_users_json"])),
        risk_tier=_rtier,
        mutating=bool(row["mutating"]),
        lifecycle=row["lifecycle"],
        tenant_id=row["tenant_id"],
        store_id=row["store_id"],
        namespace_id=row["namespace_id"],
        created_by=row["created_by"],
        submitted_by=row["submitted_by"],
        promoted_from_uri=row["promoted_from_uri"],
        approval_state=row["approval_state"],
        share_state=row["share_state"],
        signature_status=row["signature_status"],
        provenance_status=row["provenance_status"],
        risk_review_status=row["risk_review_status"],
       metadata=json.loads(row["metadata_json"]),
        source_commit=row["source_commit"] if "source_commit" in row.keys() else None,
        license=row["license"] if "license" in row.keys() else None,
    )


def upsert_capability(con: sqlite3.Connection, cap: Capability) -> int:
    cap = apply_default_user_namespace(cap)
    # Enforce lifecycle transition validity: if the capability already exists
    # with the SAME content hash (i.e. no content change, so this is an
    # explicit lifecycle update rather than an automatic content-change
    # reset), verify the transition is allowed.  Invalid transitions are
    # silently clamped to the current state.  When content_hash differs the
    # SQL ON CONFLICT CASE logic correctly resets lifecycle to the new value
    # (typically "draft"), which is the expected ingest behavior — do not
    # interfere with that.  The governance API uses
    # lifecycle_transitions.transition_capability for explicit, audited changes.
    try:
        from .lifecycle_transitions import is_valid_transition
        existing = con.execute(
            "SELECT lifecycle, content_hash FROM capabilities WHERE uri = ?", (cap.uri,)
        ).fetchone()
        if existing is not None:
            current = str(existing["lifecycle"])
            existing_hash = str(existing["content_hash"] or "")
            if (current != cap.lifecycle
                    and existing_hash == (cap.content_hash or "")
                    and not is_valid_transition(current, cap.lifecycle)):
                cap = dataclasses.replace(cap, lifecycle=current)
    except Exception:  # noqa: BLE001, S110
        pass
    # Sample the write counter so we can tell whether the upsert below actually wrote. The
    # DO UPDATE ... WHERE suppresses no-op rewrites, and everything after it (capability_sources,
    # the FTS delete+insert) is only worth doing when something really changed. Without this the
    # row write is skipped but the FTS index is still torn down and rebuilt per capability, which
    # is the expensive half — measured as the bulk of the churn from the 15-minute re-ingest.
    _changes_before = con.total_changes
    con.execute(
        """
        INSERT INTO capabilities (
            uri, canonical_key, tenant_id, store_id, namespace_id, type, name, version, title, description,
            package_path, entrypoint, source_path, source_kind, source_system,
            content_hash, visibility, discovery_mode, owner, plugin, category,
            keywords_json, required_scopes_json, allow_groups_json, allow_users_json,
            risk_tier, mutating, lifecycle, created_by, submitted_by, promoted_from_uri,
           approval_state, share_state, signature_status, provenance_status, risk_review_status,
            metadata_json, source_commit, license, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(uri) DO UPDATE SET
           canonical_key=excluded.canonical_key,
            tenant_id=excluded.tenant_id,
            store_id=excluded.store_id,
            namespace_id=excluded.namespace_id,
            type=excluded.type,
            name=excluded.name,
            version=excluded.version,
            title=excluded.title,
            description=excluded.description,
            package_path=excluded.package_path,
            entrypoint=excluded.entrypoint,
            source_path=excluded.source_path,
            source_kind=excluded.source_kind,
            source_system=excluded.source_system,
            content_hash=excluded.content_hash,
            visibility=excluded.visibility,
            discovery_mode=excluded.discovery_mode,
            owner=excluded.owner,
            plugin=excluded.plugin,
            category=excluded.category,
            keywords_json=excluded.keywords_json,
            required_scopes_json=excluded.required_scopes_json,
            allow_groups_json=excluded.allow_groups_json,
            allow_users_json=excluded.allow_users_json,
            risk_tier=excluded.risk_tier,
            mutating=excluded.mutating,
            lifecycle=CASE
                WHEN capabilities.content_hash = excluded.content_hash
                     AND capabilities.approval_state = 'approved'
                THEN capabilities.lifecycle
                ELSE excluded.lifecycle
            END,
            created_by=excluded.created_by,
            submitted_by=COALESCE(capabilities.submitted_by, excluded.submitted_by),
            promoted_from_uri=COALESCE(capabilities.promoted_from_uri, excluded.promoted_from_uri),
            approval_state=CASE
                WHEN capabilities.content_hash = excluded.content_hash THEN capabilities.approval_state
                WHEN capabilities.approval_state = 'approved' THEN 'pending'
                ELSE excluded.approval_state
            END,
            share_state=CASE
                WHEN capabilities.content_hash = excluded.content_hash THEN capabilities.share_state
                WHEN capabilities.share_state = 'shared' THEN 'not_shared'
                ELSE excluded.share_state
            END,
            signature_status=CASE
                WHEN capabilities.content_hash = excluded.content_hash THEN capabilities.signature_status
                WHEN capabilities.signature_status = 'verified' THEN 'pending'
                ELSE excluded.signature_status
            END,
            provenance_status=CASE
                WHEN capabilities.content_hash = excluded.content_hash THEN capabilities.provenance_status
                WHEN capabilities.provenance_status = 'verified' THEN 'pending'
                ELSE excluded.provenance_status
            END,
            risk_review_status=CASE
                WHEN capabilities.content_hash = excluded.content_hash THEN capabilities.risk_review_status
                WHEN capabilities.risk_review_status = 'approved' THEN 'pending'
                ELSE excluded.risk_review_status
            END,
           metadata_json=excluded.metadata_json,
            source_commit=excluded.source_commit,
            license=excluded.license,
            updated_at=CURRENT_TIMESTAMP
        WHERE
            -- NO-OP SUPPRESSION. Skip the UPDATE entirely when this row would be rewritten
            -- to exactly the values it already holds.
            --
            -- The scheduled re-ingest (asg-capability-mesh-refresh, every 15 min) rewrote all
            -- 2191 rows every run regardless of change. Measured 2026-07-19: one refresh wrote
            -- 13,645,472 bytes of WAL while leaving the row count and every value identical.
            -- That is ~13 MB of WAL churn four times an hour for zero net change, and it is a
            -- bulk writer competing for the single SQLite write lock — the same lock that
            -- /api/v1/whoami wedged on that morning. Removing the churn removes the contention.
            --
            -- SQLite evaluates this WHERE against the conflicting row: false means no write at
            -- all, so an unchanged capability costs a read and nothing else.
            --
            -- Every column compared below is one the SET clause assigns UNCONDITIONALLY from
            -- excluded. The remaining SET targets are safe to omit:
            --   * approval_state / share_state / signature_status / provenance_status /
            --     risk_review_status branch on content_hash, and content_hash is compared here,
            --     so any transition they could make implies a difference already listed.
            --   * submitted_by / promoted_from_uri use COALESCE, so they can only change when
            --     the stored value is NULL and the incoming one is not — both cases are
            --     compared explicitly at the end.
            -- `IS NOT` is used throughout rather than `!=` because `NULL != NULL` is NULL, which
            -- would silently drop rows out of the comparison and skip writes that should happen.
            capabilities.content_hash        IS NOT excluded.content_hash
            OR capabilities.canonical_key    IS NOT excluded.canonical_key
            OR capabilities.tenant_id        IS NOT excluded.tenant_id
            OR capabilities.store_id         IS NOT excluded.store_id
            OR capabilities.namespace_id     IS NOT excluded.namespace_id
            OR capabilities.type             IS NOT excluded.type
            OR capabilities.name             IS NOT excluded.name
            OR capabilities.version          IS NOT excluded.version
            OR capabilities.title            IS NOT excluded.title
            OR capabilities.description      IS NOT excluded.description
            OR capabilities.package_path     IS NOT excluded.package_path
            OR capabilities.entrypoint       IS NOT excluded.entrypoint
            OR capabilities.source_path      IS NOT excluded.source_path
            OR capabilities.source_kind      IS NOT excluded.source_kind
            OR capabilities.source_system    IS NOT excluded.source_system
            OR capabilities.visibility       IS NOT excluded.visibility
            OR capabilities.discovery_mode   IS NOT excluded.discovery_mode
            OR capabilities.owner            IS NOT excluded.owner
            OR capabilities.plugin           IS NOT excluded.plugin
            OR capabilities.category         IS NOT excluded.category
            OR capabilities.keywords_json    IS NOT excluded.keywords_json
            OR capabilities.required_scopes_json IS NOT excluded.required_scopes_json
            OR capabilities.allow_groups_json    IS NOT excluded.allow_groups_json
            OR capabilities.allow_users_json     IS NOT excluded.allow_users_json
            OR capabilities.risk_tier        IS NOT excluded.risk_tier
            OR capabilities.mutating         IS NOT excluded.mutating
            OR (
                NOT (capabilities.content_hash = excluded.content_hash AND capabilities.approval_state = 'approved')
                AND capabilities.lifecycle IS NOT excluded.lifecycle
            )
            OR capabilities.created_by       IS NOT excluded.created_by
           OR capabilities.metadata_json    IS NOT excluded.metadata_json
            OR capabilities.source_commit   IS NOT excluded.source_commit
            OR capabilities.license        IS NOT excluded.license
            OR (capabilities.submitted_by IS NULL AND excluded.submitted_by IS NOT NULL)
            OR (capabilities.promoted_from_uri IS NULL AND excluded.promoted_from_uri IS NOT NULL)
        """,
        (
            cap.uri,
            cap.canonical_key,
            cap.tenant_id,
            cap.store_id,
            cap.namespace_id,
            cap.capability_type,
            cap.name,
            cap.version,
            cap.title,
            cap.description,
            cap.package_path,
            cap.entrypoint,
            cap.source_path,
            cap.source_kind,
            cap.source_system,
            cap.content_hash,
            cap.visibility,
            cap.discovery_mode,
            cap.owner,
            cap.plugin,
            cap.category,
            json.dumps(list(cap.keywords)),
            json.dumps(list(cap.required_scopes)),
            json.dumps(list(cap.allow_groups)),
            json.dumps(list(cap.allow_users)),
            cap.risk_tier,
            int(cap.mutating),
            cap.lifecycle,
            cap.created_by,
            cap.submitted_by,
            cap.promoted_from_uri,
            cap.approval_state,
            cap.share_state,
            cap.signature_status,
            cap.provenance_status,
            cap.risk_review_status,
           json.dumps(cap.metadata, sort_keys=True),
            cap.source_commit,
            cap.license,
        ),
    )
    row = con.execute("SELECT id FROM capabilities WHERE uri = ?", (cap.uri,)).fetchone()
    if row is None:
        raise RuntimeError(f"Failed to upsert capability {cap.uri}")
    cap_id = int(row["id"])

    expected_sources = _capability_source_rows(cap)
    expected_fts = (
        cap.uri,
        cap.name,
        cap.title,
        cap.description,
        " ".join(cap.keywords),
        cap.plugin or "",
        cap.category or "",
        cap.index_text(),
    )

    fts_row = con.execute(
        """
        SELECT uri, name, title, description, keywords, plugin, category, content
        FROM capability_fts WHERE rowid = ?
        """,
        (cap_id,),
    ).fetchone()
    actual_sources = tuple(
        tuple(row)
        for row in con.execute(
            """
            SELECT source_path, uri, source_kind, source_system, content_hash
            FROM capability_sources WHERE uri = ? ORDER BY source_path
            """,
            (cap.uri,),
        ).fetchall()
    )
    fts_matches = fts_row is not None and tuple(fts_row) == expected_fts
    sources_match = actual_sources == expected_sources
    if con.total_changes == _changes_before and fts_matches and sources_match:
        return cap_id

    # Synchronize each provenance record independently. In particular, never delete all
    # sources before reinserting one discovery pass: aliases that resolve to this same URI
    # must coexist. The conflict WHERE also makes repair of a missing sibling write only that
    # sibling instead of churning every already-correct source row.
    if not sources_match:
        for source in expected_sources:
            con.execute(
                """
                INSERT INTO capability_sources(source_path, uri, source_kind, source_system, content_hash)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_path) DO UPDATE SET
                    uri=excluded.uri,
                    source_kind=excluded.source_kind,
                    source_system=excluded.source_system,
                    content_hash=excluded.content_hash
                WHERE capability_sources.uri IS NOT excluded.uri
                   OR capability_sources.source_kind IS NOT excluded.source_kind
                   OR capability_sources.source_system IS NOT excluded.source_system
                   OR capability_sources.content_hash IS NOT excluded.content_hash
                """,
                source,
            )
        expected_paths = tuple(source[0] for source in expected_sources)
        placeholders = ",".join("?" for _ in expected_paths)
        con.execute(
            f"DELETE FROM capability_sources WHERE uri = ? AND source_path NOT IN ({placeholders})",
            (cap.uri, *expected_paths),
        )
    if not fts_matches:
        con.execute("DELETE FROM capability_fts WHERE rowid = ?", (cap_id,))
        con.execute(
            """
            INSERT INTO capability_fts(rowid, uri, name, title, description, keywords, plugin, category, content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (cap_id, *expected_fts),
        )
    return cap_id


def _capability_source_rows(cap: Capability) -> tuple[tuple[str, str, str, str, str], ...]:
    """Return the exact, deterministic source rows represented by a capability."""
    sources: dict[str, tuple[str, str, str, str, str]] = {}
    provenance = cap.metadata.get("sourceProvenance")
    if isinstance(provenance, list):
        for item in provenance:
            if not isinstance(item, dict) or not item.get("sourcePath"):
                continue
            source_path = normalize_path(str(item["sourcePath"]))
            record = (
                source_path,
                cap.uri,
                str(item.get("sourceKind") or cap.source_kind),
                str(item.get("sourceSystem") or cap.source_system),
                str(item.get("contentHash") or cap.content_hash),
            )
            if source_path in sources and sources[source_path] != record:
                raise ValueError(f"conflicting provenance records for source path {source_path}")
            sources[source_path] = record

    raw_source_paths = cap.metadata.get("sourcePaths") or (cap.source_path,)
    if isinstance(raw_source_paths, str):
        raw_source_paths = (raw_source_paths,)
    for raw_source_path in raw_source_paths:
        source_path = normalize_path(str(raw_source_path))
        sources.setdefault(
            source_path,
            (source_path, cap.uri, cap.source_kind, cap.source_system, cap.content_hash),
        )
    source_path = normalize_path(cap.source_path)
    sources.setdefault(
        source_path,
        (source_path, cap.uri, cap.source_kind, cap.source_system, cap.content_hash),
    )
    return tuple(sources[source_path] for source_path in sorted(sources))


def normalize_existing_capability_namespaces(con: sqlite3.Connection) -> int:
    """Move pre-governance capability rows into the default user namespace.

    This covers existing SQLite DBs that are opened by the service without a
    full rebuild. Source rows are recreated because `capability_sources.uri`
    references `capabilities.uri` without ON UPDATE CASCADE.
    """

    rows = con.execute("SELECT * FROM capabilities WHERE source_kind != 'system_capability'").fetchall()
    changed = 0
    for row in rows:
        cap = capability_from_row(row)
        normalized = apply_default_user_namespace(cap)
        if normalized == cap:
            continue
        normalized_uri = unique_migration_uri(con, normalized.uri, int(row["id"]), normalized.canonical_key)
        con.execute("DELETE FROM capability_sources WHERE uri = ?", (cap.uri,))
        con.execute(
            """
            UPDATE capabilities
            SET uri = ?,
                tenant_id = ?,
                store_id = ?,
                namespace_id = ?,
                visibility = ?,
                discovery_mode = ?,
                owner = ?,
                lifecycle = ?,
                created_by = ?,
                approval_state = ?,
                metadata_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                normalized_uri,
                normalized.tenant_id,
                normalized.store_id,
                normalized.namespace_id,
                normalized.visibility,
                normalized.discovery_mode,
                normalized.owner,
                normalized.lifecycle,
                normalized.created_by,
                normalized.approval_state,
                json.dumps(normalized.metadata, sort_keys=True),
                row["id"],
            ),
        )
        for source in _capability_source_rows(normalized):
            con.execute(
                """
                INSERT OR REPLACE INTO capability_sources(source_path, uri, source_kind, source_system, content_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (source[0], normalized_uri, *source[2:]),
            )
        con.execute("UPDATE shares SET capability_uri = ? WHERE capability_uri = ?", (normalized_uri, cap.uri))
        con.execute("UPDATE promotion_requests SET capability_uri = ? WHERE capability_uri = ?", (normalized_uri, cap.uri))
        con.execute("UPDATE relationship_tuples SET object = ? WHERE object = ?", (normalized_uri, cap.uri))
        con.execute("UPDATE policy_decisions SET resource_uri = ? WHERE resource_uri = ?", (normalized_uri, cap.uri))
        con.execute("DELETE FROM capability_fts WHERE rowid = ?", (row["id"],))
        con.execute(
            """
            INSERT INTO capability_fts(rowid, uri, name, title, description, keywords, plugin, category, content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"],
                normalized_uri,
                normalized.name,
                normalized.title,
                normalized.description,
                " ".join(normalized.keywords),
                normalized.plugin or "",
                normalized.category or "",
                normalized.index_text(),
            ),
        )
        changed += 1
    return changed


def unique_migration_uri(con: sqlite3.Connection, uri: str, row_id: int, canonical_key: str) -> str:
    existing = con.execute("SELECT id FROM capabilities WHERE uri = ? AND id != ?", (uri, row_id)).fetchone()
    if existing is None:
        return uri
    suffix = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:10]
    if "@" in uri:
        base, version = uri.rsplit("@", 1)
        candidate = f"{base}-{suffix}@{version}"
    else:
        candidate = f"{uri}-{suffix}"
    idx = 2
    while con.execute("SELECT 1 FROM capabilities WHERE uri = ? AND id != ?", (candidate, row_id)).fetchone() is not None:
        if "@" in uri:
            base, version = uri.rsplit("@", 1)
            candidate = f"{base}-{suffix}-{idx}@{version}"
        else:
            candidate = f"{uri}-{suffix}-{idx}"
        idx += 1
    return candidate



def write_ingest_audit_log(
    db_path: str | Path,
    roots: Iterable[str | Path],
    replace_all: bool,
    count_before: int,
    count_after: int | None,
    outcome: str,  # "ok", "shrink_guard_abort", "error"
    error_message: str | None = None,
    *,
    operation: str = "ingest",
    discovered: int | None = None,
    added: int | None = None,
    updated: int | None = None,
    removed: int | None = None,
) -> None:
    """Write an append-only JSONL audit log entry for ingest operations.
    
    Never raises an exception — always wraps in try/except and continues.
    This ensures logging failures never break an ingest.
    """
    try:
        db_path_obj = Path(db_path).expanduser()
        log_path = db_path_obj.parent / "ingest-audit.jsonl"
        
        # Get username with fallback to getpass.getuser() if os.getlogin() fails
        try:
            username = os.getlogin()
        except Exception:  # noqa: BLE001
            try:
                username = getpass.getuser()
            except Exception:  # noqa: BLE001
                username = "unknown"
        
        # Get hostname
        try:
            hostname = socket.gethostname()
        except Exception:  # noqa: BLE001
            hostname = "unknown"
        
        # Build audit entry with sys.argv for full command capture
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "hostname": hostname,
            "username": username,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "roots": [str(r) for r in roots],
            "operation": operation,
            "replace_all": replace_all,
            "count_before": count_before,
            "count_after": count_after,
            "discovered": discovered,
            "added": added,
            "updated": updated,
            "removed": removed,
            "outcome": outcome,
            "error": error_message,
            "command": " ".join(sys.argv),
        }
        
        # Append to JSONL log file (create parent dirs if needed)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:  # noqa: BLE001,S110
        # Silently swallow all logging errors — never let logging break an ingest
        pass


class IngestShrinkGuard(RuntimeError):
    """Backward-compatible name for callers handling unsafe replacement attempts."""


class UnexpectedRemovalError(IngestShrinkGuard):
    """Raised when a staged rebuild removes a capability without explicit approval."""


class CandidateValidationError(RuntimeError):
    """Raised when a shadow database fails integrity or index invariants."""


def _live_capability_count(con: sqlite3.Connection) -> int:
    row = con.execute(
        "SELECT COUNT(*) FROM capabilities "
        "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
    ).fetchone()
    return int(row[0]) if row else 0


def _catalog_generation(con: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for row in con.execute(
        "SELECT uri,content_hash,approval_state,share_state FROM capabilities ORDER BY uri"
    ).fetchall():
        digest.update("\t".join(str(value) for value in row).encode("utf-8"))
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest()


def refresh_catalog_generation(con: sqlite3.Connection) -> str:
    """Refresh the logical catalog generation after governance mutations.

    Promotion and approval can change canonical URIs and lifecycle state without
    running ingest. Replicas already compare the same logical fields directly;
    keeping the health generation current makes consumer parity checks equally
    strong. This deliberately does not update the ingest-freshness timestamp.
    """
    generation = _catalog_generation(con)
    con.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('last_successful_ingest_generation', ?)",
        (generation,),
    )
    return generation


def _record_catalog_generation(con: sqlite3.Connection) -> str:
    generation = refresh_catalog_generation(con)
    con.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('last_successful_ingest_at', ?)",
        (datetime.datetime.now(datetime.UTC).isoformat(),),
    )
    return generation


def _migrate_canonical_uri(con: sqlite3.Connection, old_uri: str, new_uri: str) -> None:
    """Move a canonical capability to a new namespace URI without orphaning governance rows."""

    if old_uri == new_uri:
        return
    row = con.execute("SELECT id FROM capabilities WHERE uri = ?", (old_uri,)).fetchone()
    if row is None:
        return
    con.execute("PRAGMA defer_foreign_keys=ON")
    con.execute("DELETE FROM capability_sources WHERE uri = ?", (old_uri,))
    con.execute("UPDATE capabilities SET uri = ? WHERE uri = ?", (new_uri, old_uri))
    con.execute("UPDATE shares SET capability_uri = ? WHERE capability_uri = ?", (new_uri, old_uri))
    con.execute("UPDATE promotion_requests SET capability_uri = ? WHERE capability_uri = ?", (new_uri, old_uri))
    con.execute("UPDATE relationship_tuples SET object = ? WHERE object = ?", (new_uri, old_uri))
    con.execute("UPDATE policy_decisions SET resource_uri = ? WHERE resource_uri = ?", (new_uri, old_uri))


def _upsert_vector(
    con: sqlite3.Connection,
    cap_id: int,
    cap: Capability,
    *,
    enabled: bool,
    index_text_unchanged: bool = False,
) -> bool:
    if not enabled:
        return False
    # An embedding is a pure function of cap.index_text(), not only the source file hash.
    # Parser/root attribution can change derived fields such as plugin/category/title while
    # content_hash stays unchanged. Compare the previous FTS content (which stores index_text)
    # before suppressing a rewrite, or semantic search can retain a stale vector.
    #
    # Guarded on the vector row actually existing, for the same reason as the FTS guard: an
    # unchanged capability whose vector is missing (sqlite_vec unavailable during an earlier
    # run, restored DB, interrupted ingest) must still be embedded, or it silently drops out of
    # semantic search while looking present in `capabilities`.
    if index_text_unchanged:
        try:
            if con.execute(
                "SELECT 1 FROM capability_vec WHERE rowid = ?", (cap_id,)
            ).fetchone() is not None:
                return True
        except (sqlite3.Error, RuntimeError):
            # Vector table unavailable — fall through and let the normal path decide.
            pass
    try:
        con.execute("DELETE FROM capability_vec WHERE rowid = ?", (cap_id,))
        con.execute(
            "INSERT INTO capability_vec(rowid, embedding) VALUES (?, ?)",
            (cap_id, json.dumps(embed_text(cap.index_text()))),
        )
        return True
    except (sqlite3.Error, RuntimeError, ValueError):
        return False


def _mark_vector_failure(con: sqlite3.Connection, cap_id: int) -> None:
    """Record a per-capability vector-embedding failure on the cap row.

    The global vector subsystem stays enabled when only an isolated row fails
    (an isolated bad row must not disable semantic search for the whole mesh),
    but the failed cap is flagged in its ``metadata_json`` so the partial
    coverage is observable per-capability rather than only through aggregate
    counts. A later successful ingest clears the flag naturally: the fresh
    discovery metadata omits ``vectorStatus``, so ``upsert_capability``'s no-op
    suppression no longer matches and the row is rewritten without it. See
    ``docs/IMPROVEMENT-PLAN.md`` CM-08 for the contract.
    """
    row = con.execute(
        "SELECT metadata_json FROM capabilities WHERE id = ?", (cap_id,)
    ).fetchone()
    if row is None:
        return
    raw = row["metadata_json"]
    try:
        meta = json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    if meta.get("vectorStatus") == "failed":
        return
    meta["vectorStatus"] = "failed"
    con.execute(
        "UPDATE capabilities SET metadata_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (json.dumps(meta, sort_keys=True), cap_id),
    )


class EffectiveUriCollisionError(ValueError):
    """Equal-authority discoveries resolve to one URI with different content."""


def _merge_by_effective_uri(capabilities: Iterable[Capability]) -> list[Capability]:
    """Collapse capabilities only after their final namespace URI is known.

    Discovery roots can expose the same file under different source paths and therefore
    different path-derived canonical keys. Canonical-key deduplication cannot see that alias.
    Namespace placement *does*: both records resolve to the same effective URI. That URI is the
    durable database identity, so mirrors are merged with an explicit authority order instead of
    filesystem walk order. Different content at the same authority tier is recorded and
    resolved deterministically in normal operation; strict CI mode fails closed.
    """
    groups: dict[str, list[Capability]] = defaultdict(list)
    for capability in capabilities:
        groups[capability.uri].append(capability)

    merged: list[Capability] = []
    for uri in sorted(groups):
        caps = groups[uri]
        if len(caps) == 1:
            merged.append(caps[0])
            continue
        ranked = sorted(
            caps,
            key=lambda cap: (
                -source_authority_rank(cap.source_system, cap.source_path),
                cap.canonical_key or "",
                cap.source_system or "",
                normalize_path(cap.source_path),
            ),
        )
        winner = ranked[0]
        top_rank = source_authority_rank(winner.source_system, winner.source_path)
        top_hashes = {
            cap.content_hash
            for cap in ranked
            if source_authority_rank(cap.source_system, cap.source_path) == top_rank
        }
        ambiguous_sources: list[str] = []
        if len(top_hashes) > 1:
            ambiguous_sources = sorted(
                normalize_path(cap.source_path)
                for cap in ranked
                if source_authority_rank(cap.source_system, cap.source_path) == top_rank
            )
            message = (
                f"effective URI collision for {uri}: equal-authority sources contain "
                f"{len(top_hashes)} content hashes: {ambiguous_sources}; selected "
                f"{normalize_path(winner.source_path)} deterministically. Recorded as "
                "ambiguousEffectiveUriCollision in capability metadata."
            )
            if strict_collisions():
                raise EffectiveUriCollisionError(message)
            print(f"capmesh: {message}", file=sys.stderr)
        provenance: set[tuple[str, str, str, str]] = set()
        for cap in caps:
            prior = cap.metadata.get("sourceProvenance")
            represented_paths: set[str] = set()
            if isinstance(prior, list):
                for item in prior:
                    if not isinstance(item, dict) or not item.get("sourcePath"):
                        continue
                    source_path = normalize_path(str(item["sourcePath"]))
                    represented_paths.add(source_path)
                    provenance.add(
                        (
                            source_path,
                            str(item.get("sourceKind") or cap.source_kind),
                            str(item.get("sourceSystem") or cap.source_system),
                            str(item.get("contentHash") or cap.content_hash),
                        )
                    )
            for source_path in cap.metadata.get("sourcePaths") or [cap.source_path]:
                if source_path:
                    normalized_source_path = normalize_path(str(source_path))
                    if normalized_source_path in represented_paths:
                        continue
                    provenance.add(
                        (
                            normalized_source_path,
                            cap.source_kind,
                            cap.source_system,
                            cap.content_hash,
                        )
                    )

        metadata = dict(winner.metadata)
        metadata["sourcePaths"] = sorted({item[0] for item in provenance})
        metadata["sourceProvenance"] = [
            {
                "sourcePath": source_path,
                "sourceKind": source_kind,
                "sourceSystem": source_system,
                "contentHash": content_hash,
            }
            for source_path, source_kind, source_system, content_hash in sorted(provenance)
        ]
        conflicts = [
            item for item in metadata["sourceProvenance"] if item["contentHash"] != winner.content_hash
        ]
        if conflicts:
            metadata["staleMirrorDetected"] = True
            metadata["sourceConflicts"] = conflicts
            metadata["sourceAuthority"] = {
                "selectedSourcePath": normalize_path(winner.source_path),
                "selectedSourceSystem": winner.source_system,
                "rank": top_rank,
            }
        if ambiguous_sources:
            metadata["ambiguousEffectiveUriCollision"] = True
            metadata["ambiguousSources"] = ambiguous_sources
            metadata["sourceAuthority"] = {
                "selectedSourcePath": normalize_path(winner.source_path),
                "selectedSourceSystem": winner.source_system,
                "rank": top_rank,
                "resolvedBy": "deterministic-tiebreak",
            }
        merged.append(dataclasses.replace(winner, metadata=metadata))
    return merged


def _upsert_discovered(
    con: sqlite3.Connection,
    capabilities: Iterable[Capability],
    *,
    vector_enabled: bool,
) -> dict[str, int | bool]:
    placement_index = load_vault_placement_index(vault_placement_path())
    added = updated = unchanged = 0
    # A single failed embed used to latch `vectors_ok` False for the REST OF THE
    # RUN, silently leaving every later capability unvectorized while the run
    # still reported success. Observed 2026-07-27 after an embedding-model swap:
    # the signature change correctly dropped capability_vec, then one transient
    # failure at ~#180 left 3,300 of 3,479 caps with no vector at all. Hybrid
    # search degraded to FTS-only for 95% of the corpus and nothing said so.
    #
    # Count failures instead of latching, and only stop early on a sustained
    # outage (the backend is genuinely down) rather than one bad row.
    vector_failures = 0
    vectors_written = 0
    consecutive_failures = 0
    vector_aborted = False
    max_consecutive_failures = 25
    effective_capabilities: list[Capability] = []
    for cap in capabilities:
        placed = apply_vault_placement(con, cap, placement_index)
        effective_capabilities.append(placed if placed is not None else apply_default_user_namespace(cap))

    for effective in _merge_by_effective_uri(effective_capabilities):
        previous = con.execute(
            """SELECT uri, content_hash, metadata_json, store_id, namespace_id, approval_state,
                      visibility, discovery_mode, owner, submitted_by, promoted_from_uri
               FROM capabilities WHERE uri = ?""",
            (effective.uri,),
        ).fetchone()
        if previous is None:
            previous = con.execute(
                """SELECT uri, content_hash, metadata_json, store_id, namespace_id, approval_state,
                          visibility, discovery_mode, owner, submitted_by, promoted_from_uri
                   FROM capabilities WHERE canonical_key = ?""",
                (effective.canonical_key,),
            ).fetchone()
        # An approved promotion is an authoritative governance decision layered
        # over the authored source identity. Discovery still returns the source
        # URI, recorded in promoted_from_uri, but ingest must update content at
        # the promoted address rather than migrating the row back to private.
        if (
            previous is not None
            and previous["promoted_from_uri"]
            and previous["approval_state"] == "approved"
        ):
            effective = dataclasses.replace(
                effective,
                uri=previous["uri"],
                store_id=previous["store_id"],
                namespace_id=previous["namespace_id"],
                visibility=previous["visibility"],
                discovery_mode=previous["discovery_mode"],
                owner=previous["owner"],
                submitted_by=previous["submitted_by"],
                promoted_from_uri=previous["promoted_from_uri"],
            )
        previous_index_text: str | None = None
        if previous is not None:
            previous_fts = con.execute(
                """
                SELECT capability_fts.content
                FROM capability_fts
                JOIN capabilities ON capabilities.id = capability_fts.rowid
                WHERE capabilities.uri = ?
                """,
                (previous["uri"],),
            ).fetchone()
            if previous_fts is not None:
                previous_index_text = str(previous_fts["content"])
        if previous is None:
            added += 1
        else:
            if previous["uri"] != effective.uri:
                _migrate_canonical_uri(con, previous["uri"], effective.uri)
            if previous["content_hash"] == effective.content_hash:
                unchanged += 1
            else:
                updated += 1
        # A matching active quarantine is a real serving hold, not merely an
        # audit record. Keep the row in the catalog for operator inspection but
        # make every normal discover/load/call policy treat it as inactive.
        held = con.execute(
            """SELECT 1 FROM capguard_quarantine
               WHERE tenant_id = ? AND capability_uri = ? AND content_hash = ?
                 AND status = 'quarantined' LIMIT 1""",
            (effective.tenant_id or "asg", effective.uri, effective.content_hash),
        ).fetchone()
        if held is not None:
            effective = dataclasses.replace(
                effective, lifecycle="draft", approval_state="pending"
            )
        cap_id = upsert_capability(con, effective)
        if vector_enabled and not vector_aborted:
            if _upsert_vector(
                con,
                cap_id,
                effective,
                enabled=True,
                index_text_unchanged=previous_index_text == effective.index_text(),
            ):
                vectors_written += 1
                consecutive_failures = 0
            else:
                vector_failures += 1
                consecutive_failures += 1
                # Record the failure on the cap row so it is observable per-cap,
                # not only through aggregate counts. The global vector flag is
                # NOT flipped here: an isolated bad row must not disable semantic
                # search for the whole mesh.
                _mark_vector_failure(con, cap_id)
                if consecutive_failures >= max_consecutive_failures:
                    # Sustained failure means the backend is down, not a bad row.
                    # Stop hammering it, but record that coverage is incomplete.
                    vector_aborted = True
    removed = _delete_source_orphaned_capabilities(con)
    return {
        "added": added,
        "updated": updated,
        "unchanged": unchanged,
        "removed": removed,
        # "Is the vector subsystem functioning?" — deliberately NOT "did every
        # embed succeed". An isolated bad row must not disable semantic search
        # for the whole mesh; only a sustained outage does. Coverage is carried
        # by the counts below, which are always reported, so partial coverage
        # can be seen without conflating it with a dead subsystem.
        "vectorsOk": bool(vector_enabled and not vector_aborted),
        "vectorsWritten": vectors_written,
        "vectorFailures": vector_failures,
        "vectorAborted": vector_aborted,
    }


def _delete_source_orphaned_capabilities(con: sqlite3.Connection) -> int:
    """Remove stale identities only when a discovered source moved elsewhere.

    ``capability_sources.source_path`` is unique. When corrected package
    attribution or frontmatter changes a capability URI, upserting the new
    identity transfers that path away from the old row. A merge ingest must
    retire that now-source-less identity or it remains searchable as a ghost.

    This is intentionally narrower than general deletion: capabilities with a
    share, pending promotion, relationship, or scoped role assignment fail the
    transaction closed and require explicit governance reconciliation.
    Terminal review/promotion/audit records remain immutable history and may
    continue to reference the retired URI.
    """

    rows = con.execute(
        """
        SELECT c.id, c.uri
        FROM capabilities c
        WHERE c.source_kind NOT IN ('system_capability', 'capmesh_draft')
          AND NOT EXISTS (
              SELECT 1 FROM capability_sources s WHERE s.uri = c.uri
          )
        ORDER BY c.uri
        """
    ).fetchall()
    removed = 0
    for row in rows:
        uri = str(row["uri"])
        blockers = {
            "shares": int(
                con.execute("SELECT COUNT(*) FROM shares WHERE capability_uri = ?", (uri,)).fetchone()[0]
            ),
            "pendingPromotions": int(
                con.execute(
                    "SELECT COUNT(*) FROM promotion_requests WHERE capability_uri = ? AND state = 'pending'",
                    (uri,),
                ).fetchone()[0]
            ),
            "relationships": int(
                con.execute("SELECT COUNT(*) FROM relationship_tuples WHERE object = ?", (uri,)).fetchone()[0]
            ),
            "roleAssignments": int(
                con.execute(
                    "SELECT COUNT(*) FROM role_assignments "
                    "WHERE scope_type = 'capability' AND scope_id = ? AND revoked_at IS NULL",
                    (uri,),
                ).fetchone()[0]
            ),
        }
        active = {name: count for name, count in blockers.items() if count}
        if active:
            raise CandidateValidationError(
                f"source reassignment stranded governed capability {uri}: {active}"
            )
        try:
            con.execute("DELETE FROM capability_vec WHERE rowid = ?", (int(row["id"]),))
        except (sqlite3.Error, RuntimeError):
            pass
        con.execute("DELETE FROM capability_fts WHERE rowid = ?", (int(row["id"]),))
        con.execute("DELETE FROM capabilities WHERE id = ?", (int(row["id"]),))
        removed += 1
    return removed


def _enforce_install_guards(
    con: sqlite3.Connection,
    capabilities: Iterable[Capability],
    roots: Iterable[str | Path],
) -> list[Capability]:
    """Run the per-capability admission guards against a discovered batch.

    Both guards are fatal by design. The failure this exists to prevent is not
    a bad row -- it is a bad row that was accepted quietly and only surfaced
    hundreds of rows later as an unservable catalog.

    The duplicate guard checks the incoming batch against itself as well as
    against the live catalog, because a single run pointed at two roots can
    introduce the duplicate pair without either copy being present beforehand.

    One exception to "fatal": a ``SupersededCapability`` -- a copy from a
    strictly LOWER-authority root than the one that already owns the capability
    -- is dropped from the batch instead of aborting. That is not a quiet
    accept; it is a quiet REJECT of the row, which is precisely the outcome the
    guard wants, and it is logged. Returns the capabilities that were admitted.
    """

    roots = tuple(roots)
    existing = con.execute(
        "SELECT plugin, name, package_path, uri FROM capabilities WHERE lifecycle != 'removed'"
    ).fetchall()
    seen: list[tuple[str | None, str, str, str]] = []
    admitted: list[Capability] = []
    superseded = 0
    for cap in capabilities:
        assert_body_resolvable(cap.package_path, cap.entrypoint, roots)
        try:
            assert_not_duplicate(
                cap.plugin,
                cap.name,
                list(existing) + seen,
                package_path=cap.package_path,
                uri=cap.uri,
            )
        except SupersededCapability as exc:
            superseded += 1
            print(f"capmesh: {exc}", file=sys.stderr)
            continue
        seen.append((cap.plugin, cap.name, cap.package_path, cap.uri))
        admitted.append(cap)
    if superseded:
        print(
            f"capmesh: {superseded} lower-authority capability copies skipped in "
            "favour of the canonical root",
            file=sys.stderr,
        )
    return admitted


def _is_system_or_draft(cap: Capability) -> bool:
    return cap.source_kind in ("system_capability", "capmesh_draft")


def _existing_capability_identity(con: sqlite3.Connection) -> dict[str, str]:
    """URIs already in ``capabilities`` (the set a new discovery must NOT be in).

    Used by the CapGuard quarantine gate to decide which discovered capabilities
    are genuinely *new* (added) versus a refresh of an already-indexed row, so the
    gate quarantines only first-time capabilities and never re-holds a previously
    released one on a no-op re-ingest.
    """
    return {
        str(row["uri"]): str(row["content_hash"])
        for row in con.execute("SELECT uri, content_hash FROM capabilities").fetchall()
    }


def _quarantine_new_capabilities(
    con: sqlite3.Connection,
    capabilities: Iterable[Capability],
    *,
    tenant_id: str = "asg",
) -> dict[str, int]:
    """Quarantine every genuinely-new capability BEFORE it is indexed.

    CapGuard contract: quarantine-before-indexing. A capability is placed into the
    per-tenant quarantine store (a signed-attestation-bound row keyed by
    ``(tenant, uri, content_hash)``) before it is ever written to the live
    ``capabilities`` table, so an unscanned artifact cannot become callable by
    bypassing quarantine. The quarantine row is idempotent for identical content
    (see :func:`capmesh.capguard.quarantine_capability`), so a no-op re-ingest of
    unchanged content touches nothing.

    Only capabilities that are NOT already in ``capabilities`` (genuinely new) are
    quarantined here, so a previously-released capability is never re-held on a
    refresh, and system/draft capabilities (builtins, governance drafts) are
    excluded — they enter the catalog through their own authoritative paths.

    The quarantine row is keyed by the *effective* (post-placement) URI and
    content hash, NOT the raw discovered identity, so it matches the row
    ``_upsert_discovered`` actually writes to ``capabilities``. The placement
    transform (``apply_vault_placement`` / ``apply_default_user_namespace``) can
    re-namespace a discovered URI; without mirroring it here the quarantine row
    would be keyed by a URI that is never indexed, so a re-ingest would
    re-quarantine forever and the release path could not correlate the
    quarantine item to the live capability. The placement here is computed
    identically to ``_upsert_discovered`` so the two agree on identity.

    Runs OUTSIDE the ingest write transaction: the quarantine store is a separate
    SQLite table with its own commit, so a quarantine row is durable the instant
    it is recorded, even if the later ``BEGIN IMMEDIATE`` write is rolled back.
    That ordering is the fail-closed guarantee: a new capability either has a
    quarantine row before it is indexed, or the ingest does not reach the index.
    """
    from .capguard import quarantine_capability
    from .governance import apply_default_user_namespace, apply_vault_placement

    placement_index = load_vault_placement_index(vault_placement_path())
    existing = _existing_capability_identity(con)
    quarantined = 0
    fresh_for_content = 0
    for cap in capabilities:
        if _is_system_or_draft(cap):
            continue
        # Mirror _upsert_discovered's placement so the quarantine row is keyed
        # by the exact URI + content_hash that will be written to capabilities.
        placed = apply_vault_placement(con, cap, placement_index)
        effective = placed if placed is not None else apply_default_user_namespace(cap)
        if existing.get(effective.uri) == effective.content_hash:
            # An unchanged refresh is idempotent. Changed content is a new
            # security subject and must obtain fresh scan/release evidence.
            continue
        record = quarantine_capability(
            con,
            tenant_id=effective.tenant_id or tenant_id,
            capability_uri=effective.uri,
            capability_type=effective.capability_type,
            name=effective.name,
            version=effective.version,
            source_path=effective.source_path,
            content_hash=effective.content_hash,
            reason="pending_scan",
            submitted_by=effective.submitted_by or effective.created_by or "ingest@capmesh",
            metadata={
                "discoveredSourceSystem": cap.source_system,
                "discoveredSourceKind": cap.source_kind,
                "effectiveUri": effective.uri,
            },
            commit=True,
        )
        quarantined += 1
        # A changed content_hash for an existing URI opens a fresh quarantine
        # row (the store's active-quarantine unique index allows it). Track it
        # so operators can see re-quarantines on the result surface.
        if record.get("reason") == "pending_scan":
            fresh_for_content += 1
    return {"quarantined": quarantined, "freshForContent": fresh_for_content}


def ingest_index(
    db_path: str | Path,
    roots: Iterable[str | Path],
    *,
    enable_vector: bool = True,
    post_ingest: Callable[[sqlite3.Connection], dict[str, Any]] | None = None,
    quarantine_new: bool = True,
) -> dict[str, Any]:
    """Add or refresh capabilities discovered under *roots* without deleting others.

    This is the only behavior exposed by ``capmesh ingest``.  A narrow root has a
    narrow write scope, which makes the July 17 2110->16 failure mode impossible.

    Every genuinely-new discovered
    capability is recorded in the CapGuard quarantine store BEFORE it is indexed,
    so no unscanned artifact can become callable by bypassing the gate. The
    quarantine row is the fail-closed anchor for the signed scan/release
    attestation chain; the capability stays ``quarantined`` until an explicit,
    evidence-bound release (see :mod:`capmesh.capguard`).
    """

    roots = tuple(roots)
    con = connect(db_path)
    status = init_db(con, enable_vector=enable_vector)
    capabilities = discover_capabilities(roots)
    # Also discover capabilities via the plugin_hook scanner.  Non-fatal:
    # if plugin_hook is unavailable, the manifest-based discovery result
    # is used as-is.  The plugin_hook scanner looks for cap.json files
    # and generates capability metadata from them.
    plugin_hook_discovered = 0
    try:
        from .plugin_hook import scan_and_emit
        for root in roots:
            hook_caps = scan_and_emit(root, write=False)
            if hook_caps:
                plugin_hook_discovered += len(hook_caps)
    except (ImportError, Exception):  # noqa: BLE001, S110
        pass
    # Admission guards run BEFORE the write transaction opens, so a refused
    # capability aborts the whole run loudly instead of being skipped into a
    # partially-written catalog. See install_policy.InstallPolicyError.
    #
    # The guards also FILTER: a copy from a strictly lower-authority root than
    # the one that already owns the capability is dropped here rather than
    # written, so the canonical row is not shadowed by a mirror. The filtered
    # list is what gets ingested.
    try:
        capabilities = _enforce_install_guards(con, capabilities, roots)
    except Exception as exc:
        con.close()
        write_ingest_audit_log(
            db_path,
            roots,
            False,
            0,
            0,
            "error",
            str(exc),
            operation="ingest",
            discovered=len(capabilities),
            removed=0,
        )
        raise
    # CapGuard quarantine-before-indexing (CM-CapGuard). Run AFTER admission
    # guards (so a refused capability is not quarantined) and BEFORE the write
    # transaction opens (so the quarantine row is durable before the capability
    # is ever written to `capabilities`). A new capability either has a
    # quarantine row before it is indexed, or the ingest does not reach the
    # index — there is no path that writes a new row to `capabilities` without a
    # corresponding `capguard_quarantine` row. See `_quarantine_new_capabilities`.
    # ``quarantine_new`` is retained only as a source-compatibility argument.
    # It can no longer disable the security boundary: callers cannot opt user
    # uploads out of CapGuard.
    capguard_quarantine: dict[str, int] = {"quarantined": 0, "freshForContent": 0}
    try:
        capguard_quarantine = _quarantine_new_capabilities(con, capabilities)
    except Exception as exc:
        # A quarantine-store failure is fail-closed: do NOT proceed to index
        # capabilities that may not have a quarantine row. Close the handle
        # and surface the error exactly like an admission-guard failure.
        con.close()
        write_ingest_audit_log(
            db_path,
            roots,
            False,
            0,
            0,
            "error",
            f"capguard quarantine failed: {exc}",
            operation="ingest",
            discovered=len(capabilities),
            removed=0,
        )
        raise
    before = _live_capability_count(con)
    try:
        con.execute("BEGIN IMMEDIATE")
        changes = _upsert_discovered(
            con,
            capabilities,
            vector_enabled=bool(status["vector"]["enabled"]),
        )
        post_ingest_result = post_ingest(con) if post_ingest is not None else None
        generation = _record_catalog_generation(con)
        con.commit()
        after = _live_capability_count(con)
        coverage = coverage_report(con, roots)
    except Exception as exc:
        con.rollback()
        con.close()
        write_ingest_audit_log(
            db_path,
            roots,
            False,
            before,
            before,
            "error",
            str(exc),
            operation="ingest",
            discovered=len(capabilities),
            removed=0,
        )
        raise
    # Security scans on ingested capabilities.  Non-fatal: a scan failure is
    # logged but never aborts a successful ingest.  Only capabilities that
    # were added or updated in this run are scanned to avoid re-scanning the
    # entire catalog on every 15-minute refresh.
    security_scans: dict[str, Any] = {}
    try:
        from .dependency_audit import scan_capability as _scan_deps
        from .malware_scan import scan_capability as _scan_malware
        scan_count = 0
        malware_findings = 0
        dep_findings = 0
        for cap in capabilities:
            uri = getattr(cap, "uri", None)
            if not uri:
                continue
            try:
                result = _scan_malware(con, uri, tenant_id=getattr(cap, "tenant_id", "asg"), commit=False)
                if not result.get("passed", True):
                    malware_findings += 1
            except Exception:  # noqa: BLE001, S110
                pass
            try:
                deps = _scan_deps(con, uri, tenant_id=getattr(cap, "tenant_id", "asg"))
                dep_findings += len(deps)
            except Exception:  # noqa: BLE001, S110
                pass
            scan_count += 1
        if scan_count:
            security_scans = {
                "scanned": scan_count,
                "malwareFindings": malware_findings,
                "dependencyFindings": dep_findings,
            }
            con.commit()
    except (ImportError, sqlite3.Error):
        pass
    # Track capability dependencies discovered during ingest.  Non-fatal:
    # a failure to track dependencies does not abort ingest.  The dependency
    # graph module scans metadata for "depends_on" entries and records them.
    try:
        from .dependency_graph import add_dependency, ensure_dependency_table
        ensure_dependency_table(con)
        for cap in capabilities:
            deps = (cap.metadata or {}).get("depends_on", [])
            if isinstance(deps, list):
                for dep_uri in deps:
                    if isinstance(dep_uri, str) and dep_uri.strip():
                        try:
                            add_dependency(con, cap.uri, dep_uri.strip(), tenant_id=getattr(cap, "tenant_id", "asg"), commit=False)
                        except Exception:  # noqa: BLE001, S110
                            pass
    except (ImportError, sqlite3.Error):
        pass
    # Detect semver version conflicts among ingested capabilities.  Non-fatal:
    # conflicts are reported in the result but do not abort ingest.
    version_conflicts: list[dict[str, Any]] = []
    try:
        from .semver_policy import check_version_conflicts
        cap_dicts = [
            {"uri": getattr(c, "uri", ""), "version": getattr(c, "version", ""), "name": getattr(c, "name", "")}
            for c in capabilities
        ]
        version_conflicts = check_version_conflicts(cap_dicts)
    except (ImportError, Exception):  # noqa: BLE001, S110
        pass
    # Build SLSA provenance statement for this ingest run.  Non-fatal.
    provenance: dict[str, Any] = {}
    try:
        from .slsa_provenance import build_provenance_statement
        provenance = build_provenance_statement(
            subject_uris=[getattr(c, "uri", "") for c in capabilities],
            source_system=str(os.environ.get("CAPMESH_SOURCE_SYSTEM", "asg-os")),
            builder="capmesh-ingest",
        )
    except (ImportError, Exception):  # noqa: BLE001, S110
        pass
    # Verify the OUTCOME, not the intent, while the connection is still open.
    # `vectorsWritten` counts successful _upsert_vector calls, but that function
    # also returns True on its "already present" fast path, so it reports intent.
    # On 2026-07-27 a run reported vectorsWritten=3458 / vectorFailures=0 while
    # capability_vec actually held 1,670 rows for 3,479 capabilities — a
    # flawless-looking report next to 48% real coverage.
    vector_coverage: dict[str, Any] = {}
    if status["vector"]["enabled"]:
        try:
            embedded = int(con.execute("SELECT count(*) FROM capability_vec").fetchone()[0])
            # Denominator must be the SAME population as the numerator. `after`
            # is a filtered count (3,464 vs 3,479 real rows on 2026-07-27), so
            # comparing a full-table vector count against it made "complete"
            # true while 15 capabilities could still be unvectorized.
            total_caps = int(con.execute("SELECT count(*) FROM capabilities").fetchone()[0])
            # Self-heal before reporting. On 2026-07-27, 1,809 capabilities ended
            # a run with no vector even though every per-capability call returned
            # success, and the cause is still not identified. Rather than let an
            # unexplained gap silently degrade every client to FTS-only until a
            # human notices, close it here: re-embed anything missing, using the
            # index_text already stored in FTS (the exact string _upsert_vector
            # embeds). Bounded, counted, and reported — never silent.
            # Drop vectors whose capability is gone. Nothing reads them (search
            # joins back to `capabilities`), but they make `embedded` exceed the
            # capability count, which masks a real shortfall: 15 orphans would
            # make 15 genuinely-unvectorized capabilities look like full coverage.
            orphans = 0
            try:
                cur = con.execute(
                    "DELETE FROM capability_vec WHERE rowid NOT IN (SELECT id FROM capabilities)"
                )
                orphans = int(cur.rowcount or 0)
                if orphans:
                    con.commit()
                    embedded = int(
                        con.execute("SELECT count(*) FROM capability_vec").fetchone()[0]
                    )
            except (sqlite3.Error, RuntimeError):
                orphans = -1

            healed = 0
            heal_failed = 0
            if embedded < total_caps:
                rows = con.execute(
                    """
                    SELECT c.id, f.content FROM capabilities c
                    JOIN capability_fts f ON f.rowid = c.id
                    WHERE c.id NOT IN (SELECT rowid FROM capability_vec)
                    """
                ).fetchall()
                for cap_id, text in rows:
                    try:
                        con.execute("DELETE FROM capability_vec WHERE rowid = ?", (cap_id,))
                        con.execute(
                            "INSERT INTO capability_vec(rowid, embedding) VALUES (?, ?)",
                            (cap_id, json.dumps(embed_text(str(text or "")))),
                        )
                        healed += 1
                    except (sqlite3.Error, RuntimeError, ValueError):
                        heal_failed += 1
                if healed:
                    con.commit()
                embedded = int(
                    con.execute("SELECT count(*) FROM capability_vec").fetchone()[0]
                )
            vector_coverage = {
                "capabilities": total_caps,
                "embedded": embedded,
                "missing": max(total_caps - embedded, 0),
                "complete": embedded >= total_caps,
                "healed": healed,
                "healFailed": heal_failed,
                "orphansRemoved": orphans,
            }
        except (sqlite3.Error, RuntimeError) as exc:
            vector_coverage = {"error": str(exc)}
    con.close()
    write_ingest_audit_log(
        db_path,
        roots,
        False,
        before,
        after,
        "ok",
        operation="ingest",
        discovered=len(capabilities),
        added=int(changes["added"]),
        updated=int(changes["updated"]),
        removed=int(changes["removed"]),
    )
    result = {
        "operation": "merge",
        "capabilities": after,
        "vectorCoverage": vector_coverage,
        "securityScans": security_scans,
        "versionConflicts": version_conflicts,
        "provenance": provenance,
        "pluginHookDiscovered": plugin_hook_discovered,
        "discoveredCapabilities": len(capabilities),
        "countBefore": before,
        "countAfter": after,
        "added": changes["added"],
        "updated": changes["updated"],
        "unchanged": changes["unchanged"],
        "removed": changes["removed"],
        "generation": generation,
        "sources": coverage["indexedSources"],
        "discoveredSources": coverage["discoveredSources"],
        "coverageOk": coverage["coverageOk"],
        "missingSources": coverage["missingSources"],
        "capGuard": {
            "quarantineEnabled": True,
            "quarantined": capguard_quarantine.get("quarantined", 0),
            "freshForContent": capguard_quarantine.get("freshForContent", 0),
        },
        "vector": (
            # Coverage counts ride along on EVERY run, not only failing ones.
            # A run that wrote 179 of 3,479 vectors previously reported a bare
            # enabled:true and looked indistinguishable from full coverage.
            {
                **status["vector"],
                "vectorsWritten": changes["vectorsWritten"],
                "vectorFailures": changes["vectorFailures"],
            }
            if not status["vector"]["enabled"] or changes["vectorsOk"]
            else {
                **status["vector"],
                "enabled": False,
                # Name the actual coverage. "vector upsert failed" read the same
                # whether 1 or 3,300 capabilities were left unvectorized.
                "reason": (
                    f"vector upsert failed for {changes['vectorFailures']} capabilities "
                    f"({changes['vectorsWritten']} written"
                    + ("; aborted after sustained failures" if changes.get("vectorAborted") else "")
                    + "); lexical FTS remains active"
                ),
                "vectorsWritten": changes["vectorsWritten"],
                "vectorFailures": changes["vectorFailures"],
            }
        ),
        "sqlite": status["sqlite"],
    }
    if post_ingest_result is not None:
        result["postIngest"] = post_ingest_result
    return result


def _approved_removal_uris(manifest: str | Path | Iterable[str] | None) -> set[str]:
    if manifest is None:
        return set()
    if isinstance(manifest, (str, Path)):
        raw = json.loads(Path(manifest).expanduser().read_text(encoding="utf-8"))
        values = raw.get("approvedRemovals", []) if isinstance(raw, dict) else raw
    else:
        values = manifest
    if not isinstance(values, (list, tuple, set)) or any(not isinstance(value, str) for value in values):
        raise ValueError("Removal manifest must be a JSON list or {'approvedRemovals': [uri, ...]}")
    return {str(value) for value in values}


def validate_candidate_database(con: sqlite3.Connection, roots: Iterable[str | Path]) -> dict[str, Any]:
    quick = str(con.execute("PRAGMA quick_check").fetchone()[0])
    if quick != "ok":
        raise CandidateValidationError(f"candidate quick_check failed: {quick}")
    foreign_key_rows = con.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_rows:
        raise CandidateValidationError(f"candidate foreign_key_check failed: {len(foreign_key_rows)} violation(s)")
    cap_count = int(con.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0])
    fts_count = int(con.execute("SELECT COUNT(*) FROM capability_fts").fetchone()[0])
    if cap_count != fts_count:
        raise CandidateValidationError(f"candidate FTS mismatch: capabilities={cap_count}, fts={fts_count}")
    source_orphans = int(
        con.execute(
            """
            SELECT COUNT(*)
            FROM capabilities c
            WHERE c.source_kind NOT IN ('system_capability', 'capmesh_draft')
              AND NOT EXISTS (SELECT 1 FROM capability_sources s WHERE s.uri = c.uri)
            """
        ).fetchone()[0]
    )
    if source_orphans:
        raise CandidateValidationError(
            f"candidate contains {source_orphans} source-orphaned capability row(s)"
        )
    orphan_queries = {
        "shares": "SELECT COUNT(*) FROM shares s LEFT JOIN capabilities c ON c.uri=s.capability_uri WHERE c.uri IS NULL",
        # Approved/recalled/rejected promotion rows are immutable audit history: their
        # original private source URI may legitimately disappear after canonical
        # placement or a package rename. Only an actionable pending request must still
        # resolve to a live source capability.
        "promotionRequests": "SELECT COUNT(*) FROM promotion_requests p LEFT JOIN capabilities c ON c.uri=p.capability_uri WHERE p.state = 'pending' AND c.uri IS NULL",
        "relationships": "SELECT COUNT(*) FROM relationship_tuples r LEFT JOIN capabilities c ON c.uri=r.object WHERE r.object LIKE 'cap://%' AND c.uri IS NULL",
    }
    governance_orphans = {
        name: int(con.execute(sql).fetchone()[0])
        for name, sql in orphan_queries.items()
    }
    if any(governance_orphans.values()):
        raise CandidateValidationError(f"candidate has orphaned governance references: {governance_orphans}")
    coverage = coverage_report(con, roots)
    if not coverage["coverageOk"]:
        raise CandidateValidationError(
            f"candidate is missing {len(coverage['missingSources'])} discovered source(s)"
        )
    return {
        "quickCheck": quick,
        "foreignKeyCheck": "ok",
        "capabilities": cap_count,
        "ftsRows": fts_count,
        "governanceOrphans": governance_orphans,
        "coverage": coverage,
        "sqlite": sqlite_wal_safety(),
    }


def stage_rebuild_index(
    db_path: str | Path,
    roots: Iterable[str | Path],
    *,
    enable_vector: bool = True,
    approved_removals: str | Path | Iterable[str] | None = None,
    candidate_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build and validate a full replacement in a shadow DB without promoting it."""

    roots = tuple(roots)
    db = Path(db_path).expanduser().resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    source = connect(db)
    init_db(source, enable_vector=enable_vector)
    before_uris = {
        row["uri"]
        for row in source.execute(
            "SELECT uri FROM capabilities WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
        ).fetchall()
    }
    before = len(before_uris)
    if candidate_path is None:
        fd, raw_candidate = tempfile.mkstemp(prefix=f".{db.name}.candidate-", suffix=".db", dir=db.parent)
        os.close(fd)
        candidate = Path(raw_candidate)
    else:
        candidate = Path(candidate_path).expanduser().resolve()
        if candidate.parent != db.parent:
            source.close()
            raise ValueError("Candidate DB must be on the same filesystem/directory as the live DB")
        candidate.unlink(missing_ok=True)
    target = sqlite3.connect(candidate)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()

    capabilities = discover_capabilities(roots)
    approved = _approved_removal_uris(approved_removals)
    con = connect(candidate)
    status = init_db(con, enable_vector=enable_vector)
    # A staged rebuild is an ingestion path too.  Quarantine new capabilities
    # while the candidate still contains the live catalog snapshot, so the
    # new-vs-existing comparison is accurate and the quarantine records travel
    # with the candidate if it is promoted.  Failure is deliberately fatal:
    # no candidate containing an unscanned new capability may be produced.
    try:
        capguard_quarantine = _quarantine_new_capabilities(con, capabilities)
    except Exception as exc:
        con.close()
        candidate.unlink(missing_ok=True)
        write_ingest_audit_log(
            db,
            roots,
            True,
            before,
            before,
            "error",
            f"capguard quarantine failed: {exc}",
            operation="rebuild.stage",
            discovered=len(capabilities),
            removed=0,
        )
        raise
    try:
        con.execute("BEGIN IMMEDIATE")
        drafts = [
            capability_from_row(row)
            for row in con.execute("SELECT * FROM capabilities WHERE source_kind = 'capmesh_draft'").fetchall()
        ]
        con.execute("DELETE FROM capability_fts")
        con.execute("DELETE FROM capability_sources")
        con.execute("DELETE FROM capabilities WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')")
        vector_enabled = bool(status["vector"]["enabled"])
        if vector_enabled:
            con.execute("DELETE FROM capability_vec")
        for preserved in [*builtin_system_capabilities(), *drafts]:
            cap_id = upsert_capability(con, preserved)
            if vector_enabled and not _upsert_vector(con, cap_id, preserved, enabled=True):
                raise CandidateValidationError("candidate vector rebuild failed for a preserved capability")
        changes = _upsert_discovered(con, capabilities, vector_enabled=vector_enabled)
        if vector_enabled and not changes["vectorsOk"]:
            raise CandidateValidationError("candidate vector rebuild failed")
        after_uris = {
            row["uri"]
            for row in con.execute(
                "SELECT uri FROM capabilities WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
            ).fetchall()
        }
        removed_uris = before_uris - after_uris
        unexpected = removed_uris - approved
        if unexpected:
            preview = sorted(unexpected)[:10]
            raise UnexpectedRemovalError(
                f"staged rebuild rejected {len(unexpected)} unapproved removal(s): {preview}"
            )
        unused = approved - removed_uris
        if unused:
            raise UnexpectedRemovalError(
                f"staged rebuild rejected {len(unused)} unused removal approval(s): {sorted(unused)[:10]}"
            )
        generation = _record_catalog_generation(con)
        con.commit()
        validation = validate_candidate_database(con, roots)
    except Exception as exc:
        con.rollback()
        con.close()
        candidate.unlink(missing_ok=True)
        write_ingest_audit_log(
            db,
            roots,
            True,
            before,
            before,
            "error",
            str(exc),
            operation="rebuild.stage",
            discovered=len(capabilities),
            removed=0,
        )
        raise
    after = _live_capability_count(con)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    candidate_sha256 = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
    write_ingest_audit_log(
        db,
        roots,
        True,
        before,
        after,
        "ok",
        operation="rebuild.stage",
        discovered=len(capabilities),
        added=len(after_uris - before_uris),
        updated=int(changes["updated"]),
        removed=len(removed_uris),
    )
    return {
        "operation": "rebuild.stage",
        "candidatePath": str(candidate),
        "candidateSha256": candidate_sha256,
        "generation": generation,
        "countBefore": before,
        "countAfter": after,
        "discoveredCapabilities": len(capabilities),
        "added": len(after_uris - before_uris),
        "updated": changes["updated"],
        "removed": len(removed_uris),
        "approvedRemovals": sorted(removed_uris),
        "unusedRemovalApprovals": [],
        "capguard": {
            "quarantined": capguard_quarantine.get("quarantined", 0),
            "freshForContent": capguard_quarantine.get("freshForContent", 0),
        },
        "validation": validation,
        "vector": status["vector"],
        "sqlite": status["sqlite"],
    }


def promote_shadow_database(
    db_path: str | Path,
    candidate_path: str | Path,
    *,
    workers_drained: bool = False,
    rollback_path: str | Path | None = None,
    expected_sha256: str | None = None,
) -> dict[str, str]:
    """Atomically promote a validated candidate after the service pool is drained."""

    if not workers_drained:
        raise RuntimeError("Atomic DB promotion requires a drained/stopped Capmesh worker pool")
    db = Path(db_path).expanduser().resolve()
    candidate = Path(candidate_path).expanduser().resolve()
    if candidate.parent != db.parent:
        raise ValueError("Candidate DB must be in the live DB directory for atomic os.replace")
    actual_sha256 = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
    if expected_sha256 is not None and not hmac.compare_digest(actual_sha256, expected_sha256):
        raise CandidateValidationError("candidate digest no longer matches the validated staged artifact")
    if os.environ.get("CAPMESH_ENVIRONMENT", "").strip().lower() in {"production", "prod"} and expected_sha256 is None:
        raise CandidateValidationError("production promotion requires the staged candidate SHA-256")
    proc_root = Path("/proc")
    if proc_root.is_dir():
        holders: set[int] = set()
        for fd_dir in proc_root.glob("[0-9]*/fd"):
            try:
                pid = int(fd_dir.parent.name)
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            try:
                if any(path.resolve(strict=False) == db for path in fd_dir.iterdir()):
                    holders.add(pid)
            except (FileNotFoundError, PermissionError, OSError):
                continue
        if holders:
            raise RuntimeError(f"live database is still open by process(es): {sorted(holders)[:10]}")
    candidate_con = connect(candidate)
    validation = validate_candidate_database(candidate_con, ())
    candidate_con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    candidate_con.close()
    if validation["quickCheck"] != "ok":
        raise CandidateValidationError("candidate failed final validation")

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    rollback = Path(rollback_path).expanduser().resolve() if rollback_path else db.with_name(f"{db.name}.pre-rebuild-{stamp}")
    if db.exists():
        live = connect(db)
        live.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        rollback_target = sqlite3.connect(rollback)
        try:
            live.backup(rollback_target)
        finally:
            rollback_target.close()
            live.close()
    for suffix in ("-wal", "-shm"):
        Path(f"{db}{suffix}").unlink(missing_ok=True)
        Path(f"{candidate}{suffix}").unlink(missing_ok=True)
    os.replace(candidate, db)
    return {"databasePath": str(db), "rollbackPath": str(rollback)}


def rebuild_index(
    db_path: str | Path,
    roots: Iterable[str | Path],
    *,
    enable_vector: bool = True,
    replace_all: bool = False,
) -> dict[str, Any]:
    """Compatibility wrapper; ordinary callers now receive safe merge semantics."""

    if replace_all:
        raise ValueError("replace_all was removed; use stage_rebuild_index with an approved-removal manifest")
    result = ingest_index(db_path, roots, enable_vector=enable_vector)
    # rebuild_index performs a full rebuild, so the caller-facing label is "rebuild".
    result["operation"] = "rebuild"
    return result


def get_capability(con: sqlite3.Connection, uri_or_name: str) -> Capability | None:
    row = con.execute("SELECT * FROM capabilities WHERE uri = ?", (uri_or_name,)).fetchone()
    if row is None:
        row = con.execute(
            "SELECT * FROM capabilities WHERE name = ? OR title = ? ORDER BY source_system = 'asg-os.plugins' DESC LIMIT 1",
            (uri_or_name, uri_or_name),
        ).fetchone()
    if row is None:
        return None
    cap = capability_from_row(row)
    return None if _capguard_is_held(con, cap) else cap


def _capguard_is_held(con: sqlite3.Connection, capability: Capability) -> bool:
    """Return whether this exact tenant/URI/content version remains quarantined."""
    try:
        row = con.execute(
            """SELECT 1 FROM capguard_quarantine
               WHERE tenant_id = ? AND capability_uri = ? AND content_hash = ?
                 AND status = 'quarantined' LIMIT 1""",
            (
                capability.tenant_id or "asg",
                capability.uri,
                capability.content_hash,
            ),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-migration databases are upgraded by init_db; until then, fail
        # closed only when the table exists rather than breaking diagnostics.
        return False
    return row is not None


def list_capabilities(
    con: sqlite3.Connection,
    principal: Principal,
    *,
    capability_type: str | None = None,
    plugin: str | None = None,
    cursor: str | None = None,
    page_size: int = 50,
) -> dict[str, Any]:
    page_size = min(max(page_size, 1), 100)
    offset = int(cursor or "0")
    where = []
    params: list[Any] = []
    if capability_type:
        where.append("type = ?")
        params.append(capability_type)
    if plugin:
        where.append("plugin = ?")
        params.append(plugin)
    sql = "SELECT * FROM capabilities"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY type, plugin, name LIMIT ? OFFSET ?"
    rows = con.execute(sql, (*params, page_size + 1, offset)).fetchall()
    items = []
    for row in rows[:page_size]:
        cap = capability_from_row(row)
        if _capguard_is_held(con, cap):
            continue
        visible, locked = can_discover(cap, principal, con=con, audit=False)
        if visible:
            items.append(cap.to_record(stub=locked, include_paths=False))
    next_cursor = str(offset + page_size) if len(rows) > page_size else None
    return {"items": items, "nextCursor": next_cursor, "pageSize": page_size}


def search(con: sqlite3.Connection, query: str, principal: Principal, *, k: int = 10, capability_type: str | None = None) -> list[SearchResult]:
    k = min(max(k, 1), 50)
    ranks: dict[str, list[tuple[str, int, float]]] = defaultdict(list)
    candidate_limit = min(max(k * 12, 50), 600)
    normalized_query = slug_query(query)

    exact_where = [
        "(lower(name) = lower(?) OR lower(title) = lower(?) OR lower(replace(name, '-', ' ')) = lower(?) OR canonical_key LIKE ?)",
    ]
    exact_params: list[Any] = [query.strip(), query.strip(), query.strip(), f"%:{normalized_query}:%"]
    if capability_type:
        exact_where.append("type = ?")
        exact_params.append(capability_type)
    exact_rows = con.execute(
        "SELECT * FROM capabilities WHERE " + " AND ".join(exact_where) + " ORDER BY source_system = 'asg-os.plugins' DESC LIMIT ?",
        (*exact_params, candidate_limit),
    ).fetchall()
    for idx, row in enumerate(exact_rows, start=1):
        ranks[row["uri"]].append(("exact", idx, 0.0))

    fts_query = to_fts_query(query)
    if fts_query:
        try:
            type_clause = " AND c.type = ?" if capability_type else ""
            params: list[Any] = [fts_query]
            if capability_type:
                params.append(capability_type)
            params.append(candidate_limit)
            rows = con.execute(
                f"""
                SELECT c.*, bm25(capability_fts, 0.0, 12.0, 8.0, 4.0, 3.0, 2.0, 2.0, 1.0) AS fts_score
                FROM capability_fts
                JOIN capabilities c ON c.id = capability_fts.rowid
                WHERE capability_fts MATCH ?{type_clause}
                ORDER BY fts_score
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
            for idx, row in enumerate(rows, start=1):
                ranks[row["uri"]].append(("fts", idx, float(row["fts_score"])))
        except sqlite3.Error:
            pass

    # Query expansion fallback: if the original FTS query returned no results,
    # retry with taxonomy/synonym-expanded terms to improve recall.
    if fts_query and not any(kind == "fts" for kind, _, _ in (v for vals in ranks.values() for v in vals)):
        try:
            from .query_expansion import expand_search_terms
            expanded = expand_search_terms(query)
            if expanded and expanded != fts_query:
                type_clause = " AND c.type = ?" if capability_type else ""
                exp_params: list[Any] = [expanded]
                if capability_type:
                    exp_params.append(capability_type)
                exp_params.append(candidate_limit)
                exp_rows = con.execute(
                    f"""
                    SELECT c.*, bm25(capability_fts, 0.0, 12.0, 8.0, 4.0, 3.0, 2.0, 2.0, 1.0) AS fts_score
                    FROM capability_fts
                    JOIN capabilities c ON c.id = capability_fts.rowid
                    WHERE capability_fts MATCH ?{type_clause}
                    ORDER BY fts_score
                    LIMIT ?
                    """,
                    tuple(exp_params),
                ).fetchall()
                for idx, row in enumerate(exp_rows, start=1):
                    ranks[row["uri"]].append(("fts_expanded", idx, float(row["fts_score"])))
        except (sqlite3.Error, ImportError):
            pass

    for idx, row in enumerate(vector_rows(con, query, candidate_limit, capability_type=capability_type), start=1):
        ranks[row["uri"]].append(("vector", idx, float(row.get("distance", 0.0))))

    if not ranks:
        terms = query_terms(query)
        pattern = f"%{'%'.join(terms) if terms else query}%"
        where = "(name LIKE ? OR title LIKE ? OR description LIKE ?)"
        params = [pattern, pattern, pattern]
        if capability_type:
            where += " AND type = ?"
            params.append(capability_type)
        params.append(candidate_limit)
        rows = con.execute(
            f"SELECT * FROM capabilities WHERE {where} ORDER BY source_system = 'asg-os.plugins' DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        for idx, row in enumerate(rows, start=1):
            ranks[row["uri"]].append(("like", idx, 0.0))

    scored: list[tuple[float, Capability, tuple[str, ...]]] = []
    uris = list(ranks.keys())
    if uris:
        placeholders = ",".join("?" for _ in uris)
        cap_map: dict[str, Capability] = {}
        for row in con.execute(f"SELECT * FROM capabilities WHERE uri IN ({placeholders})", uris).fetchall():
            cap_map[row["uri"]] = capability_from_row(row)
    else:
        cap_map = {}
    for uri, parts in ranks.items():
        cap = cap_map.get(uri)
        if cap is None:
            continue
        if _capguard_is_held(con, cap):
            continue
        visible, locked = can_discover(cap, principal, con=con, audit=False)
        if not visible:
            continue
        weights = {"exact": 8.0, "fts": 1.5, "vector": 1.0, "like": 0.5}
        rrf = sum(weights.get(kind, 1.0) / (60.0 + rank) for kind, rank, _ in parts)
        cap_name = slug_query(cap.name)
        title_terms = set(query_terms(cap.title))
        wanted_terms = set(query_terms(query))
        if cap_name == normalized_query:
            rrf += 2.0
        elif wanted_terms and wanted_terms.issubset(title_terms | set(query_terms(cap.name))):
            rrf += 0.25
        # Capability names are deliberately concise routing contracts. Reward
        # multi-term name coverage after FTS/vector candidate generation so a
        # large corpus cannot bury the specifically named operator behind broad
        # prose matches. Four-character keys handle common morphology
        # (build/building, audit/auditing, response/respond) without adding an
        # unbounded fuzzy matcher. The boost is capped and requires two terms.
        name_keys = retrieval_term_keys(cap.name)
        query_keys = retrieval_term_keys(query)
        overlap = len(name_keys & query_keys)
        if len(name_keys) >= 2 and overlap >= 2:
            rrf += 0.20 * (overlap / len(name_keys))
        if cap.source_system == "asg-os.plugins":
            rrf += 0.005
        if locked:
            rrf *= 0.25
        scored.append((rrf, cap, tuple(sorted({kind for kind, _, _ in parts}))))

    scored.sort(key=lambda item: item[0], reverse=True)
    out: list[SearchResult] = []
    seen_equivalents: set[tuple[str, str]] = set()
    for score, cap, matched_by in scored:
        equivalent = (cap.capability_type, cap.content_hash)
        if equivalent in seen_equivalents:
            continue
        seen_equivalents.add(equivalent)
        idx = len(out) + 1
        out.append(SearchResult(capability=cap, score=score, rank=idx, matched_by=matched_by, locked=can_discover(cap, principal, con=con, audit=False)[1]))
        if len(out) >= k:
            break
    return out


QUERY_STOPWORDS = {
    "a", "an", "and", "for", "from", "in", "into", "is", "of", "on", "or", "the", "this", "to", "whether", "with",
}

QUERY_SYNONYMS = {
    "auth": ("authentication", "authorization", "oauth"),
    "ci": ("continuous-integration", "pipeline"),
    "db": ("database", "sqlite"),
    "mcp": ("model-context-protocol",),
    "observability": ("telemetry", "metrics", "tracing"),
    "plugin": ("extension", "skill"),
    "restore": ("recovery", "backup"),
}


def query_terms(query: str) -> list[str]:
    raw = [token.lower() for token in re.findall(r"[A-Za-z0-9_./:-]+", query)]
    terms: list[str] = []
    for token in raw:
        pieces = [token, *re.split(r"[-_./:]+", token)]
        for piece in pieces:
            if len(piece) <= 1 or piece in QUERY_STOPWORDS or piece in terms:
                continue
            terms.append(piece)
    return terms[:16]


def retrieval_term_keys(text: str) -> set[str]:
    """Return bounded morphology-tolerant keys for retrieval reranking."""

    return {term if len(term) <= 4 else term[:4] for term in query_terms(text)}


def slug_query(query: str) -> str:
    return "-".join(query_terms(query))


def to_fts_query(query: str) -> str:
    terms = query_terms(query)
    expanded = list(terms)
    for term in terms:
        expanded.extend(synonym for synonym in QUERY_SYNONYMS.get(term, ()) if synonym not in expanded)
    return " OR ".join(f'"{term}"' for term in expanded[:24])


def lexical_embedding(text: str, dims: int) -> list[float]:
    vec = [0.0] * dims
    tokens = re.findall(r"[a-z0-9_./:-]+", text.lower())
    for token in tokens:
        h = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16)
        vec[h % dims] += 1.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [round(x / norm, 6) for x in vec]


# --- Embedding hard-deadline + circuit breaker ---------------------------------
# The local Qwen3 embedding service (port 8090) can livelock under load and
# trickle response bytes, so urlopen's per-socket timeout never fires and
# embed_text would otherwise block forever. A hard wall-clock deadline (via a
# single-worker ThreadPoolExecutor) bounds the worst case, and a process-local
# circuit breaker stops us from hammering a dead/trickling endpoint: after a
# threshold of consecutive failures (or a single hard-deadline), the breaker
# trips for a cooldown and embed_text fails fast so callers fall back to the
# deterministic FTS path. The lexical provider never touches the network and
# short-circuits before the breaker.

_embed_breaker_lock = threading.Lock()
_embed_breaker_failures = 0
_embed_breaker_tripped_until = 0.0


def _embed_breaker_settings() -> tuple[float, int, float]:
    """Read breaker tuning from the environment on each call.

    Mirrors the dynamic env reads in ``embedding_config`` so tests can patch
    ``os.environ`` per-case. Returns ``(hard_deadline_s, failure_threshold,
    cooldown_s)``.
    """
    try:
        hard_deadline = float(os.environ.get("CAPMESH_EMBEDDING_HARD_DEADLINE_SECONDS", "20"))
    except ValueError:
        hard_deadline = 20.0
    try:
        threshold = int(os.environ.get("CAPMESH_EMBEDDING_FAILURE_THRESHOLD", "3"))
    except ValueError:
        threshold = 3
    try:
        cooldown = float(os.environ.get("CAPMESH_EMBEDDING_COOLDOWN_SECONDS", "300"))
    except ValueError:
        cooldown = 300.0
    return hard_deadline, threshold, cooldown


def _embed_breaker_allows() -> bool:
    """True when the breaker is closed (cooldown expired or never tripped)."""
    with _embed_breaker_lock:
        return time.monotonic() >= _embed_breaker_tripped_until


def _embed_breaker_record_failure(*, hard_deadline_fired: bool) -> None:
    """Record one embed failure; trip the breaker past the threshold or
    immediately on a hard-deadline timeout."""
    global _embed_breaker_failures, _embed_breaker_tripped_until
    with _embed_breaker_lock:
        _embed_breaker_failures += 1
        _hard_deadline, threshold, cooldown = _embed_breaker_settings()
        if hard_deadline_fired or _embed_breaker_failures >= threshold:
            _embed_breaker_tripped_until = time.monotonic() + cooldown


def _embed_breaker_record_success() -> None:
    """Reset the failure counter and clear any trip on a successful embed."""
    global _embed_breaker_failures, _embed_breaker_tripped_until
    with _embed_breaker_lock:
        _embed_breaker_failures = 0
        _embed_breaker_tripped_until = 0.0


def _embed_fetch_vector(
    text: str, config: dict[str, Any], provider: str, dims: int
) -> list[float]:
    """Issue one embedding HTTP request and parse/normalize the vector.

    Runs inside the hard-deadline executor worker thread; any error (urlopen
    exception, ValueError on a dimension mismatch) propagates to the caller so
    the breaker can record it. The per-socket ``timeoutSeconds`` is the lower
    bound; the caller's hard deadline is the upper bound.
    """
    url = str(config["url"] or "")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if provider == "ollama":
        payload: dict[str, Any] = {"model": config["model"], "prompt": text}
    elif provider == "openai-compatible":
        payload = {"model": config["model"], "input": text}
        api_key = (
            os.environ.get("CAPMESH_EMBEDDING_API_KEY")
            or os.environ.get("LITELLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        ).strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    else:
        payload = {"inputs": text}
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urlopen(request, timeout=float(config["timeoutSeconds"])) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    if provider == "ollama":
        vector = parsed.get("embedding") if isinstance(parsed, dict) else None
    elif provider == "openai-compatible":
        data = parsed.get("data") if isinstance(parsed, dict) else None
        first = data[0] if isinstance(data, list) and data else None
        vector = first.get("embedding") if isinstance(first, dict) else None
    else:
        vector = parsed[0] if isinstance(parsed, list) and parsed and isinstance(parsed[0], list) else parsed
    if not isinstance(vector, list) or len(vector) != dims:
        raise ValueError(f"{provider} returned {len(vector) if isinstance(vector, list) else 0} dimensions; expected {dims}")
    values = [float(value) for value in vector]
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [round(value / norm, 7) for value in values]


def embed_text(text: str) -> list[float]:
    config = embedding_config()
    dims = int(config["dims"])
    provider = str(config["provider"])
    if provider == "sentence-transformers":
        # Local in-process embedding via sentence_transformers.  No network
        # calls, so the circuit breaker is irrelevant.  Falls back to
        # lexical if the model is unavailable.
        from .local_embedding import embed_text_local
        model_name = str(config.get("model") or "all-MiniLM-L6-v2")
        vec = embed_text_local(text, model_name)
        if vec is not None:
            # Normalize and pad/truncate to match dims
            import math
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            normalized = [round(v / norm, 7) for v in vec]
            if len(normalized) < dims:
                normalized.extend([0.0] * (dims - len(normalized)))
            elif len(normalized) > dims:
                normalized = normalized[:dims]
            return normalized
        # Fall back to lexical if local model unavailable
        return lexical_embedding(text, dims)
    if provider == "lexical":
        # Lexical never touches the network; short-circuit before the breaker so
        # a tripped breaker can never disable deterministic FTS embedding.
        return lexical_embedding(text, dims)
    if not _embed_breaker_allows():
        _hard_deadline, _threshold, cooldown = _embed_breaker_settings()
        raise RuntimeError(f"embed circuit breaker open (cooldown {cooldown:g}s)")
    url = str(config["url"] or "")
    if not _embedding_host_allowed(url):
        raise RuntimeError(f"embedding host is not allowlisted: {urlparse(url).hostname or 'missing'}")
    hard_deadline, _threshold, _cooldown = _embed_breaker_settings()
    # Per-call executor (max_workers=1): on a hard-deadline the hung worker is
    # leaked (rare) but the caller proceeds to FTS. A shared singleton would be
    # poisoned by a single hung worker, so each call gets its own.
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_embed_fetch_vector, text, config, provider, dims)
    try:
        vector = future.result(timeout=hard_deadline)
    except FuturesTimeoutError as timeout_exc:
        if future.running():
            # Worker still running (hung/trickling endpoint): hard deadline.
            # Don't block on the worker; leak the thread and let the caller
            # fall back to FTS. A hard-deadline trips the breaker immediately.
            executor.shutdown(wait=False)
            _embed_breaker_record_failure(hard_deadline_fired=True)
            raise RuntimeError(f"embed hard deadline exceeded ({hard_deadline:g}s)")
        # The worker finished by raising a bare TimeoutError (e.g. an unwrapped
        # socket timeout); treat it as an ordinary embed failure.
        executor.shutdown(wait=True)
        _embed_breaker_record_failure(hard_deadline_fired=False)
        raise RuntimeError(f"local {provider} embedding unavailable") from timeout_exc
    except Exception as exc:
        executor.shutdown(wait=True)
        _embed_breaker_record_failure(hard_deadline_fired=False)
        # Never mix lexical vectors into an index built with semantic vectors.
        # The caller falls back to deterministic FTS retrieval; no second
        # endpoint, cloud API, or credential is tried.
        raise RuntimeError(f"local {provider} embedding unavailable") from exc
    executor.shutdown(wait=True)
    _embed_breaker_record_success()
    return vector


def vector_rows(
    con: sqlite3.Connection,
    query: str,
    limit: int,
    *,
    capability_type: str | None = None,
) -> list[dict[str, Any]]:
    try:
        # sqlite-vec vec0 KNN requires an explicit `k = ?`; a bare `LIMIT ?`
        # across a JOIN is invisible to the virtual table. vector_rows swallows
        # sqlite3.Error, so hybrid search silently degraded to FTS-only.
        knn_k = max(int(limit), 1) * (5 if capability_type else 1)
        type_clause = " AND c.type = ?" if capability_type else ""
        params: list[Any] = [json.dumps(embed_text(query)), knn_k]
        if capability_type:
            params.append(capability_type)
        rows = con.execute(
            f"""
            SELECT c.uri, v.distance AS distance
            FROM capability_vec v
            JOIN capabilities c ON c.id = v.rowid
            WHERE v.embedding MATCH ? AND k = ?
            {type_clause}
            ORDER BY v.distance
            """,
            tuple(params),
        ).fetchall()
        return [dict(row) for row in rows[: int(limit)]]
    except (sqlite3.Error, RuntimeError, ValueError):
        return []


def _admitted_after_install_guards(
    con: sqlite3.Connection, capabilities: list[Capability]
) -> list[Capability]:
    """Discovered capabilities minus the ones ingest supersedes.

    Mirrors the supersede branch of :func:`_enforce_install_guards` so the
    coverage invariant and the ingest agree on which rows should exist. Read
    only -- it never writes and never raises: a genuinely fatal duplicate would
    have aborted the ingest before coverage ran, so it is passed through here
    rather than masked.
    """

    existing = con.execute(
        "SELECT plugin, name, package_path, uri FROM capabilities WHERE lifecycle != 'removed'"
    ).fetchall()
    seen: list[tuple[str | None, str, str, str]] = []
    admitted: list[Capability] = []
    for cap in capabilities:
        try:
            assert_not_duplicate(
                cap.plugin,
                cap.name,
                list(existing) + seen,
                package_path=cap.package_path,
                uri=cap.uri,
            )
        except SupersededCapability:
            continue
        except InstallPolicyError:
            pass
        seen.append((cap.plugin, cap.name, cap.package_path, cap.uri))
        admitted.append(cap)
    return admitted


def coverage_report(con: sqlite3.Connection, roots: Iterable[str | Path]) -> dict[str, Any]:
    discovered = [normalize_path(p) for p in source_files(roots)]
    indexed = {
        row["source_path"]
        for row in con.execute("SELECT source_path FROM capability_sources WHERE source_system != 'capmesh.system'").fetchall()
    }

    # Both coverage checks below must apply the SAME admission decision the
    # ingest applied, or an admission filter reads as missing content.
    # discover_capabilities() is deliberately unfiltered, so it still returns the
    # lower-authority mirror copies that _enforce_install_guards drops (see
    # install_policy.SupersededCapability). Computed once here and used twice.
    discovered_caps_all = [
        cap
        for cap in discover_capabilities(roots)
        if cap.source_kind not in {"system_capability", "capmesh_draft"}
    ]
    discovered_caps = _admitted_after_install_guards(con, discovered_caps_all)
    _admitted_sources = {normalize_path(cap.source_path) for cap in discovered_caps}
    superseded_sources = {
        normalize_path(cap.source_path) for cap in discovered_caps_all
    } - _admitted_sources

    # A superseded capability's file is still ON DISK and still enumerated by
    # source_files(), but deliberately has no capability_sources row. Measured
    # 2026-07-31: the 8 ~/.codex/skills/meta SKILL.md files (voss-*,
    # anti-slop-voice-discipline, caviaar-prep), each byte-identical to a
    # ~/.agents/skill-registry original that IS indexed -- md5 verified on all
    # eight. Counting them as missing failed source coverage over content that
    # is fully present.
    #
    # Only the capability's own source_path is excused, not everything under its
    # package: package_path is the bare ~/.codex directory for some of these, and
    # excusing that subtree would blind the check to most of the codex roots.
    missing = sorted(set(discovered) - indexed - superseded_sources)
    extras = sorted(indexed - set(discovered))
    counts = {
        row["type"]: row["count"]
        for row in con.execute("SELECT type, COUNT(*) AS count FROM capabilities GROUP BY type").fetchall()
    }
    source_counts = {
        row["source_kind"]: row["count"]
        for row in con.execute("SELECT source_kind, COUNT(*) AS count FROM capability_sources GROUP BY source_kind").fetchall()
    }
    source_coverage_ok = not missing

    # CM-10 placement-drop invariant. The source-file check above only catches a
    # missing capability_sources row; it CANNOT detect a placement-induced drop
    # where a rebuild/placement silently loses a capability row (its canonical_key
    # disappears from `capabilities`) while every discovered source file is still
    # nominally indexed. The post-rebuild invariant asserts:
    #     distinct discovered canonical_keys (minus intentional merges)
    #     == non-system/non-draft capability rows
    # and fails coverageOk when a discovered canonical_key is absent from the
    # live rows.
    #
    # discovered_keys derivation: canonical_key is carried directly on every
    # Capability returned by discover_capabilities(roots) (see manifest.py
    # capability_uri -> canonical_key = "{type}:{plugin}:{slug}:{version}"), so
    # the set of keys that SHOULD exist post-placement is read straight from the
    # discovered capabilities. Both placement transforms (apply_vault_placement
    # and apply_default_user_namespace) use dataclasses.replace WITHOUT touching
    # canonical_key, and the two merge passes (merge_duplicate_capabilities and
    # _merge_by_effective_uri) only ever consolidate capabilities that share a
    # canonical_key (same type/plugin/name/version => same canonical_key => same
    # effective URI), so a legitimate merge never drops a canonical_key. A
    # non-empty placementDroppedKeys therefore signals a REAL placement drop
    # (e.g. a CM-01 ON CONFLICT(uri) last-writer-win collapsing two distinct
    # canonical_keys into one row, where the loser's source_path is deleted
    # rather than re-pointed).
    #
    # "non-system/non-draft" follows the codebase-wide convention
    # (source_kind NOT IN ('system_capability', 'capmesh_draft')) used by
    # _live_capability_count / _delete_source_orphaned_capabilities /
    # stage_rebuild_index. system caps come from builtin_system_capabilities and
    # drafts from the governance draft flow, neither of which is returned by
    # discover_capabilities, so the discovered_keys filter is defensive only.
    # discovered_caps is the ADMITTED set computed at the top of this function.
    # The invariant's original reasoning ("a legitimate merge never drops a
    # canonical_key") predates there being an admission FILTER at all, and is
    # still exactly right for the drop it was written to catch -- a real
    # placement bug still shows up here, because only supersede is excused.
    discovered_keys = {cap.canonical_key for cap in discovered_caps}
    live_keys = {
        row["canonical_key"]
        for row in con.execute(
            "SELECT canonical_key FROM capabilities "
            "WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"
        ).fetchall()
    }

    # Intentional-merge subtraction (CM-10). merge_duplicate_capabilities
    # (manifest.py) only ever consolidates capabilities that share a
    # canonical_key (same-key mirrors — see the by_key grouping in manifest.py),
    # so a legitimate same-key merge never removes a canonical_key from the set:
    # the surviving key stays in live_keys and is never in placementDroppedKeys.
    # The gap this closes is a CROSS-key consolidation: canonical_key A
    # deliberately folded into B, A's row deleted and A's source_path re-pointed
    # to B's row. The current merge passes do not produce that, but the
    # invariant must not false-flag it as a drop if a future placement path
    # introduces one.
    #
    # Derivation (OPTION C: derived purely from queryable state in
    # `capabilities` + `capability_sources` — manifest.py is out of scope for
    # this slice, and the merge-metadata fields staleMirrorDetected /
    # sourceConflicts / ambiguousAuthority* store source PATHS and content
    # hashes, NOT the merged-away canonical_key, so the lost key cannot be read
    # from metadata directly). A discovered key K absent from live is
    # intentionally merged away iff K's source_path is now owned in
    # capability_sources by a DIFFERENT live canonical_key — i.e. the source file
    # was re-pointed to the survivor's row rather than orphaned.
    # capability_sources.source_path is PRIMARY KEY, so a source maps to exactly
    # one uri; the source_path -> canonical_key owner map therefore gives an
    # unambiguous re-pointing signal. A REAL placement drop (the row AND its
    # source rows deleted while the file is still on disk) leaves K's
    # source_path unowned, so K is NOT subtracted and stays a reported drop —
    # exactly the signal placementDroppedKeys is meant to surface.
    source_to_live_key = {
        row["source_path"]: row["canonical_key"]
        for row in con.execute(
            "SELECT cs.source_path AS source_path, c.canonical_key AS canonical_key "
            "FROM capability_sources cs "
            "JOIN capabilities c ON c.uri = cs.uri "
            "WHERE c.source_kind NOT IN ('system_capability', 'capmesh_draft')"
        ).fetchall()
    }
    discovered_by_key = {cap.canonical_key: cap for cap in discovered_caps}
    merged_away_keys = set()
    for key in discovered_keys - live_keys:
        cap = discovered_by_key.get(key)
        if cap is None:
            continue
        source_paths = {normalize_path(cap.source_path)}
        raw_paths = cap.metadata.get("sourcePaths")
        if isinstance(raw_paths, list):
            source_paths.update(normalize_path(str(item)) for item in raw_paths)
        for source_path in source_paths:
            owner = source_to_live_key.get(source_path)
            if owner is not None and owner != key:
                merged_away_keys.add(key)
                break
    placement_dropped_keys = (discovered_keys - live_keys) - merged_away_keys
    placement_extra_keys = live_keys - discovered_keys
    # A dropped key fails coverage; extras alone are a warning. Extras are
    # expected for a narrow-root merge ingest (caps from other roots remain in
    # the DB) and for empty roots (promote_shadow_database validates with ()),
    # so they must not flip coverageOk.
    placement_ok = not placement_dropped_keys
    return {
        "coverageOk": source_coverage_ok and placement_ok,
        "discoveredSources": len(discovered),
        "indexedSources": len(indexed),
        "missingSources": missing,
        "extraSources": extras,
        "capabilityCounts": counts,
        "sourceCounts": source_counts,
        "placementOk": placement_ok,
        "placementDroppedKeys": sorted(placement_dropped_keys),
        "placementExtraKeys": sorted(placement_extra_keys),
    }


def export_jsonl(con: sqlite3.Connection, path: str | Path) -> int:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = con.execute("SELECT * FROM capabilities ORDER BY type, plugin, name").fetchall()
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(capability_from_row(row).to_record(include_paths=True), sort_keys=True) + "\n")
    return len(rows)


def registry_diff(con: sqlite3.Connection, previous_jsonl: str | Path) -> dict[str, Any]:
    """Diff the current capability DB against a previous JSONL export.

    Returns added/removed/changed URIs with a summary. The previous JSONL is
    the canonical export produced by ``export_jsonl``: one JSON object per
    line with at least ``uri`` and ``content_hash`` keys.
    """
    prev_path = Path(previous_jsonl).expanduser()
    if not prev_path.exists():
        raise FileNotFoundError(f"Previous JSONL not found: {prev_path}")
    prev: dict[str, str] = {}
    with prev_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            uri = str(record.get("uri") or "")
            if uri:
                prev[uri] = str(record.get("content_hash") or "")
    current: dict[str, str] = {}
    for row in con.execute("SELECT uri, content_hash FROM capabilities WHERE source_kind NOT IN ('system_capability', 'capmesh_draft')"):
        current[str(row["uri"])] = str(row["content_hash"] or "")
    prev_uris = set(prev)
    curr_uris = set(current)
    added = sorted(curr_uris - prev_uris)
    removed = sorted(prev_uris - curr_uris)
    changed = sorted(uri for uri in (prev_uris & curr_uris) if prev[uri] != current[uri])
    return {"added": added, "removed": removed, "changed": changed, "summary": {"addedCount": len(added), "removedCount": len(removed), "changedCount": len(changed), "previousCount": len(prev), "currentCount": len(current)}}
