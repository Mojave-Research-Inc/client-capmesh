#!/usr/bin/env bash
# Pull one transactionally consistent catalog snapshot from authoritative primary node.

set -euo pipefail
IFS=$'\n\t'

AUTHORITY="${CAPMESH_AUTHORITY_HOST:-127.0.0.1}"
AUTHORITY_URL="${CAPMESH_AUTHORITY_URL:-http://127.0.0.1:8000}"
REMOTE_USER="${CAPMESH_REMOTE_USER:-jason}"
REMOTE_STATE="${CAPMESH_AUTHORITY_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"
MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"
if [[ "$(uname -s)" == Darwin ]]; then
  ENV_FILE="${CAPMESH_ENV_FILE:-$HOME/.config/asgcode/capmesh-fallback.env}"
else
  ENV_FILE="${CAPMESH_ENV_FILE:-${CAPMESH_AUTHORITY_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}/capmesh.env}"
fi
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
else
  SHA256=(shasum -a 256)
fi

fail() { printf '[capmesh-nonvoting-sync] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[capmesh-nonvoting-sync] %s\n' "$*"; }

[[ -n "$AUTHORITY" ]] \
  || fail "authority host must be set"
[[ -n "$AUTHORITY_URL" ]] \
  || fail "authority URL must be set"
[[ "$MIN_HEALTHY" =~ ^[1-9][0-9]*$ ]] || fail "invalid minimum catalog size"
[[ -r "$ENV_FILE" ]] || fail "missing member environment $ENV_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
if [[ "$(uname -s)" == Darwin ]]; then
  LOCAL_STATE="${CAPMESH_STATE:-$HOME/.capmesh}"
else
  LOCAL_STATE="${CAPMESH_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"
fi
DB="${CAPMESH_DB:-$LOCAL_STATE/asg-capmesh.db}"
DIGEST_TOOL="${CAPMESH_LOGICAL_DIGEST_TOOL:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logical-catalog-digest.py}"
[[ "${CAPMESH_NODE_ROLE:-}" == non-voting-raft ]] \
  || fail "CAPMESH_NODE_ROLE must be non-voting-raft"
[[ -n "${CAPMESH_AUTHORITY_URL:-}" ]] \
  || fail "member must pin an authority URL"
[[ -r "$DIGEST_TOOL" ]] || fail "missing logical catalog digest tool: $DIGEST_TOOL"

case "$DB" in
  "${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/asg-capmesh.db"|"${HOME}"/.capmesh/asg-capmesh.db) ;;
  *) fail "refusing unsafe member database path: $DB" ;;
esac
mkdir -p "$LOCAL_STATE"
# BEGIN testable lock acquisition
lock="$LOCAL_STATE/.nonvoting-sync.lock"
STALE_LOCK_SECONDS="${CAPMESH_NONVOTING_LOCK_STALE_SECONDS:-1800}"
if ! mkdir "$lock" 2>/dev/null; then
  # Stale lock recovery: a crashed sync can leave the lock dir forever, blocking
  # all subsequent member catalog pulls (observed Mac stuck at old generation).
  if [[ -d "$lock" && "$STALE_LOCK_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    lock_mtime="$(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock" 2>/dev/null || true)"
    if [[ "$lock_mtime" =~ ^[0-9]+$ ]] \
      && (( (lock_age = $(date +%s) - lock_mtime) > STALE_LOCK_SECONDS )); then
      log "WARN removing stale nonvoting sync lock age=${lock_age}s > ${STALE_LOCK_SECONDS}s"
      rmdir "$lock" 2>/dev/null || true
    fi
  fi
  if ! mkdir "$lock" 2>/dev/null; then
    log "SKIP another sync is running"
    exit 0
  fi
fi
# END testable lock acquisition
remote_snapshot=""
remote_content=""
candidate="$LOCAL_STATE/.nonvoting-candidate-$$.db"
content_bundle="$LOCAL_STATE/.nonvoting-content-$$.tar"
cleanup() {
  rc=$?
  rm -f -- "$candidate" "$candidate-wal" "$candidate-shm" "$content_bundle"
  if [[ -n "$remote_snapshot" ]]; then
    case "$remote_snapshot" in
      "$REMOTE_STATE"/rehearsal/nonvoting-*.db)
        ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$AUTHORITY" "rm -f -- '$remote_snapshot'" >/dev/null 2>&1 || true
        ;;
    esac
  fi
  if [[ -n "$remote_content" ]]; then
    case "$remote_content" in
      "$REMOTE_STATE"/rehearsal/nonvoting-*-content.tar)
        ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$AUTHORITY" "rm -f -- '$remote_content'" >/dev/null 2>&1 || true
        ;;
    esac
  fi
  rmdir "$lock" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

member="$(hostname -s | tr -cd 'A-Za-z0-9._-' | cut -c1-40)"
need_content=0
[[ "$(uname -s)" == Darwin ]] && need_content=1
metadata="$({ ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$AUTHORITY" "bash -s -- '$REMOTE_STATE' '$member' '$need_content'" <<'REMOTE'
set -euo pipefail
state="$1"; member="$2"; need_content="$3"
snapshot="$state/rehearsal/nonvoting-$member-$(date -u +%Y%m%dT%H%M%SZ)-$$.db"
content="$state/rehearsal/nonvoting-$member-$(date -u +%Y%m%dT%H%M%SZ)-$$-content.tar"
case "$snapshot" in "$state"/rehearsal/nonvoting-*.db) ;; *) exit 2 ;; esac
# Feed .backup via stdin so nested quoting cannot leave $snapshot unexpanded under set -u.
printf '.backup %s\n' "$snapshot" | sqlite3 "$state/asg-capmesh.db"
chmod 600 "$snapshot"
sha="$(sha256sum "$snapshot" | awk '{print $1}')"
count="$(sqlite3 "$snapshot" 'SELECT COUNT(*) FROM capabilities;')"
# Compliance bar is scoped to SHARED content (org / all_users / system stores). User-owned
# stores legitimately hold drafts and privately-published capabilities that are, by design,
# not approved/verified -- counting them made every user publish abort the replica sync and
# was a standing reason the mirror could never converge. Shared content keeps the strict bar.
noncompliant="$(sqlite3 "$snapshot" "SELECT COUNT(*) FROM capabilities c WHERE c.source_kind != 'system_capability' AND COALESCE((SELECT s.kind FROM stores s WHERE s.id = c.store_id), '') NOT IN ('user_private', 'user_shared') AND (c.approval_state != 'approved' OR c.lifecycle != 'published' OR c.signature_status != 'verified' OR c.provenance_status != 'verified' OR c.risk_review_status != 'approved');")"
logical="$(python3 "$state/current/ops/logical-catalog-digest.py" "$snapshot")"
content_sha=none
content_count=0
if [[ "$need_content" == 1 ]]; then
  case "$content" in "$state"/rehearsal/nonvoting-*-content.tar) ;; *) exit 2 ;; esac
  content_count="$(python3 - "$snapshot" "$content" <<'PY'
import hashlib
import io
import json
import sqlite3
import sys
import tarfile
from pathlib import Path

db_path, tar_path = sys.argv[1:]
con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
rows = con.execute(
    "SELECT content_hash, source_path, metadata_json FROM capabilities "
    "WHERE source_kind != 'system_capability' ORDER BY content_hash, source_path"
)
sources = {}
for content_hash, source_path, metadata_json in rows:
    metadata = json.loads(metadata_json or "{}")
    if metadata.get("fileHashes"):
        raise SystemExit(
            f"secondary file references require package replication: {source_path}"
        )
    digest = content_hash.removeprefix("sha256:")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise SystemExit(f"invalid content hash: {content_hash}")
    if digest in sources:
        continue
    path = Path(source_path)
    if not path.is_file():
        raise SystemExit(f"missing authoritative capability body: {source_path}")
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != digest:
        raise SystemExit(f"capability body hash mismatch: {source_path}")
    sources[digest] = body

with tarfile.open(tar_path, "w") as archive:
    for digest, body in sorted(sources.items()):
        info = tarfile.TarInfo(f"sha256/{digest}")
        info.size = len(body)
        info.mode = 0o600
        archive.addfile(info, io.BytesIO(body))
print(len(sources))
PY
)"
  chmod 600 "$content"
  content_sha="$(sha256sum "$content" | awk '{print $1}')"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$snapshot" "$sha" "$count" "$noncompliant" "$logical" \
  "$content" "$content_sha" "$content_count"
REMOTE
} | tail -n 1)"
IFS=$'\t' read -r remote_snapshot expected_sha expected_count noncompliant expected_logical \
  remote_content expected_content_sha expected_content_count <<<"$metadata"
case "$remote_snapshot" in
  "$REMOTE_STATE"/rehearsal/nonvoting-*.db) ;;
  *) fail "authority returned an unsafe snapshot path" ;;
esac
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || fail "authority returned an invalid snapshot hash"
[[ "$expected_logical" =~ ^[0-9a-f]{64}$ ]] || fail "authority returned an invalid logical digest"
[[ "$expected_count" =~ ^[1-9][0-9]*$ ]] || fail "authority returned an invalid catalog count"
(( expected_count >= MIN_HEALTHY )) || fail "authority catalog is below the health floor"
[[ "$noncompliant" == 0 ]] || fail "authority catalog contains $noncompliant noncompliant capabilities"

scp "${SSH_OPTS[@]}" "$REMOTE_USER@$AUTHORITY:$remote_snapshot" "$candidate" >/dev/null
actual_sha="$("${SHA256[@]}" "$candidate" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || fail "snapshot hash changed in transit"

if [[ "$(uname -s)" == Darwin ]]; then
  case "$remote_content" in
    "$REMOTE_STATE"/rehearsal/nonvoting-*-content.tar) ;;
    *) fail "authority returned an unsafe content bundle path" ;;
  esac
  [[ "$expected_content_sha" =~ ^[0-9a-f]{64}$ ]] \
    || fail "authority returned an invalid content bundle hash"
  [[ "$expected_content_count" =~ ^[1-9][0-9]*$ ]] \
    || fail "authority returned an invalid content body count"
  scp "${SSH_OPTS[@]}" "$REMOTE_USER@$AUTHORITY:$remote_content" "$content_bundle" >/dev/null
  actual_content_sha="$("${SHA256[@]}" "$content_bundle" | awk '{print $1}')"
  [[ "$actual_content_sha" == "$expected_content_sha" ]] \
    || fail "content bundle hash changed in transit"

  # Do not re-ingest a replica: ingest can recanonicalize or add/remove rows.
  # Materialize the exact authoritative bodies by content hash and repoint only
  # source_path, which is deliberately excluded from the logical generation.
  content_store="$LOCAL_STATE/content/sha256"
  mkdir -p "$content_store"
  python3 - "$candidate" "$content_bundle" "$content_store" "$expected_content_count" <<'PY'
import hashlib
import os
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path

db_path, bundle_path, store_path, expected_text = sys.argv[1:]
expected = int(expected_text)
store = Path(store_path)
seen = set()
with tarfile.open(bundle_path, "r") as archive:
    for member in archive.getmembers():
        parts = Path(member.name).parts
        if len(parts) != 2 or parts[0] != "sha256" or len(parts[1]) != 64:
            raise SystemExit(f"unsafe content member: {member.name}")
        digest = parts[1]
        if any(ch not in "0123456789abcdef" for ch in digest) or not member.isfile():
            raise SystemExit(f"invalid content member: {member.name}")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit(f"unreadable content member: {member.name}")
        body = source.read()
        if hashlib.sha256(body).hexdigest() != digest:
            raise SystemExit(f"content member hash mismatch: {member.name}")
        target = store / digest
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise SystemExit(f"corrupt existing content body: {target}")
        else:
            fd, temp_name = tempfile.mkstemp(prefix=".incoming-", dir=store)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(body)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o600)
                os.replace(temp_name, target)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        seen.add(digest)
if len(seen) != expected:
    raise SystemExit(f"content bundle count mismatch: {len(seen)} != {expected}")

con = sqlite3.connect(db_path)
with con:
    rows = con.execute(
        "SELECT id, content_hash FROM capabilities WHERE source_kind != 'system_capability'"
    ).fetchall()
    updates = []
    for capability_id, content_hash in rows:
        digest = content_hash.removeprefix("sha256:")
        target = store / digest
        if digest not in seen or not target.is_file():
            raise SystemExit(f"missing materialized body: {content_hash}")
        # The production corpus currently has no indexed secondary fileHashes.
        # Make the verified blob the local package entrypoint so Router.safe_file_target
        # resolves inside the local content store instead of a primary-only package path.
        updates.append((str(store), digest, str(target), capability_id))
    con.executemany(
        "UPDATE capabilities SET package_path = ?, entrypoint = ?, source_path = ? WHERE id = ?",
        updates,
    )
con.close()
PY
fi

[[ "$(sqlite3 "$candidate" 'PRAGMA quick_check;' | head -n 1)" == ok ]] \
  || fail "candidate quick_check failed"
actual_count="$(sqlite3 "$candidate" 'SELECT COUNT(*) FROM capabilities;')"
fts_count="$(sqlite3 "$candidate" 'SELECT COUNT(*) FROM capability_fts;')"
[[ "$actual_count" == "$expected_count" && "$fts_count" == "$expected_count" ]] \
  || fail "candidate catalog/FTS parity failed"
actual_noncompliant="$(sqlite3 "$candidate" "SELECT COUNT(*) FROM capabilities WHERE source_kind != 'system_capability' AND (approval_state != 'approved' OR lifecycle != 'published' OR signature_status != 'verified' OR provenance_status != 'verified' OR risk_review_status != 'approved');")"
[[ "$actual_noncompliant" == 0 ]] || fail "candidate contains $actual_noncompliant noncompliant capabilities"
if [[ "$(uname -s)" == Darwin ]]; then
  missing_sources="$(python3 - "$candidate" <<'PY'
import sqlite3, sys
from pathlib import Path
con = sqlite3.connect(sys.argv[1])
rows = con.execute("SELECT source_path FROM capabilities WHERE source_kind != 'system_capability'")
print(sum(1 for (source_path,) in rows if not Path(source_path).is_file()))
PY
)"
  [[ "$missing_sources" == 0 ]] || fail "macOS member has $missing_sources capabilities without a local loadable source"
fi
actual_logical="$(python3 "$DIGEST_TOOL" "$candidate")"
[[ "$actual_logical" == "$expected_logical" ]] \
  || fail "member logical catalog differs from authoritative primary node"
if [[ -f "$DB" ]]; then
  live_logical="$(python3 "$DIGEST_TOOL" "$DB" 2>/dev/null || true)"
  live_localized=0
  if [[ "$(uname -s)" == Darwin ]]; then
    live_localized="$(sqlite3 "$DB" "SELECT COUNT(*) FROM capabilities WHERE source_kind != 'system_capability' AND source_path NOT LIKE '$LOCAL_STATE/content/sha256/%';" 2>/dev/null || printf 1)"
  fi
  if [[ "$live_logical" == "$expected_logical" && "$live_localized" == 0 ]]; then
    # Freshness carry-forward (fix 2026-07-22): the authority re-ingests an
    # IDENTICAL catalog and advances its last_successful_ingest_at, but this
    # short-circuit used to leave the member's timestamp frozen. After ~6h of
    # quiet-but-identical catalog, the member's catalogFreshness readiness
    # check 503'd, /health/ready failed, and rolling deploys were refused on a
    # perfectly synchronized member. Mirror the authority's freshness meta
    # (timestamp + generation only — content already proven identical by the
    # logical digest above) before exiting.
    authority_meta="$(curl -fsS --max-time 15 "${CAPMESH_AUTHORITY_HEALTH_URL:-https://capmesh.asg.ts.net/health}" 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin)["catalog"]; print((d.get("latestSuccessfulIngest") or "")+"\t"+(d.get("generation") or ""))' \
      2>/dev/null || true)"
    IFS=$'\t' read -r authority_ingest authority_generation <<<"$authority_meta"
    if [[ "$authority_ingest" =~ ^2[0-9]{3}-[0-9]{2}-[0-9]{2}T ]]; then
      sqlite3 "$DB" \
        "INSERT INTO meta(key, value) VALUES ('last_successful_ingest_at', '$authority_ingest')
           ON CONFLICT(key) DO UPDATE SET value = excluded.value;" || true
      if [[ "$authority_generation" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        sqlite3 "$DB" \
          "INSERT INTO meta(key, value) VALUES ('last_successful_ingest_generation', '$authority_generation')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;" || true
      fi
      log "OK already synchronized count=$expected_count logical=$expected_logical freshness=$authority_ingest"
    else
      log "OK already synchronized count=$expected_count logical=$expected_logical (freshness carry-forward unavailable)"
    fi
    exit 0
  fi
fi

if [[ "$(uname -s)" == Linux ]]; then
  # systemd includes the bare template (asg-capability-mesh@.service) in this
  # listing. It is not a runnable instance and makes a transactional sync fail
  # during the stop phase; operate only on explicitly numbered workers.
  mapfile -t units < <(
    systemctl list-unit-files 'asg-capability-mesh@*.service' --no-legend \
      | awk '$1 ~ /^asg-capability-mesh@[0-9]+\.service$/ {print $1}'
  )
  if (( ${#units[@]} > 0 )); then sudo systemctl stop "${units[@]}"; fi
fi
previous=""
if [[ -f "$DB" ]]; then
  previous="$DB.pre-nonvoting-$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$DB" "$previous"
  # A SQLite database plus its WAL/SHM files is one generation. Leaving old
  # sidecars at the live pathname lets SQLite replay the previous generation's
  # WAL over the newly mirrored snapshot when workers reopen it.
  for suffix in -wal -shm; do
    [[ -e "$DB$suffix" ]] && mv "$DB$suffix" "$previous$suffix"
  done
fi
[[ ! -e "$DB-wal" && ! -e "$DB-shm" ]] \
  || fail "stale SQLite sidecars remain at the live database path"
mv "$candidate" "$DB"
chmod 600 "$DB"
if [[ "$(uname -s)" == Linux ]] && (( ${#units[@]} > 0 )); then
  sudo systemctl start "${units[@]}"
elif [[ "$(uname -s)" == Darwin ]]; then
  # Only kill-restart when loopback readiness is down (avoids SIGTERM thrash).
  local_ready_code="$(
    curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:17778/health/ready 2>/dev/null || true
  )"
  if [[ "$local_ready_code" == 200 ]]; then
    log "OK macOS HTTP already ready after mirror; skip kickstart"
  else
    launchctl kickstart -k "gui/$UID/ai.asg.capmesh-http" >/dev/null 2>&1 || true
  fi
fi
printf '{"timestamp":"%s","action":"nonvoting-sync","authority":"${CAPMESH_AUTHORITY_HOST:-primary}","count":%s,"sha256":"%s","previous":"%s"}\n' \
  "$(date -u +%FT%TZ)" "$expected_count" "$expected_sha" "$(basename "${previous:-none}")" \
  >> "$LOCAL_STATE/nonvoting-sync-audit.jsonl"
mapfile_compat=()
while IFS= read -r old; do mapfile_compat+=("$old"); done < <(
  find "$LOCAL_STATE" -maxdepth 1 -type f -name 'asg-capmesh.db.pre-nonvoting-*' -print \
    | sort -r | tail -n +4
)
for old in "${mapfile_compat[@]}"; do
  case "$old" in
    "$LOCAL_STATE"/asg-capmesh.db.pre-nonvoting-*)
      rm -f -- "$old" "$old-wal" "$old-shm"
      ;;
  esac
done
log "OK mirrored primary generation count=$expected_count sha256=$expected_sha"
