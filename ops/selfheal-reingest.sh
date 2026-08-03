#!/usr/bin/env bash
# selfheal-reingest.sh — rebuild THIS host's capmesh index from its own roots, safely.
#
# WHY THIS EXISTS (production incident 2026-07-17, primary node):
# A `capmesh ingest` scoped to a single new package wiped the mesh 2110 -> 16 capabilities,
# because ingest is a FULL REPLACE. It then stayed broken for ~24h, and the reason is the part
# that matters here: NOTHING COULD REBUILD THE WRITER.
#   - git-sync.sh only re-ingests in REPLICA mode; the primary node runs as WRITER, so it never
#     re-ingested itself.
#   - parity-check.sh detected the drift hourly and "self-healed" by pushing the registry to
#     git and telling the REPLICA to pull — neither action rebuilds the deficient host's index.
#     The journal shows six consecutive identical DRIFT lines with zero effect.
# So the host that lost its data was structurally the one host that could not recover.
#
# This script is the missing piece: it rebuilds the LOCAL index, in place, safely.
#
# SAFETY MODEL — never make things worse than they already are:
#   1. flock, so two heals can never run at once.
#   2. Build into a TEMP COPY of the live DB (not a fresh file) so capmesh_draft rows and
#      governance state survive the rebuild.
#   3. The ingest itself is protected by the shrink guard in capmesh/index.py.
#   4. Refuse to install a rebuild that is SMALLER than what is already live (unless the live
#      index is itself below MIN_HEALTHY, i.e. already broken — that is the case we are fixing).
#   5. Verify integrity_check + count BEFORE swapping.
#   6. Stop workers -> swap -> start workers -> verify /health. Old DB kept as .preswap-<ts>.
set -euo pipefail

ENV_FILE="${CAPMESH_ENV_FILE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/capmesh.env}"
if [[ -r "$ENV_FILE" ]]; then
  set -a
  # The file is generated mode 0600 for the service account and contains only
  # KEY=VALUE assignments. Loading it here makes manual/watchdog recovery use
  # the same canonical roots and SQLite runtime as systemd-triggered refresh.
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi
# Best-effort source of the non-secret embed config. capmesh.env above is the
# canonical source and is generated mode 0600 for the service account, so a
# jason-run selfheal may not be able to read it. This file is non-secret (e.g.
# the tei:1024 embed endpoint config) and lets the selfheal still pick up the
# embed config when capmesh.env is unreadable. Sourced AFTER capmesh.env so any
# value already set by capmesh.env (if readable) is preserved; absence is not
# an error.
if [[ -r "${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/capmesh-embed.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/capmesh-embed.env"
  set +a
fi
DB="${CAPMESH_DB:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/asg-capmesh.db}"
# SERVICE_DIR/PY are derived from the DB's own directory, NOT CAPMESH_STATE_DIR:
# capmesh.env may set CAPMESH_STATE_DIR to a subdir (e.g. .../state) while the
# activated release, db, and venv live one level up alongside the db. Deriving
# from dirname(DB) keeps prod (/secure/asg-capmesh) and local
# (~/.capmesh/state) both correct.
_STATE_ROOT="$(dirname "$DB")"
SERVICE_DIR="${CAPMESH_SERVICE_DIR:-$_STATE_ROOT/current}"
[[ -d "$SERVICE_DIR/capmesh" ]] || SERVICE_DIR="$_STATE_ROOT/service" # one-release migration compatibility
PY="${CAPMESH_PY:-$SERVICE_DIR/.venv/bin/python}"
[[ -x "$PY" ]] || PY="$_STATE_ROOT/venv/bin/python" # one-release migration compatibility
UNIT_GLOB="${CAPMESH_UNIT_GLOB:-asg-capability-mesh@*}"
HEALTH_PORT="${CAPMESH_HEALTH_PORT:-17781}"
READY_ATTEMPTS="${CAPMESH_SELFHEAL_READY_ATTEMPTS:-12}"
READY_INTERVAL="${CAPMESH_SELFHEAL_READY_INTERVAL_SECONDS:-2}"
READY_TIMEOUT="${CAPMESH_SELFHEAL_READY_TIMEOUT_SECONDS:-3}"
# Wall-clock cap on the ingest subprocess. A wedged 8090 or a hung embed must
# never block the selfheal forever. The 600s default is well under the
# 15-min/900s refresh interval, leaving margin. On timeout (timeout(1) exit
# 124) the live index is left untouched — see the abort before rebuilt-count /
# shrink / swap below.
INGEST_TIMEOUT="${CAPMESH_INGEST_TIMEOUT_SECONDS:-600}"
for value_name in READY_ATTEMPTS READY_INTERVAL READY_TIMEOUT INGEST_TIMEOUT; do
  value="${!value_name}"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] \
    || { printf '[capmesh-selfheal] ABORT invalid %s=%q\n' "$value_name" "$value" >&2; exit 2; }
done
(( READY_ATTEMPTS <= 30 && READY_INTERVAL <= 10 && READY_TIMEOUT <= 10 )) \
  || { printf '[capmesh-selfheal] ABORT readiness retry bounds are unsafe\n' >&2; exit 2; }
# A healthy ASG mesh is thousands of capabilities. Anything under this is by definition a
# broken index, which is what licenses replacing it with a smaller-but-correct rebuild.
MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"
EXPECTED_COUNT="${CAPMESH_EXPECTED_COUNT:-}"
if [[ -n "$EXPECTED_COUNT" && ! "$EXPECTED_COUNT" =~ ^[1-9][0-9]*$ ]]; then
  printf '[capmesh-selfheal] ABORT invalid CAPMESH_EXPECTED_COUNT=%q\n' "$EXPECTED_COUNT" >&2
  exit 2
fi
TMPDB="/tmp/capmesh-heal-$$.db"
DB_DIR="$(dirname "$DB")"
CANDIDATE="$DB_DIR/.asg-capmesh.candidate-$$.db"
LOCK="${CAPMESH_SELFHEAL_LOCK:-$DB_DIR/.capmesh-selfheal.lock}"
INGEST_LOG=""
LIVE_PROJ=""
REBUILT_PROJ=""

log() { logger -t capmesh-selfheal "$*"; printf '[capmesh-selfheal] %s\n' "$*"; }
systemctl_workers() {
  local action="$1" pattern="${UNIT_GLOB%.service}.service"
  local -a units=()
  mapfile -t units < <(
    systemctl list-unit-files "$pattern" --no-legend \
      | awk '$1 ~ /@[^.]+\.service$/ { print $1 }'
  )
  (( ${#units[@]} > 0 )) || { log "ABORT no worker instances match $pattern"; return 1; }
  sudo systemctl "$action" "${units[@]}"
}
ROLLBACK_REQUIRED=0
PRESWAP=""
# Invoked by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  rc=$?
  if (( ROLLBACK_REQUIRED == 1 )) && [[ -n "$PRESWAP" && -f "$PRESWAP" ]]; then
    log "ROLLBACK restoring pre-heal database after rc=$rc"
    systemctl_workers stop >/dev/null 2>&1 || true
    rm -f "$DB" "$DB-wal" "$DB-shm"
    mv "$PRESWAP" "$DB"
    systemctl_workers start >/dev/null 2>&1 || true
  fi
  rm -f "$TMPDB" "$TMPDB-wal" "$TMPDB-shm" "$CANDIDATE" "$CANDIDATE-wal" "$CANDIDATE-shm"
  case "$INGEST_LOG" in /tmp/capmesh-ingest.*.log) rm -f -- "$INGEST_LOG" ;; esac
  for _p in "$LIVE_PROJ" "$REBUILT_PROJ"; do
    case "$_p" in /tmp/capmesh-proj.*) rm -f -- "$_p" ;; esac
  done
  return "$rc"
}
trap cleanup EXIT

exec 9>"$LOCK"
flock -n 9 || { log "SKIP another heal is already running"; exit 0; }

count_of() { sqlite3 "$1" "SELECT COUNT(*) FROM capabilities;" 2>/dev/null; }

live=$(count_of "$DB")
[[ -z "$live" ]] && { log "ABORT cannot read live DB $DB"; exit 1; }
DB_UID="$(stat -c '%u' "$DB")"
DB_GID="$(stat -c '%g' "$DB")"
DB_MODE="$(stat -c '%a' "$DB")"
log "start live=$live db=$DB"

# 1. Consistent snapshot of the live DB (hot — workers stay up during the rebuild).
if ! sqlite3 "$DB" ".backup '$TMPDB'"; then
  log "ABORT snapshot failed"; exit 1
fi

# LOST-WRITE GUARD (baseline half). This heal rebuilds INTO the snapshot and later
# `mv`s it over live. There is no merge step, so ANY write committed to live after
# this point is destroyed by that `mv` — not just capability rows, but immutable
# audit history and promotion gate verdicts.
#
# Observed 2026-07-31: a promotion approved at 20:30:00 vanished when the 20:30:17
# swap landed. The audit log proved it -- `promotion.approved` and
# `capability.gates.run` existed only in the preswap copy, and the surviving
# promotion_requests row had reverted to all-`pending` gates. The ingest itself had
# changed nothing (added:0 updated:0 removed:0); the row was simply overwritten by
# stale data.
#
# The `flock` above only excludes a second heal. It does NOT serialise against
# `capmesh submit|approve|gates run`, which write live directly. Worse, a promotion
# changes `uri`, which is exactly the column the SKIP projection compares -- so a
# promotion is GUARANTEED to defeat the skip and trigger a swap on the next tick.
#
# Record the live audit watermark as captured by the snapshot; the swap step
# re-reads live and refuses to clobber it if it has advanced. Cheap: one indexed
# aggregate. Failure to read is non-fatal (empty => guard is skipped, preserving
# previous behaviour rather than blocking the heal).
SNAP_AUDIT_WATERMARK="$(sqlite3 "$TMPDB" "SELECT COUNT(*)||':'||COALESCE(MAX(id),0) FROM audit_events;" 2>/dev/null || true)"

# 2. Full ingest from the DEFAULT roots into the snapshot. No --root: a narrow root is exactly
#    what caused the incident, and the shrink guard would refuse it anyway.
INGEST_LOG="$(mktemp /tmp/capmesh-ingest.XXXXXX.log)"
chmod 600 "$INGEST_LOG"
# Capture the ingest exit code so a timeout (timeout(1) returns 124) can be
# distinguished from a normal failure. The original `if !` form negated the
# status and hid the 124; the captured var lets a timeout fall through to its
# own abort below (after the diagnostics block), so the timeout message is the
# last word and the live DB is left untouched.
ingest_rc=0
( cd "$SERVICE_DIR" && timeout "$INGEST_TIMEOUT" "$PY" -m capmesh --db "$TMPDB" ingest >"$INGEST_LOG" 2>&1 ) || ingest_rc=$?
if (( ingest_rc != 0 && ingest_rc != 124 )); then
  log "ABORT ingest failed (shrink guard or error) — live index left untouched"
  tail -n 80 "$INGEST_LOG" >&2 || true
  exit 1
fi
if [[ -s "$INGEST_LOG" ]]; then
  log "ingest completed with diagnostics (last 80 lines follow)"
  tail -n 80 "$INGEST_LOG" >&2 || true
fi
if (( ingest_rc == 124 )); then
  log "ABORT ingest timed out after ${INGEST_TIMEOUT}s — live index left untouched"
  exit 1
fi

rebuilt=$(count_of "$TMPDB")
[[ -z "$rebuilt" ]] && { log "ABORT rebuilt DB unreadable"; exit 1; }
if [[ -n "$EXPECTED_COUNT" && "$rebuilt" != "$EXPECTED_COUNT" ]]; then
  log "ABORT rebuilt=$rebuilt does not match rehearsed=$EXPECTED_COUNT — live index left untouched"
  exit 1
fi

# 3. Verify before swapping.
if [[ "$(sqlite3 "$TMPDB" 'PRAGMA integrity_check;' 2>/dev/null | head -1)" != "ok" ]]; then
  log "ABORT rebuilt DB failed integrity_check"; exit 1
fi
fts=$(sqlite3 "$TMPDB" 'SELECT COUNT(*) FROM capability_fts;' 2>/dev/null)
if [[ -z "$fts" || "$fts" != "$rebuilt" ]]; then
  log "ABORT rebuilt DB FTS mismatch capabilities=$rebuilt fts=${fts:-unreadable}"; exit 1
fi
if (( rebuilt < MIN_HEALTHY )); then
  log "ABORT rebuilt=$rebuilt is below MIN_HEALTHY=$MIN_HEALTHY — refusing to install a broken index"
  exit 1
fi
if (( rebuilt < live && live >= MIN_HEALTHY )); then
  log "ABORT rebuilt=$rebuilt < live=$live and live is healthy — refusing to shrink a good index"
  exit 1
fi

# 3b. Skip-when-unchanged fast path.
# WHY: asg-capability-mesh-refresh.service runs this script every 15 min. The
# swap below STOPS all 16 workers, swaps the shared DB, then STARTS them — a
# ~3-5s window where every nginx capmesh_pool backend is down and bursts of
# requests get 502/504. In steady state the catalog is unchanged, so that
# disruptive restart is pure waste and the #1 availability risk for the
# 100s-of-concurrent-requests goal. This fast path detects an unchanged
# catalog and exits with NO worker restart at all.
# WHAT WE COMPARE: the capability count (already in `live`/`rebuilt`) PLUS a
# deterministic projection of the sorted (uri,name,version) rows of the
# capabilities table, compared byte-for-byte with `cmp`. That catches all
# real catalog changes (added, removed, renamed, re-versioned capabilities).
# WHY NOT sha1()/md5() HERE: an earlier version wrapped the projection in
# sha1(group_concat(...)) (and before that md5(...)) to shrink it to a short
# hash. That is NOT robust: the sqlite3 CLI this script invokes
# (/usr/bin/sqlite3, 3.46.1) provides NEITHER sha1() NOR md5() as SQL
# functions, so the query errored, `|| true` swallowed it into an empty
# fingerprint, the non-empty guard failed, and the skip NEVER triggered — the
# every-15-min swap blip persisted undiagnosed. (The bundled capmesh sqlite3
# under runtime/sqlite-3.53.3-capmesh2 is a different binary this script does
# not call.) Comparing the raw projection needs no hash function and uses the
# same /usr/bin/sqlite3 the rest of the script already uses for count_of. The
# projection is ~0.5MB for a ~3500-cap mesh — trivial for two temp files and
# `cmp -s`.
# TRADEOFF: a capability whose ONLY change is a field not in the projection
# (e.g. a description tweak) is skipped until a uri/name/version changes —
# acceptable for a 15-min refresh.
# SAFETY: only skip when BOTH projections are non-empty AND byte-identical;
# on any read error we FALL THROUGH to the existing safe swap (the skip is
# purely optional).
projection_of() {
  sqlite3 "$1" "SELECT uri||char(31)||name||char(31)||version FROM capabilities ORDER BY uri,name,version;" 2>/dev/null
}
LIVE_PROJ="$(mktemp /tmp/capmesh-proj.XXXXXX)"
REBUILT_PROJ="$(mktemp /tmp/capmesh-proj.XXXXXX)"
projection_of "$DB" >"$LIVE_PROJ"
projection_of "$TMPDB" >"$REBUILT_PROJ"
if (( live == rebuilt )) \
  && [[ -s "$LIVE_PROJ" && -s "$REBUILT_PROJ" ]] \
  && cmp -s "$LIVE_PROJ" "$REBUILT_PROJ"; then
  log "SKIP rebuild identical to live (count=$rebuilt, projection match) — no swap, workers stay up (no 15-min restart blip)"
  printf '{"timestamp":"%s","action":"selfheal-skip","countBefore":%s,"countAfter":%s}\n' \
    "$(date -u +%FT%TZ)" "$live" "$live" >> "$DB_DIR/ingest-audit.jsonl"
  ROLLBACK_REQUIRED=0
  exit 0
fi

# 4. Prepare on the same filesystem, then swap with workers stopped. `mv` is
# atomic here; never copy directly onto the live DB path.
ts=$(date +%Y%m%d-%H%M%S)
PRESWAP="$DB.preswap-$ts"

# LOST-WRITE GUARD (enforcement half). Re-read the live audit watermark and refuse
# the swap if live advanced past the snapshot -- those writes exist ONLY in live and
# the `mv` below would destroy them irrecoverably (see the baseline comment above).
#
# Deliberately placed BEFORE `systemctl_workers stop` so an abort costs nothing and
# leaves the workers untouched. Exit 0, not 1: a deferred heal is normal operation,
# not a failure, and the next tick retries against a quiet database.
if [[ -n "$SNAP_AUDIT_WATERMARK" ]]; then
  live_audit_now="$(sqlite3 "$DB" "SELECT COUNT(*)||':'||COALESCE(MAX(id),0) FROM audit_events;" 2>/dev/null || true)"
  if [[ -n "$live_audit_now" && "$live_audit_now" != "$SNAP_AUDIT_WATERMARK" ]]; then
    log "SKIP live advanced during rebuild (audit $SNAP_AUDIT_WATERMARK -> $live_audit_now) — refusing swap so concurrent governance writes are not lost"
    exit 0
  fi
fi

log "swapping live=$live -> rebuilt=$rebuilt"
cp "$TMPDB" "$CANDIDATE"
chmod 640 "$CANDIDATE"
systemctl_workers stop >/dev/null 2>&1
sleep 2
sqlite3 "$DB" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1 || true
mv "$DB" "$PRESWAP"
ROLLBACK_REQUIRED=1
rm -f "$DB-wal" "$DB-shm"
mv "$CANDIDATE" "$DB"
# The deploy orchestrator may invoke self-heal as root while workers run as an
# unprivileged service account. Preserve the live database's numeric ownership
# and mode instead of accidentally transferring it to the invoking user.
chown "$DB_UID:$DB_GID" "$DB"
chmod "$DB_MODE" "$DB"
systemctl_workers start >/dev/null 2>&1

final=$(count_of "$DB")
workers="$(pgrep -fc "capmesh.*serve-http" 2>/dev/null || true)"
workers="${workers:-0}"
health=""
ready_attempt=0
for ((ready_attempt=1; ready_attempt<=READY_ATTEMPTS; ready_attempt++)); do
  health=$(curl -fsS -m "$READY_TIMEOUT" \
    "http://127.0.0.1:${HEALTH_PORT}/health/ready" 2>/dev/null || true)
  if printf '%s' "$health" | python3 -c \
    'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("status") == "ready" else 1)' \
    2>/dev/null; then
    break
  fi
  (( ready_attempt < READY_ATTEMPTS )) && sleep "$READY_INTERVAL"
done

if printf '%s' "$health" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("status") == "ready" else 1)' 2>/dev/null; then
  printf '{"timestamp":"%s","action":"selfheal","countBefore":%s,"countAfter":%s,"preswap":"%s"}\n' \
    "$(date -u +%FT%TZ)" "$live" "$final" "$(basename "$PRESWAP")" >> "$DB_DIR/ingest-audit.jsonl"
  ROLLBACK_REQUIRED=0
  # Rotate preswap snapshots so hourly self-heal cannot fill the root filesystem
  # (observed 160+ × ~77MB files → multi-GB root pressure on the primary node).
  PRESWAP_KEEP="${CAPMESH_PRESWAP_KEEP:-3}"
  if [[ "$PRESWAP_KEEP" =~ ^[1-9][0-9]*$ ]]; then
    mapfile -t _preswaps < <(ls -1t "$DB".preswap-* 2>/dev/null || true)
    if ((${#_preswaps[@]} > PRESWAP_KEEP)); then
      for _old in "${_preswaps[@]:PRESWAP_KEEP}"; do
        rm -f -- "$_old" && log "rotated preswap removed $(basename "$_old")"
      done
    fi
  fi
  log "OK healed live=$live -> $final workers=$workers ready_attempt=$ready_attempt (previous DB kept at $PRESWAP)"
  exit 0
fi

log "FAIL service unhealthy after swap (final=$final workers=$workers attempts=$ready_attempt health=$health)"
exit 1
