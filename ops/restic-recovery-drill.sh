#!/usr/bin/env bash
# Read-only repository inventory and staging-only Capmesh restore drill.
# Never restores over /secure or the live service tree.

set -euo pipefail
IFS=$'\n\t'
export PATH="${CAPMESH_PATH:-/usr/local/bin:/usr/bin:/bin}"

MODE="${1:-inventory}"
shift || true
ENV_FILE="${CAPMESH_RESTIC_ENV_FILE:-/etc/restic/backup.env}"
RESTIC_BIN="${CAPMESH_RESTIC_BIN:-/usr/local/bin/restic}"
STAGE_BASE="/var/tmp/capmesh-restic-recovery"
TEST_MODE="${CAPMESH_RESTIC_TEST_MODE:-0}"
if [[ "$TEST_MODE" == 1 ]]; then
  STAGE_BASE="${CAPMESH_RESTORE_STAGE_BASE:-$STAGE_BASE}"
fi
SNAPSHOT="${CAPMESH_RESTIC_SNAPSHOT:-latest}"
SUBSET="${CAPMESH_RESTIC_CHECK_SUBSET:-5%}"
TARGET=""

while (( $# )); do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    -h|--help)
      printf 'Usage: %s inventory|check|stage-restore|verify [--env-file FILE] [--snapshot ID] [--target DIR]\n' "$0"
      exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

log() { printf '[capmesh-restic] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ -x "$RESTIC_BIN" ]] || die "restic binary missing at $RESTIC_BIN"
[[ -r "$ENV_FILE" ]] || die "restic environment file is not readable: $ENV_FILE"
case "$ENV_FILE" in /*) ;; *) die "environment file must be absolute" ;; esac

if [[ "$TEST_MODE" != 1 ]]; then
  case "$ENV_FILE" in /etc/restic/*.env) ;; *) die "production environment file must be /etc/restic/*.env" ;; esac
  [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die "environment file must be a regular non-symlink"
  [[ "$(stat -c '%u' "$ENV_FILE")" == 0 ]] || die "environment file must be root-owned"
  mode="$(stat -c '%a' "$ENV_FILE")"
  (( (8#$mode & 8#022) == 0 )) || die "environment file must not be group/world writable"
fi

# Parse data, never shell-source it. This prevents command substitution or
# arbitrary shell statements in a privileged recovery workflow.
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" == \#* ]] && continue
  if (( ${#value} >= 2 )) && { [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; }; then
    value="${value:1:${#value}-2}"
  fi
  case "$key" in
    RESTIC_REPOSITORY|RESTIC_PASSWORD|RESTIC_PASSWORD_FILE|RESTIC_PASSWORD_COMMAND|RESTIC_CACHE_DIR|RESTIC_COMPRESSION|AWS_*|AZURE_*|GOOGLE_*|B2_*|RCLONE_*)
      export "$key=$value" ;;
    *) die "unsupported key in Restic environment: $key" ;;
  esac
done < "$ENV_FILE"
[[ -n "${RESTIC_REPOSITORY:-}" ]] || die "RESTIC_REPOSITORY is required"

canonical_path() {
  python3 - "$1" <<'PY'
import pathlib, sys
print(pathlib.Path(sys.argv[1]).resolve(strict=False))
PY
}

stage_real="$(canonical_path "$STAGE_BASE")"
case "$stage_real" in /secure|/secure/*) die "staging base may not resolve under /secure" ;; esac

canonical_stage_target() {
  local requested="$1" resolved
  resolved="$(canonical_path "$requested")"
  case "$resolved" in "$stage_real"/*) printf '%s\n' "$resolved" ;; *) die "restore target must resolve below $stage_real" ;; esac
}

case "$MODE" in
  inventory)
    "$RESTIC_BIN" snapshots --no-lock --json | python3 -c '
import json, sys
for s in json.load(sys.stdin):
    print("%s\t%s\t%s\t%s" % (str(s.get("id", ""))[:8], s.get("time", ""), s.get("hostname", ""), ",".join(s.get("paths") or [])))
' ;;
  check)
    log "read-only repository check (subset=$SUBSET)"
    "$RESTIC_BIN" check "--read-data-subset=$SUBSET" ;;
  stage-restore)
    if [[ -z "$TARGET" ]]; then
      mkdir -p "$STAGE_BASE"
      chmod 700 "$STAGE_BASE"
      TARGET="$STAGE_BASE/$(date -u +%Y%m%dT%H%M%SZ)-${SNAPSHOT:0:8}"
    fi
    TARGET="$(canonical_stage_target "$TARGET")"
    [[ ! -e "$TARGET" ]] || die "restore target already exists: $TARGET"
    mkdir -m 700 "$TARGET"
    start="$(date +%s)"
    log "restoring snapshot ${SNAPSHOT:0:8} to isolated staging target $TARGET"
    "$RESTIC_BIN" restore "$SNAPSHOT" --target "$TARGET"
    printf 'snapshot=%s\ntarget=%s\nstarted=%s\ncompleted=%s\nelapsedSeconds=%s\n' \
      "${SNAPSHOT:0:8}" "$TARGET" "$start" "$(date +%s)" "$(( $(date +%s) - start ))" > "$TARGET/RESTORE-EVIDENCE.txt"
    "$0" verify --env-file "$ENV_FILE" --snapshot "$SNAPSHOT" --target "$TARGET" ;;
  verify)
    [[ -n "$TARGET" && -d "$TARGET" ]] || die "--target must identify a staged restore"
    TARGET="$(canonical_stage_target "$TARGET")"
    mapfile -t dbs < <(find "$TARGET" -type f -name 'asg-capmesh.db' -print)
    (( ${#dbs[@]} == 1 )) || die "expected exactly one asg-capmesh.db, found ${#dbs[@]}"
    db="${dbs[0]}"
    [[ "$(sqlite3 "$db" 'PRAGMA quick_check;' | head -1)" == ok ]] || die "quick_check failed"
    [[ "$(sqlite3 "$db" 'PRAGMA integrity_check;' | head -1)" == ok ]] || die "integrity_check failed"
    count="$(sqlite3 "$db" 'SELECT COUNT(*) FROM capabilities;' 2>/dev/null)"
    sources="$(sqlite3 "$db" 'SELECT COUNT(*) FROM capability_sources;' 2>/dev/null)"
    printf 'snapshot=%s db=%s capabilities=%s sources=%s integrity=ok\n' "${SNAPSHOT:0:8}" "$db" "$count" "$sources"
    (( count >= ${CAPMESH_MIN_HEALTHY:-3000} )) || die "restored catalog is below minimum healthy count"
    ;;
  *) die "mode must be inventory, check, stage-restore, or verify" ;;
esac
