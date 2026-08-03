#!/usr/bin/env bash
# Compare content generations, not just row counts, and heal the deficient side.

set -euo pipefail
DB="${CAPMESH_DB:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/asg-capmesh.db}"
STATE="${CAPMESH_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"
REPLICA="${CAPMESH_REPLICA:-127.0.0.1}"
SSH_BIN="${CAPMESH_SSH_BIN:-ssh}"
HEAL="${CAPMESH_PARITY_HEAL:-1}"
MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"
SKIP_STATE_FILE="${CAPMESH_PARITY_SKIP_STATE:-$STATE/.parity-skip-count}"
MAX_SKIPS="${CAPMESH_PARITY_MAX_SKIPS:-3}"
TAG=capmesh-parity

log() { logger -t "$TAG" "$*" 2>/dev/null || true; printf '[capmesh-parity] %s\n' "$*"; }
digest_sql="SELECT uri || char(9) || content_hash || char(9) || approval_state || char(9) || share_state FROM capabilities ORDER BY uri;"
local_count="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM capabilities;' 2>/dev/null)" || { log "ERROR local DB unreadable"; exit 1; }
local_digest="$(sqlite3 "$DB" "$digest_sql" 2>/dev/null | sha256sum | awk '{print $1}')"
local_release="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("releaseId", "legacy"))' "$STATE/current/DEPLOYED_VERSION.json" 2>/dev/null || printf legacy)"

remote_data="$($SSH_BIN -o ConnectTimeout=30 -o BatchMode=yes "${CAPMESH_REMOTE_USER:-operator}@$REPLICA" \
  "DB='$DB'; STATE='$STATE'; c=\$(sqlite3 \"\$DB\" 'SELECT COUNT(*) FROM capabilities;' 2>/dev/null) || exit 1; d=\$(sqlite3 \"\$DB\" \"$digest_sql\" 2>/dev/null | sha256sum | awk '{print \$1}'); r=\$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(\"releaseId\", \"legacy\"))' \"\$STATE/current/DEPLOYED_VERSION.json\" 2>/dev/null || printf legacy); printf '%s %s %s\\n' \"\$c\" \"\$d\" \"\$r\"" 2>/dev/null || true)"

if [[ -z "$remote_data" ]]; then
  skips="$(cat "$SKIP_STATE_FILE" 2>/dev/null || printf 0)"; skips=$((skips + 1))
  printf '%s\n' "$skips" > "$SKIP_STATE_FILE" 2>/dev/null || true
  (( skips > MAX_SKIPS )) && { log "ERROR replica unreachable skips=$skips"; exit 1; }
  log "WARN replica unreachable skips=$skips/$MAX_SKIPS"
  exit 0
fi
printf '0\n' > "$SKIP_STATE_FILE" 2>/dev/null || true
read -r remote_count remote_digest remote_release <<< "$remote_data"

if [[ "$local_digest" == "$remote_digest" ]]; then
  log "OK generation=$local_digest count=$local_count primaryRelease=$local_release replicaRelease=$remote_release"
  exit 0
fi

log "DRIFT primary=$local_count/$local_digest replica=$remote_count/$remote_digest releases=$local_release/$remote_release"
(( HEAL == 1 )) || exit 1

if (( local_count < MIN_HEALTHY && remote_count >= MIN_HEALTHY )); then
  log "HEAL authoritative node is below the independently configured health floor; rebuilding from its installed immutable roots"
  "$STATE/selfheal-reingest.sh"
elif (( remote_count < MIN_HEALTHY && local_count >= MIN_HEALTHY )); then
  log "HEAL replica is below the independently configured health floor; rebuilding its subordinate copy from installed immutable roots"
  "$SSH_BIN" -o ConnectTimeout=30 -o BatchMode=yes "${CAPMESH_REMOTE_USER:-operator}@$REPLICA" \
    "'$STATE/selfheal-reingest.sh'"
else
  log "ERROR both catalogs are above the health floor but their content digests diverge; refusing count-based authority selection"
  exit 1
fi
log "HEAL completed; proving digest parity in the same run"
CAPMESH_PARITY_HEAL=0 exec "$0"
