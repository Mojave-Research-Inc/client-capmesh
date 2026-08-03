#!/usr/bin/env bash
# Semantic freshness/readiness watchdog for a local Capmesh catalog.

set -euo pipefail
DB="${CAPMESH_DB:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/asg-capmesh.db}"
AUDIT="${CAPMESH_INGEST_AUDIT:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/ingest-audit.jsonl}"
MIN_CAPS="${CAPMESH_MIN_HEALTHY:-3000}"
MAX_AGE="${CAPMESH_MAX_REFRESH_AGE_SEC:-1800}"
TAG="capmesh-catalog-watchdog"

fail() { logger -t "$TAG" "FAIL $*" 2>/dev/null || true; printf '[capmesh-catalog-watchdog] FAIL %s\n' "$*" >&2; exit 1; }
[[ -r "$DB" ]] || fail "database unreadable: $DB"
[[ "$(sqlite3 "$DB" 'PRAGMA quick_check;' 2>/dev/null | head -1)" == ok ]] || fail "quick_check"
caps="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM capabilities;' 2>/dev/null)" || fail "capability count"
fts="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM capability_fts;' 2>/dev/null)" || fail "FTS count"
sources="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM capability_sources;' 2>/dev/null)" || fail "source count"
(( caps >= MIN_CAPS )) || fail "catalog too small caps=$caps minimum=$MIN_CAPS"
(( fts == caps )) || fail "FTS mismatch caps=$caps fts=$fts"
(( sources > 0 )) || fail "no indexed sources"
[[ -s "$AUDIT" ]] || fail "ingest audit missing: $AUDIT"
now="$(date +%s)"
mtime="$(stat -c %Y "$AUDIT" 2>/dev/null || stat -f %m "$AUDIT" 2>/dev/null)" || fail "audit timestamp"
age=$(( now - mtime ))
(( age <= MAX_AGE )) || fail "catalog stale age=${age}s maximum=${MAX_AGE}s"
logger -t "$TAG" "OK caps=$caps fts=$fts sources=$sources age=${age}s" 2>/dev/null || true
printf '{"status":"ok","capabilities":%s,"fts":%s,"sources":%s,"refreshAgeSeconds":%s}\n' "$caps" "$fts" "$sources" "$age"
