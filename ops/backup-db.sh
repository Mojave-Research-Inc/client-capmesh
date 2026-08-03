#!/usr/bin/env bash
# Create and rotate an online SQLite recovery point with the pinned runtime.

set -euo pipefail
IFS=$'\n\t'
umask 077

STATE="${CAPMESH_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"
DB="${CAPMESH_DB:-$STATE/asg-capmesh.db}"
DIR="${CAPMESH_BACKUP_DIR:-$STATE/backups}"
SQLITE="${CAPMESH_SQLITE_BIN:-$STATE/runtime/sqlite/bin/sqlite3}"
KEEP="${CAPMESH_BACKUP_KEEP:-14}"

[[ -f "$DB" ]] || { echo "missing Capmesh database: $DB" >&2; exit 1; }
[[ -x "$SQLITE" ]] || { echo "missing pinned SQLite CLI: $SQLITE" >&2; exit 1; }
[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || { echo "invalid backup retention: $KEEP" >&2; exit 2; }

runtime="$(cd -P "$(dirname "$SQLITE")/.." && pwd)"
export LD_LIBRARY_PATH="$runtime/lib:$runtime/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p "$DIR"
chmod 700 "$DIR"
out="$DIR/asg-capmesh-$(date -u +%Y%m%dT%H%M%SZ)-$$.db"
"$SQLITE" "$DB" ".backup '$out'"
[[ "$("$SQLITE" "$out" 'PRAGMA quick_check;' | head -n 1)" == ok ]] \
  || { echo 'backup quick_check failed' >&2; exit 1; }
gzip "$out"
chmod 600 "$out.gz"
find -L "$DIR" -maxdepth 1 -type f -name 'asg-capmesh-*.db.gz' -print0 \
  | xargs --null --no-run-if-empty ls -1t 2>/dev/null | tail -n "+$((KEEP + 1))" \
  | while IFS= read -r old; do rm -f -- "$old"; done
printf '[capmesh-backup] OK %s\n' "$out.gz"
