#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sync_script="$test_dir/../sync-nonvoting-member.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/capmesh-lock-test.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

lock="$scratch/.nonvoting-sync.lock"
mkdir "$lock"
touch -t 200001010000 "$lock"

lock_block="$(awk '
  /^# BEGIN testable lock acquisition$/ { capture = 1; next }
  /^# END testable lock acquisition$/ { capture = 0 }
  capture { print }
' "$sync_script")"
[[ -n "$lock_block" ]] || {
  printf 'FAIL: lock acquisition block was not found\n' >&2
  exit 1
}

LOCAL_STATE="$scratch"
CAPMESH_NONVOTING_LOCK_STALE_SECONDS=1
log() { printf '[test] %s\n' "$*"; }

output="$(eval "$lock_block")"
[[ -d "$lock" ]] || {
  printf 'FAIL: stale lock was not reacquired\n' >&2
  exit 1
}
lock_mtime="$(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock")"
lock_age=$(( $(date +%s) - lock_mtime ))
(( lock_age <= CAPMESH_NONVOTING_LOCK_STALE_SECONDS )) || {
  printf 'FAIL: lock was not refreshed (age=%ss)\n' "$lock_age" >&2
  exit 1
}
[[ "$output" == *"WARN removing stale nonvoting sync lock"* ]] || {
  printf 'FAIL: stale-lock recovery was not logged\n' >&2
  exit 1
}

printf 'PASS: stale lock was removed and reacquired\n'
