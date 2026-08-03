#!/usr/bin/env bash
# check-deploy-drift.sh — Compare deployed files against repo and manifest
# Checks sha256 of each deployed file, reports drift, exits non-zero if drift detected.
# Safe read-only script; suitable for timer/audit execution.
#
# Usage: ./check-deploy-drift.sh [--host HOST] [--verbose]
#   --host HOST      Check only one host (primary or replica)
#   --verbose        Show per-file sha256 values

set -euo pipefail

# Config
REPO_ROOT="${CAPMESH_ASG_OS_REPO:-${CAPMESH_HOME:-$HOME/.capmesh}/asg-os}"
CAPMESH_REPO_DIR="${REPO_ROOT}/services/asg-capmesh"
REMOTE_SERVICE_DIR="${CAPMESH_REMOTE_STATE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"

# The host layout is NOT a mirror of the repo layout. Assuming it is made this checker report
# every python file as MISSING (verified 2026-07-18: it flagged capmesh/index.py absent on
# primary-node while that exact module was loaded and serving). A drift checker that cries wolf on
# every run is worse than none — it trains you to ignore it.
#   repo capmesh/<f>.py -> <REMOTE_SERVICE_DIR>/service/capmesh/<f>.py
#   repo ops/<f>.sh     -> <REMOTE_SERVICE_DIR>/<f>.sh   (flat, no ops/ dir on the host)
remote_path_for() {
  case "$1" in
    capmesh/*) printf '%s/service/%s\n' "$REMOTE_SERVICE_DIR" "$1" ;;
    ops/*)     printf '%s/%s\n' "$REMOTE_SERVICE_DIR" "${1#ops/}" ;;
    *)         printf '%s/%s\n' "$REMOTE_SERVICE_DIR" "$1" ;;
  esac
}
HOSTS=("${CAPMESH_PRIMARY_HOST:-127.0.0.1}" "${CAPMESH_REPLICA_HOST:-127.0.0.1}")
VERBOSE=0
TARGET_HOST=""
DRIFT_DETECTED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) TARGET_HOST="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Validate TARGET_HOST if specified
if [[ -n "$TARGET_HOST" ]]; then
  if [[ ! " ${HOSTS[@]} " =~ " ${TARGET_HOST} " ]]; then
    echo -e "${RED}ERROR: Invalid host '${TARGET_HOST}'. Must be one of: ${HOSTS[*]}${NC}"
    exit 1
  fi
  HOSTS=("$TARGET_HOST")
fi

echo -e "${YELLOW}=== capmesh Deployment Drift Check ===${NC}"
echo "Repo: $CAPMESH_REPO_DIR"
echo "Checking hosts: ${HOSTS[*]}"
[[ $VERBOSE -eq 1 ]] && echo "Verbose mode: ON"
echo

# Build expected file list with repo sha256
# Associative arrays need bash >= 4. macOS still ships bash 3.2.57 as /bin/bash (GPLv2), so on
# the operator's Mac this script dies with "declare: -A: invalid option" unless it is run under
# a newer bash. Re-exec into one automatically rather than making every caller remember.
if [[ -z "${BASH_VERSINFO:-}" || ${BASH_VERSINFO[0]} -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$candidate" ]]; then exec "$candidate" "$0" "$@"; fi
  done
  echo "ERROR: this script needs bash >= 4 (macOS /bin/bash is 3.2). Install: brew install bash" >&2
  exit 1
fi

declare -A REPO_SHAS
echo -e "${YELLOW}Computing repo file hashes...${NC}"

for py_file in "$CAPMESH_REPO_DIR"/capmesh/*.py; do
  if [[ -f "$py_file" ]]; then
    relpath="capmesh/$(basename "$py_file")"
    sha256=$(sha256sum < "$py_file" | awk '{print $1}')
    REPO_SHAS["$relpath"]="$sha256"
    [[ $VERBOSE -eq 1 ]] && echo "  $relpath: $sha256"
  fi
done

for sh_file in "$CAPMESH_REPO_DIR"/ops/*.sh; do
  if [[ -f "$sh_file" ]]; then
    relpath="ops/$(basename "$sh_file")"
    sha256=$(sha256sum < "$sh_file" | awk '{print $1}')
    REPO_SHAS["$relpath"]="$sha256"
    [[ $VERBOSE -eq 1 ]] && echo "  $relpath: $sha256"
  fi
done

echo "Total files in repo: ${#REPO_SHAS[@]}"
echo

# Check each host
for host in "${HOSTS[@]}"; do
  echo -e "${BLUE}=== Checking ${host} ===${NC}"
  
  # Verify host is reachable
  if ! ssh -q -o ConnectTimeout=5 "${CAPMESH_REMOTE_USER:-operator}@${host}" "exit 0" 2>/dev/null; then
    echo -e "${RED}ERROR: Cannot reach ${host}${NC}"
    DRIFT_DETECTED=1
    continue
  fi
  
  # Check for manifest file
  manifest_file="${REMOTE_SERVICE_DIR}/DEPLOYED_VERSION.json"
  if ! ssh "${CAPMESH_REMOTE_USER:-operator}@${host}" "test -f '${manifest_file}' 2>/dev/null"; then
    echo -e "${YELLOW}WARNING: No manifest file found on ${host}${NC}"
    echo "  Expected: ${manifest_file}"
    echo "  This may indicate the host has never been deployed."
  else
    # Show manifest info
    echo -e "${YELLOW}Manifest Info:${NC}"
    ssh "${CAPMESH_REMOTE_USER:-operator}@${host}" "cat '${manifest_file}' 2>/dev/null | grep -E '(git_commit|deployed_at|deployed_by)' | sed 's/^/  /'" || true
  fi
  
  # Drift check: compare repo files to deployed files
  echo -e "${YELLOW}File Drift Check:${NC}"
  host_drift=0
  
  # ONE ssh per host, not one per file. The per-file version issued two round trips per file
  # (test -f, then sha256sum) = ~80 for 20 files across 2 hosts, each paying full Tailscale +
  # tsrecorder connection setup. It exceeded a 300s timeout and exited 124, which makes it
  # useless for the timer it was written for. Here the whole file list goes over in one
  # heredoc and comes back as "relpath<TAB>sha-or-MISSING" lines.
  remote_query=""
  for relpath in "${!REPO_SHAS[@]}"; do
    remote_query+="${relpath}|$(remote_path_for "${relpath}")"$'\n'
  done

  # BatchMode so a host that prompts for auth fails fast instead of hanging the timer.
  hash_output=$(ssh -o ConnectTimeout=15 -o BatchMode=yes "${CAPMESH_REMOTE_USER:-operator}@${host}" 'while IFS="|" read -r rel path; do
      [ -z "$rel" ] && continue
      if [ -f "$path" ]; then
        printf "%s\t%s\n" "$rel" "$(sha256sum "$path" 2>/dev/null | awk "{print \$1}")"
      else
        printf "%s\tMISSING\n" "$rel"
      fi
    done' <<< "$remote_query" 2>/dev/null) || {
    echo -e "${RED}  ✗ ERROR: could not collect hashes from ${host}${NC}"
    DRIFT_DETECTED=1
    continue
  }

  while IFS=$'\t' read -r relpath actual_sha; do
    [[ -z "$relpath" ]] && continue
    expected_sha="${REPO_SHAS[$relpath]:-}"
    if [[ "$actual_sha" == "MISSING" ]]; then
      echo -e "${RED}  ✗ MISSING: ${relpath}${NC}"
      host_drift=1; DRIFT_DETECTED=1
    elif [[ "$actual_sha" == "$expected_sha" ]]; then
      echo -e "${GREEN}  ✓ OK${NC}: $relpath"
      [[ $VERBOSE -eq 1 ]] && echo "      sha256: $actual_sha"
    else
      echo -e "${RED}  ✗ DRIFT${NC}: $relpath"
      echo "      expected: $expected_sha"
      echo "      actual  : $actual_sha"
      host_drift=1; DRIFT_DETECTED=1
    fi
  done <<< "$hash_output"
  
  # Check for unexpected files (in remote but not in repo)
  echo -e "${YELLOW}Checking for unexpected files...${NC}"
  ssh "${CAPMESH_REMOTE_USER:-operator}@${host}" "find '${REMOTE_SERVICE_DIR}/capmesh' -maxdepth 1 -name '*.py' -type f 2>/dev/null" | while read remote_py; do
    relpath="capmesh/$(basename "$remote_py")"
    if [[ ! -v REPO_SHAS["$relpath"] ]]; then
      echo -e "${YELLOW}  ! UNEXPECTED: ${relpath} (in remote, not in repo)${NC}"
    fi
  done || true
  
  ssh "${CAPMESH_REMOTE_USER:-operator}@${host}" "find '${REMOTE_SERVICE_DIR}/ops' -maxdepth 1 -name '*.sh' -type f 2>/dev/null" | while read remote_sh; do
    relpath="ops/$(basename "$remote_sh")"
    if [[ ! -v REPO_SHAS["$relpath"] ]]; then
      echo -e "${YELLOW}  ! UNEXPECTED: ${relpath} (in remote, not in repo)${NC}"
    fi
  done || true
  
  if [[ $host_drift -eq 0 ]]; then
    echo -e "${GREEN}✓ No drift detected on ${host}${NC}"
  else
    echo -e "${RED}✗ Drift detected on ${host}${NC}"
  fi
  echo
done

# Summary and exit
if [[ $DRIFT_DETECTED -eq 0 ]]; then
  echo -e "${GREEN}=== All hosts in sync ===${NC}"
  exit 0
else
  echo -e "${RED}=== Drift detected - manual review required ===${NC}"
  echo "Run: ./deploy-capmesh.sh to sync from repo"
  exit 1
fi
