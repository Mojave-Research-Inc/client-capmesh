#!/usr/bin/env bash
# Provision the protected same-host client contract used by primary-node services.
set -euo pipefail

STATE="${1:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}}"
NODE_ROLE="${2:-}"
PORT="${3:-17778}"
CLIENT_GROUP="${CAPMESH_LOCAL_CLIENT_GROUP:-capmesh-clients}"
ENV_FILE="$STATE/capmesh.env"
CLIENT_ENV="$STATE/primary-local.env"

case "$STATE" in /secure/*|*/state/*) ;; *) printf 'state must be below /secure\n' >&2; exit 2 ;; esac
case "$NODE_ROLE" in authoritative|non-voting-raft|read-replica) ;; *) printf 'invalid node role\n' >&2; exit 2 ;; esac
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1024 && PORT <= 65535 )) \
  || { printf 'invalid local port\n' >&2; exit 2; }

# A replica must never advertise a credential named for the authoritative
# primary node path. Replica-local reads have a separate, read-only client contract.
if [[ "$NODE_ROLE" != authoritative ]]; then
  rm -f -- "$CLIENT_ENV"
  exit 0
fi

[[ -r "$ENV_FILE" ]] || { printf 'missing protected Capmesh environment\n' >&2; exit 1; }
TOKEN="$(awk -F= '$1 == "CAPMESH_BEARER_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[[ -n "$TOKEN" ]] || { printf 'missing Capmesh service bearer\n' >&2; exit 1; }

getent group "$CLIENT_GROUP" >/dev/null 2>&1 || groupadd --system "$CLIENT_GROUP"
command -v setfacl >/dev/null 2>&1 || { printf 'setfacl is required\n' >&2; exit 1; }
setfacl -m "g:${CLIENT_GROUP}:--x" /secure "$STATE"

umask 077
candidate="$(mktemp "$STATE/.primary-local.env.XXXXXX")"
trap 'rm -f -- "$candidate"' EXIT
{
  printf 'CAPMESH_BASE_URL=http://127.0.0.1:%s\n' "$PORT"
  printf 'CAPMESH_MCP_URL=http://127.0.0.1:%s/mcp\n' "$PORT"
  printf 'CAPMESH_BEARER_TOKEN=%s\n' "$TOKEN"
  printf 'CAPMESH_NODE_ROLE=authoritative\n'
  printf 'CAPMESH_AUTHORITY_URL=%s\n' "${CAPMESH_AUTHORITY_URL:-https://capmesh.asg.ts.net}"
} > "$candidate"
chown "root:${CLIENT_GROUP}" "$candidate"
chmod 0640 "$candidate"
mv -f -- "$candidate" "$CLIENT_ENV"
# Compatibility: pre-2026-07-27 consumers read cpubox-local.env.
ln -sfn "$(basename "$CLIENT_ENV")" "$STATE/cpubox-local.env"
trap - EXIT

# Report metadata only. Never print or hash the bearer into routine logs.
printf 'provisioned %s for group %s\n' "$CLIENT_ENV" "$CLIENT_GROUP"
