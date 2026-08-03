#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${CAPMESH_ENV_FILE:-$HOME/.config/asgcode/capmesh-fallback.env}"
CLIENT_ENV_FILE="${CAPMESH_CLIENT_ENV_FILE:-$HOME/.config/asgcode/capmesh.env}"
[[ -r "$ENV_FILE" ]] || { echo "missing $ENV_FILE" >&2; exit 1; }
set -a
# Reuse the managed client bearer for authenticated loopback tool calls. The
# fallback environment is sourced second so primary node client routing can never
# override this process's subordinate role or local database path.
if [[ -r "$CLIENT_ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CLIENT_ENV_FILE"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
[[ "${CAPMESH_NODE_ROLE:-}" == non-voting-raft ]] || exit 78
[[ -n "${CAPMESH_AUTHORITY_URL:-}" ]] || exit 78
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="${CAPMESH_SERVICE_DIR:-$(cd -P "$SCRIPT_DIR/.." && pwd)}"
PY="${CAPMESH_PYTHON:-$SERVICE_DIR/.venv/bin/python}"
exec "$PY" -m capmesh --db "$CAPMESH_DB" serve-http --host 127.0.0.1 --port 17778
