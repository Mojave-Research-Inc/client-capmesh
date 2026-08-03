#!/usr/bin/env bash
# Explicit cpubox-only CapMesh authority-key bootstrap. Never run on replicas.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${CAPMESH_STATE_DIR:-/secure/asg-capmesh}"
AUTHORITY_DIR="${CAPMESH_AUTHORITY_DIR:-$STATE_DIR/authority}"
EXPORT_DIR="${CAPMESH_AUTHORITY_EXPORT_DIR:-$STATE_DIR/authority-client-export}"
PYTHON="${CAPMESH_PYTHON:-$ROOT/.venv/bin/python}"

export CAPMESH_NODE_ROLE="${CAPMESH_NODE_ROLE:-authoritative}"
[[ "$CAPMESH_NODE_ROLE" == "authoritative" ]] || { echo "authority bootstrap: cpubox authoritative role required" >&2; exit 2; }

"$PYTHON" -m capmesh.authority_keys bootstrap \
  --private "$AUTHORITY_DIR/capmesh-authority-ed25519.pem" \
  --public "$AUTHORITY_DIR/capmesh-authority-ed25519.pub.pem" \
  --record "$AUTHORITY_DIR/capmesh-authority-trust.v1.json" >/dev/null
"$PYTHON" -m capmesh.authority_keys export-client \
  --public "$AUTHORITY_DIR/capmesh-authority-ed25519.pub.pem" \
  --record "$AUTHORITY_DIR/capmesh-authority-trust.v1.json" \
  --output-dir "$EXPORT_DIR" >/dev/null
printf '%s\n' "authority bootstrap complete; distribute only: $EXPORT_DIR"
