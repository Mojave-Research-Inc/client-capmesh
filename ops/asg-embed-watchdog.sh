#!/usr/bin/env bash
# asg-embed-watchdog.sh -- liveness watchdog for qwen-embedding.service (port 8090)
#
# WHY /health IS INSUFFICIENT (it lies while wedged):
#   qwen-embedding.service exposes /health, which returns {"status":"ok"} from
#   a lightweight handler that NEVER exercises the model. Under batch load the
#   service can livelock via torch thread oversubscription: the /embed path
#   spins at ~1300% CPU and never responds, while /health KEEPS answering
#   {"status":"ok"} from the same wedged process. Because the process never
#   exits, systemd's Restart=always never fires and the wedge persists
#   indefinitely. Consumers (capmesh, via CAPMESH_TEI_EMBED_URL) are left
#   hitting a dead endpoint with no capmesh-side visibility.
#
#   The REAL liveness signal is therefore a successful /embed round-trip: if a
#   tiny inference cannot complete within the timeout, the service is
#   functionally dead and must be restarted regardless of what /health
#   claims. This watchdog probes /embed (NOT /health).
#
# Behavior:
#   - POST http://127.0.0.1:8090/embed {"inputs":"watchdog probe"}
#   - curl --max-time, default 15s (env ASG_EMBED_WATCHDOG_TIMEOUT)
#   - HANG := curl exit != 0  OR  empty/non-JSON response body
#   - On HANG: logger -t asg-embed-watchdog, then
#     `systemctl restart qwen-embedding.service` (at most once per probe).
#   - State file /run/asg-embed-watchdog.fail records consecutive failures.
#   - On a healthy probe: clear failure state, do NOT touch the service.
#   - Always exits 0. A watchdog must never itself become a failing unit.

set -euo pipefail

EMBED_URL="http://127.0.0.1:8090/embed"
PAYLOAD='{"inputs":"watchdog probe"}'
TIMEOUT="${ASG_EMBED_WATCHDOG_TIMEOUT:-15}"
STATE_FILE="/run/asg-embed-watchdog.fail"
SERVICE="qwen-embedding.service"
TAG="asg-embed-watchdog"

log() { logger -t "$TAG" "$*" 2>/dev/null || true; }

# body_is_json: return 0 iff $1 parses as JSON. Empty input -> non-zero.
# Prefers jq for a real parse; falls back to a structural check (leading '{'
# or '[') so a MISSING jq never causes a false HANG.
body_is_json() {
    local b="$1"
    [[ -n "$b" ]] || return 1
    if command -v jq >/dev/null 2>&1; then
        if printf '%s' "$b" | jq -e . >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    local trimmed
    trimmed="$(printf '%s' "$b" | sed 's/^[[:space:]]*//')"
    case "$trimmed" in
        \{*|\[*) return 0 ;;
        *) return 1 ;;
    esac
}

# --- Probe the REAL liveness endpoint (/embed), NOT /health ---
# Explicit error capture so set -e never aborts the watchdog on a probe
# failure: a hang is data, not a script error.
rc=0
body=""
body="$(curl -sS --max-time "$TIMEOUT" -X POST "$EMBED_URL" \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" 2>/dev/null)" || rc=$?

is_hang=0
if [[ "$rc" -ne 0 ]]; then
    is_hang=1
    log "probe HANG: curl exit=$rc (url=$EMBED_URL timeout=${TIMEOUT}s)"
elif ! body_is_json "$body"; then
    is_hang=1
    log "probe HANG: empty/non-JSON body (url=$EMBED_URL timeout=${TIMEOUT}s) body=${body:0:200}"
fi

if [[ "$is_hang" -eq 0 ]]; then
    # Healthy probe: clear any prior failure state. Do NOT touch the service.
    if [[ -f "$STATE_FILE" ]]; then
        rm -f "$STATE_FILE"
        log "probe OK: /embed responded; cleared failure state"
    fi
    exit 0
fi

# --- HANG path: report consecutive failures and restart ONCE this probe ---
prev=0
if [[ -f "$STATE_FILE" ]]; then
    prev="$(cat "$STATE_FILE" 2>/dev/null || echo 0)"
    prev="${prev//[^0-9]/}"   # sanitize to digits only
    prev="${prev:-0}"
fi
curr=$((prev + 1))
printf '%s\n' "$curr" > "$STATE_FILE" 2>/dev/null || true

log "restart $SERVICE: consecutive failures=$curr (url=$EMBED_URL timeout=${TIMEOUT}s)"
systemctl restart "$SERVICE" 2>/dev/null || log "WARN: systemctl restart $SERVICE failed (exit=$?)"

exit 0
