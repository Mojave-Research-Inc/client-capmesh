#!/usr/bin/env bash
# service-endpoint-watchdog.sh — probe what SERVICES actually answer, not what podman claims.
#
# WHY THIS EXISTS (all three happened on the primary node on 2026-07-18):
#   - asgcrm-grafana reported "Up" in `podman ps` while crash-looping 554 times.
#   - asgcrm-prometheus/grafana/loki reported "Up 7 hours" with DEAD pids; their published
#     ports answered nothing for ~7 hours and nobody noticed.
#   - the capability mesh sat wiped 2110 -> 16 for ~24h behind an hourly self-heal that
#     reported success every time.
# In every case the container/unit layer said healthy and the SERVICE was not. Container
# status is a claim about a process; only an endpoint probe is evidence about a service.
#
# Exit codes: 0 = all probes pass, 1 = at least one failed (systemd marks the unit failed,
# so it lands in `systemctl --failed` where a human sees it). Failures also go to the journal
# under tag `service-watchdog`.
#
# Deliberately dependency-light: curl + bash. No agent, no network beyond loopback.
set -uo pipefail

TAG=service-watchdog
TIMEOUT="${WATCHDOG_TIMEOUT:-8}"
FAILED=0
CHECKED=0

log()  { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
fail() {
  FAILED=$((FAILED + 1))
  log "FAIL: $*"
  logger -t "$TAG" "FAIL: $*" 2>/dev/null || true
}

# probe <label> <url> [expected-substring] [expected-code]
#
# EVERY probe must assert an IDENTIFYING substring, not just a 2xx. Verified 2026-07-18: a
# synthetic "dead port" test pointed a probe at 127.0.0.1:19999 expecting failure — and it
# PASSED, because an unrelated service was serving HTML 200 there. Accepting any 2xx means a
# wrong port, a recycled port, or a captive portal all read as healthy, which is precisely the
# false-confidence this watchdog exists to eliminate.
# Passes on any 2xx/3xx, or on an expected substring in the body when one is given.
# A 404 from a service that is genuinely up (e.g. loki at /) is handled by giving that
# probe its own health path rather than by loosening the check here.
probe() {
  local label="$1" url="$2" expect="${3:-}"
  CHECKED=$((CHECKED + 1))
  local body code
  body=$(curl -sk -m "$TIMEOUT" -w $'\n%{http_code}' "$url" 2>/dev/null) || {
    fail "$label: no response from $url"
    return 1
  }
  code=$(printf '%s' "$body" | tail -1)
  body=$(printf '%s' "$body" | sed '$d')

  if [[ -n "$expect" ]]; then
    if [[ "$body" == *"$expect"* ]]; then
      log "ok: $label ($code)"
      return 0
    fi
    fail "$label: $url returned $code but body lacked '$expect'"
    return 1
  fi

  if [[ "$code" =~ ^[23] ]]; then
    log "ok: $label ($code)"
    return 0
  fi
  fail "$label: $url returned HTTP $code"
  return 1
}

# probe_code <label> <url> <exact-code> — for endpoints with no body to assert on.
probe_code() {
  local label="$1" url="$2" want="$3" code
  CHECKED=$((CHECKED + 1))
  code=$(curl -sk -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
  if [[ "$code" == "$want" ]]; then log "ok: $label ($code)"; return 0; fi
  fail "$label: $url returned $code, expected exactly $want"
  return 1
}

# tcp <label> <host> <port> — for services with no HTTP surface (postgres, redis).
tcp() {
  local label="$1" host="$2" port="$3"
  CHECKED=$((CHECKED + 1))
  if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
    log "ok: $label (tcp ${host}:${port})"
    return 0
  fi
  fail "$label: nothing listening on ${host}:${port}"
  return 1
}

log "watchdog start"

# ── capability mesh (production, serves the primary node) ──────────────────
probe "capmesh worker"      "http://127.0.0.1:17781/health" '"status": "ready"'

# The identity path, through the nginx LB. /health alone is NOT sufficient and that gap cost a
# day: on 2026-07-19 /api/v1/whoami hung indefinitely under any concurrency (unconditional
# writes in ensure_identity_for_principal serialising on one SQLite write lock across 16
# workers) while /health stayed green the whole time, because /health never writes. New-client
# onboarding was broken and nothing alerted.
#
# A same-host request without a service bearer must fail closed. Tailscale
# identity is only present when traffic traverses Serve; loopback itself is not
# an identity boundary.
probe_code "capmesh local unauthenticated boundary" \
  "http://127.0.0.1:17778/api/v1/whoami" 401

# Exercise the supported primary-local service contract without placing the
# bearer in argv or output. Python reads the protected env file directly and
# verifies the application principal returned through nginx.
CHECKED=$((CHECKED + 1))
if python3 - "${CAPMESH_LOCAL_ENV:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/primary-local.env}" <<'PY'
import json
import pathlib
import sys
import urllib.request

values = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition("=")
    if separator:
        values[key] = value
token = values.get("CAPMESH_BEARER_TOKEN", "")
base = values.get("CAPMESH_BASE_URL", "")
if not token or base != "http://127.0.0.1:17778":
    raise SystemExit(1)
request = urllib.request.Request(
    base + "/api/v1/whoami",
    headers={"Authorization": "Bearer " + token},
)
with urllib.request.urlopen(request, timeout=8) as response:
    payload = json.load(response)
if payload.get("subject") != "capmesh-service" or "app_service" not in payload.get("roles", []):
    raise SystemExit(1)
PY
then
  log "ok: capmesh local authenticated service identity"
else
  fail "capmesh local authenticated service identity: protected bearer path failed"
fi

# LB pool integrity: every nginx upstream must have a live worker. A configured-but-dead
# backend does not fail this watchdog's single-request probes reliably (round-robin means most
# requests land somewhere healthy), so check the invariant directly instead of sampling.
CHECKED=$((CHECKED + 1))
_ups=()
while IFS= read -r _p; do
  _ups+=("$_p")
# Source the EFFECTIVE config via `nginx -T`, NOT a conf.d/*.conf glob. On the primary node the capmesh
# upstream block is not in conf.d, so the glob returns ZERO — which first shipped as a vacuous
# "all 0 upstreams have listeners" pass (the exact false confidence this script exists to kill),
# and would now trip the empty-pool FAIL below as a false alarm instead. `nginx -T` renders every
# include, so it sees the block wherever it lives. Verified 2026-07-19: glob=0, nginx -T=16.
done < <(nginx -T 2>/dev/null | grep -oE 'server[[:space:]]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | grep -E '^(1778[1-9]|1779[0-9])$' | sort -u || true)
_missing=()
for _p in "${_ups[@]}"; do
  timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${_p}" 2>/dev/null || _missing+=("$_p")
done
if (( ${#_ups[@]} == 0 )); then
  fail "capmesh LB pool: nginx has no Capmesh upstreams"
elif (( ${#_missing[@]} )); then
  fail "capmesh LB pool: nginx upstreams with no listener: ${_missing[*]}"
else
  log "ok: capmesh LB pool (all ${#_ups[@]} upstreams have listeners)"
fi

# incontainer <label> <container> <command...> — for services with NO published host port.
# asgcrm postgres/redis are internal to the compose network on purpose; probing a host port
# would fail forever and train everyone to ignore this watchdog. Ask the container directly.
incontainer() {
  local label="$1" container="$2"; shift 2
  CHECKED=$((CHECKED + 1))
  if timeout "$TIMEOUT" podman exec "$container" "$@" >/dev/null 2>&1; then
    log "ok: $label (exec in $container)"
    return 0
  fi
  fail "$label: '$*' failed inside $container"
  return 1
}

# ── asg-crm monitoring tier (the stack that was dead behind a healthy status) ─
probe "asgcrm grafana"      "http://127.0.0.1:13000/api/health"   '"database"'
probe "asgcrm prometheus"   "http://127.0.0.1:19090/-/healthy"    "Healthy"
probe "asgcrm loki"         "http://127.0.0.1:13100/ready"        "ready"
# minio /health/live returns an EMPTY body, so there is no substring to assert. Pin the
# exact status code instead of accepting any 2xx.
probe_code "asgcrm minio"   "http://127.0.0.1:19000/minio/health/live" 200
incontainer "asgcrm postgres" asgcrm-postgres pg_isready -U postgres
incontainer "asgcrm redis"    asgcrm-redis    redis-cli ping

# ── jw-seesuite (data lake + app) ────────────────────────────────────────────
# Backend health is /health — NOT /api/health, which 404s. The frontend binds the TAILNET
# address, not loopback, so probing 127.0.0.1 fails. Use the HOSTNAME, not the IP:
# tailscaled terminates TLS and requires matching SNI, so https://100.87.89.35:8444/
# is refused outright while ${CAPMESH_SEESUITE_FRONTEND_URL:-https://127.0.0.1:8444} returns 200.
probe "seesuite backend"    "http://127.0.0.1:8010/health"        '"ok"'
probe "seesuite frontend"   "${CAPMESH_SEESUITE_FRONTEND_URL:-https://127.0.0.1:8444/}"     "<div id=\"root\""
probe "seesuite qdrant"     "http://127.0.0.1:6333/collections" '"status":"ok"'
incontainer "seesuite postgres" seesuite_postgres_1 pg_isready -U postgres

if (( FAILED > 0 )); then
  log "RESULT: $FAILED of $CHECKED probes FAILED"
  logger -t "$TAG" "RESULT: $FAILED of $CHECKED service probes FAILED" 2>/dev/null || true
  exit 1
fi

log "RESULT: all $CHECKED probes passed"
exit 0
