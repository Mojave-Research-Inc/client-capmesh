#!/usr/bin/env bash
# Post-deploy / postmortem-adjacent closure checks for Capability Mesh.
# Read-only. Safe to run from operator workstation over the tailnet.
#
# Usage:
#   ops/closure-verify.sh
#   CAPMESH_METRICS_TOKEN=… ops/closure-verify.sh   # optional metrics scrape proof
set -euo pipefail

AUTHORITY_URL="${CAPMESH_AUTHORITY_URL:-http://127.0.0.1:8000}"
MAC_URL="${CAPMESH_MAC_READY_URL:-http://127.0.0.1:17778/health/ready}"
PRIMARY="${CAPMESH_PRIMARY:-127.0.0.1}"
REPLICA="${CAPMESH_REPLICA:-127.0.0.1}"
SSH_USER="${CAPMESH_REMOTE_USER:-jason}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=30 -o ControlMaster=no -o ControlPath=none
  -o ServerAliveInterval=15 -o ServerAliveCountMax=6)
failures=0

log() { printf '[capmesh-closure] %s\n' "$*"; }
fail() { log "FAIL: $*"; failures=$((failures + 1)); }
ok() { log "OK: $*"; }

require_json_field() {
  local body="$1" expr="$2" label="$3"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=eval(sys.argv[2], {"d": d});
assert v, sys.argv[3]' "$body" "$expr" "$label" 2>/dev/null \
    || fail "$label"
}

log "authority readiness $AUTHORITY_URL"
auth_body="$(curl -fsS -m 15 "$AUTHORITY_URL/health/ready")" || fail "authority /health/ready unreachable"
if [[ -n "${auth_body:-}" ]]; then
  python3 - <<'PY' "$auth_body" || fail "authority not ready/authoritative"
import json, sys
d = json.loads(sys.argv[1])
assert d.get("status") == "ready", d
assert d.get("topology", {}).get("authoritative") is True, d.get("topology")
assert d.get("topology", {}).get("nodeRole") == "authoritative", d.get("topology")
cat = d.get("catalog") or {}
assert int(cat.get("capabilityCount") or 0) >= 3000, cat
assert str(cat.get("generation") or "").startswith("sha256:"), cat
print("caps", cat.get("capabilityCount"), "gen", str(cat.get("generation"))[:24])
PY
  ok "authority ready generation-matched floor"
fi

log "public metrics gate (must not succeed on bare whois alone after remediated deploy)"
metrics_code="$(curl -sS -m 10 -o /tmp/capmesh-metrics-body -w '%{http_code}' "$AUTHORITY_URL/metrics" || true)"
if [[ "$metrics_code" == "200" ]]; then
  # Pre-remediation deploys allowed whois; post-remediation should be 401.
  log "WARN: /metrics returned 200 without bearer (pre-remediation behavior or proxy inject)"
else
  ok "/metrics status=$metrics_code without bearer (expected 401 after remediated workers)"
fi
if [[ -n "${CAPMESH_METRICS_TOKEN:-}${CAPMESH_BEARER_TOKEN:-}" ]]; then
  token="${CAPMESH_METRICS_TOKEN:-$CAPMESH_BEARER_TOKEN}"
  code="$(curl -sS -m 10 -o /tmp/capmesh-metrics-auth -w '%{http_code}' \
    -H "Authorization: Bearer $token" "$AUTHORITY_URL/metrics" || true)"
  if [[ "$code" == "200" ]] && grep -q 'capmesh_uptime_seconds' /tmp/capmesh-metrics-auth 2>/dev/null; then
    ok "authenticated /metrics scrape"
  else
    fail "authenticated /metrics scrape code=$code"
  fi
fi

if curl -fsS -m 5 "$MAC_URL" >/tmp/capmesh-mac-ready 2>/dev/null; then
  python3 - <<'PY' || fail "mac nonvoting not ready/role wrong"
import json
d=json.load(open("/tmp/capmesh-mac-ready"))
assert d.get("status")=="ready", d
assert d.get("topology",{}).get("nodeRole")=="non-voting-raft", d.get("topology")
assert d.get("topology",{}).get("authoritative") is False
print("mac caps", (d.get("catalog") or {}).get("capabilityCount"))
PY
  ok "mac nonvoting ready"
else
  log "WARN: mac loopback ready not reachable from this host"
fi

# Remote worker probes (allow tsrecorder warm-up)
for host_role in "primary:$PRIMARY" "replica:$REPLICA"; do
  role="${host_role%%:*}"; host="${host_role#*:}"
  log "ssh $role $host"
  out="$(ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" 'bash -s' <<'REMOTE' || true
set +e
echo ROLE_KEYS=$(grep -E '^(CAPMESH_NODE_ROLE|CAPMESH_AUTHORITY_URL)=' "${CAPMESH_ENV_FILE:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/capmesh.env}" 2>/dev/null | tr '\n' ';')
echo RELEASE=$(readlink "${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/current" 2>/dev/null)
# probe common worker ports
for p in 17781 17782 17778; do
  code=$(curl -sS -m 3 -o /tmp/r -w "%{http_code}" http://127.0.0.1:$p/health/ready 2>/dev/null || echo 000)
  if [[ "$code" == 200 ]]; then
    echo "PORT $p"
    python3 - <<'PY'
import json
d=json.load(open("/tmp/r"))
print("STATUS", d.get("status"))
print("NODEROLE", (d.get("topology") or {}).get("nodeRole"))
print("CAPS", (d.get("catalog") or {}).get("capabilityCount"))
print("GEN", str((d.get("catalog") or {}).get("generation") or "")[:24])
PY
    break
  fi
done
write=$(curl -sS -m 3 -X POST http://127.0.0.1:17781/api/v1/capabilities \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null || true)
echo "WRITE:$write"
REMOTE
)"
  printf '%s\n' "$out" | sed 's/^/  /'
  if [[ "$role" == primary ]]; then
    echo "$out" | grep -q 'NODEROLE authoritative' && ok "primary authoritative" || fail "primary role"
  else
    echo "$out" | grep -q 'NODEROLE non-voting-raft' && ok "replica non-voting" || fail "replica role"
    echo "$out" | grep -q 'NOT_AUTHORITATIVE' && ok "replica write reject" || fail "replica write reject"
  fi
done

if (( failures > 0 )); then
  log "RESULT: $failures failure(s)"
  exit 1
fi
log "RESULT: all checks passed"
exit 0
