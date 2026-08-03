#!/usr/bin/env bash
# Semantic readiness watchdog and worker-pool recovery.

set -euo pipefail

STATE="${CAPMESH_STATE_DIR:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/state}"
URL="${CAPMESH_READY_URL:-http://127.0.0.1:17778/health/ready}"
SERVICE_USER="${CAPMESH_SERVICE_USER:-jason}"
UNIT_PATTERN="${CAPMESH_UNIT_PATTERN:-asg-capability-mesh@*.service}"

ready() {
  local code
  code="$(curl -s -m5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || true)"
  [[ "$code" == "200" ]] && "$STATE/catalog-watchdog.sh" >/dev/null 2>&1
}

for _ in 1 2; do
  ready && exit 0
  sleep 3
done

logger -t capmesh-watchdog "semantic readiness failed -> rebuilding catalog and restarting worker pool"
sudo -u "$SERVICE_USER" -H "$STATE/selfheal-reingest.sh" || true

mapfile -t units < <(
  systemctl list-unit-files "$UNIT_PATTERN" --no-legend \
    | awk '$1 ~ /@[^.]+\.service$/ { print $1 }'
)
(( ${#units[@]} > 0 )) || exit 1
systemctl start "${units[@]}"
systemctl reload nginx 2>/dev/null || true

for _ in 1 2 3; do
  ready && exit 0
  sleep 2
done
exit 1
