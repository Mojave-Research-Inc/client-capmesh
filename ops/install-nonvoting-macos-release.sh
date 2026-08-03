#!/usr/bin/env bash
# Install one exact asg-os commit as the local immutable non-voting member.

set -euo pipefail
IFS=$'\n\t'

[[ "$(uname -s)" == Darwin ]] || { echo 'macOS is required' >&2; exit 2; }

REPO_ROOT="${ASG_OS_REPO_ROOT:-$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
GIT_SHA="${1:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
RELEASE_ID="${2:-$(date -u +%Y%m%dT%H%M%SZ)-${GIT_SHA:0:12}}"
STATE="${CAPMESH_MACOS_STATE:-$HOME/.capmesh}"
ENV_FILE="${CAPMESH_ENV_FILE:-$HOME/.config/asgcode/capmesh-fallback.env}"
LAUNCH_DIR="$HOME/Library/LaunchAgents"
RELEASES="$STATE/releases"
RELEASE="$RELEASES/$RELEASE_ID"
STAGING="$RELEASES/.$RELEASE_ID.staging-$$"
NEXT_LINK="$STATE/.current-$RELEASE_ID-$$"
UV="${CAPMESH_UV:-$(command -v uv || true)}"

case "$GIT_SHA" in (*[!0-9a-f]*) echo 'unsafe git commit' >&2; exit 2;; esac
[[ ${#GIT_SHA} == 40 ]] || { echo 'git commit must be a full SHA' >&2; exit 2; }
case "$RELEASE_ID" in (''|*[!A-Za-z0-9._-]*) echo 'unsafe release id' >&2; exit 2;; esac
case "$STATE" in ("$HOME"/.capmesh) ;; (*) echo 'state must be ~/.capmesh' >&2; exit 2;; esac
[[ -r "$ENV_FILE" && -n "$UV" ]] || { echo 'member env and uv are required' >&2; exit 1; }
git -C "$REPO_ROOT" cat-file -e "$GIT_SHA^{commit}"

cleanup() {
  case "$STAGING" in ("$RELEASES"/.*.staging-*) rm -rf -- "$STAGING";; esac
  rm -f -- "$NEXT_LINK"
}
trap cleanup EXIT
mkdir -p "$RELEASES" "$LAUNCH_DIR"

if [[ -d "$RELEASE" ]]; then
  installed=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["gitCommit"])' \
    "$RELEASE/DEPLOYED_VERSION.json")
  [[ "$installed" == "$GIT_SHA" ]] || { echo 'release id collision' >&2; exit 1; }
else
  mkdir -m 700 "$STAGING"
  git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" services/asg-capmesh \
    | tar -xf - -C "$STAGING" --strip-components=2
  (
    unset VIRTUAL_ENV
    cd "$STAGING"
    # The staging directory is atomically renamed below. An editable install
    # records that temporary path in site-packages and breaks as soon as the
    # rename completes, so immutable releases must contain a regular wheel
    # install whose imports are independent of the checkout path.
    "$UV" sync --frozen --no-dev --no-editable --link-mode=copy
    .venv/bin/python -m py_compile capmesh/*.py
    .venv/bin/python -c 'import capmesh'
    .venv/bin/python - "$GIT_SHA" "$RELEASE_ID" > DEPLOYED_VERSION.json <<'PY'
import json, sys
print(json.dumps({"gitCommit": sys.argv[1], "releaseId": sys.argv[2]}, sort_keys=True))
PY
  )
  chmod -R a-w "$STAGING"
  mv "$STAGING" "$RELEASE"
fi

# Validate the installed package from its final immutable path. This catches
# relocation-sensitive environments before current or launchd are changed.
"$RELEASE/.venv/bin/python" -c 'import capmesh'

ln -s "$RELEASE" "$NEXT_LINK"
mv -h -f "$NEXT_LINK" "$STATE/current"
[[ "$(readlink "$STATE/current")" == "$RELEASE" ]]

# Older local installs pinned the ambient asg-os checkout and the historical
# 3,936-row floor in this otherwise managed environment. Preserve credentials
# and unrelated settings while atomically migrating only the runtime-owned
# keys to the immutable current release and canonical health floor.
"$RELEASE/.venv/bin/python" - "$ENV_FILE" "$STATE/current" <<'PY'
import os
import pathlib
import sys

env_path = pathlib.Path(sys.argv[1]).resolve()
current = pathlib.Path(sys.argv[2])
managed = {
    "CAPMESH_SERVICE_DIR": str(current),
    "CAPMESH_PYTHON": str(current / ".venv/bin/python"),
    "CAPMESH_MIN_HEALTHY": "3000",
    "CAPMESH_READY_MIN_CAPABILITIES": "3000",
}
lines = env_path.read_text(encoding="utf-8").splitlines()
rendered = [line for line in lines if line.split("=", 1)[0] not in managed]
rendered.extend(f"{key}={value}" for key, value in managed.items())
temporary = env_path.with_name(f".{env_path.name}.capmesh-{os.getpid()}")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(rendered) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, env_path)
    os.chmod(env_path, 0o600)
    directory_fd = os.open(env_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    temporary.unlink(missing_ok=True)
PY

for label in ai.asg.capmesh-http ai.asg.capmesh-nonvoting-sync; do
  launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1 || true
  install -m 644 "$RELEASE/deploy/launchd/$label.plist" "$LAUNCH_DIR/$label.plist"
done

CAPMESH_ENV_FILE="$ENV_FILE" "$RELEASE/ops/sync-nonvoting-member.sh"
launchctl bootstrap "gui/$(id -u)" "$LAUNCH_DIR/ai.asg.capmesh-nonvoting-sync.plist"
launchctl bootstrap "gui/$(id -u)" "$LAUNCH_DIR/ai.asg.capmesh-http.plist"
launchctl kickstart -k "gui/$(id -u)/ai.asg.capmesh-http"

health=''
for _ in $(seq 1 15); do
  health=$(curl -fsS -m 3 http://127.0.0.1:17778/health/ready 2>/dev/null || true)
  if printf '%s' "$health" | "$RELEASE/.venv/bin/python" -c '
import json, sys
d=json.load(sys.stdin); c=d.get("catalog") or {}; t=d.get("topology") or {}
raise SystemExit(0 if d.get("status")=="ready" and c.get("capabilityCount",0)>=3000
                 and str(c.get("generation","")).startswith("sha256:")
                 and t.get("nodeRole")=="non-voting-raft" and t.get("writePolicy")=="primary-only" else 1)
' 2>/dev/null; then
    printf '[capmesh-macos-release] OK release=%s generation=%s count=%s\n' \
      "$RELEASE_ID" \
      "$(printf '%s' "$health" | "$RELEASE/.venv/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["catalog"]["generation"])')" \
      "$(printf '%s' "$health" | "$RELEASE/.venv/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["catalog"]["capabilityCount"])')"
    exit 0
  fi
  sleep 2
done
echo "local member failed readiness: $health" >&2
exit 1
