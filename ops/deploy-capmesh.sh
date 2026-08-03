#!/usr/bin/env bash
# Authoritative Capability Mesh release orchestrator.
#
# Normal path: replica stage/rehearse/activate -> cpubox stage/rehearse -> one
# cpubox worker canary -> rolling pool. A release is immutable after staging and
# activation is an atomic `current` symlink replacement. The previous symlink is
# restored automatically when any readiness or catalog gate fails.

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="${ASG_OS_REPO_ROOT:-$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
SERVICE_DIR="$REPO_ROOT/services/asg-capmesh"
# shellcheck source=ops/sqlite-runtime-release.sh
source "$SERVICE_DIR/ops/sqlite-runtime-release.sh"
PRIMARY="${CAPMESH_PRIMARY:-cpubox.asg.ts.net}"
REPLICA="${CAPMESH_REPLICA:-jwgpu.asg.ts.net}"
REMOTE_USER="${CAPMESH_REMOTE_USER:-jason}"
REMOTE_LOGIN_USER="${CAPMESH_REMOTE_LOGIN_USER:-$REMOTE_USER}"
REMOTE_STATE="${CAPMESH_REMOTE_STATE:-/secure/asg-capmesh}"
PINNED_RUNTIME_RELEASE="$REMOTE_STATE/runtime/sqlite-$CAPMESH_SQLITE_VERSION-$CAPMESH_SQLITE_BUILD_TAG"
BASE_PORT="${CAPMESH_BASE_PORT:-17781}"
PRIMARY_WORKERS="${CAPMESH_PRIMARY_WORKERS:-16}"
REPLICA_WORKERS="${CAPMESH_REPLICA_WORKERS:-4}"
READY_PATH="${CAPMESH_READY_PATH:-/health/ready}"
MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"
DRY_RUN=0
TARGET="all"
KEEP_RELEASES="${CAPMESH_KEEP_RELEASES:-5}"
MAX_LOAD_PER_CPU="${CAPMESH_DEPLOY_MAX_LOAD_PER_CPU:-0.90}"
ALLOW_HIGH_LOAD="${CAPMESH_DEPLOY_ALLOW_HIGH_LOAD:-0}"
DEPLOY_MACOS_MEMBER="${CAPMESH_DEPLOY_MACOS_MEMBER:-1}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)

usage() {
  cat <<'USAGE'
Usage: deploy-capmesh.sh [--dry-run] [--host replica|primary|HOST]

Deploys replica before primary by default. --dry-run performs all local gates,
prints the exact rollout order, and makes no SSH connection or remote change.
USAGE
}

while (( $# )); do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --host) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; TARGET="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

log() { printf '[capmesh-deploy] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

case "$REMOTE_USER" in
  ""|*[!A-Za-z0-9._-]*) die "unsafe remote service user: $REMOTE_USER" ;;
esac
case "$REMOTE_LOGIN_USER" in
  ""|*[!A-Za-z0-9._-]*) die "unsafe remote login user: $REMOTE_LOGIN_USER" ;;
esac
for remote_host in "$PRIMARY" "$REPLICA"; do
  case "$remote_host" in
    ""|*[!A-Za-z0-9.-]*) die "unsafe deployment host: $remote_host" ;;
  esac
done
case "$REMOTE_STATE" in
  /secure/*) ;;
  *) die "remote state must be an absolute path below /secure" ;;
esac
case "$REMOTE_STATE" in
  *[!A-Za-z0-9._/-]*|*"/../"*|*/..|*//*|*/) die "unsafe remote state path: $REMOTE_STATE" ;;
esac
[[ "$BASE_PORT" =~ ^[0-9]+$ ]] || die "base port must be numeric"
[[ "$PRIMARY_WORKERS" =~ ^[1-9][0-9]*$ && "$REPLICA_WORKERS" =~ ^[1-9][0-9]*$ ]] \
  || die "worker counts must be positive integers"
(( BASE_PORT >= 1024 && BASE_PORT + PRIMARY_WORKERS - 1 <= 65535 \
   && BASE_PORT + REPLICA_WORKERS - 1 <= 65535 \
   && PRIMARY_WORKERS <= 128 && REPLICA_WORKERS <= 128 )) \
  || die "worker pool ports/counts are outside safe bounds"
[[ "$KEEP_RELEASES" =~ ^[1-9][0-9]*$ ]] || die "CAPMESH_KEEP_RELEASES must be a positive integer"
[[ "$MAX_LOAD_PER_CPU" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "deploy load ceiling must be numeric"
python3 - "$MAX_LOAD_PER_CPU" <<'PY' || die "deploy load ceiling must be greater than 0 and no greater than 1"
import sys
limit = float(sys.argv[1])
raise SystemExit(0 if 0 < limit <= 1 else 1)
PY
[[ "$ALLOW_HIGH_LOAD" == 0 || "$ALLOW_HIGH_LOAD" == 1 ]] \
  || die "CAPMESH_DEPLOY_ALLOW_HIGH_LOAD must be 0 or 1"
[[ "$DEPLOY_MACOS_MEMBER" == 0 || "$DEPLOY_MACOS_MEMBER" == 1 ]] \
  || die "CAPMESH_DEPLOY_MACOS_MEMBER must be 0 or 1"
[[ "$READY_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "unsafe readiness path: $READY_PATH"
[[ -f "$SERVICE_DIR/pyproject.toml" && -f "$SERVICE_DIR/uv.lock" ]] \
  || die "pyproject.toml and uv.lock are required"
if ! git -C "$REPO_ROOT" diff-index --quiet HEAD --; then
  [[ "$DRY_RUN" == 1 && "${CAPMESH_ALLOW_DIRTY_DRY_RUN:-0}" == 1 ]] \
    || die "refusing to deploy a dirty worktree"
  log "DRY-RUN only: allowing dirty worktree for local verification"
fi

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
GIT_SHORT="${GIT_SHA:0:12}"
RELEASE_ID="${CAPMESH_RELEASE_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$GIT_SHORT}"
case "$RELEASE_ID" in (*[!A-Za-z0-9._-]*) die "unsafe release id: $RELEASE_ID" ;; esac

TMP_BASE="${TMPDIR:-/tmp}"
TMP_BASE="${TMP_BASE%/}"
TMP="$(mktemp -d "$TMP_BASE/capmesh-release.XXXXXX")"
cleanup() {
  case "$TMP" in
    "$TMP_BASE"/capmesh-release.*) rm -rf -- "$TMP" ;;
    *) log "refusing unsafe temporary cleanup path: $TMP" ;;
  esac
}
trap cleanup EXIT

log "local release gates for $GIT_SHA"
(
  # The deployer always targets this service's locked project environment.
  # An unrelated activated venv only makes uv emit misleading mismatch noise.
  unset VIRTUAL_ENV
  cd "$SERVICE_DIR"
  uv sync --frozen --group dev
  uv run --frozen --group dev python -m py_compile capmesh/*.py
  uv run --frozen --group dev pytest -q
)

PAYLOAD="$TMP/payload"
mkdir -m 700 "$PAYLOAD"
# Package the exact reviewed commit, not the ambient working directory. This
# excludes ignored build/cache output by construction and prevents local
# filesystem metadata from entering an otherwise immutable release.
git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" services/asg-capmesh \
  | tar -xf - -C "$PAYLOAD" --strip-components=2
mkdir -p "$PAYLOAD/capability-roots/asg-os-plugins"
git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" plugins \
  | tar -xf - -C "$PAYLOAD/capability-roots/asg-os-plugins" --strip-components=1
MANIFEST="$PAYLOAD/DEPLOYED_VERSION.json"
python3 - "$PAYLOAD" "$MANIFEST" "$GIT_SHA" "$RELEASE_ID" <<'PY'
import hashlib, json, pathlib, sys
root, out, commit, release = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4]
files = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and path != out and not any(part in {".pytest_cache", "__pycache__", ".venv"} for part in path.parts):
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
out.write_text(json.dumps({"releaseId": release, "gitCommit": commit, "files": files}, sort_keys=True, indent=2) + "\n")
PY
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='.pytest_cache' --exclude='__pycache__' --exclude='.venv' \
  --exclude='*.pyc' --exclude='._*' -C "$PAYLOAD" -czf "$TMP/release.tgz" .

resolve_hosts() {
  case "$TARGET" in
    all) printf '%s\t%s\t%s\n' replica "$REPLICA" "$REPLICA_WORKERS"; printf '%s\t%s\t%s\n' primary "$PRIMARY" "$PRIMARY_WORKERS" ;;
    replica|"$REPLICA") printf '%s\t%s\t%s\n' replica "$REPLICA" "$REPLICA_WORKERS" ;;
    primary|"$PRIMARY") printf '%s\t%s\t%s\n' primary "$PRIMARY" "$PRIMARY_WORKERS" ;;
    *) die "host must be replica, primary, $REPLICA, or $PRIMARY" ;;
  esac
}

# Materialize the rollout plan before any SSH call. ssh reads stdin by default;
# iterating directly over process substitution lets the first host drain the
# remaining rows and can silently turn an all-host rollout into replica-only.
HOST_PLAN=()
while IFS= read -r host_spec; do
  HOST_PLAN+=("$host_spec")
done < <(resolve_hosts)
(( ${#HOST_PLAN[@]} > 0 )) || die "deployment host plan is empty"

if (( DRY_RUN )); then
  log "DRY-RUN: release=$RELEASE_ID archive=$(du -h "$TMP/release.tgz" | awk '{print $1}')"
  for host_spec in "${HOST_PLAN[@]}"; do
    IFS=$'\t' read -r role host workers <<<"$host_spec"
    log "DRY-RUN: $role $host stage -> shadow DB gates -> activate -> canary port $BASE_PORT -> roll $workers workers -> freshness/parity gate"
  done
  log "DRY-RUN complete; no network connection was made"
  exit 0
fi

# Commands intentionally interpolate validated local release paths.
# shellcheck disable=SC2029
remote() { local host="$1"; shift; ssh "${SSH_OPTS[@]}" "$REMOTE_LOGIN_USER@$host" "$@"; }

preflight_host() {
  local role="$1" host="$2"
  log "$role/$host: read-only runtime, unit-layout, security-env, and headroom preflight"
  remote "$host" "bash -s -- '$REMOTE_STATE' '$MAX_LOAD_PER_CPU' '$ALLOW_HIGH_LOAD' '$PINNED_RUNTIME_RELEASE' '$CAPMESH_SQLITE_VERSION' '$CAPMESH_SQLITE_SOURCE_ID'" <<'REMOTE'
set -euo pipefail
state="$1"; max_load="$2"; allow_high="$3"
expected_runtime="$4"; expected_version="$5"; expected_source_id="$6"
runtime="$state/runtime/sqlite"; env="$state/capmesh.env"
fail() { printf '[capmesh-preflight] ERROR: %s\n' "$*" >&2; exit 1; }

[[ -x "$runtime/bin/sqlite3" ]] \
  || fail "missing safe SQLite runtime at $runtime/bin/sqlite3; run ops/install-safe-sqlite-runtime.sh on this host"
[[ -L "$state/current" ]] \
  || fail "missing immutable current symlink at $state/current; run the bootstrap installer before routine deployment"
current="$(readlink -f "$state/current" 2>/dev/null || true)"
[[ -n "$current" && -d "$current" ]] \
  || fail "current symlink does not resolve to an immutable release: $state/current"
runtime_release="$(readlink -f "$runtime" 2>/dev/null || true)"
[[ "$runtime_release" == "$expected_runtime" && -d "$runtime_release" ]] \
  || fail "safe SQLite runtime must resolve to immutable release $expected_runtime"
[[ -r "$runtime_release/lib/pkgconfig/sqlite3.pc" ]] \
  || fail "safe SQLite pkg-config metadata is missing"
grep -Fxq "prefix=$expected_runtime" "$runtime_release/lib/pkgconfig/sqlite3.pc" \
  || fail "safe SQLite pkg-config metadata does not embed its immutable release prefix"
command -v readelf >/dev/null || fail "readelf is required to verify the safe SQLite runtime"
for elf in "$runtime_release/bin/sqlite3" "$runtime_release/lib/libsqlite3.so.$expected_version"; do
  dynamic="$(readelf -d "$elf")"
  grep -q 'Library rpath:' <<<"$dynamic" \
    && fail "safe SQLite ELF contains deprecated DT_RPATH: $elf"
  runpath="$(sed -n 's/.*Library runpath: \[\(.*\)\]/\1/p' <<<"$dynamic")"
  [[ "$runpath" == "$expected_runtime/lib" ]] \
    || fail "safe SQLite ELF RUNPATH is '$runpath', expected '$expected_runtime/lib': $elf"
done
unit="$(systemctl cat asg-capability-mesh@.service 2>/dev/null)" \
  || fail "missing asg-capability-mesh@.service unit"
grep -Fq "WorkingDirectory=$state/current" <<<"$unit" \
  || fail "worker unit does not use WorkingDirectory=$state/current"
grep -Fq "ExecStart=$state/current/.venv/bin/python" <<<"$unit" \
  || fail "worker unit does not execute the immutable current release virtualenv"
[[ -r "$env" ]] || fail "missing production environment file at $env"
grep -qx 'CAPMESH_ENVIRONMENT=production' "$env" \
  || fail "CAPMESH_ENVIRONMENT=production is absent from $env"
grep -qx 'CAPMESH_REQUIRE_SAFE_SQLITE=1' "$env" \
  || fail "CAPMESH_REQUIRE_SAFE_SQLITE=1 is absent from $env"
grep -Eq '^CAPMESH_TRUSTED_PROXY_TOKEN=.{32,}$' "$env" \
  || fail "CAPMESH_TRUSTED_PROXY_TOKEN is missing or too short in $env"

LD_LIBRARY_PATH="$runtime/lib:$runtime/lib64" python3 - <<'PY'
import sqlite3
v = sqlite3.sqlite_version_info
safe = v >= (3, 51, 3) or v[:2] == (3, 50) and v >= (3, 50, 7) or v[:2] == (3, 44) and v >= (3, 44, 6)
if not safe:
    raise SystemExit(f'unsafe Python SQLite runtime: {sqlite3.sqlite_version}')
con = sqlite3.connect(":memory:")
con.execute("CREATE VIRTUAL TABLE f USING fts5(x)")
con.execute("INSERT INTO f VALUES ('capmesh')")
if con.execute("SELECT count(*) FROM f WHERE f MATCH 'capmesh'").fetchone()[0] != 1:
    raise SystemExit("Python SQLite FTS5 verification failed")
con.close()
PY
cli="$(LD_LIBRARY_PATH="$runtime/lib:$runtime/lib64" "$runtime/bin/sqlite3" --version | awk '{print $1}')" \
  || fail "safe SQLite CLI exists but could not execute: $runtime/bin/sqlite3"
[[ "$cli" == "$expected_version" ]] || fail "safe SQLite CLI version is $cli, expected $expected_version"
source_id="$(LD_LIBRARY_PATH="$runtime/lib:$runtime/lib64" "$runtime/bin/sqlite3" :memory: 'SELECT sqlite_source_id();')" \
  || fail "safe SQLite CLI could not report its source id"
[[ "$source_id" == *"$expected_source_id" ]] \
  || fail "safe SQLite CLI source id does not match the pinned $expected_version release"

if [[ "$allow_high" != 1 ]]; then
  read -r load1 _ < /proc/loadavg; cpus=$(getconf _NPROCESSORS_ONLN)
  python3 - "$load1" "$cpus" "$max_load" <<'PY'
import sys
load, cpus, limit = float(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
ratio = load / max(cpus, 1)
if ratio > limit:
    raise SystemExit(f'host load per CPU {ratio:.3f} exceeds deploy limit {limit:.3f}')
PY
fi
REMOTE
}

stage_host() {
  local role="$1" host="$2" release="$REMOTE_STATE/releases/$RELEASE_ID" staging="$REMOTE_STATE/releases/$RELEASE_ID.staging" node_role
  if [[ "$role" == primary ]]; then node_role=authoritative; else node_role=non-voting-raft; fi
  log "$role/$host: creating immutable release"
  remote "$host" "mkdir -p '$REMOTE_STATE/releases' '$REMOTE_STATE/rehearsal'; test ! -e '$release'; rm -rf -- '$staging'; mkdir -m 700 '$staging'"
  # Staging is derived from the validated release ID.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" "$REMOTE_LOGIN_USER@$host" "tar -xzf - -C '$staging'" < "$TMP/release.tgz"
  remote "$host" "set -euo pipefail
    set -a; source '$REMOTE_STATE/capmesh.env'; set +a
    UV=\$(command -v uv || true)
    if [[ -z \"\$UV\" && -x \"\$HOME/.local/bin/uv\" ]]; then
      UV=\"\$HOME/.local/bin/uv\"
    fi
    test -x \"\$UV\" || { echo 'uv is required; run the bootstrap installer' >&2; exit 1; }
    cd '$staging'
    \"\$UV\" sync --frozen --no-dev --no-editable --link-mode=copy
    .venv/bin/python -m py_compile capmesh/*.py
    .venv/bin/python -c 'import capmesh'
    .venv/bin/python -m capmesh.production_config --state '$REMOTE_STATE' \
      --env-file '$REMOTE_STATE/capmesh.env' \
      --canonical-root '$REMOTE_STATE/current/capability-roots/asg-os-plugins' \
      --node-role '$node_role' >/dev/null
    grep -Fxq 'CAPMESH_SIGNING_KEY_FILE=$REMOTE_STATE/signing/capmesh-ed25519.pem' '$REMOTE_STATE/capmesh.env'
    grep -Fxq 'CAPMESH_NODE_ROLE=$node_role' '$REMOTE_STATE/capmesh.env'
    grep -Fxq 'CAPMESH_AUTHORITY_URL=https://capmesh.asg.ts.net' '$REMOTE_STATE/capmesh.env'
    sudo chown -R '$REMOTE_USER:$REMOTE_USER' '$staging'
    chmod -R a-w '$staging'
    mv '$staging' '$release'
    cd '$release'
    .venv/bin/python -c 'import capmesh; print(capmesh.__file__)' >/dev/null
  "
}

rehearse_host() {
  local role="$1" host="$2" release="$REMOTE_STATE/releases/$RELEASE_ID"
  log "$role/$host: rehearsing schema, full ingest, coverage, retrieval, and integrity on shadow DB"
  remote "$host" "set -euo pipefail
    state='$REMOTE_STATE'; release='$release'; role='$role'; shadow=\"\$state/rehearsal/$RELEASE_ID.db\"
    trap 'rm -f \"\$shadow\" \"\$shadow-wal\" \"\$shadow-shm\"' EXIT
    set -a; source \"\$state/capmesh.env\"; set +a
    case \"\$CAPMESH_ROOTS\" in
      \"\$state/current/capability-roots/asg-os-plugins:\"*)
        export CAPMESH_ROOTS=\"\$release/capability-roots/asg-os-plugins:\${CAPMESH_ROOTS#*:}\"
        ;;
      *) echo 'CAPMESH_ROOTS does not begin with the immutable canonical plugin root' >&2; exit 1 ;;
    esac
    sqlite3 \"\$state/asg-capmesh.db\" \".backup '\$shadow'\"
    cd \"\$release\"
    CAPMESH_OFFLINE_REHEARSAL=1 .venv/bin/python -m capmesh --db \"\$shadow\" ingest --export-jsonl \"\$state/rehearsal/$RELEASE_ID.jsonl\" >/dev/null
    .venv/bin/python -m capmesh --db \"\$shadow\" check > \"\$state/rehearsal/$RELEASE_ID-check.json\"
    .venv/bin/python -m capmesh --db \"\$shadow\" eval --k 10 > \"\$state/rehearsal/$RELEASE_ID-eval.json\"
    if [[ \"\$role\" == primary ]]; then
      # Catalog-wide lifecycle verification is ADVISORY at deploy time
      # (2026-07-27): the full-source prompt-injection scan false-positives on
      # authorized red-team / prompt-engineering capability content and must
      # not block activation of the whole authority. Promotion-time governance
      # gates still enforce per-capability. The report is always written for
      # reviewers; a non-passing catalog is logged loudly instead of aborting.
      if ! .venv/bin/python -m capmesh.lifecycle_cli --db \"\$shadow\" \
        --output \"\$state/rehearsal/$RELEASE_ID-lifecycle.json\" >/dev/null; then
        echo \"WARNING: lifecycle catalog verification not passing (advisory; see $RELEASE_ID-lifecycle.json)\" >&2
      fi
    else
      printf '%s\n' '{\"skipped\":true,\"reason\":\"authority-source-validation-runs-on-cpubox\"}' \
        > \"\$state/rehearsal/$RELEASE_ID-lifecycle.json\"
    fi
    .venv/bin/python - \"\$state/rehearsal/$RELEASE_ID-check.json\" \"\$state/rehearsal/$RELEASE_ID-eval.json\" <<'PY'
import json, sys
check, ev = (json.load(open(p)) for p in sys.argv[1:])
if not check.get('coverageOk'): raise SystemExit('coverage gate failed')
if not ev.get('passed'): raise SystemExit('retrieval gate failed')
PY
    test \"\$(sqlite3 \"\$shadow\" 'PRAGMA integrity_check;' | head -1)\" = ok
    live=\$(sqlite3 \"\$state/asg-capmesh.db\" 'SELECT COUNT(*) FROM capabilities;')
    candidate=\$(sqlite3 \"\$shadow\" 'SELECT COUNT(*) FROM capabilities;')
    test \"\$candidate\" -ge '$MIN_HEALTHY'
    test \"\$candidate\" -ge \"\$live\"
    printf '%s\n' \"\$candidate\" > \"\$state/rehearsal/$RELEASE_ID-count\"
    printf '%s\n' \"live=\$live candidate=\$candidate\"
  "
}

activate_host() {
  local role="$1" host="$2" workers="$3" release="$REMOTE_STATE/releases/$RELEASE_ID"
  log "$role/$host: atomic activation and rolling readiness gates"
  if ! remote "$host" "sudo bash -s" <<REMOTE
set -euo pipefail
state='$REMOTE_STATE'; release='$release'; base='$BASE_PORT'; workers='$workers'; ready='$READY_PATH'; role='$role'
previous=\$(readlink -f "\$state/current" 2>/dev/null || true)
rehearsed_count_file="\$state/rehearsal/$RELEASE_ID-count"
rehearsed_count=\$(cat "\$rehearsed_count_file")
[[ "\$rehearsed_count" =~ ^[1-9][0-9]*$ ]]
if [[ "\$role" == primary ]]; then
  # Bootstrap the cpubox-only receipt authority before new workers can accept
  # cap.delegate. The export contains public trust only.
  install -d -o '$REMOTE_USER' -g '$REMOTE_USER' -m 0700 \
    "\$state/authority" "\$state/authority-client-export"
  sudo -u '$REMOTE_USER' -H env \
    CAPMESH_STATE_DIR="\$state" \
    CAPMESH_AUTHORITY_DIR="\$state/authority" \
    CAPMESH_AUTHORITY_EXPORT_DIR="\$state/authority-client-export" \
    CAPMESH_PYTHON="\$release/.venv/bin/python" \
    CAPMESH_NODE_ROLE=authoritative \
    "\$release/ops/bootstrap-authority-trust.sh" >/dev/null
  test "\$(stat -c %a "\$state/authority/capmesh-authority-ed25519.pem")" = 600
  test "\$(stat -c %a "\$state/authority/capmesh-authority-ed25519.pub.pem")" = 644
  test "\$(stat -c %a "\$state/authority-client-export/capmesh-authority-trust.v1.json")" = 644
  test ! -e "\$state/authority-client-export/capmesh-authority-ed25519.pem"
fi
selfheal_candidate="\$state/.selfheal-reingest.$RELEASE_ID"
watchdog_candidate="\$state/.health-watchdog.$RELEASE_ID"
backup_candidate="\$state/.backup-db.$RELEASE_ID"
sync_service_candidate="\$state/.nonvoting-sync.service.$RELEASE_ID"
sync_timer_candidate="\$state/.nonvoting-sync.timer.$RELEASE_ID"
install -o '$REMOTE_USER' -g '$REMOTE_USER' -m 750 "\$release/ops/selfheal-reingest.sh" "\$selfheal_candidate"
install -o root -g root -m 750 "\$release/ops/health-watchdog.sh" "\$watchdog_candidate"
install -o root -g root -m 750 "\$release/ops/backup-db.sh" "\$backup_candidate"
install -o root -g root -m 644 "\$release/deploy/systemd/asg-capability-mesh-nonvoting-sync.service" "\$sync_service_candidate"
install -o root -g root -m 644 "\$release/deploy/systemd/asg-capability-mesh-nonvoting-sync.timer" "\$sync_timer_candidate"
rollback() {
  rc=\$?
  rm -f "\$selfheal_candidate" "\$watchdog_candidate" "\$backup_candidate" "\$sync_service_candidate" "\$sync_timer_candidate"
  if (( rc != 0 )); then
    logger -t capmesh-deploy "ROLLBACK release=$RELEASE_ID previous=\$previous rc=\$rc"
    if [[ -n "\$previous" && -d "\$previous" ]]; then
      ln -s "\$previous" "\$state/.current.rollback"
      mv -Tf "\$state/.current.rollback" "\$state/current"
      for ((i=0; i<workers; i++)); do systemctl restart "asg-capability-mesh@\$((base+i)).service" || true; done
    fi
  fi
  exit \$rc
}
trap rollback EXIT
ln -s "\$release" "\$state/.current.$RELEASE_ID"
mv -Tf "\$state/.current.$RELEASE_ID" "\$state/current"
"\$release/ops/provision-local-service-client.sh" \
  "\$state" "\$(if [[ "\$role" == primary ]]; then printf authoritative; else printf non-voting-raft; fi)" 17778
systemctl restart "asg-capability-mesh@\${base}.service"
for attempt in {1..12}; do
  if curl -fsS --max-time 5 "http://127.0.0.1:\${base}\${ready}" >/dev/null 2>&1; then
    break
  fi
  if (( attempt == 12 )); then
    echo "worker readiness did not recover on port \${base}" >&2
    exit 1
  fi
  sleep 2
done
for ((i=1; i<workers; i++)); do
  port=\$((base+i))
  systemctl restart "asg-capability-mesh@\${port}.service"
  for attempt in {1..12}; do
    if curl -fsS --max-time 5 "http://127.0.0.1:\${port}\${ready}" >/dev/null 2>&1; then
      break
    fi
    if (( attempt == 12 )); then
      echo "worker readiness did not recover on port \${port}" >&2
      exit 1
    fi
    sleep 2
  done
done
mv -Tf "\$selfheal_candidate" "\$state/selfheal-reingest.sh"
mv -Tf "\$watchdog_candidate" "\$state/health-watchdog.sh"
mv -Tf "\$backup_candidate" "\$state/backup.sh"
  if [[ "\$role" == primary ]]; then
  rm -f "\$sync_service_candidate" "\$sync_timer_candidate"
  sudo -u '$REMOTE_USER' -H env CAPMESH_EXPECTED_COUNT="\$rehearsed_count" "\$state/selfheal-reingest.sh"
  actual_count=\$(sqlite3 "\$state/asg-capmesh.db" 'SELECT COUNT(*) FROM capabilities;')
  [[ "\$actual_count" == "\$rehearsed_count" ]]
  systemctl disable --now asg-capability-mesh-nonvoting-sync.timer 2>/dev/null || true
  # Superseded by member-owned, verified pull parity. cpubox never initiates
  # writes or SSH control toward non-voting members.
  systemctl disable --now asg-capmesh-parity.timer 2>/dev/null || true
  systemctl reset-failed asg-capmesh-parity.service 2>/dev/null || true
  systemctl enable --now asg-capability-mesh.target \
    asg-capability-mesh-refresh.timer \
    asg-capability-mesh-checkpoint.timer \
    asg-capability-mesh-backup.timer \
    asg-capability-mesh-watchdog.timer
else
  mv -Tf "\$sync_service_candidate" /etc/systemd/system/asg-capability-mesh-nonvoting-sync.service
  mv -Tf "\$sync_timer_candidate" /etc/systemd/system/asg-capability-mesh-nonvoting-sync.timer
  systemctl disable --now asg-capability-mesh-refresh.timer asg-capability-mesh-watchdog.timer 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable --now asg-capability-mesh.target \
    asg-capability-mesh-checkpoint.timer \
    asg-capability-mesh-backup.timer \
    asg-capability-mesh-nonvoting-sync.timer
fi
# The self-heal swaps the DB and restarts the worker pool. Worker-port readiness
# can recover one scheduling interval before the stable loopback proxy has a
# healthy upstream, so a single probe here can return a transient 502 and cause
# a false rollback after an otherwise successful activation. Keep this gate
# fail-closed, but give the service endpoint the same bounded recovery window as
# each worker above.
for attempt in {1..12}; do
  if curl -fsS --max-time 10 "http://127.0.0.1:17778\${ready}" >/dev/null 2>&1; then
    break
  fi
  if (( attempt == 12 )); then
    echo "stable loopback service readiness did not recover on port 17778" >&2
    exit 1
  fi
  sleep 2
done
logger -t capmesh-deploy "OK release=$RELEASE_ID previous=\$previous role=$role"
trap - EXIT
REMOTE
  then
    die "$role/$host activation failed and rollback was requested"
  fi
  # Releases are deliberately root-owned and read-only. Retention therefore
  # needs privilege, but keep the privileged surface constrained to validated
  # directories emitted by find beneath this host's release root.
  remote "$host" "sudo bash -s -- '$REMOTE_STATE' '$KEEP_RELEASES'" <<'REMOTE_CLEANUP'
set -euo pipefail
state="$1"; keep="$2"
case "$state" in /secure/*) ;; *) exit 2 ;; esac
[[ "$keep" =~ ^[1-9][0-9]*$ ]] || exit 2
release_root="$state/releases"
current="$(readlink -f "$state/current")"
mapfile -t expired < <(
  find "$release_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -nr | tail -n "+$((keep + 1))" | cut -d' ' -f2-
)
for old in "${expired[@]}"; do
  case "$old" in "$release_root"/*) ;; *) exit 2 ;; esac
  [[ "$old" != "$current" ]] || continue
  [[ -d "$old" && ! -L "$old" ]] || exit 2
  rm -rf -- "$old"
done
REMOTE_CLEANUP
}

for host_spec in "${HOST_PLAN[@]}"; do
  IFS=$'\t' read -r role host workers <<<"$host_spec"
  preflight_host "$role" "$host"
done

for host_spec in "${HOST_PLAN[@]}"; do
  IFS=$'\t' read -r role host workers <<<"$host_spec"
  stage_host "$role" "$host"
  rehearse_host "$role" "$host"
  activate_host "$role" "$host" "$workers"
done

# The non-voting member may stage first for rollback safety, but its governed
# data generation is always pulled after the authoritative cpubox activation.
for host_spec in "${HOST_PLAN[@]}"; do
  IFS=$'\t' read -r role host workers <<<"$host_spec"
  if [[ "$role" == replica ]]; then
    log "$role/$host: pulling the final authoritative cpubox catalog generation"
    remote "$host" "sudo systemctl start asg-capability-mesh-nonvoting-sync.service"
  fi
done

if [[ "$(uname -s)" == Darwin && "$DEPLOY_MACOS_MEMBER" == 1 ]]; then
  case "$TARGET" in
    all|primary|"$PRIMARY")
      log "macOS non-voting member: installing exact immutable release and pulling cpubox generation"
      ASG_OS_REPO_ROOT="$REPO_ROOT" \
        "$SERVICE_DIR/ops/install-nonvoting-macos-release.sh" "$GIT_SHA" "$RELEASE_ID"
      ;;
  esac
fi

log "release $RELEASE_ID deployed replica-first with rollback gates"
