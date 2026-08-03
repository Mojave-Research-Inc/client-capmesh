#!/usr/bin/env bash

# macOS still ships Bash 3.2, while the production ops scripts intentionally use
# Bash 4+ features such as associative arrays and mapfile. Make an explicit,
# deterministic shell transition instead of letting syntax checks fail midway.
if (( BASH_VERSINFO[0] < 4 )); then
  for modern_bash in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$modern_bash" ]] && "$modern_bash" -c '(( BASH_VERSINFO[0] >= 4 ))'; then
      exec "$modern_bash" "$0" "$@"
    fi
  done
  printf 'test-ops.sh requires Bash >=4; install modern Bash with Homebrew\n' >&2
  exit 2
fi

set -euo pipefail
# Keep child scripts on the same Bash as this harness. Delegated/lean shells can
# otherwise invoke Homebrew Bash here but resolve `/usr/bin/env bash` to macOS
# Bash 3.2 in children, producing false syntax and missing-mapfile failures.
PATH="$(dirname "$BASH"):$PATH"
export PATH
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO="$(cd -P "$ROOT/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/capmesh-ops-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state/current"

for file in "$ROOT"/ops/*.sh "$REPO"/scripts/asg-capmesh-autodeploy.sh "$REPO"/scripts/install-asg-capmesh-tailnet-service.sh; do
  "$BASH" -n "$file"
done
for plist in "$ROOT"/deploy/launchd/*.plist; do plutil -lint "$plist" >/dev/null; done

# Strict IFS excludes spaces in the runtime installer, so loadavg must be
# split explicitly instead of relying on `read` field splitting.
grep -Fq 'load1="${loadavg%% *}"' "$ROOT/ops/install-safe-sqlite-runtime.sh"
! grep -Fq 'read -r load1 _ < /proc/loadavg' "$ROOT/ops/install-safe-sqlite-runtime.sh"

# The pinned runtime is immutable per build profile and must prove both the
# CLI and Python bindings can execute FTS5 before its symlink is activated.
grep -Fq 'CAPMESH_SQLITE_VERSION="3.53.3"' "$ROOT/ops/sqlite-runtime-release.sh"
grep -Fq 'CAPMESH_SQLITE_BUILD_TAG="capmesh2"' "$ROOT/ops/sqlite-runtime-release.sh"
grep -Fq -- '-DSQLITE_ENABLE_FTS5' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'CAPMESH_SQLITE_SOURCE_ID="d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"' "$ROOT/ops/sqlite-runtime-release.sh"
grep -Fq 'source "$SCRIPT_DIR/sqlite-runtime-release.sh"' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'source "$SERVICE_DIR/ops/sqlite-runtime-release.sh"' "$ROOT/ops/deploy-capmesh.sh"
[[ "$(grep -Fc 'CREATE VIRTUAL TABLE f USING fts5(x)' "$ROOT/ops/install-safe-sqlite-runtime.sh")" -ge 2 ]]
grep -Fq -- './configure --prefix="$RELEASE"' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'make DESTDIR="$destdir" install' "$ROOT/ops/install-safe-sqlite-runtime.sh"
! grep -Fq -- './configure --prefix="$staging"' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'SQLite pkg-config metadata does not embed final prefix' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq "Library runpath:" "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'contains deprecated DT_RPATH' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'release_created=1' "$ROOT/ops/install-safe-sqlite-runtime.sh"
grep -Fq 'git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" services/asg-capmesh' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" plugins' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'capability-roots/asg-os-plugins' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'tar -xf - -C "$PAYLOAD" --strip-components=2' "$ROOT/ops/deploy-capmesh.sh"
! grep -Fq 'rsync -a' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'COPYFILE_DISABLE=1 tar --no-xattrs' "$ROOT/ops/deploy-capmesh.sh"
[[ "$(grep -Fc 'worker readiness did not recover on port' "$ROOT/ops/deploy-capmesh.sh")" -eq 2 ]]
[[ "$(grep -Fc 'stable loopback service readiness did not recover on port 17778' "$ROOT/ops/deploy-capmesh.sh")" -eq 1 ]]
[[ "$(grep -Fc 'http://127.0.0.1:17778\${ready}' "$ROOT/ops/deploy-capmesh.sh")" -eq 1 ]]
grep -Fq '\"\$UV\" sync --frozen --no-dev --no-editable --link-mode=copy' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'sudo chown -R '\''$REMOTE_USER:$REMOTE_USER'\'' '\''$staging'\''' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq ".venv/bin/python -c 'import capmesh; print(capmesh.__file__)'" "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '\"\$UV\" sync --frozen --no-dev --link-mode=copy' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'unset VIRTUAL_ENV' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'python -m capmesh.lifecycle_cli --db' "$REPO/scripts/asg-capmesh-autodeploy.sh"

# Immutable releases resolve `..` inside releases/<id>, so every persistent
# state path emitted by the bootstrap installer must be absolute.
grep -Fq 'CAPMESH_DB=\$REMOTE_STATE/asg-capmesh.db' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'CAPMESH_STATE_DIR=\$REMOTE_STATE/state' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'CAPMESH_AUTHORITY_SIGNING_KEY=\$REMOTE_STATE/authority/capmesh-authority-ed25519.pem' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'ASGCODE_CAPMESH_AUTHORITY_PUBLIC_KEY=\$REMOTE_STATE/authority/capmesh-authority-ed25519.pub.pem' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'CAPMESH_AUTHORITY_TRUST_RECORD=\$REMOTE_STATE/authority/capmesh-authority-trust.v1.json' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'provision-local-service-client.sh' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'INSTALL_NODE_ROLE=' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'for key in CAPMESH_GOOGLE_CLIENT_ID CAPMESH_GOOGLE_CLIENT_SECRET CAPMESH_GOOGLE_REDIRECT_URI CAPMESH_GOOGLE_ALLOWED_EMAILS' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'never interpolate them into this script' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'apt-get install -y "\$@"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
! grep -Fq 'apt-get install -y "$@"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq -- '--db \$REMOTE_STATE/asg-capmesh.db serve-http' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
! grep -Fq -- '--db ../asg-capmesh.db' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'MAX_LOAD_PER_CPU="0.90"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'checking remote deployment headroom before any mutation' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'exceeds bootstrap limit' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'refusing to bootstrap from a dirty worktree' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'running locked local bootstrap gates' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'git -C "$REPO_DIR" archive --format=tar "$GIT_SHA" services/asg-capmesh' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'git -C "$REPO_DIR" archive --format=tar "$GIT_SHA" plugins' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'REMOTE_CODE/capability-roots/asg-os-plugins' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'DEPLOYED_VERSION.json' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'COPYFILE_DISABLE=1 tar --no-xattrs -C "$PAYLOAD"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'bootstrap failed; restoring previous immutable release' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'if [[ "$current" == "$failed" && -d "$previous" ]]' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'ROLLBACK failed=$failed previous=$previous' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq "if [[ -e '\$REMOTE_CODE' || -L '\$REMOTE_CODE' ]]; then readlink -f -- '\$REMOTE_CODE'" "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'remote "sudo tailscale serve --service=svc:capmesh' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'active=0; i=0; while [' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'asg-capability-mesh@\${port}.service' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
if grep -Eq "asg-capability-mesh@.*\\{.*CAPMESH_BASE_PORT.*\\.\\." "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"; then
  echo "bootstrap worker verification must not use dynamic brace expansion" >&2
  exit 1
fi

# Self-heal must enumerate enabled instances explicitly. Quoted systemd wildcards
# stop the running pool but cannot reliably start inactive instances again.
grep -Fq 'LOCK="${CAPMESH_SELFHEAL_LOCK:-$DB_DIR/.capmesh-selfheal.lock}"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'source "$ENV_FILE"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'systemctl list-unit-files "$pattern"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'sudo systemctl "$action" "${units[@]}"' "$ROOT/ops/selfheal-reingest.sh"
! grep -Fq 'systemctl start "$UNIT_GLOB"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'DB_UID="$(stat -c '\''%u'\'' "$DB")"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'DB_GID="$(stat -c '\''%g'\'' "$DB")"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'DB_MODE="$(stat -c '\''%a'\'' "$DB")"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'chown "$DB_UID:$DB_GID" "$DB"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'chmod "$DB_MODE" "$DB"' "$ROOT/ops/selfheal-reingest.sh"
! grep -Fq 'chown "$(id -un):$(id -gn)" "$DB"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'EXPECTED_COUNT="${CAPMESH_EXPECTED_COUNT:-}"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'does not match rehearsed=$EXPECTED_COUNT' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'READY_ATTEMPTS="${CAPMESH_SELFHEAL_READY_ATTEMPTS:-12}"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'MIN_HEALTHY="${CAPMESH_MIN_HEALTHY:-3000}"' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'CAPMESH_READY_MIN_CAPABILITIES=3000' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'CAPMESH_MIN_HEALTHY=3000' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'for ((ready_attempt=1; ready_attempt<=READY_ATTEMPTS; ready_attempt++)); do' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'ready_attempt=$ready_attempt' "$ROOT/ops/selfheal-reingest.sh"
! grep -Fq 'sleep 4' "$ROOT/ops/selfheal-reingest.sh"
grep -Fq 'install -o jason -g jason -m 750 "\$REMOTE_CODE/ops/selfheal-reingest.sh"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'install -o root -g root -m 750 "\$REMOTE_CODE/ops/health-watchdog.sh"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'sudo -u "$SERVICE_USER" -H "$STATE/selfheal-reingest.sh"' "$ROOT/ops/health-watchdog.sh"
grep -Fq 'systemctl start "${units[@]}"' "$ROOT/ops/health-watchdog.sh"
grep -Fq 'CAPMESH_EXPECTED_COUNT="\$rehearsed_count" "\$state/selfheal-reingest.sh"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'mv -Tf "\$selfheal_candidate" "\$state/selfheal-reingest.sh"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'mv -Tf "\$watchdog_candidate" "\$state/health-watchdog.sh"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '"\$release/ops/provision-local-service-client.sh"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'CAPMESH_OFFLINE_REHEARSAL=1 .venv/bin/python -m capmesh --db \"\$shadow\" ingest' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'authority-source-validation-runs-on-authoritative' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '*[!A-Za-z0-9._-]*) die "unsafe remote service user:' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'REMOTE_LOGIN_USER="${CAPMESH_REMOTE_LOGIN_USER:-$REMOTE_USER}"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '"$REMOTE_LOGIN_USER@$host"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'sudo -u '\''$REMOTE_USER'\'' -H env' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'systemctl enable --now asg-capability-mesh.target' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'asg-capability-mesh-backup.timer' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'asg-capability-mesh-watchdog.timer' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'asg-capability-mesh-nonvoting-sync.timer' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'Do not re-ingest a replica' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'source "$CLIENT_ENV_FILE"' "$ROOT/ops/serve-nonvoting-macos.sh"
grep -Fq 'content bundle hash changed in transit' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'UPDATE capabilities SET package_path = ?, entrypoint = ?, source_path = ?' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq '<string>/opt/homebrew/bin/bash</string>' "$ROOT/deploy/launchd/ai.asg.capmesh-nonvoting-sync.plist"
grep -Fq '<key>StartInterval</key><integer>3600</integer>' "$ROOT/deploy/launchd/ai.asg.capmesh-nonvoting-sync.plist"
grep -Fq '<string>"/Users/<user>"/.capmesh/current/ops/sync-nonvoting-member.sh</string>' "$ROOT/deploy/launchd/ai.asg.capmesh-nonvoting-sync.plist"
grep -Fq '<string>"/Users/<user>"/.capmesh/current/ops/serve-nonvoting-macos.sh</string>' "$ROOT/deploy/launchd/ai.asg.capmesh-http.plist"
grep -Fq 'git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" services/asg-capmesh' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"$UV" sync --frozen --no-dev --no-editable --link-mode=copy' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"$RELEASE/.venv/bin/python" -c '\''import capmesh'\''' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq 'mv -h -f "$NEXT_LINK" "$STATE/current"' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"CAPMESH_SERVICE_DIR": str(current)' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"CAPMESH_PYTHON": str(current / ".venv/bin/python")' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"CAPMESH_READY_MIN_CAPABILITIES": "3000"' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq 'os.replace(temporary, env_path)' "$ROOT/ops/install-nonvoting-macos-release.sh"
grep -Fq '"$SERVICE_DIR/ops/install-nonvoting-macos-release.sh" "$GIT_SHA" "$RELEASE_ID"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'pulling the final authoritative node catalog generation' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '"\$release/ops/backup-db.sh" "\$backup_candidate"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'systemctl disable --now asg-capmesh-parity.timer' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'install -o root -g root -m 750 "\$REMOTE_CODE/ops/backup-db.sh" "\$BACKUP_SCRIPT"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'synchronizing non-voting capability mesh from authoritative node' "$REPO/scripts/sweep-agent-ecosystem.sh"
grep -Fq 'CAPMESH_ENV_FILE="$CAPMESH_ENV_FILE" "$sync"' "$REPO/scripts/sweep-agent-ecosystem.sh"
grep -Fq 'authoritative capability mesh unchanged; use immutable deploy/self-heal' "$REPO/scripts/sweep-agent-ecosystem.sh"
grep -Fq 'missing safe SQLite runtime at $runtime/bin/sqlite3' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'missing immutable current symlink at $state/current' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'worker unit does not execute the immutable current release virtualenv' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'CAPMESH_REQUIRE_SAFE_SQLITE=1 is absent' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '.venv/bin/python -m capmesh.production_config --state' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq -- "--node-role '\$node_role'" "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'if [[ "$role" == primary ]]; then node_role=authoritative; else node_role=non-voting-raft; fi' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'CAPMESH_NODE_ROLE=$node_role' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'CAPMESH_AUTHORITY_URL=http://127.0.0.1:8000' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '.venv/bin/python -m capmesh.lifecycle_cli --db' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'CAPMESH_SIGNING_KEY_FILE=' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'bootstrap-authority-trust.sh' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'install -d -o '\''$REMOTE_USER'\'' -g '\''$REMOTE_USER'\'' -m 0700 \' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '"\$state/authority" "\$state/authority-client-export"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'authority-client-export/capmesh-authority-ed25519.pem' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'capmesh.production_config --state' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq -- '--node-role \"$INSTALL_NODE_ROLE\"' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'capmesh.lifecycle_cli --db' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'PINNED_RUNTIME_RELEASE="$REMOTE_STATE/runtime/sqlite-$CAPMESH_SQLITE_VERSION-$CAPMESH_SQLITE_BUILD_TAG"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'safe SQLite pkg-config metadata does not embed its immutable release prefix' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'safe SQLite ELF RUNPATH is' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq "Library runpath:" "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'Python SQLite FTS5 verification failed' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'safe SQLite CLI source id does not match the pinned $expected_version release' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'sudo bash -s -- '\''$REMOTE_STATE'\'' '\''$KEEP_RELEASES'\''' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'case "$old" in "$release_root"/*)' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq '[[ -d "$old" && ! -L "$old" ]] || exit 2' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'rm -rf -- "$old"' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'remote state must be an absolute path below /secure' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'worker pool ports/counts are outside safe bounds' "$ROOT/ops/deploy-capmesh.sh"
if CAPMESH_REMOTE_STATE="/tmp/not-secure" CAPMESH_ALLOW_DIRTY_DRY_RUN=1 \
  "$ROOT/ops/deploy-capmesh.sh" --dry-run >"$TMP/unsafe-state.out" 2>&1; then
  echo "unsafe remote state unexpectedly accepted" >&2
  exit 1
fi
grep -Fq 'remote state must be an absolute path below /secure' "$TMP/unsafe-state.out"
grep -Fq 'systemctl enable --now asg-capability-mesh.target asg-capability-mesh-refresh.timer asg-capability-mesh-checkpoint.timer asg-capability-mesh-backup.timer asg-capability-mesh-watchdog.timer' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'INSTALL_NODE_ROLE=non-voting-raft' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq 'asg-capability-mesh-nonvoting-sync.timer' "$REPO/scripts/install-asg-capmesh-tailnet-service.sh"
grep -Fq "awk '\$1 ~ /^asg-capability-mesh@[0-9]+\\.service\$/ {print \$1}'" "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'mv "$DB$suffix" "$previous$suffix"' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'stale SQLite sidecars remain at the live database path' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'rm -f -- "$old" "$old-wal" "$old-shm"' "$ROOT/ops/sync-nonvoting-member.sh"
grep -Fq 'the replica host' "$ROOT/ops/deploy-capmesh.sh"
grep -Fq 'AUTHORITY_HOST="${CAPMESH_AUTHORITY_HOST:-authoritative}"' "$ROOT/ops/git-sync.sh"
grep -Fq 'only %s may push the auxiliary registry mirror' "$ROOT/ops/git-sync.sh"
grep -Fq 'authoritative node is the sole runtime authority' "$ROOT/ops/git-sync.sh"

# Same-host service clients receive an explicit, protected HTTP contract. The
# helper must never emit the bearer and replicas must not retain a the authoritative node-local
# authority credential.
LOCAL_STATE="$TMP~/.capmesh/state"
mkdir -p "$LOCAL_STATE" "$TMP/local-bin"
printf 'CAPMESH_BEARER_TOKEN=test-only-secret\n' > "$LOCAL_STATE/capmesh.env"
cat > "$TMP/local-bin/getent" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$TMP/local-bin/setfacl" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$TMP/local-bin/chown" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 755 "$TMP/local-bin/"{getent,setfacl,chown}
sed "s|case \"\$STATE\" in /secure/\*)|case \"\$STATE\" in */secure/*)|" \
  "$ROOT/ops/provision-local-service-client.sh" > "$TMP/provision-local-service-client.sh"
chmod 755 "$TMP/provision-local-service-client.sh"
PATH="$TMP/local-bin:$PATH" "$TMP/provision-local-service-client.sh" "$LOCAL_STATE" authoritative 17778 \
  > "$TMP/local-client.out"
grep -Fxq 'CAPMESH_BASE_URL=http://127.0.0.1:8000' "$LOCAL_STATE/authoritative-local.env"
grep -Fxq 'CAPMESH_MCP_URL=http://127.0.0.1:8000/mcp' "$LOCAL_STATE/authoritative-local.env"
grep -Fxq 'CAPMESH_NODE_ROLE=authoritative' "$LOCAL_STATE/authoritative-local.env"
! grep -Fq 'test-only-secret' "$TMP/local-client.out"
PATH="$TMP/local-bin:$PATH" "$TMP/provision-local-service-client.sh" "$LOCAL_STATE" non-voting-raft 17778
[[ ! -e "$LOCAL_STATE/authoritative-local.env" ]]

# Exercise recovery with a fake systemd surface: the first two readiness probes
# fail, self-heal runs as the service user, and every enabled instance is started.
mkdir -p "$TMP/watchdog-state"
cat > "$TMP/watchdog-state/catalog-watchdog.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$TMP/watchdog-state/selfheal-reingest.sh" <<SH
#!/usr/bin/env bash
touch '$TMP/selfheal-ran'
SH
cat > "$TMP/bin/curl" <<SH
#!/usr/bin/env bash
count=0
[[ -r '$TMP/curl-count' ]] && count=\$(< '$TMP/curl-count')
count=\$((count + 1)); printf '%s' "\$count" > '$TMP/curl-count'
if (( count < 3 )); then printf 503; else printf 200; fi
SH
cat > "$TMP/bin/systemctl" <<SH
#!/usr/bin/env bash
case "\$1" in
  list-unit-files)
    printf '%s\n' \
      'asg-capability-mesh@.service linked enabled' \
      'asg-capability-mesh@17781.service enabled enabled' \
      'asg-capability-mesh@17782.service enabled enabled'
    ;;
  start) printf '%s\n' "\$@" > '$TMP/systemctl-start' ;;
  reload) exit 0 ;;
  *) exit 1 ;;
esac
SH
cat > "$TMP/bin/sudo" <<'SH'
#!/usr/bin/env bash
exec "${@: -1}"
SH
cat > "$TMP/bin/logger" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$TMP/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 755 "$TMP/watchdog-state/"*.sh "$TMP/bin/"{curl,systemctl,sudo,logger,sleep}
PATH="$TMP/bin:$PATH" CAPMESH_STATE_DIR="$TMP/watchdog-state" "$ROOT/ops/health-watchdog.sh"
[[ -e "$TMP/selfheal-ran" ]]
grep -Fxq 'asg-capability-mesh@17781.service' "$TMP/systemctl-start"
grep -Fxq 'asg-capability-mesh@17782.service' "$TMP/systemctl-start"
! grep -Fxq 'asg-capability-mesh@.service' "$TMP/systemctl-start"

# A dry-run must prove replica-first order without ever invoking SSH.
cat > "$TMP/bin/uv" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat > "$TMP/bin/ssh" <<SH
#!/usr/bin/env bash
touch '$TMP/ssh-was-called'
exit 99
SH
chmod 755 "$TMP/bin/uv" "$TMP/bin/ssh"
PATH="$TMP/bin:$PATH" ASG_OS_REPO_ROOT="$REPO" CAPMESH_ALLOW_DIRTY_DRY_RUN=1 \
  "$ROOT/ops/deploy-capmesh.sh" --dry-run > "$TMP/deploy.out" 2>&1
[[ ! -e "$TMP/ssh-was-called" ]]
replica_line="$(grep -n 'DRY-RUN: replica' "$TMP/deploy.out" | cut -d: -f1)"
primary_line="$(grep -n 'DRY-RUN: primary' "$TMP/deploy.out" | cut -d: -f1)"
(( replica_line < primary_line ))
grep -Fq 'HOST_PLAN+=("$host_spec")' "$ROOT/ops/deploy-capmesh.sh"
[[ "$(grep -Fc 'for host_spec in "${HOST_PLAN[@]}"' "$ROOT/ops/deploy-capmesh.sh")" -eq 4 ]]
[[ "$(grep -Fc 'done < <(resolve_hosts)' "$ROOT/ops/deploy-capmesh.sh")" -eq 1 ]]

# Catalog watchdog fixture covers integrity, FTS parity, sources, and freshness.
sqlite3 "$TMP/catalog.db" <<'SQL'
CREATE TABLE capabilities(uri TEXT, content_hash TEXT, approval_state TEXT, share_state TEXT);
CREATE TABLE capability_fts(uri TEXT);
CREATE TABLE capability_sources(source_path TEXT);
INSERT INTO capabilities VALUES('cap://test','sha256:x','published','not_shared');
INSERT INTO capability_fts VALUES('cap://test');
INSERT INTO capability_sources VALUES('/fixture/SKILL.md');
SQL
printf '{}\n' > "$TMP/ingest-audit.jsonl"
CAPMESH_DB="$TMP/catalog.db" CAPMESH_INGEST_AUDIT="$TMP/ingest-audit.jsonl" CAPMESH_MIN_HEALTHY=1 \
  "$ROOT/ops/catalog-watchdog.sh" | grep -q '"status":"ok"'

# Backups must use the explicitly selected SQLite CLI, remain readable after
# compression, never depend on a host-global `sqlite3` lookup, and never run
# the retention command with an empty file list (which makes `ls` enumerate
# the current directory and can feed unrelated paths to the delete loop).
grep -Fq 'xargs --null --no-run-if-empty ls -1t' "$ROOT/ops/backup-db.sh"
CAPMESH_DB="$TMP/catalog.db" CAPMESH_BACKUP_DIR="$TMP/backups" \
  CAPMESH_SQLITE_BIN="$(command -v sqlite3)" "$ROOT/ops/backup-db.sh" >/dev/null
backup="$(find "$TMP/backups" -type f -name 'asg-capmesh-*.db.gz' -print -quit)"
gzip -cd "$backup" > "$TMP/restored.db"
[[ "$(sqlite3 "$TMP/restored.db" 'PRAGMA quick_check;' | head -n 1)" == ok ]]

# Restic inventory returns short IDs and never prints repository credentials.
cat > "$TMP/bin/restic" <<'SH'
#!/usr/bin/env bash
case "$1" in
  snapshots) printf '[{"id":"1234567890abcdef","time":"2026-07-17T17:00:00Z","hostname":"the authoritative node","paths":["~/.capmesh/state"]}]\n' ;;
  *) exit 0 ;;
esac
SH
chmod 755 "$TMP/bin/restic"
printf 'RESTIC_REPOSITORY=/redacted\nRESTIC_PASSWORD_FILE=/redacted-password\n' > "$TMP/restic.env"
CAPMESH_RESTIC_TEST_MODE=1 CAPMESH_RESTIC_BIN="$TMP/bin/restic" CAPMESH_RESTIC_ENV_FILE="$TMP/restic.env" \
  "$ROOT/ops/restic-recovery-drill.sh" inventory | grep -q '^12345678'

# Canonicalization must reject traversal even though the textual prefix looks valid.
if CAPMESH_RESTIC_TEST_MODE=1 CAPMESH_RESTORE_STAGE_BASE="$TMP/stage" \
  CAPMESH_RESTIC_BIN="$TMP/bin/restic" CAPMESH_RESTIC_ENV_FILE="$TMP/restic.env" \
  "$ROOT/ops/restic-recovery-drill.sh" stage-restore --target "$TMP/stage/../../secure/escape" >/dev/null 2>&1; then
  echo 'restic traversal guard failed' >&2
  exit 1
fi

printf 'ops fixtures: PASS\n'
