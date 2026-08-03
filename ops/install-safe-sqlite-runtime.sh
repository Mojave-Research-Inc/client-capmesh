#!/usr/bin/env bash
# Build the pinned SQLite runtime used by every Capmesh Python worker/checkpoint.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ops/sqlite-runtime-release.sh
source "$SCRIPT_DIR/sqlite-runtime-release.sh"
VERSION="$CAPMESH_SQLITE_VERSION"
BUILD_TAG="$CAPMESH_SQLITE_BUILD_TAG"
AUTOCONF_VERSION="$CAPMESH_SQLITE_AUTOCONF_VERSION"
ARCHIVE_SHA3="$CAPMESH_SQLITE_ARCHIVE_SHA3"
SOURCE_ID="$CAPMESH_SQLITE_SOURCE_ID"
URL="https://sqlite.org/2026/sqlite-autoconf-${AUTOCONF_VERSION}.tar.gz"
RUNTIME_ROOT="${CAPMESH_RUNTIME_ROOT:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/runtime}"
RELEASE="$RUNTIME_ROOT/sqlite-$VERSION-$BUILD_TAG"
CURRENT="$RUNTIME_ROOT/sqlite"
MAX_LOAD_PER_CPU="${CAPMESH_SQLITE_BUILD_MAX_LOAD_PER_CPU:-0.75}"
JOBS="${CAPMESH_SQLITE_BUILD_JOBS:-2}"

log() { printf '[capmesh-sqlite-runtime] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
case "$RUNTIME_ROOT" in /secure/*) ;; *) die "runtime root must be under /secure" ;; esac
[[ "$JOBS" =~ ^[1-4]$ ]] || die "CAPMESH_SQLITE_BUILD_JOBS must be 1..4"

verify_runtime() {
  local root="$1" expected_prefix="${2:-$1}" cli_result source_id elf dynamic runpath
  [[ "$(LD_LIBRARY_PATH="$root/lib:$root/lib64" "$root/bin/sqlite3" --version | awk '{print $1}')" == "$VERSION" ]] \
    || die "SQLite CLI at $root has the wrong version"
  cli_result="$(LD_LIBRARY_PATH="$root/lib:$root/lib64" "$root/bin/sqlite3" :memory: \
    "CREATE VIRTUAL TABLE f USING fts5(x); INSERT INTO f VALUES('capmesh'); SELECT count(*) FROM f WHERE f MATCH 'capmesh';")"
  [[ "$cli_result" == 1 ]] || die "SQLite CLI at $root lacks working FTS5 support"
  source_id="$(LD_LIBRARY_PATH="$root/lib:$root/lib64" "$root/bin/sqlite3" :memory: 'SELECT sqlite_source_id();')" \
    || die "SQLite CLI at $root could not report its source id"
  [[ "$source_id" == *"$SOURCE_ID" ]] \
    || die "SQLite CLI at $root has unexpected source id: $source_id"
  LD_LIBRARY_PATH="$root/lib:$root/lib64" python3 - "$VERSION" <<'PY'
import sqlite3
import sys

if sqlite3.sqlite_version != sys.argv[1]:
    raise SystemExit(f"Python loaded SQLite {sqlite3.sqlite_version}, expected {sys.argv[1]}")
con = sqlite3.connect(":memory:")
con.execute("CREATE VIRTUAL TABLE f USING fts5(x)")
con.execute("INSERT INTO f VALUES ('capmesh')")
if con.execute("SELECT count(*) FROM f WHERE f MATCH 'capmesh'").fetchone()[0] != 1:
    raise SystemExit("Python SQLite FTS5 verification failed")
con.close()
PY
  [[ -r "$root/lib/pkgconfig/sqlite3.pc" ]] \
    || die "SQLite pkg-config metadata is missing at $root"
  grep -Fxq "prefix=$expected_prefix" "$root/lib/pkgconfig/sqlite3.pc" \
    || die "SQLite pkg-config metadata does not embed final prefix $expected_prefix"
  for elf in "$root/bin/sqlite3" "$root/lib/libsqlite3.so.$VERSION"; do
    dynamic="$(readelf -d "$elf")"
    grep -q 'Library rpath:' <<<"$dynamic" \
      && die "SQLite ELF $elf contains deprecated DT_RPATH; expected DT_RUNPATH"
    runpath="$(sed -n 's/.*Library runpath: \[\(.*\)\]/\1/p' <<<"$dynamic")"
    [[ "$runpath" == "$expected_prefix/lib" ]] \
      || die "SQLite ELF $elf has RUNPATH '$runpath', expected '$expected_prefix/lib'"
  done
}

loadavg="$(< /proc/loadavg)"
load1="${loadavg%% *}"
cpus="$(getconf _NPROCESSORS_ONLN)"
python3 - "$load1" "$cpus" "$MAX_LOAD_PER_CPU" <<'PY' || die "host lacks safe build headroom"
import sys
load, cpus, limit = float(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
if load / max(cpus, 1) > limit:
    raise SystemExit(1)
PY

for command in awk grep python3 readelf sed; do command -v "$command" >/dev/null || die "$command is required"; done

if [[ -x "$RELEASE/bin/sqlite3" ]]; then
  verify_runtime "$RELEASE" "$RELEASE"
  ln -sfn "$RELEASE" "$CURRENT.next"
  mv -Tf "$CURRENT.next" "$CURRENT"
  log "runtime already verified at $RELEASE"
  exit 0
fi

for command in curl tar make cc; do command -v "$command" >/dev/null || die "$command is required"; done
mkdir -p "$RUNTIME_ROOT"
tmp=""
destdir=""
release_created=0
cleanup() {
  if (( release_created )); then
    case "$RELEASE" in
      "$RUNTIME_ROOT"/sqlite-"$VERSION"-"$BUILD_TAG") rm -rf -- "$RELEASE" ;;
    esac
  fi
  case "${tmp:-}" in "$RUNTIME_ROOT"/.sqlite-build.*) rm -rf -- "$tmp" ;; esac
  case "${destdir:-}" in "$RUNTIME_ROOT"/.sqlite-dest.*) rm -rf -- "$destdir" ;; esac
}
trap cleanup EXIT
tmp="$(mktemp -d "$RUNTIME_ROOT/.sqlite-build.XXXXXX")"
destdir="$(mktemp -d "$RUNTIME_ROOT/.sqlite-dest.XXXXXX")"

archive="$tmp/sqlite.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 20 -o "$archive" "$URL"
python3 - "$archive" "$ARCHIVE_SHA3" <<'PY'
import hashlib, pathlib, sys
actual = hashlib.sha3_256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit(f"SHA3-256 mismatch: {actual}")
PY
tar -xzf "$archive" -C "$tmp"
src="$tmp/sqlite-autoconf-$AUTOCONF_VERSION"
# Configure for the immutable final prefix, then divert installation through
# DESTDIR. Configuring directly against a temporary staging prefix embeds that
# deleted path in ELF RUNPATH and sqlite3.pc, leaving the artifact dependent on
# LD_LIBRARY_PATH and unsuitable for promotion to another compatible host.
staging="$destdir$RELEASE"
(
  cd "$src"
  CFLAGS='-O2 -fPIC -DSQLITE_ENABLE_FTS5' ./configure --prefix="$RELEASE" --disable-static --enable-shared
  make -j "$JOBS"
  make DESTDIR="$destdir" install
)
verify_runtime "$staging" "$RELEASE"
chmod -R a-w "$staging"
[[ ! -e "$RELEASE" ]] || die "immutable SQLite release appeared during build: $RELEASE"
mv -T "$staging" "$RELEASE"
release_created=1
verify_runtime "$RELEASE" "$RELEASE"
release_created=0
ln -sfn "$RELEASE" "$CURRENT.next"
mv -Tf "$CURRENT.next" "$CURRENT"
log "installed and verified SQLite $VERSION at $CURRENT"
