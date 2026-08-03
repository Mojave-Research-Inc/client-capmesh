#!/usr/bin/env bash
# capmesh-git-sync.sh — pull-only GitOps for the capmesh registry.
#
# This private Git registry is an auxiliary runtime-mirror transport, not the
# production authority. Canonical authored packages live in asg-os/plugins;
# the primary node is the sole runtime authority. Single-writer mirror model:
#   --push  : primary node only — commit local mirror changes + push.
#   (none)  : subordinate read replica — fetch + fast-forward + reingest. Never writes.
#
# All functions propagate: the writer commits adds/edits/DELETES; replicas fast-forward,
# which applies every change (including removals) to their work-tree, then reingest.
#
# SAFETY: work-tree is $HOME but the repo only tracks the two pathspecs below, and every
# work-tree-mutating op is SCOPED to them (checkout -- <paths>, clean -fd -- <paths>) or is
# a fast-forward (which only touches tracked files). There is NO unscoped reset --hard /
# clean, so nothing else in $HOME is ever touched.
set -uo pipefail

REPO_SSH="git@github.com:MRIHub/capmesh-registry.git"
GD="${CAPMESH_GIT_DIR:-$HOME/.local/state/capmesh-registry.gitdir}"
PATHS=( ".agents/skill-registry" ".codex/skills" )
MODE="replica"; [[ "${1:-}" == "--push" ]] && MODE="writer"
AUTHORITY_HOST="${CAPMESH_AUTHORITY_HOST:-the-authoritative-node}"
if [[ "$MODE" == writer && "$(hostname -s)" != "$AUTHORITY_HOST" ]]; then
  printf '[capmesh-git/writer] FATAL only %s may push the auxiliary registry mirror\n' "$AUTHORITY_HOST" >&2
  exit 1
fi

if   [[ -f "${CAPMESH_DEPLOY_KEY_PATH:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/deploy_key}" ]]; then KEY="${CAPMESH_DEPLOY_KEY_PATH:-${CAPMESH_STATE_DIR:-/secure/asg-capmesh}/deploy_key}"
elif [[ -f "$HOME/.ssh/capmesh_deploy"        ]]; then KEY="$HOME/.ssh/capmesh_deploy"
else KEY=""; fi
[[ -n "$KEY" ]] && export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=25"
TS="$(date +%Y-%m-%dT%H:%M:%S)"
log(){ echo "[$TS capmesh-git/$MODE] $*"; }

cd "$HOME" || { log "FATAL no HOME"; exit 1; }
export GIT_DIR="$GD" GIT_WORK_TREE="$HOME"

# --- bootstrap the detached git-dir on first run ---
if [[ ! -d "$GD" ]]; then
  mkdir -p "$(dirname "$GD")"
  git init -q -b main
  git config status.showUntrackedFiles no
  git config core.excludesFile /dev/null
  git config gc.auto 256
  git config user.name  "capmesh-autosync"
  git config user.email "capmesh-autosync@${CAPMESH_CORPORATE_EMAIL_DOMAIN:-example.com}"
  git remote add origin "${CAPMESH_GIT_ORIGIN:-$REPO_SSH}" 2>/dev/null || true
  if git fetch -q origin 2>/dev/null && git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    git reset -q --mixed origin/main            # index only — work-tree untouched
    git symbolic-ref HEAD refs/heads/main 2>/dev/null
    git branch -q --set-upstream-to=origin/main main 2>/dev/null || true
    log "bootstrapped ($(git rev-parse --short origin/main))"
  else
    log "FATAL central repo unreachable/empty on bootstrap"; exit 1
  fi
fi

before="$(git rev-parse -q HEAD 2>/dev/null)"

if [[ "$MODE" == "writer" ]]; then
  # capture adds/edits/DELETES within the tracked paths, then push (single writer: no conflicts)
  git add -A -f -- "${PATHS[@]}" 2>/dev/null
  git commit --no-verify -q -m "autosync writer $(hostname -s) $TS" >/dev/null 2>&1 || true
  git fetch -q origin main 2>/dev/null
  git merge -q --ff-only origin/main >/dev/null 2>&1        # absorb any direct-to-repo commits
  if git push -q origin HEAD:main 2>/dev/null; then
    after="$(git rev-parse -q HEAD)"
    [[ "$before" != "$after" ]] && log "pushed ($after)" || log "up-to-date"
  else
    log "WARN push failed (remote ahead? will retry next run)"; exit 1
  fi
else
  # REPLICA: fast-forward to the primary node's state, reingest. Only discard drift if actually
  # dirty (a full checkout of thousands of files every run is needless when clean).
  if ! git fetch -q origin main 2>/dev/null; then log "WARN fetch failed"; exit 1; fi
  if ! git diff --quiet -- "${PATHS[@]}" 2>/dev/null; then
    git checkout -q --force -- "${PATHS[@]}" 2>/dev/null     # scoped: revert local drift only
  fi
  if git merge -q --ff-only origin/main >/dev/null 2>&1; then
    git clean -q -fd -- "${PATHS[@]}" 2>/dev/null            # scoped: drop files deleted upstream
    after="$(git rev-parse -q HEAD)"
    if [[ "$before" != "$after" ]]; then
      sudo systemctl start asg-capability-mesh-refresh.service 2>/dev/null \
        || systemctl start asg-capability-mesh-refresh.service 2>/dev/null
      log "updated + reingest ($after)"
    else
      log "up-to-date ($after)"
    fi
  else
    log "WARN not fast-forwardable (replica diverged — manual review); left unchanged"; exit 1
  fi
fi
exit 0
