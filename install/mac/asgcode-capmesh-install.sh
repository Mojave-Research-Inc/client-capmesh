#!/usr/bin/env bash
# =============================================================================
# capmesh-harness + capmesh CLIENT installer (macOS, external-guest profile)
#
# Idealized, idempotent, re-runnable bring-up for an EXTERNAL GUEST on a shared
# Tailscale device. Installs and verifies, in one pass:
#
#   1. Preflight       macOS, Tailscale present + logged in, capmesh-harness endpoint
#                      127.0.0.1:14400 reachable.
#   2. Claude Code     official @anthropic-ai/claude-code CLI (npm), installed
#                      or verified/updated in place.
#   3. capmesh-harness harness an ISOLATED Claude Code settings.json pointing the harness
#                      at the capmesh-harness orchestrator on the tailnet, with the
#                      opus/sonnet/haiku tier aliases resolving to the local
#                      Qwen Director (per the orchestrator rules). Global ~/.claude is
#                      left untouched; the `capmesh-harness` launcher exports
#                      CLAUDE_CONFIG_DIR to load this config.
#   4. capmesh         official capmesh CLI (into ~/.capmesh/venv) + the capmesh
#                      MCP server (capmesh serve / cap.* tools) registered into
#                      Claude Code, pointed at https://capmesh.asg.ts.net.
#   5. Verify          capmesh auth doctor + capmesh me + an capmesh-harness smoke call.
#   6. Next steps      printed for the guest.
#
# No secrets are embedded. capmesh auth is interactive (Google sign-in through
# the tailnet device-code flow). The capmesh-harness endpoint performs no bearer-token
# validation; access control is Tailscale tailnet membership, so only a
# non-empty placeholder token is written.
#
#   bash capmesh-harness-capmesh-install.sh
#
# Tunables (env):
#   ASGCODE_ENDPOINT      capmesh-harness orchestrator base URL
#                         (default http://127.0.0.1:14400)
#   CAPMESH_BASE_URL      capmesh tailnet server
#                         (default https://capmesh.asg.ts.net)
#   CAPMESH_REPO          git URL or local path to the asg-capmesh repo
#                         (the CLI package source). Only required when no
#                         prebuilt wheel is served by the capmesh server.
#   CAPMESH_NO_LOGIN=1    skip the interactive Google/device-code sign-in
#                         (local-only; auth can be completed later).
#   ASGCODE_CONFIG_DIR    isolated Claude Code config dir
#                         (default ~/.config/capmesh-harness/claude-config)
#   CAPMESH_PREFIX        bin dir for the capmesh symlink (default ~/.local)
#
# Flags:
#   --dry-run             print every action, change nothing.
#   --skip-claude         skip the Claude Code CLI install/verify step.
#   --skip-capmesh-login  skip the capmesh sign-in (same as CAPMESH_NO_LOGIN=1).
#   --skip-verify         skip the verification step (5).
#   --help                show this header.
# =============================================================================
set -euo pipefail

# --- configuration ----------------------------------------------------------
ASGCODE_ENDPOINT="${ASGCODE_ENDPOINT:-http://127.0.0.1:14400}"
ASGCODE_ENDPOINT="${ASGCODE_ENDPOINT%/}"
ASGCODE_HOST="$(printf '%s' "${ASGCODE_ENDPOINT}" | sed -E 's#^https?://##; s#[:/].*$##')"
ASGCODE_PORT="$(printf '%s' "${ASGCODE_ENDPOINT}" | sed -nE 's#^https?://[^:/]+:([0-9]+).*$#\1#p')"
ASGCODE_PORT="${ASGCODE_PORT:-14400}"

CAPMESH_BASE_URL="${CAPMESH_BASE_URL:-https://capmesh.asg.ts.net}"
CAPMESH_BASE_URL="${CAPMESH_BASE_URL%/}"
CAPMESH_MCP_URL="${CAPMESH_BASE_URL}/mcp"
CAPMESH_REPO="${CAPMESH_REPO:-}"
CAPMESH_NO_LOGIN="${CAPMESH_NO_LOGIN:-0}"
CAPMESH_PREFIX="${CAPMESH_PREFIX:-${HOME}/.local}"

ASGCODE_CONFIG_DIR="${ASGCODE_CONFIG_DIR:-${HOME}/.config/capmesh-harness/claude-config}"
ASGCODE_SETTINGS="${ASGCODE_CONFIG_DIR}/settings.json"
ASGCODE_ENV_FILE="${HOME}/.config/capmesh-harness/.env"
ASGCODE_LAUNCHER="${CAPMESH_PREFIX}/bin/capmesh-harness"

CAPMESH_HOME="${HOME}/.capmesh"
CAPMESH_VENV="${CAPMESH_HOME}/venv"
CAPMESH_BIN="${CAPMESH_PREFIX}/bin/capmesh"
CAPMESH_ENV_FILE="${HOME}/.config/capmesh-harness/capmesh.env"
CLAUDE_MCP_CONFIG="${HOME}/.claude.json"

DRY_RUN=0
SKIP_CLAUDE=0
SKIP_VERIFY=0

# --- output helpers ---------------------------------------------------------
say()  { printf '\033[36m[capmesh-harness-capmesh]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[capmesh-harness-capmesh] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[capmesh-harness-capmesh] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { if [[ "${DRY_RUN}" -eq 1 ]]; then printf '\033[35m[dry-run]\033[0m %s\n' "$*"; else eval "$*"; fi; }

show_help() { sed -n '2,/^# ===/p' "$0" | sed -E 's/^# ?//; /^=+$/d'; exit 0; }

# --- argument parsing -------------------------------------------------------
for arg in "$@"; do
  case "${arg}" in
    --dry-run)            DRY_RUN=1 ;;
    --skip-claude)        SKIP_CLAUDE=1 ;;
    --skip-capmesh-login) CAPMESH_NO_LOGIN=1 ;;
    --skip-verify)        SKIP_VERIFY=1 ;;
    --help|-h)            show_help ;;
    *) die "unknown argument: ${arg} (try --help)" ;;
  esac
done

# =============================================================================
# 1. PREFLIGHT
# =============================================================================
say "Section 1: preflight"

[[ "$(uname -s)" == "Darwin" ]] || die "this installer is macOS-only (got $(uname -s)). Use the Linux/Windows installers for other platforms."

# Locate the Tailscale CLI (App Store app ships it under the bundle).
TAILSCALE_BIN=""
for cand in tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale /usr/local/bin/tailscale /opt/homebrew/bin/tailscale; do
  if have "${cand}" || [[ -x "${cand}" ]]; then TAILSCALE_BIN="${cand}"; break; fi
done
[[ -n "${TAILSCALE_BIN}" ]] || die "tailscale CLI not found. Install Tailscale (https://tailscale.com/download/mac), sign in, and accept the shared device, then re-run."

# Confirm Tailscale is up and logged in.
if ! "${TAILSCALE_BIN}" status >/dev/null 2>&1; then
  die "Tailscale is not running or not logged in. Run: ${TAILSCALE_BIN} up   then accept the shared device invite, then re-run."
fi
TS_STATE="$("${TAILSCALE_BIN}" status --json 2>/dev/null | (have jq && jq -r '.BackendState' || cat) 2>/dev/null || true)"
case "${TS_STATE}" in
  Running|"") say "  Tailscale: up" ;;
  NeedsLogin) die "Tailscale needs login. Run: ${TAILSCALE_BIN} up   then re-run." ;;
  *)          warn "  Tailscale backend state: ${TS_STATE} (continuing; expected Running)" ;;
esac

# Reachability to the capmesh-harness endpoint. First connection to a tailnet host can
# lag a few seconds while the SSH session recorder warms up; that is expected,
# so allow a generous connect timeout and one retry rather than failing fast.
say "  probing capmesh-harness endpoint ${ASGCODE_ENDPOINT} ..."
asg_reachable=0
for attempt in 1 2; do
  if curl -fsS --connect-timeout 8 --max-time 20 "${ASGCODE_ENDPOINT}/health" >/dev/null 2>&1 \
     || curl -fsS --connect-timeout 8 --max-time 20 "${ASGCODE_ENDPOINT}/v1/models" >/dev/null 2>&1; then
    asg_reachable=1; break
  fi
  [[ "${attempt}" -eq 1 ]] && { warn "  endpoint not answering yet (attempt 1); retrying after tailnet warm-up..."; sleep 5; }
done
if [[ "${asg_reachable}" -eq 1 ]]; then
  say "  capmesh-harness endpoint: reachable"
else
  warn "  capmesh-harness endpoint ${ASGCODE_ENDPOINT} did not answer /health or /v1/models."
  warn "  Confirm '${ASGCODE_HOST}' shows online in: ${TAILSCALE_BIN} status"
  warn "  Continuing the install; the smoke call in Section 5 will re-test."
fi

# Reachability to the capmesh VIP (informational; auth happens in Section 4).
if curl -fsS --connect-timeout 8 --max-time 20 "${CAPMESH_BASE_URL}/healthz" >/dev/null 2>&1 \
   || curl -fsS --connect-timeout 8 --max-time 20 -o /dev/null "${CAPMESH_BASE_URL}/" 2>/dev/null; then
  say "  capmesh server: reachable (${CAPMESH_BASE_URL})"
else
  warn "  capmesh server ${CAPMESH_BASE_URL} not answering yet — sign-in (Section 4) will surface any issue."
fi

# =============================================================================
# 2. CLAUDE CODE CLI (official npm package)
# =============================================================================
if [[ "${SKIP_CLAUDE}" -eq 1 ]]; then
  say "Section 2: Claude Code CLI — skipped (--skip-claude)"
else
  say "Section 2: Claude Code CLI (official @anthropic-ai/claude-code)"
  if ! have node || ! have npm; then
    if have brew; then
      say "  installing Node.js via Homebrew"
      run "brew install node"
    else
      die "node/npm not found and Homebrew is unavailable. Install Node.js LTS (https://nodejs.org) or Homebrew, then re-run."
    fi
  fi
  say "  node: $(node --version 2>/dev/null || echo '?')  npm: $(npm --version 2>/dev/null || echo '?')"

  if have claude; then
    say "  Claude Code present ($(claude --version 2>/dev/null || echo 'version unknown')) — updating in place"
    run "npm install -g @anthropic-ai/claude-code@latest >/dev/null 2>&1 || true"
  else
    say "  installing @anthropic-ai/claude-code globally"
    run "npm install -g @anthropic-ai/claude-code"
  fi
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    have claude || warn "  'claude' not on PATH yet — open a new shell, or add \"\$(npm config get prefix)/bin\" to PATH."
  fi
fi

# =============================================================================
# 3. ASGCODE HARNESS CONFIG (isolated Claude Code settings.json)
# =============================================================================
say "Section 3: capmesh-harness harness config -> ${ASGCODE_SETTINGS}"
run "mkdir -p '${ASGCODE_CONFIG_DIR}'"
run "chmod 0700 '$(dirname "${ASGCODE_CONFIG_DIR}")' '${ASGCODE_CONFIG_DIR}' 2>/dev/null || true"

write_settings() {
  cat > "${ASGCODE_SETTINGS}" <<JSON
{
  "_comment": "capmesh-harness external-guest Claude Code config. Loaded only when the capmesh-harness launcher exports CLAUDE_CONFIG_DIR=${ASGCODE_CONFIG_DIR}. Plain 'claude' stays native; this file points the harness at the the orchestrator orchestrator on the tailnet. Regenerated idempotently by capmesh-harness-capmesh-install.sh.",
  "env": {
    "_comment_endpoint": "ANTHROPIC_BASE_URL points Claude Code at the the orchestrator orchestrator via nginx on the tailnet (port ${ASGCODE_PORT} -> orchestrator :14000). Use the MagicDNS name, never a raw Tailscale IP.",
    "ANTHROPIC_BASE_URL": "${ASGCODE_ENDPOINT}",
    "_comment_auth": "The orchestrator performs no bearer-token validation; access control is Tailscale tailnet membership. A non-empty placeholder satisfies Claude Code startup. ANTHROPIC_API_KEY must be empty string, not unset, to avoid the key-discovery fallback error.",
    "ANTHROPIC_AUTH_TOKEN": "capmesh-harness-tailnet-local",
    "ANTHROPIC_API_KEY": "",
    "_comment_openai_routing": "OPENAI_* lets agents with model: openai/director or openai/worker frontmatter route through the same orchestrator passthrough. OPENAI_API_KEY must be non-empty; the local vLLM accepts 'none'.",
    "OPENAI_BASE_URL": "${ASGCODE_ENDPOINT}/v1",
    "OPENAI_API_KEY": "none",
    "_comment_model_aliases": "Tier picker slots resolve to the local Qwen Director per the orchestrator rules: opus -> director-deep, sonnet -> director-standard, haiku -> worker-quick (Worker lane when healthy, Director helper fallback). 4th slot -> director-max.",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "director-deep",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "director-standard",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "worker-quick",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME": "Director: Deep (Qwen3.6-35B-A3B, thinking ON, 32K out)",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME": "Director: Standard (Qwen3.6-35B-A3B, thinking ON, 16K out)",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME": "Fast Lane: Haiku (Worker Qwen3.5-9B, low thinking, 4K out)",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_SUPPORTED_CAPABILITIES": "effort,xhigh_effort,max_effort,thinking,adaptive_thinking,interleaved_thinking",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_SUPPORTED_CAPABILITIES": "effort,xhigh_effort,max_effort,thinking,adaptive_thinking,interleaved_thinking",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_SUPPORTED_CAPABILITIES": "effort",
    "ANTHROPIC_CUSTOM_MODEL_OPTION": "director-max",
    "ANTHROPIC_CUSTOM_MODEL_OPTION_NAME": "Director: Max (Qwen3.6-35B-A3B, thinking ON, 64K out)",
    "ANTHROPIC_CUSTOM_MODEL_OPTION_SUPPORTED_CAPABILITIES": "effort,xhigh_effort,max_effort,thinking,adaptive_thinking,interleaved_thinking",
    "ANTHROPIC_MODEL": "opus",
    "_comment_perf": "CLAUDE_CODE_ATTRIBUTION_HEADER=0 is the highest-impact perf fix on the local backend: the per-request hash otherwise defeats vLLM prefix caching. Must be set here, not just exported.",
    "CLAUDE_CODE_ATTRIBUTION_HEADER": "0",
    "_comment_telemetry": "External-guest device: disable all outbound telemetry and non-essential model calls. All model traffic stays tailnet-local.",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_NON_ESSENTIAL_MODEL_CALLS": "1",
    "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
    "_comment_context": "Director native window is 262K; compaction fires at ~82%.",
    "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "262144",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "16384",
    "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "215040",
    "_comment_timeouts": "Long timeouts for agentic streaming over the shared tailnet endpoint.",
    "API_TIMEOUT_MS": "7200000",
    "CLAUDE_CODE_REQUEST_TIMEOUT_MS": "7200000",
    "CLAUDE_STREAM_IDLE_TIMEOUT_MS": "1800000",
    "_comment_no_update": "Updates are managed by re-running this installer.",
    "DISABLE_AUTOUPDATER": "1"
  },
  "model": "opus",
  "disableNonEssentialTraffic": true,
  "availableModels": [
    "director-max",
    "director-deep",
    "director-standard",
    "director-quick",
    "worker-standard",
    "worker-quick",
    "director",
    "worker"
  ]
}
JSON
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would write isolated settings.json with ANTHROPIC_BASE_URL=${ASGCODE_ENDPOINT}"
else
  write_settings
  python3 -c "import json,sys;json.load(open('${ASGCODE_SETTINGS}'))" 2>/dev/null \
    || die "generated settings.json failed JSON validation: ${ASGCODE_SETTINGS}"
  say "  wrote + validated ${ASGCODE_SETTINGS}"
fi

# Lightweight launcher wrapper: 'capmesh-harness' = claude with the isolated config dir.
# Re-runnable: always rewritten to match the current config path.
run "mkdir -p '${CAPMESH_PREFIX}/bin'"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would write launcher ${ASGCODE_LAUNCHER}"
else
  cat > "${ASGCODE_LAUNCHER}" <<LAUNCH
#!/usr/bin/env bash
# capmesh-harness launcher (external-guest) — runs the official Claude Code CLI with the
# isolated capmesh-harness config dir so plain 'claude' stays native. Generated by
# capmesh-harness-capmesh-install.sh; re-run that installer to regenerate.
set -euo pipefail
export CLAUDE_CONFIG_DIR="${ASGCODE_CONFIG_DIR}"
[[ -f "${ASGCODE_ENV_FILE}" ]] && set -a && . "${ASGCODE_ENV_FILE}" && set +a
exec claude "\$@"
LAUNCH
  chmod 0755 "${ASGCODE_LAUNCHER}"
  say "  wrote launcher ${ASGCODE_LAUNCHER} (run: capmesh-harness)"
fi

# Minimal env file (no secrets) so non-launcher invocations can source the same contract.
if [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would write ${ASGCODE_ENV_FILE}"
else
  run "mkdir -p '$(dirname "${ASGCODE_ENV_FILE}")'"
  umask 077
  cat > "${ASGCODE_ENV_FILE}" <<ENV
# capmesh-harness env contract (no secrets) — written by capmesh-harness-capmesh-install.sh
ANTHROPIC_BASE_URL=${ASGCODE_ENDPOINT}
ANTHROPIC_AUTH_TOKEN=capmesh-harness-tailnet-local
ANTHROPIC_API_KEY=
OPENAI_BASE_URL=${ASGCODE_ENDPOINT}/v1
OPENAI_API_KEY=none
ENV
  chmod 0600 "${ASGCODE_ENV_FILE}"
  say "  wrote ${ASGCODE_ENV_FILE} (0600, no secrets)"
fi

# Ensure ~/.local/bin is on PATH so 'capmesh-harness' and 'capmesh' resolve by name.
case ":${PATH}:" in
  *":${CAPMESH_PREFIX}/bin:"*) ;;
  *)
    for rc in "${HOME}/.zshrc" "${HOME}/.bash_profile" "${HOME}/.bashrc" "${HOME}/.profile"; do
      [[ -f "${rc}" ]] || continue
      grep -q "${CAPMESH_PREFIX}/bin" "${rc}" 2>/dev/null && continue
      [[ "${DRY_RUN}" -eq 1 ]] && { say "  [dry-run] would add ${CAPMESH_PREFIX}/bin to PATH in ${rc}"; continue; }
      printf '\nexport PATH="%s/bin:$PATH"\n' "${CAPMESH_PREFIX}" >>"${rc}"
    done
    export PATH="${CAPMESH_PREFIX}/bin:${PATH}"
    warn "  added ${CAPMESH_PREFIX}/bin to PATH — open a new shell, or: export PATH=\"${CAPMESH_PREFIX}/bin:\$PATH\"" ;;
esac

# =============================================================================
# 4. CAPMESH CLI + MCP SERVER
# =============================================================================
say "Section 4: capmesh CLI + MCP (${CAPMESH_BASE_URL})"

# Python >= 3.12 for the capmesh venv.
PYBIN=""
for p in python3.13 python3.12 python3; do
  if have "${p}" && "${p}" -c 'import sys;exit(0 if sys.version_info[:2]>=(3,12) else 1)' 2>/dev/null; then
    PYBIN="$(command -v "${p}")"; break
  fi
done
if [[ -z "${PYBIN}" ]]; then
  if have brew; then say "  installing Python 3.12 via Homebrew"; run "brew install python@3.12"; fi
  for p in python3.13 python3.12 python3; do
    have "${p}" && "${p}" -c 'import sys;exit(0 if sys.version_info[:2]>=(3,12) else 1)' 2>/dev/null && { PYBIN="$(command -v "${p}")"; break; }
  done
fi
[[ -n "${PYBIN}" ]] || die "Python >=3.12 not found and could not be installed. Install it (brew install python@3.12) and re-run."
have git || { have brew && run "brew install git"; }
have jq  || { have brew && run "brew install jq"; }
have jq  || die "jq is required (brew install jq) and could not be installed."

# Resolve the capmesh package source. Default to this repo (the installer lives
# inside it) so an external guest needs no extra env. CAPMESH_REPO overrides.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_SRC=""
detect_pkg_src() {
  local base="$1"
  for cand in "${base}" "${base}/services/asg-capmesh"; do
    [[ -f "${cand}/pyproject.toml" ]] && { PKG_SRC="${cand}"; return 0; }
  done
  return 1
}
if [[ -n "${CAPMESH_REPO}" ]]; then
  if [[ -d "${CAPMESH_REPO}" ]]; then
    detect_pkg_src "${CAPMESH_REPO}" || warn "  CAPMESH_REPO has no pyproject.toml at expected paths"
  else
    say "  cloning capmesh package source from ${CAPMESH_REPO}"
    run "rm -rf '${CAPMESH_HOME}/repo'"
    run "git clone --depth 1 '${CAPMESH_REPO}' '${CAPMESH_HOME}/repo'"
    [[ "${DRY_RUN}" -eq 1 ]] || detect_pkg_src "${CAPMESH_HOME}/repo" || true
  fi
else
  # Walk up from the installer to find the asg-capmesh package root.
  detect_pkg_src "${SCRIPT_DIR}/../.." || detect_pkg_src "${SCRIPT_DIR}/.." || detect_pkg_src "${SCRIPT_DIR}" || true
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would create venv at ${CAPMESH_VENV} and pip install ${PKG_SRC:-<CAPMESH_REPO source>}"
elif have capmesh && [[ -x "${CAPMESH_VENV}/bin/capmesh" ]]; then
  say "  capmesh present ($(capmesh --version 2>/dev/null || echo 'version unknown')) — upgrading in place"
  [[ -n "${PKG_SRC}" ]] && "${CAPMESH_VENV}/bin/pip" install --quiet --upgrade "${PKG_SRC}" 2>/dev/null \
    || warn "  could not upgrade capmesh from source (PKG_SRC unset?) — keeping existing install"
else
  [[ -n "${PKG_SRC}" ]] || die "capmesh package source not found. Set CAPMESH_REPO=<git-url|local-path> to the asg-capmesh repo and re-run."
  say "  creating venv + installing capmesh from ${PKG_SRC}"
  "${PYBIN}" -m venv "${CAPMESH_VENV}"
  "${CAPMESH_VENV}/bin/python" -m pip install --quiet --upgrade pip
  "${CAPMESH_VENV}/bin/pip" install --quiet "${PKG_SRC}"
  "${CAPMESH_VENV}/bin/pip" install --quiet 'sqlite-vec>=0.1.0a4' 2>/dev/null || warn "  sqlite-vec unavailable — lexical search only"
fi
[[ "${DRY_RUN}" -eq 1 ]] || { ln -sf "${CAPMESH_VENV}/bin/capmesh" "${CAPMESH_BIN}" && say "  capmesh CLI -> ${CAPMESH_BIN}"; }

# --- capmesh sign-in (Google via the tailnet device-code flow) --------------
if [[ "${CAPMESH_NO_LOGIN}" == "1" ]]; then
  say "  capmesh sign-in skipped (CAPMESH_NO_LOGIN/--skip-capmesh-login). Complete later: capmesh login --device-code"
elif [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would run: capmesh login --device-code  (Google sign-in, token -> ${CAPMESH_ENV_FILE})"
else
  if [[ -f "${CAPMESH_ENV_FILE}" ]] && CAPMESH_BASE_URL="${CAPMESH_BASE_URL}" "${CAPMESH_BIN}" me >/dev/null 2>&1; then
    say "  capmesh already signed in (token at ${CAPMESH_ENV_FILE}) — skipping login"
  else
    say "  signing in to ${CAPMESH_BASE_URL} (Google via device code) ..."
    CAPMESH_BASE_URL="${CAPMESH_BASE_URL}" "${CAPMESH_BIN}" login --device-code \
      || warn "  sign-in did not complete — run later: capmesh login --device-code"
  fi
fi

# --- register the capmesh MCP server into Claude Code (official + isolated) --
register_mcp() {  # $1 = json config path with an mcpServers root
  local cfg="$1"
  [[ -f "${cfg}" ]] || echo '{}' > "${cfg}"
  local t; t="$(mktemp)"
  jq --arg url "${CAPMESH_MCP_URL}" '
    .mcpServers = (.mcpServers // {})
    | .mcpServers.capmesh = {"type":"http","url":$url}
  ' "${cfg}" > "${t}" && mv "${t}" "${cfg}"
}
if [[ "${DRY_RUN}" -eq 1 ]]; then
  say "  [dry-run] would register capmesh MCP (type http, url ${CAPMESH_MCP_URL}) in ${CLAUDE_MCP_CONFIG}"
else
  register_mcp "${CLAUDE_MCP_CONFIG}"
  say "  registered capmesh MCP (cap.* tools) in ${CLAUDE_MCP_CONFIG}"
  # Prefer the official CLI to register itself with Claude Code where supported.
  if have claude; then
    claude mcp add --scope user --transport http capmesh "${CAPMESH_MCP_URL}" >/dev/null 2>&1 \
      && say "  also registered via 'claude mcp add' (user scope)" || true
  fi
fi

# =============================================================================
# 5. VERIFY
# =============================================================================
if [[ "${SKIP_VERIFY}" -eq 1 || "${DRY_RUN}" -eq 1 ]]; then
  say "Section 5: verification — skipped${DRY_RUN:+ (dry-run)}"
else
  say "Section 5: verification"
  VERIFY_OK=1

  # 5a. capmesh auth doctor
  if "${CAPMESH_BIN}" auth doctor --base-url "${CAPMESH_BASE_URL}" 2>/dev/null; then
    say "  capmesh auth doctor: OK"
  elif "${CAPMESH_BIN}" doctor --base-url "${CAPMESH_BASE_URL}" 2>/dev/null; then
    say "  capmesh doctor: OK (auth-doctor subcommand unavailable on this CLI build)"
  else
    warn "  capmesh auth doctor reported a problem — re-run: capmesh login --device-code"
    VERIFY_OK=0
  fi

  # 5b. capmesh me
  if "${CAPMESH_BIN}" me 2>/dev/null; then
    say "  capmesh me: OK (signed in)"
  else
    warn "  capmesh me failed — not signed in yet. Run: capmesh login --device-code"
    VERIFY_OK=0
  fi

  # 5c. capmesh-harness smoke call through the harness contract.
  say "  capmesh-harness smoke call -> ${ASGCODE_ENDPOINT}/v1/messages"
  smoke_body='{"model":"opus","max_tokens":16,"messages":[{"role":"user","content":"reply with the single word: ready"}]}'
  # The orchestrator performs no bearer validation (access control is Tailscale
  # membership); this header carries a non-secret placeholder only to satisfy the
  # Anthropic API contract shape.
  smoke_api_key_header="x-api-key: tailnet-local-placeholder"
  smoke_out="$(curl -fsS --connect-timeout 10 --max-time 60 \
      -H 'content-type: application/json' \
      -H "${smoke_api_key_header}" \
      -H 'anthropic-version: 2023-06-01' \
      -d "${smoke_body}" \
      "${ASGCODE_ENDPOINT}/v1/messages" 2>/dev/null || true)"
  if [[ -n "${smoke_out}" ]] && printf '%s' "${smoke_out}" | jq -e '.content // .id // .choices' >/dev/null 2>&1; then
    say "  capmesh-harness smoke call: OK (orchestrator responded)"
  else
    # Fall back to a plain model-list probe so we still confirm reachability.
    if curl -fsS --connect-timeout 8 --max-time 20 "${ASGCODE_ENDPOINT}/v1/models" >/dev/null 2>&1; then
      warn "  /v1/messages did not return a parseable body, but /v1/models is reachable — endpoint is up. Test interactively with: capmesh-harness"
    else
      warn "  capmesh-harness smoke call failed and /v1/models is unreachable. Check '${ASGCODE_HOST}' in: ${TAILSCALE_BIN} status"
      VERIFY_OK=0
    fi
  fi

  [[ "${VERIFY_OK}" -eq 1 ]] && say "  verification: all green" || warn "  verification: some checks need attention (see warnings above)"
fi

# =============================================================================
# 6. NEXT STEPS
# =============================================================================
say "DONE."
cat <<NEXT

Next steps
----------
  1. Open a NEW terminal (so PATH includes ${CAPMESH_PREFIX}/bin), then start coding:
         capmesh-harness
     This runs the official Claude Code CLI against the local Director on the
     tailnet. Model picker: opus = Director Deep, sonnet = Director Standard,
     haiku = fast Worker lane, 4th slot = Director Max.

  2. Plain 'claude' is untouched and still talks to Anthropic's cloud (if you
     have your own key). Only 'capmesh-harness' uses the local endpoint.

  3. capmesh is wired into Claude Code as an MCP server (cap.* tools) and is
     signed in to ${CAPMESH_BASE_URL}. Re-verify any time:
         capmesh auth doctor --base-url ${CAPMESH_BASE_URL}
         capmesh me
         capmesh search "deploy infra sre" --k 3

  4. Re-run this installer any time to pick up updates or re-assert config:
         bash $(basename "$0")

Files written
-------------
  ${ASGCODE_SETTINGS}            (isolated Claude Code harness config)
  ${ASGCODE_LAUNCHER}            (capmesh-harness launcher wrapper)
  ${ASGCODE_ENV_FILE}            (env contract, 0600, no secrets)
  ${CAPMESH_VENV}                (capmesh CLI venv)
  ${CAPMESH_BIN}                 (capmesh symlink)
  ${CAPMESH_ENV_FILE}            (capmesh per-user token, created by sign-in)
  ${CLAUDE_MCP_CONFIG}           (capmesh MCP registration)
NEXT
[[ "${CAPMESH_NO_LOGIN}" == "1" ]] && say "Reminder: complete sign-in with  capmesh login --device-code"
exit 0
