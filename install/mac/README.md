# asgcode + capmesh client install (macOS, external guest)

One idempotent script that brings up a complete **asgcode + capmesh client** on a
macOS machine for an **external guest** who has been added to a shared Tailscale
device on the tailnet. After it runs, the guest can type `asgcode`
to drive the official Claude Code CLI against the local Qwen Director, with the
capmesh capability mesh wired in as an MCP server.

It prefers official tooling throughout: the Claude Code CLI is installed via its
official npm package (`@anthropic-ai/claude-code`), Tailscale via the official
CLI, and the capmesh CLI and MCP server as-is.

## What it installs

| Section | Action |
|---------|--------|
| 1. Preflight | Confirms macOS, the Tailscale CLI is present and logged in, and the asgcode endpoint `asgcode-gpu-internal:14400` is reachable. The capmesh VIP is probed too (informational). |
| 2. Claude Code CLI | Installs or updates the official `@anthropic-ai/claude-code` npm package globally (installing Node.js via Homebrew if needed). |
| 3. asgcode harness config | Writes an **isolated** Claude Code `settings.json` at `~/.config/asgcode/claude-config/` that points `ANTHROPIC_BASE_URL` at the asgcode orchestrator and maps the tier picker (opus/sonnet/haiku + custom) onto the local Director aliases (`director-deep`/`director-standard`/`worker-quick`/`director-max`). Writes an `asgcode` launcher and a no-secret env contract. Global `~/.claude` is left untouched. |
| 4. capmesh CLI + MCP | Installs the official `capmesh` CLI into `~/.capmesh/venv` (symlinked to `~/.local/bin/capmesh`), signs in via Google through the device-code flow, and registers the capmesh MCP server (`the capmesh authority URL (env CAPMESH_BASE_URL)/mcp`, exposing the `cap.*` tools) into Claude Code. |
| 5. Verify | Runs `capmesh auth doctor`, `capmesh me`, and an asgcode smoke call against `/v1/messages` (with a `/v1/models` reachability fallback). |
| 6. Next steps | Prints how to start coding and how to re-verify. |

The script is idempotent and re-runnable: every config file is regenerated to
match the current settings, existing CLIs are upgraded in place, and an existing
capmesh sign-in is detected and reused. No secrets are embedded; the only
credential is the per-user capmesh token minted interactively at sign-in.

## Prerequisites

1. **Tailscale device share accepted.** An operator shares the asgcode device
   with the guest and the guest accepts the invite, then signs in to Tailscale
   on this Mac. Verify with `tailscale status` — `asgcode-gpu-internal` should
   appear online. (First contact with a tailnet host can lag a few seconds while
   the SSH session recorder warms up; that is expected, not a fault.)
2. **A Google account that can sign in to capmesh.** Section 4 runs
   `capmesh login --device-code`, which opens a Google sign-in. The guest must
   complete it for the `cap.*` MCP tools and `capmesh` CLI to authenticate.
3. **Homebrew** (recommended) so the script can install Node.js, Python 3.12+,
   `git`, and `jq` if they are absent. Install from <https://brew.sh>. Node.js
   can alternatively be installed manually from <https://nodejs.org>.

## Usage

```sh
bash asgcode-capmesh-install.sh
```

Common variations:

```sh
bash asgcode-capmesh-install.sh --dry-run            # print actions, change nothing
bash asgcode-capmesh-install.sh --skip-capmesh-login # install now, sign in to capmesh later
bash asgcode-capmesh-install.sh --skip-claude        # leave the Claude Code CLI as-is
bash asgcode-capmesh-install.sh --help               # full option list
```

Tunables (environment variables):

| Variable | Default | Purpose |
|----------|---------|---------|
| `ASGCODE_ENDPOINT` | `http://asgcode-gpu-internal:14400` | asgcode orchestrator base URL |
| `CAPMESH_BASE_URL` | `the capmesh authority URL (env CAPMESH_BASE_URL)` | capmesh server (MCP is `<base>/mcp`) |
| `CAPMESH_REPO` | (auto) | git URL or local path to the asg-capmesh repo, if the CLI package source is not found beside the installer |
| `CAPMESH_NO_LOGIN` | `0` | set `1` to skip the interactive sign-in |
| `ASGCODE_CONFIG_DIR` | `~/.config/asgcode/claude-config` | isolated Claude Code config dir |
| `CAPMESH_PREFIX` | `~/.local` | bin dir for the `asgcode` and `capmesh` symlinks |

## Verification

After the run, in a **new** terminal:

```sh
# capmesh
capmesh auth doctor --base-url the capmesh authority URL (env CAPMESH_BASE_URL)
capmesh me
capmesh search "deploy infra sre" --k 3

# asgcode (interactive — uses the local Director on the tailnet)
asgcode
```

`asgcode` is the official Claude Code CLI launched with `CLAUDE_CONFIG_DIR`
pointed at the isolated config. The `/model` picker shows: opus = Director Deep,
sonnet = Director Standard, haiku = fast Worker lane, 4th slot = Director Max.
Plain `claude` is unaffected and still uses Anthropic's cloud.

## Files written

```
~/.config/asgcode/claude-config/settings.json   isolated Claude Code harness config
~/.local/bin/asgcode                             launcher (claude + isolated config)
~/.config/asgcode/.env                           env contract (0600, no secrets)
~/.capmesh/venv/                                 capmesh CLI virtualenv
~/.local/bin/capmesh                             capmesh symlink
~/.config/asgcode/capmesh.env                    per-user capmesh token (from sign-in)
~/.claude.json                                   capmesh MCP server registration
```

## Troubleshooting

**`tailscale CLI not found`**
Install Tailscale from <https://tailscale.com/download/mac>, sign in, and accept
the shared device invite, then re-run.

**`Tailscale is not running or not logged in`**
Run `tailscale up`, complete sign-in, accept the device share, then re-run. This
is a Tailscale issue, not asgcode.

**asgcode endpoint did not answer**
Confirm `asgcode-gpu-internal` is online in `tailscale status`. A few-seconds
delay on first contact is the SSH session recorder warming up — wait and re-run;
do not switch to a raw IP or alter firewall/WireGuard. The Section 5 smoke call
re-tests reachability.

**`claude: command not found` after install**
Open a new shell (PATH changes need a new session), or add
`"$(npm config get prefix)/bin"` to your PATH.

**`asgcode: command not found`**
Add `~/.local/bin` to PATH: `export PATH="$HOME/.local/bin:$PATH"` (the installer
appends this to your shell rc, effective in new shells).

**`capmesh me` fails / `auth doctor` reports a problem**
You are not signed in. Run `capmesh login --device-code` and complete the Google
sign-in. The token lands in `~/.config/asgcode/capmesh.env`.

**capmesh MCP tools (`cap.*`) do not appear in Claude Code**
Start a new `asgcode` session (MCP servers load at session start). Confirm the
registration with `jq '.mcpServers.capmesh' ~/.claude.json`.

**`capmesh package source not found`**
The installer looks for the asg-capmesh package beside itself. If it cannot
find it, set `CAPMESH_REPO=<git-url|local-path>` to the asg-capmesh repo and
re-run.

**Re-running**
Safe any time. Config is regenerated, CLIs are upgraded in place, and an existing
capmesh sign-in is reused.
