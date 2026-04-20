#!/usr/bin/env bash
# my-secrets — one-shot installer for macOS.
#
# What this does:
#   1. Checks prerequisites (Homebrew, git).
#   2. Installs Homebrew packages: go, gopass, gnupg.
#   3. Builds the mys binary.
#   4. Copies it to /usr/local/bin (asks for sudo).
#   5. Runs `gopass setup` if the store is not initialised yet.
#   6. Runs `mys init` to create the policy file and audit DB.
#   7. Installs the Claude Code skill.
#   8. Registers `my-secrets` as an MCP server in the user's
#      Claude Code settings.
#
# Safe to re-run — every step is idempotent.

set -euo pipefail

banner() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
ok()     { printf "    \033[32m✓\033[0m %s\n" "$*"; }
warn()   { printf "    \033[33m!\033[0m %s\n" "$*"; }
die()    { printf "    \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

# --- 1. Prerequisites -----------------------------------------------------

banner "Checking prerequisites"

if [[ "$(uname -s)" != "Darwin" ]]; then
  die "This installer is macOS-only. For other platforms, build manually from source."
fi

command -v brew >/dev/null 2>&1 || die "Homebrew not found. Install from https://brew.sh and re-run."
command -v git  >/dev/null 2>&1 || die "git not found. Install Xcode Command Line Tools."
ok "Homebrew and git present"

# --- 2. Homebrew packages -------------------------------------------------

banner "Installing Homebrew packages"

brew_install_if_missing() {
  local pkg="$1"
  if brew list --formula "$pkg" >/dev/null 2>&1; then
    ok "$pkg already installed"
  else
    brew install "$pkg"
    ok "$pkg installed"
  fi
}

brew_install_if_missing go
brew_install_if_missing gopass
brew_install_if_missing gnupg

# pinentry-touchid is optional (Homebrew tap can fail) — try but don't block.
if ! command -v pinentry-touchid >/dev/null 2>&1; then
  warn "pinentry-touchid not installed. Biometric unlock will not work."
  warn "  To install later:  brew install jorgelbg/tap/pinentry-touchid"
  warn "  Or build from source: https://github.com/jorgelbg/pinentry-touchid"
else
  ok "pinentry-touchid present"
fi

# --- 3. Build -------------------------------------------------------------

banner "Building mys"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p bin
/opt/homebrew/bin/go build -ldflags "-X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
  -o bin/mys ./cmd/mys
ok "bin/mys built ($(du -h bin/mys | cut -f1))"

# --- 4. Install to /usr/local/bin ----------------------------------------

banner "Installing mys to /usr/local/bin"

INSTALL_PATH="/usr/local/bin/mys"
if [[ -w "$(dirname "$INSTALL_PATH")" ]]; then
  cp bin/mys "$INSTALL_PATH"
else
  echo "    /usr/local/bin is not writable — sudo needed to install."
  sudo cp bin/mys "$INSTALL_PATH"
fi
ok "mys → $INSTALL_PATH"

# --- 5. gopass setup -----------------------------------------------------

banner "Configuring gopass"

# Detect if gopass already has a configured store.
if gopass ls >/dev/null 2>&1; then
  ok "gopass store already initialised — skipping setup"
else
  warn "gopass store not yet initialised."
  echo "    Running 'gopass setup' now — follow the prompts."
  echo "    If you already have a GPG key, gopass will offer to use it."
  echo "    Otherwise it will generate a new one."
  read -r -p "    Press Enter to continue (Ctrl-C to abort and run 'gopass setup' manually later)..."
  gopass setup
  ok "gopass setup done"
fi

# --- 6. mys init ---------------------------------------------------------

banner "Running 'mys init'"

mys init
ok "policy + audit DB in place"

# --- 7. Install Claude Code skill ----------------------------------------

banner "Installing Claude Code skill"

if [[ -d "$HOME/.claude" ]]; then
  mys install-skill
  ok "skill symlinked into ~/.claude/skills/my-secrets"
else
  warn "~/.claude not found — skipping skill install."
  warn "  After installing Claude Code, run:  mys install-skill"
fi

# --- 8. Register MCP server in Claude Code settings ---------------------

banner "Registering my-secrets as a Claude MCP server"

# Claude Code looks for MCP config under different files depending on platform
# and scope. We write to user-scope settings.json, which takes effect for all
# projects.
CLAUDE_SETTINGS="$HOME/.claude/settings.json"

if [[ ! -f "$CLAUDE_SETTINGS" ]]; then
  mkdir -p "$(dirname "$CLAUDE_SETTINGS")"
  printf '%s\n' '{}' > "$CLAUDE_SETTINGS"
fi

# Use python3 (stdlib json) to merge rather than depending on jq.
python3 - "$CLAUDE_SETTINGS" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
data = json.loads(p.read_text() or "{}")
mcp = data.setdefault("mcpServers", {})
if mcp.get("my-secrets") != {"command": "mys", "args": ["mcp"]}:
    mcp["my-secrets"] = {"command": "mys", "args": ["mcp"]}
    p.write_text(json.dumps(data, indent=2) + "\n")
    print("    registered in", p)
else:
    print("    already registered in", p)
PY

ok "MCP entry in ~/.claude/settings.json"

# --- Done -----------------------------------------------------------------

banner "Done"
cat <<EOF
    my-secrets is installed.

    Try it:
      mys ls
      echo "test-pw" | mys add zuhause/test --kind password --user me
      mys get zuhause/test
      mys audit tail
      mys web          # opens http://127.0.0.1:7823

    Claude Code will pick up the MCP server on the next session start.
    If you want biometric unlock (Touch ID), install pinentry-touchid
    — see INSTALL.md.

    Uninstall: ./uninstall.sh
EOF
