#!/usr/bin/env bash
# my-secrets — one-shot installer for macOS.
#
# What this does:
#   1. Checks prerequisites (Homebrew, git).
#   2. Installs Homebrew packages: go, gopass, gnupg.
#   3. Builds the mys binary.
#   4. Copies it to ~/bin (no sudo needed).
#   5. Runs `mys init --install-skill` which — in this one command —
#      generates/picks a GPG key, initialises the gopass store, wires
#      up pinentry-touchid (macOS), writes the scope policy, creates
#      the audit DB, and installs the Claude Code skill.
#   6. Registers `my-secrets` as an MCP server in the user's
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

# macOS 15+/26 runs a codesigning monitor that SIGKILLs binaries whose
# ad-hoc signature it won't accept. Re-sign explicitly so the binary runs;
# cp preserves the embedded signature, so the installed copy inherits it.
if command -v codesign >/dev/null 2>&1; then
  codesign --sign - --force bin/mys && ok "bin/mys codesigned (ad-hoc)"
else
  warn "codesign not found — skipping ad-hoc signing (binary may be killed on macOS 15+)"
fi

# --- 4. Install to ~/bin --------------------------------------------------
# /usr/local/bin is a bad target here: it does not exist on a fresh
# Apple-Silicon Mac, needs sudo, and the surrounding tooling expects
# the binary at $HOME/bin/mys (MYS_BIN).

banner "Installing mys to ~/bin"

INSTALL_PATH="$HOME/bin/mys"
mkdir -p "$HOME/bin"
# Remove first: overwriting a signed binary in place keeps the inode and
# macOS then SIGKILLs it with a stale code-signature cache.
rm -f "$INSTALL_PATH"
cp bin/mys "$INSTALL_PATH"
ok "mys → $INSTALL_PATH"

case ":$PATH:" in
  *":$HOME/bin:"*) ;;
  *) warn "$HOME/bin is not in your PATH — add it to your shell profile:  export PATH=\"\$HOME/bin:\$PATH\"" ;;
esac

# --- 5. mys init (GPG key + gopass store + policy + audit + skill) ------

banner "Running 'mys init --install-skill'"

# mys init is the single entry point: it detects or generates a GPG key,
# initialises the gopass store, configures pinentry-touchid (best-effort),
# writes the scope policy, creates the audit DB, and — because of
# --install-skill — symlinks the Claude Code skill into ~/.claude/skills.
# The command is idempotent, so re-running the installer is safe.
if [[ -d "$HOME/.claude" ]]; then
  "$INSTALL_PATH" init --install-skill
  ok "mys initialised (key, store, policy, audit, skill)"
else
  warn "$HOME/.claude not found — running 'mys init' without skill install."
  "$INSTALL_PATH" init
  ok "mys initialised (key, store, policy, audit)"
  warn "  After installing Claude Code, run:  mys install-skill"
fi

# --- 6. Register MCP server in Claude Code settings ---------------------

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
# Register the absolute binary path — ~/bin is not guaranteed to be on
# the PATH of the process that spawns the MCP server.
python3 - "$CLAUDE_SETTINGS" "$INSTALL_PATH" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
data = json.loads(p.read_text() or "{}")
mcp = data.setdefault("mcpServers", {})
want = {"command": sys.argv[2], "args": ["mcp"]}
if mcp.get("my-secrets") != want:
    mcp["my-secrets"] = want
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
