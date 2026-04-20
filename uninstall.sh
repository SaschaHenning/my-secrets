#!/usr/bin/env bash
# Removes the mys binary, the Claude skill symlink, and the Claude MCP
# server entry. Leaves the gopass store and the audit DB untouched —
# delete those manually if you want a full wipe.

set -euo pipefail

banner() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
ok()     { printf "    \033[32m✓\033[0m %s\n" "$*"; }
warn()   { printf "    \033[33m!\033[0m %s\n" "$*"; }

banner "Removing mys binary"
if [[ -f /usr/local/bin/mys ]]; then
  if [[ -w /usr/local/bin ]]; then
    rm /usr/local/bin/mys
  else
    sudo rm /usr/local/bin/mys
  fi
  ok "removed /usr/local/bin/mys"
else
  warn "/usr/local/bin/mys not found"
fi

banner "Removing Claude Code skill symlink"
if [[ -e "$HOME/.claude/skills/my-secrets" ]]; then
  rm -f "$HOME/.claude/skills/my-secrets"
  ok "removed ~/.claude/skills/my-secrets"
fi

banner "Removing MCP server entry from ~/.claude/settings.json"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
if [[ -f "$CLAUDE_SETTINGS" ]]; then
  python3 - "$CLAUDE_SETTINGS" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
data = json.loads(p.read_text() or "{}")
mcp = data.get("mcpServers", {})
if "my-secrets" in mcp:
    del mcp["my-secrets"]
    if not mcp:
        data.pop("mcpServers", None)
    p.write_text(json.dumps(data, indent=2) + "\n")
    print("    removed from", p)
else:
    print("    no entry present")
PY
  ok "MCP config cleaned"
fi

banner "Preserved"
cat <<EOF
    The following are NOT removed — delete manually if you want a full wipe:
      ~/.password-store                          # gopass store + GPG secrets
      ~/.local/share/my-secrets/audit.sqlite     # audit log
      ~/.config/my-secrets/scope-policy.yaml     # scope policy
      Your GPG keys in the macOS Keychain

    To remove those:
      rm -rf ~/.password-store
      rm -rf ~/.local/share/my-secrets
      rm -rf ~/.config/my-secrets
EOF
