---
name: my-secrets
description: Access local credentials via the `mys` MCP server. Use when any task needs an API key, token, password, or other secret. Provides list/search/get with org-scoped access and full audit logging.
---

# my-secrets

Local credential access for Claude Code, routed exclusively through the `mys` MCP server.

## Absolute rules

- **NEVER** read `~/.password-store/` files directly.
- **NEVER** invoke `gopass`, `security`, `bw`, `op`, or any other credential CLI.
- **NEVER** log, echo, or print secret values in your own output. Copy them into tool arguments only.
- **ALWAYS** go through the `mys` MCP server (`creds_list`, `creds_search`, `creds_get`). No shell fallback.
- If the MCP server is not available, tell the user — do not try to work around it.

## Tools exposed by the MCP server

| Tool | Arguments | Purpose |
|---|---|---|
| `creds_list` | `{ org?: string }` | List credential paths visible to the AI actor |
| `creds_search` | `{ query: string }` | Full-text search over paths and metadata |
| `creds_get` | `{ path: string }` | Fetch a single entry (metadata + password) |

The MCP server enforces a scope policy (`~/.config/my-secrets/scope-policy.yaml`). Denied calls return `{ "denied": true, "reason": "..." }` — **never retry on deny**. Tell the user what was denied and wait for guidance.

## Org inference

Before calling `creds_get` or `creds_list`, infer the org from the project context:

| CWD pattern | Org |
|---|---|
| `~/Code/JASP-*`, `~/Code/jasp-*`, `~/Code/congplan*` | `jasp` |
| `~/Code/Zuhause`, `~/Code/my-secrets` | `zuhause` |
| Anything else | ask the user, or try `creds_list` without org first |

When unsure, prefer `creds_list --org <guess>` first, show the user, confirm.

## Typical flow

1. Task mentions a credential need (e.g. "use my GitHub token").
2. Call `creds_search { query: "github" }`.
3. Pick the right path from the list.
4. Call `creds_get { path: "<path>" }`.
5. Use the returned value **only** in the tool argument the user asked for. Do not store it anywhere, do not print it.

## Installation

```bash
# One-time setup
brew install go gopass gnupg
gopass setup
mys init
mys install-skill    # symlinks this SKILL.md into ~/.claude/skills/my-secrets

# Claude Code MCP config — add to the project or user scope
# settings file:
#   "mcpServers": {
#     "my-secrets": { "command": "mys", "args": ["mcp"] }
#   }
```

## If the user wants to see what the AI accessed

- CLI: `mys audit tail --actor ai`
- Web UI: `mys web` then open http://127.0.0.1:7823/audit?actor=ai

Every `creds_*` call is written to the audit log with `actor_kind=ai` and full parent-process detail.
