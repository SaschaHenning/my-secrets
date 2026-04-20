> **Auto-setup check:** At the start of every conversation, verify that `.claude/shared-rules.md` exists and is a valid symlink (not broken). If it is missing or broken:
>
> 1. Find JASP-Shared: `find ~ -maxdepth 4 -type d -name "JASP-Shared" 2>/dev/null | head -5`
> 2. If not found, clone it as a sibling of this project: `git clone https://github.com/JASP-eu/JASP-Shared.git ../JASP-Shared`
> 3. Pull latest: `cd <SHARED_DIR> && git pull && cd -`
> 4. Create shared rules symlink:
>    - `mkdir -p .claude && ln -sf <SHARED_DIR>/AI-Rules/CLAUDE.md .claude/shared-rules.md`
> 5. Install agents globally (if not already present):
>    - `mkdir -p ~/.claude/agents`
>    - `for f in <SHARED_DIR>/AI-Rules/agents/*.md; do ln -sf "$f" ~/.claude/agents/$(basename "$f"); done`
> 6. Clean up project-level agent symlinks (if any exist from older setup):
>    - `for f in <SHARED_DIR>/AI-Rules/agents/*.md; do rm -f ".claude/agents/$(basename "$f")"; done`
>    - `rmdir .claude/agents 2>/dev/null || true`
> 7. Tell the user: "Shared AI rules were missing — I've set them up automatically."
>
> If `.claude/shared-rules.md` exists and is valid, skip this silently — do not mention it.

# my-secrets — Claude Instructions

## Project Purpose

Local credential manager for macOS. Thin Go wrapper around the gopass library with audit logging, caller identification, org-scoped access, a web UI for inspection, and MCP server support for AI tools.

Primary design goal: **every access to a secret — human or AI — is logged with enough detail to answer the question "which process, at what time, from what working directory, read which secret, and why."**

## Architecture

See `docs/plan.html` for the full planning overview with three evaluated architecture approaches. The implemented approach is **Ansatz C (Library-Variante)**:

- **Storage**: gopass imported as Go library (no subprocess), GPG keys in the macOS Keychain, unlocked via `pinentry-touchid` (Secure Enclave / Touch ID).
- **Audit log**: local SQLite database, append-only, one row per read/write/list/delete operation.
- **Caller identification**: PPID walk up to PID 1, env-var inspection (`CLAUDECODE=1`, `ANTHROPIC_*`, `TERM_PROGRAM`), optional explicit `--requester` flag set by the Claude skill.
- **Org scoping**: gopass folder structure maps to orgs (`jasp/`, `zuhause/`, `private/`), a `scope-policy.yaml` defines which caller classes may access which orgs.
- **Web UI**: small embedded HTTP server on localhost, reads the audit DB and gopass store read-only, gated behind Touch ID.
- **MCP server**: the binary can run in MCP mode over stdio — this is the ONLY entry point for Claude Code to read secrets, guaranteeing audit coverage for AI access.
- **Bitwarden sync** (optional, explicit, one-way): exports to Bitwarden JSON format; no live cloud backend.

## Code Style

- Go, standard project layout (`cmd/`, `internal/`)
- English for code, comments, commit messages, branch names
- German for user-facing CLI output and Web-UI labels
- Commit convention: Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`)
- Small, focused PRs; each PR links to an issue

## Binary

The CLI binary is named `mys` (short for my-secrets). Commands follow the pattern the plan document lists: `mys get`, `mys ls`, `mys search`, `mys add`, `mys rotate`, `mys rm`, `mys audit tail`, `mys web`, `mys mcp`, `mys bw-export`.

## Security Boundaries

- The binary is the only sanctioned entry point for AI access. The Claude skill must never call `gopass` directly, must never read `~/.password-store` files, must always go through `mys` (CLI or MCP).
- Secrets must never appear in logs, terminal output without `--reveal`, or commit messages.
- The audit log is append-only; deletion requires an explicit `mys audit purge` command that itself writes an audit entry.
- Org policy denials are hard failures, never warnings.

## Testing

- Unit tests for each internal package
- Integration tests against a temporary gopass store initialized with a test GPG key
- E2E test for the MCP server using a test MCP client

## Skills & Agents

Shared agents and skills are loaded via `.claude/shared-rules.md` (symlink to JASP-Shared). Use the standard workflow documented there:

1. Load relevant skill before coding (`/backend`, `/testing`, `/security`)
2. Spawn `quality`, `security`, `testing` agents after implementation
3. Never commit to main — always feature branch + PR
4. Every non-trivial task gets an issue first
