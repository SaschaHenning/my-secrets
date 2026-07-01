# Architecture

## Goal

Give a single-user Mac a credential store where every access — human or AI —
is visible in one place, and where AI callers can be scoped away from
sensitive paths without relying on manual discipline.

## Chosen approach

**Ansatz C (Library-Variante)** from `docs/plan.html`: thin Go binary built
on top of the gopass library. Instead of spawning `gopass` as a subprocess
(which would leave audit gaps whenever someone invokes `gopass` directly),
we import `github.com/gopasspw/gopass/pkg/gopass/api` and route every
operation through an in-process orchestrator.

## Component diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Clients                                                     │
│  mys CLI          Claude Skill (MCP)         Web browser    │
└───────┬──────────────────┬─────────────────────┬────────────┘
        │                  │                     │
        │  stdin/stdout    │ stdin/stdout        │ HTTP (loopback)
        ▼                  ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│ cmd/mys                                                     │
│  cobra CLI ─┬──► internal/app (Facade)                      │
│             │       │                                       │
│  mcp  ──────┤       │                                       │
│             │       │                                       │
│  web  ──────┘       │                                       │
│                     │                                       │
│  ┌──────────────────┼──────────────────────┐                │
│  │                  │                      │                │
│  ▼                  ▼                      ▼                │
│ caller            policy               (every op)           │
│ (PPID+env)      (YAML globs)                 │              │
│  │                  │                        │              │
│  └── identify ──────┘                        │              │
│        ↓                                     │              │
│   actor detail                               │              │
│        ↓                                     │              │
│        └──────────────┬──────────────────────┘              │
│                       ▼                                     │
│                     audit                                   │
│                     (SQLite append-only)                    │
│                       │                                     │
│                       └──▶ also: store (gopass library)     │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
                      ~/.password-store
                      (GPG-encrypted files)
                                │
                                ▼
                      gpg-agent → Keychain (+ optional Touch ID)
```

## Package layout

| Package               | Responsibility                                                       |
| --------------------- | -------------------------------------------------------------------- |
| `cmd/mys`             | CLI parsing, subcommand wiring, output formatting.                   |
| `internal/app`        | Facade. Every action is identify → policy → store → audit in order.  |
| `internal/store`      | gopass library wrapper. CRUD, search, metadata mapping.              |
| `internal/audit`      | Append-only SQLite log, query helpers, verify integrity.             |
| `internal/caller`     | Classify caller via env + PPID walk + TTY + explicit override.       |
| `internal/policy`     | YAML allow/deny rules with glob matching.                            |
| `internal/mcp`        | Minimal JSON-RPC 2.0 MCP server over stdio.                          |
| `internal/web`        | Embedded HTTP UI, loopback-only, read-only, no secret values.        |

The `internal/app` boundary is load-bearing: anything that talks to the
store MUST go through it, and it MUST write audit rows for every outcome
(OK, denied, error).

## Data flow — a Get call

```
CLI/MCP/Web
    │
    ▼ Get(ctx, "jasp/github-token")
    │
    │  1. caller.Identify(override)
    │         reads env, walks PPID, sets kind = human|ai|script
    │
    │  2. policy.Evaluate(kind, agentLabel, path)
    │         decides Allowed = true/false with MatchedRule
    │
    │  3a. denied → audit.Write(result=denied, reason)
    │              return ErrDenied
    │  3b. allowed → store.Get(ctx, path)
    │              gopass decrypts via gpg-agent
    │              audit.Write(result=ok, reason=MatchedRule)
    │              return Entry
```

Every branch writes an audit row. There is no code path that reaches the
gopass store without first calling `policy.Evaluate` and without
subsequently calling `audit.Write`.

## Metadata model

Entries are stored as gopass AKV secrets (password plus header key/value
pairs). The `store.Entry` type maps:

| Field             | Stored as gopass key  |
| ----------------- | --------------------- |
| `Password`        | (first line / body)   |
| `Username`        | `username`            |
| `URL`             | `url`                 |
| `Kind`            | `kind`                |
| `GitHubProject`   | `github_project`      |
| `Notes`           | `notes`               |
| `Tags`            | `tags` (comma-joined) |
| `Org`             | derived from path     |

## Audit schema

```sql
audit_log (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT    (RFC3339 UTC),
  action        TEXT    (init|get|list|search|add|rotate|remove|export|web_open|mcp_start),
  secret_path   TEXT,
  org           TEXT,
  actor_kind    TEXT    (human|ai|script),
  actor_detail  TEXT    (JSON: pid, ppid, ppid_chain, env_flags, tty, override, reason),
  result        TEXT    (ok|denied|error),
  reason        TEXT
);
```

`BEFORE UPDATE` and `BEFORE DELETE` triggers abort with
`audit_log is append-only`, preventing accidental or intentional
tampering via the `db` handle.

## Caller classification

First-match order:

1. Explicit override via `--requester <label>` or MCP internal override
2. AI env flag (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR`, …)
3. Parent-process chain contains a known agent binary
4. Interactive TTY → `human`
5. Fallback → `script`

The `actor_detail` blob records all signals, not just the winning one —
so you can retrospectively spot cases where heuristics conflict
(e.g. `CLAUDECODE=1` set but TTY is present).

## Policy evaluation

1. Look up rules under `agentLabel` (e.g. `claude-code`); fall back to
   `kind` (e.g. `ai`) if no specific rules.
2. If any `deny` pattern matches → deny.
3. If no `allow` pattern matches → deny.
4. Otherwise → allow, record the matched pattern.

Patterns are shell-style globs, extended with `**` meaning „any subpath".
`jasp/**` matches `jasp/x` and `jasp/x/y/z` but **not** `jasp` itself.

## MCP server

Uses a minimal JSON-RPC 2.0 stdio implementation (single file,
~220 lines). Exposes three tools: `creds_list`, `creds_search`,
`creds_get`. The server forces `actor_kind=ai` regardless of env
detection — invocation through the MCP path is always treated as AI.

Denied calls return a textual payload with `{ "denied": true, "reason": ...}`
rather than a JSON-RPC error, so the calling agent can react gracefully
without retry loops.

## Web UI

Loopback-only (`127.0.0.1`), behind a Touch-ID login (`internal/web/auth_darwin.go`)
with a cookie-based session (`internal/web/session.go`, 30 min idle
timeout). Three page groups: overview + audit filters, and a secrets
browser (`/entries`, `/entries/{path...}`) for browsing/searching
policy-visible entries by org, with metadata (kind, tags, domain,
username). Templates embedded via `//go:embed`.

The browser decrypts entries to render metadata (gopass has no
metadata-only decrypt) but does so through `App.BrowseDetailed`/`App.Inspect`,
which write a single aggregated `list_detail` audit row per call instead of
one `get` row per path — browsing the list must not look, in the audit
log, like reading every secret in it. `App.Get` (an actual reveal) stays
the only path that writes `get` rows. The UI still has no write endpoints
and does not render password values.

Auto-shutdown on parent context cancel. A `localhostOnly` middleware
rejects non-loopback `RemoteAddr`.

## Trade-offs documented in plan.html

- We did not build the signed hash-chain audit log from Ansatz B —
  append-only triggers + `audit verify` detect the common corruption
  cases without the signing complexity.
- No native Swift daemon (Ansatz A) — machine binding comes from
  gopass's GPG key in the Keychain with `AccessibleWhenUnlockedThisDeviceOnly`,
  which is strong enough for the single-user threat model.
- Audit coverage for human CLI users relies on them going through `mys`
  and not invoking `gopass` directly. For AI, the MCP-only path makes
  this guarantee tight.
