# Architecture

## Goal

Give a Mac a credential store where every access **through `mys`** — human
or AI — is visible in one place, and where AI callers can be scoped away
from sensitive paths without relying on manual discipline. The default
store is personal; explicitly shared mounts add team availability but do
not make client-side auditing enforceable.

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
| `internal/sync`       | Git remotes, mount config, locking, and shared-mount provisioning.   |
| `internal/recipient`  | Mount-aware GPG/gopass recipient control.                            |
| `internal/teamkeys`   | Strict, reusable `team-keys.yaml` identity-manifest loader.          |

The `internal/app` boundary is load-bearing for secret CRUD, search,
browse, and reveal operations: those paths MUST go through it, and they
MUST write audit rows for every outcome (OK, denied, error). Sync and
recipient administration form a separate control plane. They may invoke
the `gopass`/Git/GPG CLIs to alter encrypted repository metadata, but do
not consume decrypted secret values and are audited by their command
handlers.

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

Every branch writes an audit row. There is no secret CRUD or reveal path
through `mys` that reaches the gopass store without first calling
`policy.Evaluate` and subsequently calling `audit.Write`. A recipient
can still invoke bare `gpg`/`gopass` outside `mys`; that out-of-band
trust boundary is especially important for shared mounts.

## Store topology and shared-mount control plane

The personal default mount remains `root`. Shared team data lives in a
separate named mount such as `jasp`, so the top-level secret path keeps
the mount/org identifiable (`jasp/...`) for later policy and audit work.
`~/.config/my-secrets/sync.yaml` records the distinction:

```yaml
version: 1
layout: single
remotes:
  - mount: root
    url: git@github.com:alice/my-secrets-store.git
  - mount: jasp
    url: git@github.com:jasp/mys-store-shared.git
    shared: true
```

`shared` is fail-closed metadata: the root mount can never be shared,
duplicate mount entries are invalid, and an invalid/ambiguous config
never authorizes foreign-recipient enrollment. The normal personal
setup wizard preserves existing shared entries instead of reconstructing
them as personal remotes.

The shared repository normally contains a versioned identity manifest:

```yaml
version: 1
members:
  - name: Alice Example
    fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
    email: alice@example.org
    public_key: keys/alice.asc
```

`internal/teamkeys` strictly validates and canonicalizes this file.
Names, emails, and full fingerprints are required and unique; an optional
public-key path is repository-relative and may not traverse parents or
symlinks. The exported loader is intentionally not tied to Cobra because
later identity/audit phases can reuse the fingerprint-to-member map.
Provisioning also accepts an explicit list of already imported
fingerprints for bootstrap. That fallback creates no identity map, so
later mount-targeted foreign additions remain fail-closed until a valid
manifest is present.

`mys sync shared setup` is convergent provisioning:

1. Preflight the manifest/public keys and require at least one matching
   local secret key.
2. Lock the mount, reject root/path collisions, create or attach the
   gopass mount, and reconcile the Git remote.
3. Add new recipients before removing stale recipients, then verify the
   exact `.gpg-id` set.
4. When a manifest was supplied, commit `team-keys.yaml` plus referenced
   public keys; push, and only then persist `shared: true` in
   `sync.yaml`.

One non-fast-forward push can trigger one fetch/reconcile/retry. Shared
mounts are excluded from write-triggered personal auto-sync; provisioning
pushes its own control-plane changes, while explicit sync commands remain
available. The setup command is AI-denied before provisioning; `--yes`
does not override caller classification.

`mys recipient add --mount <name>` imports a foreign public key only
after both the config marker and the live mount manifest validate. A
fingerprint absent from the manifest is reported as a warning because a
new member may arrive before the manifest update; a later full
provisioning run converges back to the manifest. Add/remove mutations
remain AI-denied, and add retains the human confirmation gate. Removing
a member from `.gpg-id` without also removing it from the manifest is
likewise temporary: provisioning will restore the declared fingerprint.

`mys bw-import --org <source> --mount <shared-target>` is the phase-3
data-plane bridge. It rebases only canonical `source/relative` paths to
`shared-target/relative`; store lookup, duplicate detection, policy
evaluation, output, and audit all use the target path. The command
validates the shared marker before locking, then holds the mount lock
from live-mount revalidation through pull, reads, writes, and the final
shared sync. It pulls before any Bitwarden access and suppresses
per-entry personal auto-sync. Successful writes are still synced when a
later entry fails, while the command and summary audit remain failed.
`LastSync` is merged into a freshly loaded config under a separate
config lock. Persistent audit reasons contain stage/count metadata,
never raw Git or Bitwarden subprocess errors.

### Shared-read policy and signed audit data plane

Each configured shared remote may carry an independent `team_audit`
configuration:

```yaml
remotes:
  - mount: jasp
    url: git@github.com:jasp/mys-store-shared.git
    shared: true
    team_audit:
      url: git@github.com:jasp/mys-store-shared-audit.git
      signing_fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
```

`mys sync shared audit setup` resolves the candidate remote before taking the
global cooperative `mys` lock on a validated, stable home-directory inode. It
creates or validates the restrictive shared policy monotonically, then
provisions the audit dependency. GitHub-backed
repositories must report `PRIVATE`, including immediately after creation.
Provisioning validates the signer against the current `team-keys.yaml` and
`.gpg-id`, verifies the full audit repository, pushes a unique empty probe
branch, confirms its exact OID, deletes it with a lease, and confirms that
deletion. A query, push, confirmation, cleanup, or visibility uncertainty
leaves `sync.yaml` unchanged. A valid policy already materialized by that
attempt is deliberately retained and reused by the next idempotent setup; the
code never races another process to delete policy state.

`internal/app` creates one fresh `accessOperation` per public operation. It
reloads global policy, sync config, and the mount policy. The bound Store opener
takes the same global cooperative lock, captures each team-audited mount's real
path and directory identity, opens the gopass Store, and post-verifies every
captured inode under an in-process open gate. The lock remains held until that
operation closes its Store. The operation uses only the frozen resolver, which
rechecks directory identity before returning a path; drift closes the Store and
fails closed. Shared access is the logical AND of global and mount-local
decisions. Before decrypting, `teamaudit.Preflight` records:

1. the published shared-store Git commit;
2. SHA-256 of the exact parsed shared-policy bytes;
3. SHA-256 of `team-keys.yaml`; and
4. SHA-256 of the canonical `.gpg-id` set.

The same snapshot is passed back to `AppendBatch` after decrypt. Immediately
before signing, the manager repeats preflight, reloads signer identity and
membership, then repeats preflight again. Any difference rejects the append.
Caller-generated UUID event IDs remain stable across the manager's ambiguous
push/confirmation handling, so a remotely present batch is confirmed instead
of duplicated.

```text
authorize(global AND shared)
        │
        ▼
Preflight(store, policy, team keys, recipients)
        │
        ▼
decrypt requested values
        │
        ▼
AppendBatch(exact preflight snapshot, caller UUIDs)
        │
        ├─ AI failure ──▶ return no plaintext / no partial result
        └─ human/script backend failure ──▶ generic advisory warning
```

Successful events are strict version-1 NDJSON records. Each contains
attribution, host/device identity, all four snapshot fields, a per-branch
sequence, previous-row hash, row hash, and a detached GPG signature. Devices
append only to
`audit/v1/<mount>/<primary-fingerprint>/<device-uuid>`. Aggregation:

- validates branch names and trees;
- verifies each row hash, chain, and detached signature;
- confirms the signer was both a manifest member and recipient at the
  recorded store commit;
- rejects duplicate event IDs across branches; and
- advances local rollback watermarks only after complete verification.

The watermarks detect later branch deletion, truncation, history rewrite, or
prefix divergence. A new verifier has no pre-existing remote observation, so
its first successful aggregation establishes—not retroactively proves—the
rollback baseline.

Phases 1–6 remain an application-layer guarantee. A recipient private-key
holder can bypass `mys` with raw `gpg`/`gopass`; that read is neither blocked
by the policies nor represented in the signed repository. Operational
revocation, rotation, historical-key retention, and watermark recovery are
defined in `docs/SHARED-TEAM-RUNBOOK.md`.

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
  action        TEXT    (init|get|list|list_detail|search|add|rotate|remove|export|
                         history|web_open|mcp_start|... — see internal/audit/audit.go
                         for the full, current list of Action* constants),
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

Loopback-only (`127.0.0.1`), behind a real Touch-ID login
(`LocalAuthentication`/`LAContext` via cgo — `auth_touchid_darwin.m` +
`auth_touchid_darwin_cgo.go`, with a `security authorize` password
fallback under `CGO_ENABLED=0`)
with a cookie-based session (`internal/web/session.go`, 30 min idle
timeout). Three page groups: overview + audit filters, and a secrets
browser (`/entries`, `/entries/{path...}`) for browsing policy-visible
entries by org, with metadata (kind, tags, domain, username). Templates
embedded via `//go:embed`.

`/entries` always decrypts and renders every policy-visible entry on one
page as a table, grouped by org (`groupByOrg`) — there is no separate
cheap/scoped/expensive tiering, and no server-side search round trip.
Each row carries a `data-search` attribute (`searchableText`,
HTML-attribute-escaped by `html/template` like any other interpolated
value) that an inline script in `entries.html` filters against on every
keystroke, entirely client-side; `?q=` only pre-fills the search box's
initial value for deep links (e.g. `entry.html`'s "back to org"). This
trades the earlier three-tier design (deliberately cheap landing page,
avoid decrypting until asked) for a simpler always-decrypt one, since
`App.BrowseDetailed` already writes exactly one aggregated audit row per
call regardless of entry count — for a personal store this size, that's
fast enough that hiding entries behind an extra click was pure friction.

Decrypting every entry on one page load is slower than the server's
default 10s `WriteTimeout`, once the store has enough entries — a real
bug found via a real store, not a hypothetical: the request's context
got cancelled mid-decrypt (a wall of "context canceled" errors from the
remaining `Store.Get` calls) and the connection was torn down before any
response reached the browser, so the page silently "loaded nothing".
`handleEntries` calls `extendWriteDeadline(w, entriesWriteBudget)` (2
minutes) before decrypting, the same `http.ResponseController`-based
override already used for the Touch-ID write budget.

Even so, on a real store (156 entries × ~0.19s ≈ 30s) a synchronous
full-store decrypt is too slow to sit in front of the user, so
`handleEntries` wraps `App.BrowseDetailed` in an `entriesCache` (shared
for the server's lifetime) that serves **stale-while-revalidate**: any
cached result — fresh or stale — is returned immediately, and a stale
one additionally fires a single background refresh
(`context.Background`, so it can't be cancelled by any request). Only a
completely cold cache blocks one caller on a full decrypt. `serveWith`
also `go`-warms the cache at startup, so that first cold load is usually
already done by the time the user navigates. A hit skips the decrypt
AND its `list_detail` audit row; only successful decrypts are cached, so
a failed refresh keeps serving the last good result rather than wedging.
This is also why login lands on `/` (the start page decrypts nothing —
instant) rather than `/entries`: landing on `/entries` meant the whole
store decrypted right after login, which looked like the app hanging.
"Zuletzt gelesen"/"zuletzt gesynct" render via `relativeTime`
(recency-first: "gerade eben"/"vor N Minuten" within the last hour,
"heute"/"gestern" for the last two calendar days, the absolute date only
once it's older).

Each row has inline "copy username" (client-side only — Username isn't
secret) and "copy password" buttons; the start page's "zuletzt benutzt"
list has the same copy-password button. Both are wired globally by
`/static/app.js` via `data-copy-username`/`data-copy-password`
attributes (event delegation, one listener for every page). The
copy-password button POSTs to `/entries/{path...}` with
`Accept: application/json` (`wantsJSON`/`writeRevealJSON`), getting
`{"password": "..."}` back — same `App.Get` gate and audit row as the
detail page's Reveal button, no page navigation. It does not
re-authenticate: reveal is session-only (see below).

The page decrypts entries to render metadata (gopass has no
metadata-only decrypt) but does so through `App.BrowseDetailed`/`App.Inspect`,
which write a single aggregated `list_detail` audit row per call instead of
one `get` row per path — browsing the list must not look, in the audit
log, like reading every secret in it. `App.Get` (an actual reveal) stays
the only path that writes `get` rows. This is what makes "zuletzt
gelesen" (`audit.Log.LastAccessByPath`/`LastAccess`, filtered to
`action=get, result=ok`) meaningful in the entries list and detail
page — it reflects real reveals, never page views.

`POST /entries/{path...}` is the one write-shaped-but-actually-read
endpoint: reveal. `handleReveal` just calls `App.Get` (which re-checks
scope policy and writes the `get` audit row) and renders/returns the
value. Reveal is **session-only**: the login session is the gate, there
is no per-reveal re-authentication — a deliberate reversal of an earlier
per-reveal-Touch-ID design, on the grounds that the CLI `mys get
--reveal` is already unguarded per-call and strictly more powerful (see
docs/SECURITY.md for the full rationale). Policy denial and audit logging
are unchanged; only the per-action prompt is gone. This is the one place
the UI renders an actual password value; every other view stays masked
(`store.MaskedPassword`, `store.IsSecretLikeFieldKey` for custom
`Fields`). `authGate` sets `Cache-Control: no-store` on every gated
response so a revealed value is never cached. The overview/start page
adds a search box (→ `/entries?q=`) and a "zuletzt benutzt" list built
from `audit.LastAccessByPath` (get/ok rows) — path + relative time +
copy button, no decrypt at render time.

The entry detail page also renders a "Historie" section from
`App.History` → `internal/history.Log`, which shells out to `git log
--follow` against the store's own on-disk git repository (gopass's
`api.Gopass.Revisions` is unimplemented upstream, so there is no library
path). Mount-aware: `internal/history.resolveDir` checks `gopass config
mounts.<org>.path` first and strips the org prefix from the on-disk
relative path when the entry lives in its own mount repo (gopass's
`root.Store` does the same stripping when writing), falling back to
`internal/gopassinit.DefaultStoreDir()` for the default single-store
case. Policy-gated like `Get`/`Inspect` (`ActionHistory` audit rows) —
metadata-only, never touches decrypted content — and fails soft (empty
result, no page error) when `git` is missing or the path has no history.

Auto-shutdown on parent context cancel. A `localhostOnly` middleware
rejects non-loopback `RemoteAddr`.

### PWA shell + LaunchAgent autostart

The UI is an installable PWA: `internal/web/static/manifest.webmanifest`
(`start_url: "/"` — the start page decrypts nothing, so app launch is
instant; colors matching `styles.css`), a minimal
`internal/web/static/sw.js` (pure network passthrough — no
`caches.open`/`cache.put` anywhere, enforced by
`TestSWJS_NeverCaches`, since a Cache Storage entry for a reveal
response would be an unencrypted, disk-persistent copy outside the
audit log's reach), and two generated icons. A shared
`templates/_head.html` (`{{define "head"}}`) carries the manifest link
+ Apple meta tags + SW registration into every templated page; the
hand-written `renderLogin` (not routed through `html/template`, so it
can't use the partial) duplicates the same tags inline.

`authGate` redirects an unauthenticated request to
`/login?next=<original request>` instead of a bare `/login`, so the
PWA's `start_url` (or any deep link) survives the login round trip.
`safeNextPath` validates the `next` value before it's ever used in a
redirect — same-origin absolute path only, rejecting `//host`,
`http://host`, and a leading backslash (which some browsers resolve the
same as a forward slash when following a `Location` header) — this is
the one place in the web package that has to actively defend against an
open-redirect trick, since `next` is otherwise fully attacker-controlled
input reflected into a `Location` header and a hidden form field.

`mys web install`/`uninstall`/`status` (`cmd/mys/cmd_web_install.go`)
manage a `~/Library/LaunchAgents/com.jasp.my-secrets.web.plist`
LaunchAgent with `RunAtLoad` and unconditional `KeepAlive` — the latter
matters because it restarts the process even after the *normal*
30-minute idle-shutdown exit, not just a crash, so an installed app icon
always finds a live server rather than a connection error. The security
posture is unchanged: the session cookie still expires after 30 minutes
of inactivity, and a fresh process starts with an empty in-memory
session store, so every relaunch still demands Touch ID. All `launchctl`
calls go through the package-level `launchctlRun` var (same indirection
pattern as `requireTouchIDFunc`/`mountPathLookup` elsewhere) so tests
never touch the real, global launchd session.

## Trade-offs documented in plan.html

- The optional signed chain still protects one machine's SQLite audit history.
  Shared reads performed through `mys` are additionally recorded in signed,
  per-device Git branches and aggregated across team members with historical
  authorization and rollback-watermark verification.
- No native Swift daemon (Ansatz A) — machine binding comes from
  gopass's GPG key in the Keychain with `AccessibleWhenUnlockedThisDeviceOnly`,
  which is strong enough for the single-user threat model.
- Both audit paths remain application-layer evidence. A recipient private-key
  holder can bypass `mys` with raw `gpg` or `gopass`; those reads are neither
  blocked nor recorded in the signed team-audit repository. For AI
  integrations that expose only MCP, that interface keeps normal reads on the
  audited path, but it does not provide OS-level enforcement.
