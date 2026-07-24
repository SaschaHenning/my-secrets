# Security

## Threat model

my-secrets is a single-user macOS tool by default. An explicitly marked
shared mount can add separately owned team GPG keys, but it remains a
client-side, advisory sharing model; it does not turn the local client
into an authoritative access broker.

| In scope                                                   | Out of scope                               |
| ---------------------------------------------------------- | ------------------------------------------ |
| A compromised AI agent reading secrets it should not touch | Nation-state attackers with physical root  |
| Casual exfiltration of the DB to another machine           | Supply-chain compromise of gopass upstream |
| Local shell scripts that should not access `private/**`    | Kernel-level keylogging                    |
| Audit-log tampering by careless tools                      | Side-channels on the CPU                   |
| Foreign-team enrollment targeting a non-shared mount       | A team recipient bypassing `mys` with GPG  |

The guarantees we try to uphold:

1. Secrets are at rest only in gopass (GPG-encrypted, keyed by a GPG
   private key in the macOS Keychain).
2. Every access through `mys` (CLI / MCP / Web) produces an audit row.
3. Policy denials are hard failures — never warnings, never partial
   reveals.
4. Copying a store directory to another Mac does not grant access to its
   secrets without one of that store's recipient private keys. For the
   personal store, that key is Keychain-bound
   (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
5. The mount-targeted foreign-team enrollment path accepts only a
   non-root mount that is explicitly and unambiguously configured as
   shared and has a valid `team-keys.yaml`. The backward-compatible
   personal command still relies on its warning, human confirmation,
   and the operator's assertion that the key is their own.

## Machine binding — what „locked to this Mac" really means

We do **not** ship a native Secure-Enclave integration. The machine-bind
property comes entirely from gopass + GnuPG + Keychain:

- The master GPG key is generated locally and its private half is held
  by `gpg-agent`, which caches it from the Keychain.
- The Keychain item is stored with `AccessibleWhenUnlockedThisDeviceOnly`
  (the default for GPG-managed keychain items on macOS), which prevents
  iCloud sync and prevents copy-over via Migration Assistant.
- Optional: install `pinentry-touchid` to require biometric approval for
  every decrypt. Without it, the standard `pinentry` prompts for the key
  passphrase — that is still machine-local but without biometric confirmation.
- Optional: bind the GPG subkey to a YubiKey — then the Mac alone is
  insufficient to decrypt anything.

Explicit export is available via `mys bw-export`. That path is logged,
and its output is no longer machine-bound — handle with care.

## Claude / AI containment

The hard guarantee is narrow: **Claude Code, invoked via the MCP server,
cannot reach a denied path.** CLI calls through `mys` are also audited and
policy-checked when used by scripts/shells, but MCP remains the preferred
Claude Code path. Two layers make the MCP guarantee stick:

1. `cmd/mys mcp` hard-codes `actor_kind=ai` before any App operation runs.
   It is not possible to impersonate `human` through the MCP entry.
2. `internal/app` runs `policy.Evaluate` on every call before touching
   the store. There is no code path that lists or fetches without first
   evaluating the policy.

What we explicitly do **not** protect against:

- A human user running `gopass show private/bank-pin` directly. gopass
  has no built-in per-caller ACL, and we don't interpose on the gopass
  binary. Mitigation: `$PATH` shaping during onboarding, plus the
  understanding that the whole point of the tool is to make the AI path
  tight — humans can read what they could always read.
- An AI agent that has shell access and is NOT restricted to `mys` MCP/CLI.
  The Claude Code skill forbids direct `gopass` / `security` / `bw`
  calls, but a rogue AI with unrestricted bash could bypass this. The
  project-level `.claude/settings.json` should also deny `Read` of
  `~/.password-store/**` to make bypass require active user action.

## Audit integrity

The audit DB (`~/.local/share/my-secrets/audit.sqlite`) uses:

- `AUTOINCREMENT` primary key → a deleted row leaves a visible gap.
  `mys audit verify` detects these.
- `BEFORE UPDATE` / `BEFORE DELETE` triggers that abort with
  `audit_log is append-only`. A caller with raw sqlite access can drop
  the triggers or delete the file, but either action is visible:
  - Dropping triggers leaves a gap or a changed schema (future hardening:
    table checksum).
  - Deleting the file loses the whole history — the next `mys init` run
    starts at `seq=1`, which is detectable when correlating with other
    systems (e.g. Claude session transcripts).

These triggers are the baseline only. The optional signed-chain mode
below makes local DB edits detectable without pretending that it
aggregates or enforces team reads; the latter remains a separate,
deferred design.

### Signed-Chain-Mode (opt-in)

To detect DB-level tampering beyond what the triggers catch, set

```
export MYS_AUDIT_SIGN=1
```

in any shell that invokes `mys`. Every row written under that env gains
three additional columns:

| Column      | Contents                                                               |
| ----------- | ---------------------------------------------------------------------- |
| `prev_hash` | `row_hash` of the previous signed row (32 zero bytes for the first).   |
| `row_hash`  | `SHA-256(canonical_bytes(entry) ‖ prev_hash)`.                         |
| `signature` | Ed25519 signature over `row_hash`.                                     |

`canonical_bytes(entry)` covers `seq, ts, action, secret_path, org,
actor_kind, actor_detail, result, reason`. The `host` column (the
hostname that wrote the row, forward-compat for a possible future
cross-machine audit view) is deliberately **not** part of
`canonical_bytes` — adding a field retroactively to the signed hash
would invalidate every signature written before that field existed.
Treat `host` as informational only, never as tamper-evident: anyone
with raw write access to the DB in signed mode can set it to anything.

The private signing key is generated on first use and stored in the
macOS Keychain under service `com.jasp.my-secrets.audit-signing`,
account `default`. The matching public key is written to
`~/.local/share/my-secrets/audit-pub.key` (base64, 0644) so anyone with
read access to the audit DB can verify offline.

This mode signs the **local SQLite chain only**. It neither pushes
per-user read events to a shared repository nor prevents a recipient
from decrypting a shared-store ciphertext directly with `gpg` or
`gopass`. Those are separate, not-yet-implemented guarantees.

To verify:

```
mys audit verify --signatures
```

The verifier re-computes `canonical_bytes` per row, walks the chain,
and checks every Ed25519 signature against the public-key file. Output:

- `audit ok — N signed rows verified` on success
- `audit tampered: seqs [..] failed signature check` on any mismatch

**Threat model coverage — why the triggers alone are insufficient.**
The `BEFORE UPDATE` / `BEFORE DELETE` triggers run inside the same
SQLite DB that an attacker with write access can modify. `DROP TRIGGER
audit_no_update; UPDATE audit_log SET reason='...';` is a two-statement
bypass. Sign-mode defeats this: an attacker without the Keychain-held
private key cannot produce a valid signature for their forged row, and
the chain linkage means any silent edit upstream of a later row breaks
that later row's `prev_hash` check too. The tamper event becomes
*detectable*, not *preventable*.

**Cross-platform note.** The keychain backend is
[`zalando/go-keyring`](https://github.com/zalando/go-keyring). On macOS
it uses the system Keychain directly; on Linux it requires a running
Secret Service (e.g. GNOME Keyring). If the platform lacks a keyring
daemon, `mys` with `MYS_AUDIT_SIGN=1` will refuse to start — by design.
Unset the env to fall back to trigger-only mode, or provide a working
keychain.

## File permissions

| File                                               | Mode           |
| -------------------------------------------------- | -------------- |
| `~/.config/my-secrets/scope-policy.yaml`           | `0o600` on create |
| `~/.local/share/my-secrets/audit.sqlite`           | `0o600` on create |
| `~/.local/share/my-secrets/` directory              | `0o700` on create |
| gopass store                                        | gopass-managed, typically `0o700` on the directory, `0o600` on files |

## Web UI

- Binds on `127.0.0.1` only. A middleware rejects any `RemoteAddr` that
  is not loopback as a belt-and-suspenders measure.
- **Login is the single authentication point.** A successful login
  issues an HttpOnly, `SameSite=Lax` session cookie valid for 30 minutes
  of activity; the server shuts itself down after 30 minutes of no
  active session. Everything behind that gate — browsing, revealing,
  copying — is then frictionless. The prompt is a real Touch ID sheet
  via `LocalAuthentication`/`LAContext`
  (`deviceOwnerAuthentication` — biometrics with automatic macOS-password
  fallback), implemented in `internal/web/auth_touchid_darwin.m` +
  `auth_touchid_darwin_cgo.go`. Requires cgo (on by default in a macOS
  `go build`); a `CGO_ENABLED=0` darwin build falls back to a
  `security authorize` password dialog (`auth_touchid_darwin_nocgo.go`).
  Caveat: LocalAuthentication needs a code-signed binary to show
  biometrics — the toolchain's ad-hoc signature is usually enough, but
  on some setups it can still fall back to the password sheet (graceful,
  not a failure).
- **Reveal is session-only, by deliberate design.** Revealing/copying a
  value (`POST /entries/{path}`) does **not** re-authenticate per
  action. This is an owner's decision, not an oversight, and it reverses
  an earlier per-reveal-Touch-ID design. The rationale: the CLI
  `mys get --reveal` already re-decrypts freely within the GPG agent's
  cache and is strictly more powerful than this loopback UI, so a
  per-reveal biometric in the browser added friction without adding real
  security under this tool's single-user, local threat model. What is
  preserved: `App.Get` still re-checks scope policy on every reveal (a
  denied path is refused `403` and logged), and every reveal still
  writes a `get` audit row identical to `mys get --reveal`. So the audit
  trail — "which value was revealed, when" — is unchanged; only the
  per-action prompt is gone. If you want the stricter posture back, the
  reveal handler is the single place to re-add an auth call.
- Browsing entries and metadata (`/entries`, `/entries/{path}` on `GET`)
  never counts as reading a secret — it decrypts entries to render
  metadata but writes an aggregated `list_detail` audit action, not
  `get`. This keeps "last read per entry" (audit log, action=get)
  meaningful, and is what the start page's "zuletzt benutzt" list is
  built from.
- Every response behind the login gate carries `Cache-Control: no-store`
  so a revealed value is never written to a disk or proxy cache. The
  client-side auto-blank-after-30s and copy buttons are UX, not security
  controls.
  - The entries table's and start page's inline "copy password" buttons
    hit the same `POST /entries/{path}` endpoint with
    `Accept: application/json`, getting `{"password": "..."}` back
    instead of the HTML page. Same policy check, same `get` audit row —
    just no page navigation.
- Custom `Fields` values are masked the same way `Password` is whenever
  the field's key looks credential-shaped (`password`, `secret`, `token`,
  `api_key`, `private_key`, `credential` — see
  `store.IsSecretLikeFieldKey`). This is a heuristic blocklist, not a
  guarantee: a field named something outside that list (e.g. a
  home-grown `field.pin`) renders unmasked. Prefer the well-known
  `Password`/TOTP fields for anything sensitive.
- No separate CSRF token on the reveal form: the session cookie is
  `SameSite=Lax`, which browsers do not attach to a **cross-site**
  `POST` — a forged form on a different domain cannot reach the auth
  gate at all. Narrower case not covered: `SameSite` treats different
  ports on `127.0.0.1`/`localhost` as the *same* site, so another local
  process on a different loopback port could get the cookie attached to
  a same-site POST. Under session-only reveal this means such a process,
  *while a login session is active*, could trigger a reveal it can read
  the response of only if it is same-origin (the browser's same-origin
  policy still blocks a different origin from reading the body). Residual
  risk is bounded by the single-user local threat model: anything
  running as you on your unlocked machine can already run `mys get
  --reveal` directly.
- If you want to expose the UI through an SSH tunnel, the Touch-ID gate
  still applies remotely, but be aware a tunnel puts the loopback
  restriction on the *remote* end, not yours — only tunnel to machines
  you trust.
- **Post-login redirect (`?next=`).** `authGate` sends an
  unauthenticated request to `/login?next=<original request>` so a deep
  link (or the installed PWA's `start_url`) survives the login round
  trip. `next` is otherwise fully attacker-controlled — it's reflected
  into a `Location` header and a hidden form field — so `safeNextPath`
  restricts it to a same-origin absolute path before it's ever used:
  rejects `//host` and `http://host` (open-redirect off this server)
  and a leading backslash (some browsers resolve `\` the same as `/`
  when following a `Location` header, which plain `url.Parse` would not
  by itself flag as absolute).
- **LaunchAgent autostart (`mys web install`).** Installs
  `~/Library/LaunchAgents/com.jasp.my-secrets.web.plist` with
  `KeepAlive` unconditional, so the server process restarts immediately
  after the normal 30-minute idle-shutdown, not just after a crash. This
  does **not** weaken the login requirement: session state lives only in
  the process's memory (`internal/web/session.go`), so a relaunched
  process starts with zero active sessions and the next request always
  hits Touch ID again — only the *port* stays reachable, never an
  authenticated session. `mys web uninstall` removes the LaunchAgent;
  `mys web status` reports whether it's currently active.

## MCP server

- Reads JSON-RPC from stdin line-by-line, 1 MiB cap per line via
  `bufio.Scanner`. Malformed JSON returns a parse error and the stream
  continues.
- Does not expose `creds_set`, `creds_rotate`, or `creds_remove` — the
  MVP MCP surface is read-only for AI callers by design. Writes go
  through the CLI only (with `actor_kind=ai` audit if the caller
  explicitly uses `--requester claude-code`).
- Every denied `creds_get` returns a structured `{ denied, reason,
  path }` payload — never the secret value.

## Caller impersonation

The `--requester` flag is a convenience for humans and scripts that
want to be transparent about their role. An attacker-controlled process
can obviously set it to whatever it wants — the flag is **not** a
security boundary. The security boundary for AI callers is the MCP
server itself, which ignores the flag and enforces `actor_kind=ai`.

## Git-based sync

`mys sync setup` optionally turns the local gopass store into a
git-backed store pushed to a private GitHub repo. This default path is
deliberately scoped to **personal device redundancy** — keeping your own
secrets mirrored across your own machines. Likewise,
`mys recipient add` without `--mount` is only for the same person's
additional device or hardware-token keys. A colleague's key must never
be added to that personal recipient set.

### Explicit shared mounts

`mys sync shared setup` provisions a separate, non-root gopass mount and
persists `shared: true` for that mount in
`~/.config/my-secrets/sync.yaml`. Its `.gpg-id` contains the distinct
GPG fingerprints of all team members rather than one GPG key shared by
several people.

The repository-local `team-keys.yaml` is the normal, reusable source of
truth for provisioning:

```yaml
version: 1
members:
  - name: Alice Example
    fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
    email: alice@example.org
    public_key: keys/alice.asc
```

The loader requires a valid name, email, and 40-hex-character
fingerprint for every unique member. `public_key` is optional and is
resolved as a repository-relative regular file without symlink or
parent-directory traversal. Provisioning imports those public keys,
checks that every fingerprint is available and at least one matching
secret key is local, converges the exact `.gpg-id` set, commits the
manifest/assets, and pushes the remote before persisting the shared
configuration.

As a bootstrap alternative, setup accepts a repeated `--fingerprint`
list when all corresponding public keys are already imported. That path
does not create an identity manifest; later foreign-team additions still
fail closed until a valid `team-keys.yaml` exists in the live mount.
Shared setup itself is hard-denied for AI callers; `--yes` only bypasses
the interactive question for an invocation still classified as human.

Mount-targeted recipient commands use
`mys recipient add|list|remove --mount <name>`. A foreign-key add fails
closed unless the live mount is non-root, its sync entry is explicitly
shared, and its manifest validates. A fingerprint missing from the
manifest produces a warning rather than a hard failure because the
manifest may lag a newly added member; the manifest still wins on the
next full provisioning reconciliation. The same applies to removal:
leaving a removed member in the manifest causes a later provisioning run
to add that fingerprint again. Recipient mutations remain hard-denied
for AI callers, and adding requires explicit human confirmation (or the
human-supplied `--yes`).

Shared setup and recipient reconciliation are serialized per mount.
Provisioning adds new recipients before removing stale ones, makes at
most one reconcile-and-retry after a concurrent non-fast-forward push,
and refuses path/mount collisions with the personal root store. The
ordinary write-triggered auto-sync skips shared remotes; shared
provisioning pushes its own changes, while explicit `mys sync push` and
`mys sync pull` handle configured remotes.

### Advisory guarantee

Every recipient owns a private key that can decrypt every secret in the
shared mount. Once enrolled, that person can call bare `gpg` or
`gopass`, copy old ciphertext, and leave **no** `mys` audit row. The
current audit database is local to each machine; the optional signed
chain above protects one local log but is not an aggregated team-read
audit. Scope policy also gates only compliant, machine-local callers.

Therefore phases 1–2 provide shared availability, distinct recipient
keys, and a reusable fingerprint-to-identity manifest, but not a
provable „who read what" record or instant revocation. Removing a key
prevents future decryption only after re-encryption and does not retract
old copies; rotate every secret the departed recipient could access.
For authoritative per-user access control, use a brokered/hosted vault
such as Bitwarden rather than treating this client-side model as
enforceable.

Tier-A phases not present here are Bitwarden-to-shared seeding (phase 3),
the signed shared read-audit and team aggregation (phase 4), fail-closed
shared-read policy (phase 5), and an automated
revocation/rotation runbook (phase 6).

Sync-related subprocess calls (`gh`, `gopass git …`, `gopass sync`) are
an explicit exception to the library-only rule. They run outside the
hot secret-access path, do not read or write decrypted secret values,
and the corresponding CLI operation records an audit outcome with
`action=sync_{setup,push,pull}`. Shared provisioning reuses
`sync_setup`.

## Known limitations

- No secure-enclave signing of audit entries (Ansatz A/B feature).
- No rate-limiting on MCP calls — a runaway AI could flood the audit log.
- `mys get --format env` writes to stdout in the clear; piping to a file
  is the user's responsibility.
- `mys bw-export` writes plaintext secrets to disk — this is the only
  path that does so, and it is explicitly opt-in.

## Reporting issues

If you find a security issue, email the author or open a private issue
on the repo. Do not post exploit details publicly until a fix is
released.
