# Security

## Threat model

my-secrets is a single-user macOS tool. The threat model matches that:

| In scope                                                   | Out of scope                               |
| ---------------------------------------------------------- | ------------------------------------------ |
| A compromised AI agent reading secrets it should not touch | Nation-state attackers with physical root  |
| Casual exfiltration of the DB to another machine           | Supply-chain compromise of gopass upstream |
| Local shell scripts that should not access `private/**`    | Kernel-level keylogging                    |
| Audit-log tampering by careless tools                      | Side-channels on the CPU                   |

The guarantees we try to uphold:

1. Secrets are at rest only in gopass (GPG-encrypted, keyed by a GPG
   private key in the macOS Keychain).
2. Every access through `mys` (CLI / MCP / Web) produces an audit row.
3. Policy denials are hard failures — never warnings, never partial
   reveals.
4. Copying the `~/.password-store` directory to another Mac does not
   grant access to the secrets without the GPG private key, which is
   Keychain-bound (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).

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

For higher assurance we would need the signed hash-chain design from
Ansatz B of the planning doc — deliberately deferred for the MVP because
the single-user threat model does not require crypto-grade audit.

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
- Read-only. No endpoint returns a secret value. The audit log shows
  paths and metadata; it never logs passwords.
- No session cookies, no CSRF tokens — read-only + loopback-only makes
  that defensible for the MVP. If you want to expose the UI through an
  SSH tunnel you should add auth first.

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
git-backed store pushed to a private GitHub repo. The feature is
deliberately scoped to **personal device redundancy** — keeping your
own secrets mirrored across your own machines.

Non-goals (explicitly): sharing credentials with colleagues. A gopass
store encrypted to a single GPG key cannot distinguish between humans
who hold that key, which means:

- The audit log loses its „who accessed this secret" signal the moment
  a second human shares the key.
- Revocation would require rotating every credential in the store.
- There is no per-user policy — the scope-policy YAML here only gates
  machine-local callers (human vs. AI).

For team-shared credentials, use Bitwarden (or a comparable hosted
vault) that enforces per-user identity. The setup wizard prints this
scope anchor before any destructive step and requires explicit
confirmation.

Sync-related subprocess calls (`gh`, `gopass git …`, `gopass sync`) are
an explicit exception to the library-only rule. They run outside the
hot secret-access path, do not read or write decrypted secret values,
and every invocation writes an audit row with
`action=sync_{setup,push,pull}`.

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
