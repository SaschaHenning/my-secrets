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
cannot reach a denied path.** Two layers make that stick:

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
- An AI agent that has shell access and is NOT restricted to MCP tools.
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
