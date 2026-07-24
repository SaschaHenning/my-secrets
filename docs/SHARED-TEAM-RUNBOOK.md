# Shared Team Store Runbook

This runbook operates the Tier-A shared-store model: one gopass mount per
team, one GPG recipient key per member, a mount-local policy, and signed
per-device read events in a separate private Git repository.

## Security boundary

The signed audit is an application-layer, advisory guarantee:

- Reads through `mys` are policy-checked and can produce verified signed
  team events.
- A recipient private-key holder can bypass `mys` with raw `gpg`, `pass`, or
  `gopass`. Such a read cannot be prevented or detected by this design.
- Removing a recipient cannot retract plaintext or old ciphertext already
  copied. Revocation is complete only after re-encryption, publication, and
  rotation of every potentially exposed secret value.
- Team audit events contain secret paths and identity metadata, but never
  secret values. The audit repository must nevertheless remain private.

Use a brokered vault with server-side authorization when enforceable
per-user access control is required.

## Files and state

| Purpose | Location |
|---|---|
| Sync and audit remote config | `~/.config/my-secrets/sync.yaml` |
| Global policy | `~/.config/my-secrets/scope-policy.yaml` |
| Mount policy | `~/.config/my-secrets/shared-policies/<mount>.yaml` |
| Stable local device UUID | `~/.config/my-secrets/team-audit/device.id` |
| Audit working clone | OS cache dir under `my-secrets/team-audit/<mount>/repository` |
| Rollback watermarks | `~/.local/state/my-secrets/team-audit/<mount>/watermarks-v1.json` |
| Team identity manifest | `<shared-mount>/team-keys.yaml` |
| Current recipient set | `<shared-mount>/.gpg-id` |

`device.id`, mount policies, and watermarks are private state and must stay
mode `0600`. Never copy one device's `device.id` onto another device: each
device must own a distinct audit branch.

## Initial provisioning

### 1. Prepare team identities

Create `team-keys.yaml` with every member's full primary GPG fingerprint,
name, email, and optional repository-relative armored public-key file:

```yaml
version: 1
members:
  - name: Alice Example
    fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
    email: alice@example.org
    public_key: keys/alice.asc
  - name: Bob Example
    fingerprint: 89ABCDEF0123456789ABCDEF0123456789ABCDEF
    email: bob@example.org
    public_key: keys/bob.asc
```

At least one listed secret key must be available locally. Provision the
shared store from a human session:

```bash
mys sync shared setup \
  --mount jasp \
  --team-keys ./team-keys.yaml \
  --owner jasp \
  --repo mys-store-shared
```

For an existing credential-free Git remote or local bare repository, replace
`--owner` and `--repo` with `--remote <url-or-absolute-path>`.

### 2. Provision the signed audit remote on every device

Use the primary fingerprint belonging to the local operator:

```bash
mys sync shared audit setup \
  --mount jasp \
  --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567 \
  --owner jasp \
  --repo mys-store-shared-audit
```

The command refuses non-human callers. It takes the global cooperative `mys`
lock, creates or validates the restrictive policy monotonically, then verifies
membership and signing identity, confirms GitHub visibility `PRIVATE`, verifies
existing audit history, and proves remote write/delete access with a unique
empty probe branch. `sync.yaml` is accepted only after reloading the persisted
target state. If a later check fails, the valid policy remains for the next
idempotent setup; it is never removed by a concurrent rollback.

Do not continue past a probe cleanup or visibility error. The setup is
intentionally fail-closed because an uncertain audit repository is not a safe
read dependency.

### 3. Review the generated mount policy

The generated file allows only the selected mount and is combined with the
global policy:

```yaml
version: 1
actors:
  human:
    allow: ["jasp/**"]
  script:
    allow: ["jasp/**"]
  ai:
    allow: ["jasp/**"]
  claude-code:
    allow: ["jasp/**"]
```

Tighten actors or add `deny` rules as needed. The exact validated file bytes
are hashed into each event. A missing, malformed, symlinked, path-escaping,
group/world-accessible, or owner-unreadable policy fails closed.

### 4. Establish verification evidence

```bash
mys recipient list --mount jasp
mys sync status
mys audit team --mount jasp --format json
```

The first successful audit verification on a device establishes its local
rollback watermark. It verifies current signatures and history, but cannot
prove that no remote rewrite happened before that first observation. For a
new verifier, compare the reported branch heads with an already trusted
verifier before accepting the new baseline.

## Routine operation

Use `mys` for every read. Do not fall back to raw store tools when a compliant
audit trail is required.

Useful verification views:

```bash
mys audit team --mount jasp
mys audit team --mount jasp --since 2026-07-01
mys audit team --mount jasp --user alice@example.org
mys audit team --mount jasp --actor claude-code --path jasp/prod
mys audit team --mount jasp --limit 0 --format json
```

Aggregation succeeds only after every selected device branch, row hash,
signature, recorded store commit, historical membership, recipient set, and
watermark passes. Treat any rollback, divergence, duplicate event ID, or
invalid historical authorization as an incident, not as a stale-cache warning.

Shared writes do not use the personal five-second auto-sync. Publish shared
changes explicitly:

```bash
mys sync push
```

An audit append counts only after the exact event IDs have been fetched back
and verified from the remote. A local, unconfirmed Git commit is not evidence.
For an AI caller, append/confirmation failure returns no plaintext or partial
result. Fix connectivity or repository state, then repeat the original read.

## Add a team member

1. Obtain and independently verify the member's primary public-key
   fingerprint.
2. Add the member and optional armored key file to `team-keys.yaml`.
3. Re-run `mys sync shared setup` with the same mount and remote. It imports
   public keys, adds recipients before any removal, re-encrypts, publishes,
   and verifies the exact `.gpg-id` set.
4. On the new member's device, provision the shared mount with the same
   manifest and run `mys sync shared audit setup` with that member's primary
   signing fingerprint.
5. Run `mys recipient list --mount <mount>` and `mys audit team --mount
   <mount>` from an existing trusted verifier.

Do not use `mys recipient add --mount` as the durable source of truth without
also updating `team-keys.yaml`; the next provisioning run converges back to
the manifest.

## Add or replace a device

1. Install the member's existing secret key securely on the new device.
2. Provision/attach the shared mount from the current `team-keys.yaml`.
3. Run `mys sync shared audit setup` with the member's configured primary
   fingerprint.
4. Confirm that a new `device.id` was generated locally and that aggregation
   sees a distinct branch.
5. Compare branch heads with a trusted existing verifier before accepting
   the new device's first watermark.

Replacing hardware does not require deleting the old audit branch. Keep it:
branch deletion is intentionally treated as rollback.

## Rotate a signing key

1. Add the new primary fingerprint and public key to `team-keys.yaml` while
   retaining the old public key in a verification keyring/archive.
2. Re-run shared-store provisioning so the new key becomes a recipient.
3. Re-run `mys sync shared audit setup` on the device with the new signing
   fingerprint.
4. Verify the new branch with `mys audit team`.
5. If the old key must lose decrypt access, follow the full revocation
   procedure below. Routine signing-key replacement alone does not revoke old
   ciphertext access.

Never delete the old audit branch or old public verification key. Historical
events retain the original signer fingerprint and require that public key for
GPG verification.

## Rotate a device identity

Rotate the UUID only when a device identity was cloned or compromised. Preserve
the old file as incident evidence, then let setup create a new one:

```bash
mv ~/.config/my-secrets/team-audit/device.id \
  ~/.config/my-secrets/team-audit/device.id.retired

mys sync shared audit setup \
  --mount jasp \
  --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567 \
  --remote <existing-audit-remote>
```

Do not delete the old remote branch. Verify that the new branch uses a distinct
device UUID.

## Revoke a member

Assume the departing member retained every value and ciphertext they could
previously access.

1. Preserve evidence before mutation:
   - run `mys audit team --mount <mount> --limit 0 --format json`;
   - record the current shared-store and audit remote heads;
   - back up this verifier's watermark file; and
   - retain the departing member's public key and existing audit branch.
2. Remove the member from the current `team-keys.yaml`. Removing only
   `.gpg-id` is temporary because provisioning restores the manifest.
3. Re-run `mys sync shared setup` with the updated manifest and the same
   shared-store remote. Confirm `mys recipient list --mount <mount>` no
   longer lists the fingerprint. Gopass re-encrypts the mount for the
   remaining recipients and the command publishes the new store commit.
4. Verify `mys audit team --mount <mount>`. Signer authorization is evaluated
   against the `StoreCommit` referenced by each event, not against event time.
   The removed signer is unauthorized only for events whose referenced commit
   was published after the removal and records that fingerprint as absent from
   both `team-keys.yaml` and `.gpg-id`. Even an event created after revocation
   remains historically authorized if it references an older commit where the
   signer was still both a member and a recipient. Event time is not a
   revocation boundary.
5. Enumerate every path the member could access:

   ```bash
   mys ls --org <mount>
   ```

6. Rotate each listed secret using its provider's real rotation workflow,
   then store the new value with:

   ```bash
   mys rotate <mount/path>
   ```

   `mys rotate` reads the new value from standard input; never place it in a
   command argument, shell history, ticket, or chat.
7. Publish and verify:

   ```bash
   mys sync push
   mys audit team --mount <mount>
   ```

Revocation is incomplete until every potentially accessible value has been
rotated at its upstream provider. Re-encryption alone only protects the new
repository state.

## Watermark backup and recovery

Back up
`~/.local/state/my-secrets/team-audit/<mount>/watermarks-v1.json` together
with the device's private configuration. Restore only a watermark previously
trusted for that verifier and audit remote.

If the watermark is lost:

1. stop treating that client as rollback-detecting;
2. compare all remote audit branch OIDs and event counts with another trusted
   verifier or preserved incident record;
3. run `mys audit team --mount <mount>` only after that comparison; and
4. back up the newly established watermark.

Never silence a rollback error by deleting the watermark. That discards the
only local evidence of previously observed remote history.

## Incident checklist

Treat these as blocking incidents:

- audit repository visibility is not confirmed private;
- the write probe cannot be confirmed deleted;
- an audit branch disappears, shrinks, or stops descending from its
  watermark;
- a signer is not authorized at the recorded store commit;
- `.gpg-id`, `team-keys.yaml`, policy bytes, or store commit changes between
  preflight and signing;
- a batch is only partially present or an event ID reappears with different
  attribution/snapshot; or
- a device/private signing key is cloned or suspected compromised.

Preserve store history, audit branches, public keys, watermarks, and command
errors. Do not rewrite or force-push either repository while investigating.
