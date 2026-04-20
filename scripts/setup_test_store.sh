#!/usr/bin/env bash
# Sets up an isolated gopass store in a throwaway directory with a test GPG key.
# Produces an env-file snippet that callers can `source` to get GNUPGHOME and
# PASSWORD_STORE_DIR pointing at the throwaway store.

set -euo pipefail

ROOT="${1:-/tmp/mys-e2e}"
rm -rf "$ROOT"
mkdir -p "$ROOT/gnupg" "$ROOT/store"
chmod 700 "$ROOT/gnupg"

export GNUPGHOME="$ROOT/gnupg"
export PASSWORD_STORE_DIR="$ROOT/store"

# 1. Generate a passphrase-less test key in batch mode.
cat >"$ROOT/keygen" <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 3072
Subkey-Type: RSA
Subkey-Length: 3072
Name-Real: my-secrets E2E Test
Name-Email: e2e@mys.local
Expire-Date: 1y
%commit
EOF

gpg --batch --quiet --generate-key "$ROOT/keygen"
FP=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
echo "GPG fingerprint: $FP" >&2

# 2. Initialise gopass with the test key, non-interactively.
gopass --yes setup --crypto gpg --storage fs --name "e2e" \
  --email "e2e@mys.local" --alias "" >/dev/null 2>&1 || true

# Sometimes `gopass setup` still asks which key if multiple exist. Fall back
# to `gopass init`:
if [ ! -f "$PASSWORD_STORE_DIR/.gpg-id" ]; then
  gopass init --path "$PASSWORD_STORE_DIR" --crypto gpg "$FP" >/dev/null 2>&1 || true
fi

# Make sure the store knows the key. If .gpg-id doesn't exist, create it.
if [ ! -f "$PASSWORD_STORE_DIR/.gpg-id" ]; then
  echo "$FP" > "$PASSWORD_STORE_DIR/.gpg-id"
fi

echo "export GNUPGHOME=$GNUPGHOME"
echo "export PASSWORD_STORE_DIR=$PASSWORD_STORE_DIR"
echo "export MYS_E2E_ROOT=$ROOT"
