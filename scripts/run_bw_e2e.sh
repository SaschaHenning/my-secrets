#!/usr/bin/env bash
# E2E validation of the Bitwarden export format (issue #86):
# spins up a throwaway Vaultwarden with self-signed TLS, registers a
# test account (scripts/bw_e2e_register.py), imports the golden export
# file through the real `bw import bitwardenjson` path and asserts that
# items, folders, custom fields and TOTP codes survive the round trip.
#
# Everything is volatile: the container has no persistent volume, the
# bw CLI state lives in a temp dir, and both are removed on exit.
#
# Requirements: docker (running daemon), bw (bitwarden-cli), python3,
# openssl, curl. Network: pulls vaultwarden/server:latest once.

set -euo pipefail

PORT="${BW_E2E_PORT:-8443}"
EMAIL="test@mys.local"
PASSWORD="MysE2e-Passw0rd!"
CONTAINER="mys-bw-e2e"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GOLDEN="$REPO_ROOT/internal/bw/testdata/export_golden.json"

for dep in docker bw python3 openssl curl; do
  command -v "$dep" >/dev/null || { echo "missing dependency: $dep" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "docker daemon not running" >&2; exit 1; }
[ -f "$GOLDEN" ] || { echo "golden file missing: $GOLDEN" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mys-bw-e2e.XXXXXX")"
export BITWARDENCLI_APPDATA_DIR="$WORK/bwcli"
export NODE_EXTRA_CA_CERTS="$WORK/certs/cert.pem"
mkdir -p "$WORK/certs" "$BITWARDENCLI_APPDATA_DIR"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== self-signed cert ==="
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" -days 2 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 644 "$WORK/certs/key.pem" "$WORK/certs/cert.pem"

echo "=== vaultwarden container ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --rm -p "$PORT:80" \
  -v "$WORK/certs:/certs:ro" \
  -e 'ROCKET_TLS={certs="/certs/cert.pem",key="/certs/key.pem"}' \
  -e SIGNUPS_ALLOWED=true \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  vaultwarden/server:latest >/dev/null
for _ in $(seq 1 30); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:$PORT/alive")" = "200" ] && break
  sleep 2
done
[ "$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:$PORT/alive")" = "200" ] \
  || { echo "vaultwarden did not come up on :$PORT" >&2; exit 1; }

echo "=== register test account ==="
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" -q install cryptography requests
"$WORK/venv/bin/python" "$REPO_ROOT/scripts/bw_e2e_register.py" \
  "https://localhost:$PORT" "$EMAIL" "$PASSWORD" "$WORK/certs/cert.pem"

echo "=== bw login + import ==="
bw config server "https://localhost:$PORT" >/dev/null
SESSION="$(bw login "$EMAIL" "$PASSWORD" --raw)"
bw import bitwardenjson "$GOLDEN" --session "$SESSION"
bw sync --session "$SESSION" >/dev/null

echo "=== assertions ==="
bw list items --session "$SESSION" >"$WORK/items.json"
bw list folders --session "$SESSION" >"$WORK/folders.json"
python3 - "$WORK/items.json" "$WORK/folders.json" <<'PY'
import json, sys

items = json.load(open(sys.argv[1]))
folders = {f["id"]: f["name"] for f in json.load(open(sys.argv[2]))}

assert len(items) == 3, f"want 3 items, got {len(items)}"
names = {f for f in folders.values()}
for want in ("mys", "mys/jasp", "mys/zuhause"):
    assert want in names, f"missing folder {want}: {sorted(names)}"
for it in items:
    assert it["type"] == 1, f"{it['name']}: type={it['type']}, want 1 (login)"
    fname = folders.get(it["folderId"], "")
    assert fname.startswith("mys"), f"{it['name']}: outside mys namespace ({fname!r})"
    fields = {f["name"] for f in it.get("fields") or []}
    assert "mys-path" in fields, f"{it['name']}: mys-path field missing"
totp = [i for i in items if (i["login"] or {}).get("totp")]
assert len(totp) == 1, f"want exactly 1 totp item, got {len(totp)}"
print("payload assertions OK")
PY

ID="$(bw list items --search github-2fa --session "$SESSION" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')"
CODE="$(bw get totp "$ID" --session "$SESSION")"
case "$CODE" in
  [0-9][0-9][0-9][0-9][0-9][0-9]) echo "totp code OK ($CODE)" ;;
  *) echo "totp code invalid: $CODE" >&2; exit 1 ;;
esac

echo
echo "BW E2E: ALL GREEN"
