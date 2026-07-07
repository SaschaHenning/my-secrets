#!/usr/bin/env bash
# E2E validation of `mys bw-push` (issue #87): spins up a throwaway
# Vaultwarden with self-signed TLS (same scaffold as run_bw_e2e.sh),
# registers a test account, plants one UNRELATED item outside the mys/*
# namespace, then runs the Go E2E test (cmd/mys TestBwPushE2E) which
# pushes, re-pushes (idempotence), rotates + pushes, and prunes through
# the real bw CLI. Afterwards this script asserts that the unrelated
# item is byte-identical and that the pruned item landed in the trash.
#
# Requirements: docker (running daemon), bw (bitwarden-cli), go,
# python3, openssl, curl. Network: pulls vaultwarden/server:latest once.

set -euo pipefail
umask 077

PORT="${BW_E2E_PORT:-8443}"
EMAIL="test@mys.local"
PASSWORD="${BW_E2E_PASSWORD:-MysE2e-Passw0rd!}"
CONTAINER="mys-bw-push-e2e"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for dep in docker bw go python3 openssl curl; do
  command -v "$dep" >/dev/null || { echo "missing dependency: $dep" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "docker daemon not running" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mys-bw-push-e2e.XXXXXX")"
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
chmod 600 "$WORK/certs/key.pem"
chmod 644 "$WORK/certs/cert.pem"

echo "=== vaultwarden container ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --rm -p "127.0.0.1:$PORT:80" \
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
BW_E2E_PASSWORD="$PASSWORD" "$WORK/venv/bin/python" "$REPO_ROOT/scripts/bw_e2e_register.py" \
  "https://localhost:$PORT" "$EMAIL" "$WORK/certs/cert.pem"

echo "=== bw login ==="
bw config server "https://localhost:$PORT" >/dev/null
# Session + master password travel via env, never argv (ps-visible).
BW_SESSION="$(BW_PASSWORD="$PASSWORD" bw login "$EMAIL" --passwordenv BW_PASSWORD --raw)"
export BW_SESSION

echo "=== plant unrelated personal item (outside mys/*) ==="
UNRELATED_ID="$(printf '{"type":1,"name":"personal-untouchable","notes":"hands off","login":{"username":"me","password":"personal-pw"}}' \
  | base64 | bw create item \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
bw sync >/dev/null
bw get item "$UNRELATED_ID" >"$WORK/unrelated-before.json"

echo "=== run Go push E2E ==="
(cd "$REPO_ROOT" && MYS_BW_E2E=1 go test -count=1 -v -run TestBwPushE2E ./cmd/mys/)

echo "=== assert unrelated item untouched ==="
bw sync >/dev/null
bw get item "$UNRELATED_ID" >"$WORK/unrelated-after.json"
if ! cmp -s "$WORK/unrelated-before.json" "$WORK/unrelated-after.json"; then
  echo "unrelated item changed during push!" >&2
  diff "$WORK/unrelated-before.json" "$WORK/unrelated-after.json" >&2 || true
  exit 1
fi
echo "unrelated item byte-identical OK"

echo "=== assert pruned item is in the trash (soft delete) ==="
bw list items --trash >"$WORK/trash.json"
python3 - "$WORK/trash.json" <<'PY'
import json, sys
trash = json.load(open(sys.argv[1]))
names = [i["name"] for i in trash]
assert any(n == "github-2fa" for n in names), f"pruned item not in trash: {names}"
print("trash contains pruned item OK")
PY

echo
echo "BW-PUSH E2E: ALL GREEN"
