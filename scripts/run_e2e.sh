#!/usr/bin/env bash
# Runs the acceptance-criteria scenario matrix against the current binary
# using a throwaway test store. Expects GNUPGHOME to point at the test
# keyring (see setup_test_store.sh).
#
# This script works both from a human terminal and from inside Claude Code.
# When run inside Claude Code, the parent-process chain contains claude,
# so --requester human cannot downgrade the classification (by design —
# see the security-review follow-up notes). The "human" scenarios are
# therefore also exercised via the normal unit-test suite, which runs in
# a pure Go test environment with no AI ancestry.

set -euo pipefail

MYS="${MYS:-./bin/mys}"
if [ ! -x "$MYS" ]; then
  echo "binary not found at $MYS — run 'make build' first" >&2
  exit 1
fi

# Detect if we are under Claude or any other AI-ancestry session.
IS_AI_SESSION=0
if [ -n "${CLAUDECODE:-}" ] || [ -n "${CLAUDE_CODE_ENTRYPOINT:-}" ]; then
  IS_AI_SESSION=1
fi
if ps -o comm= -p "$PPID" 2>/dev/null | grep -qi claude; then
  IS_AI_SESSION=1
fi

# Reset local state for a clean run.
rm -f "$HOME/.local/share/my-secrets/audit.sqlite"*
rm -f "$HOME/.config/my-secrets/scope-policy.yaml"

echo "=== init ==="
$MYS init

if [ "$IS_AI_SESSION" -eq 1 ]; then
  echo
  echo "=== detected AI session — running AI-only scenarios ==="
  echo "(human scenarios are covered by the Go unit tests)"
  REQUESTER=claude-code
  CAN_WRITE_PRIVATE=0
else
  REQUESTER=human
  CAN_WRITE_PRIVATE=1
fi

echo
echo "=== add jasp/github-test ==="
echo "ghp_testtoken_0123456789abcdef" | $MYS --requester "$REQUESTER" add jasp/github-test \
  --kind api_key --user sascha --url https://github.com \
  --github SaschaHenning/my-secrets --tags infra,test

echo
echo "=== add zuhause/proxmox-root ==="
echo "proxmox-root-pw" | $MYS --requester "$REQUESTER" add zuhause/proxmox-root \
  --kind password --user root --url https://192.168.0.5

if [ "$CAN_WRITE_PRIVATE" -eq 1 ]; then
  echo
  echo "=== add private/bank-pin (as human) ==="
  echo "super-secret-bank-pin" | $MYS --requester human add private/bank-pin \
    --kind password --notes "personal"
fi

echo
echo "=== read jasp/github-test as $REQUESTER (expect ok) ==="
$MYS --requester "$REQUESTER" get jasp/github-test --reveal

echo
echo "=== read jasp via AI (expect ok) ==="
$MYS --requester claude-code get jasp/github-test --reveal

echo
echo "=== attempt to write private/deny-test as AI (expect DENY) ==="
if echo "nope" | $MYS --requester claude-code add private/deny-test 2>&1; then
  echo "FAIL: AI write to private should have been denied"
  exit 1
else
  echo "OK: AI write to private was denied"
fi

echo
echo "=== ai ls (expect jasp + zuhause, no private) ==="
$MYS --requester claude-code ls

echo
echo "=== search 'github' ==="
$MYS --requester "$REQUESTER" search github

echo
echo "=== ls --tag test ==="
$MYS --requester "$REQUESTER" ls --tag test

echo
echo "=== audit verify ==="
$MYS audit verify

echo
echo "=== audit tail (last 20) ==="
$MYS audit tail --limit 20

echo
echo "=== audit since today ==="
$MYS audit since "$(date -u +%Y-%m-%d)" --limit 50 | head -10

echo
echo "E2E scenarios passed."
