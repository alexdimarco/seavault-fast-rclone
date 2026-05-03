#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
ADDR="127.0.0.1:18787"
URL="http://$ADDR"
LOG="$WORK/gui.log"
VAULT="$WORK/cloud-sync/seavault"
PASSWORD='gui-smoke-password'

cleanup() {
  if [[ -n "${PID:-}" ]]; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

"$BIN" gui --no-open --addr "$ADDR" >"$LOG" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "$URL/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

HTML="$(curl -fsS "$URL/")"
TOKEN="$(printf '%s' "$HTML" | sed -n 's/.*data-token="\([^"]*\)".*/\1/p' | head -n 1)"
if [[ -z "$TOKEN" ]]; then
  echo "could not extract GUI token" >&2
  cat "$LOG" >&2
  exit 1
fi

post_json() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -H "X-SeaVault-Token: $TOKEN" \
    -d "$body" \
    "$URL$path"
}

mkdir -p "$(dirname "$VAULT")"
post_json /api/init "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"kdf\":\"scrypt\",\"scryptN\":16,\"scryptR\":1,\"scryptP\":1}" | grep -q '"opened":true'
curl -fsS "$URL/api/status" | grep -q '"open":true'
post_json /api/close '{}' | grep -q '"ok":true'
post_json /api/open "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"profile\":\"ignored-old-form-field\",\"kdf\":\"scrypt\",\"savePassword\":false,\"useKeychain\":false}" | grep -q '"opened":true'
curl -fsS "$URL/api/status" | grep -q '"open":true'

echo 'GUI API smoke test passed'
