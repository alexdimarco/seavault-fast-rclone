#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
export SEAVAULT_APP_HOME="$WORK/app-home"
mkdir -p "$SEAVAULT_APP_HOME"
ADDR="127.0.0.1:18878"
URL="http://$ADDR"
LOG="$WORK/webdav.log"
VAULT="$WORK/cloud-sync/seavault"
PASSWORD='webdav-smoke-password'

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

HTML="$(curl -fsS "$URL/files/")"
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

dav() {
  local method="$1"
  local path="$2"
  shift 2
  curl -fsS -X "$method" -H "X-SeaVault-Token: $TOKEN" "$@" "$URL/dav/$TOKEN/$path"
}

mkdir -p "$(dirname "$VAULT")"
post_json /api/init "{\"vaultPath\":\"$VAULT\",\"password\":\"$PASSWORD\",\"kdf\":\"scrypt\",\"scryptN\":16,\"scryptR\":1,\"scryptP\":1}" | grep -q '"opened":true'

printf 'webdav smoke\n' > "$WORK/a.txt"
curl -fsS -T "$WORK/a.txt" -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/a.txt" >/dev/null
curl -fsS -X PROPFIND -H 'Depth: 1' -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/" | grep -q '/content/'
curl -fsS -X PROPFIND -H 'Depth: 1' -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/" | grep -q 'a.txt'
curl -fsS -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/a.txt" | grep -q 'webdav smoke'
curl -fsS -X COPY -H "Destination: /dav/$TOKEN/docs/b.txt" -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/a.txt" >/dev/null
curl -fsS -X MOVE -H "Destination: /dav/$TOKEN/docs/c.txt" -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/b.txt" >/dev/null
curl -fsS -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/c.txt" | grep -q 'webdav smoke'
curl -fsS "$URL/api/export-zip?path=docs&token=$TOKEN" >/dev/null
curl -fsS -X DELETE -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/docs/c.txt" >/dev/null

if curl -fsS -X PUT -d bad -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/.seavault/bad" >/dev/null 2>&1; then
  echo 'expected .seavault PUT to fail' >&2
  exit 1
fi
post_json /api/webdav '{"readOnly":true}' | grep -q '"readOnly":true'
if curl -fsS -X PUT -d bad -H "X-SeaVault-Token: $TOKEN" "$URL/dav/$TOKEN/readonly.txt" >/dev/null 2>&1; then
  echo 'expected readonly PUT to fail' >&2
  exit 1
fi

echo 'WebDAV file manager smoke test passed'
