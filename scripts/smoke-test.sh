#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-seavault}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SEAVAULT_PASSWORD='smoke-test-password'
VAULT="$WORK/cloud-sync/SeaVault"
SRC="$WORK/source.txt"
OUT="$WORK/out.txt"

mkdir -p "$(dirname "$VAULT")"
printf 'hello encrypted cloud storage\n' > "$SRC"

"$BIN" init -kdf scrypt -scrypt-n 16 -scrypt-r 1 -scrypt-p 1 "$VAULT" >/dev/null
"$BIN" put "$VAULT" "$SRC" docs/source.txt >/dev/null
"$BIN" list "$VAULT" | grep -q '^docs/source.txt$'
"$BIN" get "$VAULT" docs/source.txt "$OUT" >/dev/null
cmp "$SRC" "$OUT"
EXPORT_DIR="$WORK/export"
"$BIN" export --dry-run "$VAULT" . "$EXPORT_DIR" >/dev/null
"$BIN" export "$VAULT" docs "$EXPORT_DIR" >/dev/null
cmp "$SRC" "$EXPORT_DIR/source.txt"
"$BIN" verify "$VAULT" >/dev/null
"$BIN" stats "$VAULT" >/dev/null
"$BIN" remove "$VAULT" docs/source.txt >/dev/null
"$BIN" gc "$VAULT" >/dev/null

echo 'smoke test passed'
