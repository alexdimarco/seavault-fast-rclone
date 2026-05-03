# Validation checklist

## Functional

- `go test ./...` passes.
- `go build ./cmd/seavault` succeeds.
- `scripts/smoke-test.sh` can initialize, put, list, get, verify, stats, remove, and garbage-collect a test vault.
- `seavault gui` opens the browser UI and can upload/download a file.
- `seavault serve` accepts basic WebDAV `PUT`, `GET`, `DELETE`, and `PROPFIND` requests.

## Storage

- The configured vault path is inside the desired sync-client directory.
- No plaintext file contents appear under `.seavault`.
- New vaults create `objects/chunks` and `manifests` sharded trees.
- Re-uploading identical content does not increase the encrypted chunk-object count.

## Security

- Wrong password fails to unlock the vault.
- Tampering with an encrypted chunk causes `verify` to fail.
- Tampering with an encrypted manifest causes manifest decryption/authentication failure.
- CLI password prompts do not echo input.
- OS keychain storage can be enabled and disabled per vault.

## Sync conflict handling

- A duplicate manifest for the same virtual path is preserved as a conflict copy.
- An older duplicate manifest does not override a newer live manifest.
- A newer delete tombstone prevents stale conflict copies from resurrecting a deleted file.
- User-facing conflict names are visible through `list`, GUI, and WebDAV.

## Rclone transport

- `seavault rclone install --from-binary <known-rclone>` records a managed runtime outside the vault.
- `seavault rclone verify-runtime` detects binary hash mismatches.
- `seavault rclone status --check-update` reports installed and latest runtime status.
- `seavault remote add` saves profiles outside the vault.
- `seavault remote dry-run` uses copy-safe rclone commands and does not call destructive sync.
- `seavault remote push` transfers only `.seavault` objects.
- `seavault remote pull` can populate a second vault directory from the encrypted remote copy.
- `scripts/rclone-local-smoke-test.sh` passes without external cloud credentials.
- Rclone config redaction removes tokens, secrets, passwords, and key material from support output.
- SSH private keys are stored in app configuration, not in `.seavault`.

## Compliance evidence to collect

- Runtime version and SHA256 hash.
- Runtime source URL or offline artifact provenance.
- Remote profile target type and provider region.
- Confirmation that plaintext files are not present in the remote target.
- Rclone transfer logs with secrets redacted.
- Data-residency and support-access evidence for the chosen provider.
- Key rotation and lost-device revocation procedure.
