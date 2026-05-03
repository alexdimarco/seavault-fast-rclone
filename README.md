# SeaVault Fast

SeaVault Fast is a cross-platform prototype for client-side encrypted storage. It stores plaintext only on the local client, splits files into Seafile-style content-defined chunks, encrypts chunks and sharded manifests, and transports only the encrypted `.seavault` repository.

This repository is a working MVP, not an audited production replacement for Cryptomator.

## What changed in v0.4

- Added rclone as the primary remote transport backend.
- Added an app-managed rclone runtime; users do not need system rclone.
- Added CLI commands for rclone runtime status, install, update, rollback, path, version, and verification.
- Added remote repository profiles for local and rclone targets.
- Added GUI panels for rclone runtime management, remote profiles, transfer actions, and SSH key management.
- Added safe copy-first remote operations: dry-run, push, pull, test, and check.
- Kept destructive `rclone sync` out of the default GUI flow.
- Added basic SSH key generation/import/list/public-key workflows for rclone SFTP profiles.
- Added tests for rclone runtime registration, profile storage, redaction, SSH keys, and rclone command construction.

## Encrypted sync location

The vault path is the encrypted local storage location. Put it inside a folder watched by a desktop sync client when using local-sync mode:

```bash
seavault init --profile nextcloud "~/Nextcloud/seavault"
seavault put nextcloud ./report.pdf reports/report.pdf
seavault list nextcloud
seavault get nextcloud reports/report.pdf ./recovered/report.pdf
```

The provider sees only `.seavault/vault.json`, encrypted chunk objects, encrypted manifests, and tombstones. Plaintext files stay outside the vault unless explicitly exported/downloaded.

## Rclone transport model

Rclone is the app-managed transport runtime, not the encryption layer. Rclone never receives plaintext user files; it only copies `<vault>/.seavault`.

Safe defaults:

```text
push:    rclone copy local .seavault objects/manifests/tombstones to remote
pull:    rclone copy remote .seavault to local
check:   rclone check local .seavault and remote .seavault
sync:    not exposed as a default GUI action
```

## Managed rclone runtime

Install or register a managed rclone runtime:

```bash
# Online install, latest stable
seavault rclone install

# Offline/controlled registration from an existing binary
seavault rclone install --from-binary /usr/local/bin/rclone --signature skip

# Status, update, rollback, and verification
seavault rclone status --check-update
seavault rclone update
seavault rclone rollback
seavault rclone verify-runtime
seavault rclone path
```

Runtime locations:

| OS | Location |
|---|---|
| Linux | `~/.local/share/seavault/rclone` |
| macOS | `~/Library/Application Support/SeaVault/rclone` |
| Windows | `%LOCALAPPDATA%\SeaVault\rclone` |

Online installs download official rclone artifacts, verify SHA256SUMS, extract only the executable, run `rclone version`, and record the binary hash. GPG signature verification is supported when `gpg` is available; use `--signature required` where signature verification must be mandatory.

## Remote profiles

```bash
# Local folder target
seavault remote add --type local --backend local local-backup ~/SeaVault/research ~/Backup/SeaVault/research

# Rclone target
seavault remote add --backend b2 research-b2 ~/SeaVault/research b2ca:seavault/research

# Operations
seavault remote list
seavault remote test research-b2
seavault remote dry-run research-b2
seavault remote push research-b2
seavault remote pull research-b2
seavault remote check research-b2
```

Remote profile configuration is stored outside the vault. Rclone config is stored under app config, not inside `.seavault`.

## GUI

```bash
seavault gui
```

The GUI listens on `127.0.0.1:8787` by default. It provides vault create/open/upload/download/delete/verify workflows, profile management, managed rclone runtime controls, remote repository profiles, transfer actions, and SSH key management.

Do not bind the GUI to a public or shared network interface.

## CLI overview

```bash
seavault init [flags] VAULT_DIR
seavault put [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]
seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH
seavault list [flags] VAULT_DIR_OR_PROFILE
seavault remove [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH
seavault verify [flags] VAULT_DIR_OR_PROFILE
seavault stats [flags] VAULT_DIR_OR_PROFILE
seavault gui [flags] [VAULT_DIR_OR_PROFILE]
seavault rclone status|install|check-update|update|rollback|version|path|verify-runtime
seavault remote add|list|show|delete|test|dry-run|push|pull|check|config
seavault ssh-key generate|import|list|public
```

Passwords are resolved in this order: `SEAVAULT_PASSWORD`, OS keychain, then hidden prompt.

## Storage model

```text
VAULT_DIR/
  .seavault/
    vault.json
    objects/chunks/xx/<object-id>.chunk
    manifests/xx/<manifest-id>.manifest
    tombstones/
```

Files are split with content-defined chunking. Each plaintext chunk gets a keyed object ID, is encrypted with AES-256-GCM, and is stored once. Each virtual file path has an encrypted manifest that references ordered chunks.

## Build and test

```bash
go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
./scripts/smoke-test.sh ./bin/seavault
./scripts/gui-api-smoke-test.sh ./bin/seavault
```

Cross-compile examples:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/seavault-linux-amd64 ./cmd/seavault
GOOS=darwin GOARCH=arm64 go build -o dist/seavault-darwin-arm64 ./cmd/seavault
GOOS=windows GOARCH=amd64 go build -o dist/seavault-windows-amd64.exe ./cmd/seavault
```

## Current limitations

- Not independently audited.
- GUI is browser-based rather than a native toolkit GUI.
- Linux keychain support requires a Secret Service provider and `secret-tool`.
- GPG signature verification for rclone downloads depends on a locally available `gpg` binary.
- SSH key passphrase storage, host-key pinning UI, and SSH-agent GUI integration are still production-hardening items.
- Native mount integrations are not included; `serve` provides a minimal WebDAV-compatible local endpoint.
- Multi-device concurrent edits are preserved as conflict copies, but the app does not merge application-level document contents.
- Password rotation, recovery keys, signed release pipelines, installer packages, and full admin policy enforcement are still future work.

## Security boundary

SeaVault protects file contents and virtual paths before the vault is synchronized. It does not hide total vault size, approximate object count, object churn, sync timing, or the existence of the vault from the cloud provider.
