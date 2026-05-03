# SeaVault Fast

SeaVault Fast is a cross-platform prototype for client-side encrypted storage. It stores plaintext only on the local client, splits files into Seafile-style content-defined chunks, encrypts chunks and sharded manifests, and transports only the encrypted `.seavault` repository.

This repository is a working MVP, not an audited production replacement for Cryptomator.

## What changed in v0.7

- Reworked the GUI into a responsive two-column desktop layout with the result/progress panel on the right.
- Added tablet and phone breakpoints, full-width controls, horizontally scrollable tables, and cross-browser colour/focus fallbacks.
- Added browser capability messaging for folder upload and core browser APIs.
- Added a GUI responsive-layout test and documentation in `docs/gui-responsive-layout.md`.

## What changed in v0.6

- Fixed large browser folder upload reliability by sending selected files in smaller batches with progress and cancel support.
- Added GUI bulk export for selected virtual folders/files and the entire vault.
- Added export dry-run counts, overwrite policy, local destination folder support, and optional ZIP export.
- Added `seavault export` for CLI bulk export with dry-run, ZIP, and overwrite controls.
- Moved the main GUI result/progress window to a right-side panel with clearer human-readable messages.
- Added GUI and API rsync status checks.
- Added rsync-assisted archive ingest for CLI `put` and GUI local path uploads.
- Added browser folder upload support in the GUI.
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
seavault put --method auto nextcloud ./report.pdf reports/report.pdf
seavault put --method rsync nextcloud ./project-folder projects/project-folder
seavault list nextcloud
seavault get nextcloud reports/report.pdf ./recovered/report.pdf
seavault export nextcloud . ~/Desktop/seavault-export
```

The provider sees only `.seavault/vault.json`, encrypted chunk objects, encrypted manifests, and tombstones. Plaintext files stay outside the vault unless explicitly exported/downloaded.

## Rsync-assisted archive ingest

The `put` command now defaults to `--method auto`, which prefers rsync when rsync is available on the machine and falls back to native ingest when rsync is missing. Use `--method rsync` when rsync must be required, or `--method native` to bypass rsync staging.

```bash
# Prefer rsync, fall back to native only when rsync is missing
seavault put --method auto nextcloud ./folder archive/folder

# Require rsync
seavault put --method rsync nextcloud ./folder archive/folder

# Override rsync binary path
seavault put --method rsync --rsync /usr/bin/rsync nextcloud ./folder archive/folder
```

Rsync is used only as a local staging/enumeration helper for ingest. It does not write plaintext into `.seavault`; the app encrypts staged files into content-defined chunks and encrypted manifests. The temporary staging directory is deleted after ingest unless debugging options are added in development builds.

The GUI now has two folder options:

- Browser folder upload, using the browser-provided relative file paths where supported.
- Local path upload, where the local GUI server reads a file or folder path from this computer and uses rsync-assisted ingest.


## Bulk export

The CLI and GUI can export a virtual folder, a single virtual file, or the entire vault. Export decrypts plaintext to a destination you choose, so do not export into `.seavault`.

```bash
# Plan an export without writing plaintext
seavault export --dry-run nextcloud . ~/Desktop/seavault-export

# Export the entire vault
seavault export nextcloud . ~/Desktop/seavault-export

# Export one virtual folder
seavault export --overwrite skip nextcloud projects/site ~/Desktop/site-export

# Export one virtual folder as ZIP
seavault export --zip nextcloud projects/site ~/Desktop
```

Overwrite policies are `fail`, `skip`, and `replace`. The GUI exposes the same controls with progress and cancel support.

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

The GUI listens on `127.0.0.1:8787` by default. It provides vault create/open/upload/download/delete/verify workflows, batched browser folder upload, rsync-assisted local path ingest, bulk export, optional ZIP export, profile management, managed rclone runtime controls, remote repository profiles, transfer actions, and SSH key management.

The desktop layout keeps the result/progress panel on the right. Narrower tablet and phone layouts collapse to one column so controls remain readable and tables do not force horizontal page scrolling. Browser folder upload is capability-detected; when a browser does not expose folder selection, use local path ingest for directory imports.

Do not bind the GUI to a public or shared network interface.

## CLI overview

```bash
seavault init [flags] VAULT_DIR
seavault put [--method auto|rsync|native] [flags] VAULT_DIR_OR_PROFILE SOURCE_PATH [VIRTUAL_PATH]
seavault get [flags] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_PATH
seavault export [--overwrite fail|skip|replace] [--zip] [--dry-run] VAULT_DIR_OR_PROFILE VIRTUAL_PATH DEST_LOCAL_FOLDER_OR_ZIP
seavault rsync status [--binary PATH]
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
./scripts/rsync-put-smoke-test.sh ./bin/seavault
```

GUI layout checks are covered by `go test ./internal/webui`. See `docs/gui-responsive-layout.md` for the static responsive-layout validation checklist and optional browser-render checks.

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
- Rsync-assisted ingest requires rsync for strict `--method rsync`; `--method auto` falls back to native ingest when rsync is missing.
- Native mount integrations are not included; `serve` provides a minimal WebDAV-compatible local endpoint.
- Multi-device concurrent edits are preserved as conflict copies, but the app does not merge application-level document contents.
- Password rotation, recovery keys, signed release pipelines, installer packages, and full admin policy enforcement are still future work.

## Security boundary

SeaVault protects file contents and virtual paths before the vault is synchronized. It does not hide total vault size, approximate object count, object churn, sync timing, or the existence of the vault from the cloud provider.
