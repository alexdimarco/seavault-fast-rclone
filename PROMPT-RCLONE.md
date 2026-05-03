Modify the seavault-fast repository to make rclone the primary transport backend while preserving the existing client-side encrypted vault design, tested CLI put/get behavior, GUI, OS keychain support, Argon2id/scrypt KDFs, sharded manifests, and conflict-safe merge behavior.

Project goal:
Build a cross-platform encrypted client-side storage application that stores plaintext only on the local client, converts files into Seafile-style content-defined encrypted chunks and encrypted sharded manifests, and then transports only the encrypted .seavault repository to local folders, remote folders, SFTP, object storage, and cloud storage using a project-managed rclone runtime.

Non-negotiable security rule:
rclone must never see plaintext user files. rclone only transfers the encrypted .seavault repository, including encrypted chunks, encrypted manifests, tombstones, config, and vault metadata.

Core architecture:
1. Keep the vault format provider-agnostic.
2. Keep the local vault layout:
   - <vault>/.seavault/vault.json
   - <vault>/.seavault/objects/chunks/...
   - <vault>/.seavault/manifests/...
   - <vault>/.seavault/tombstones/...
   - <vault>/.seavault/locks/...
3. Add a transport abstraction under:
   - internal/transport/transport.go
   - internal/transport/local/
   - internal/transport/rclone/
   - internal/rclonebin/
   - internal/remotes/
4. Make rclone the default remote transport.
5. Keep local-folder transport for desktop sync clients such as Nextcloud Desktop, OneDrive Desktop, Dropbox Desktop, iCloud Drive, Google Drive Desktop, Syncthing, SMB mounts, and external drives.
6. Keep rsync as optional future work only. Do not block rclone implementation on rsync.

Rclone runtime management:
1. The project must maintain its own app-managed rclone binary.
2. Do not rely on a system-installed rclone.
3. Do not require users to install rclone manually.
4. Do not call package managers such as apt, brew, winget, choco, yum, dnf, or pacman.
5. Store the managed rclone binary in an app-owned runtime directory:
   - Linux: ~/.local/share/seavault/rclone/<version>/rclone
   - macOS: ~/Library/Application Support/SeaVault/rclone/<version>/rclone
   - Windows: %LOCALAPPDATA%\SeaVault\rclone\<version>\rclone.exe
6. Maintain a runtime manifest:
   - installed version
   - install date
   - OS
   - architecture
   - binary path
   - SHA256 hash
   - source URL
   - release channel
   - previous working version
   - update check timestamp
7. Support release channels:
   - stable, default
   - beta, opt-in only
   - pinned version, for reproducible enterprise deployments
8. Add a rclone bootstrap installer:
   - detect current OS and architecture
   - map to the correct official rclone release artifact
   - download the official rclone zip archive for that platform
   - download official SHA256SUMS
   - verify the SHA256SUMS signature using the rclone release signing key
   - verify the downloaded archive hash against SHA256SUMS
   - extract only the rclone executable
   - set executable permissions on Unix-like systems
   - atomically install into the app-managed runtime directory
   - run `rclone version`
   - record version and hash in the runtime manifest
9. Add a rclone update manager:
   - check latest stable release
   - show current version and latest available version in CLI and GUI
   - support manual update
   - support optional automatic update checks
   - do not silently replace rclone while transfers are running
   - stage the new binary first
   - verify signature and hash before activation
   - run `rclone version` after staging
   - atomically switch the active binary pointer
   - retain the previous working binary for rollback
   - expose rollback in CLI and GUI
10. Prefer using rclone’s own `selfupdate --check` and `selfupdate --output <staged-path>` where a working managed rclone already exists and supports selfupdate.
11. For first install, corrupted installs, unsupported old versions, or missing selfupdate support, use the direct official download plus signature/hash verification path.
12. Never download rclone from mirrors, package repos, third-party CDNs, or user-provided URLs unless explicitly enabled as an enterprise policy override.
13. Add enterprise policy controls:
   - disable automatic update checks
   - force pinned version
   - allow beta channel
   - configure update check interval
   - configure allowed download hostnames
   - configure offline rclone artifact path
   - require administrator approval before runtime updates

Transport profile model:
Create a profile file under app config, not inside the vault, with this shape:

{
  "name": "research-b2-ca",
  "type": "rclone",
  "vault": "~/SeaVault/research",
  "remote": {
    "remoteName": "b2ca",
    "remotePath": "b2ca:seavault/research/.seavault",
    "backend": "b2",
    "configMode": "managed",
    "rcloneConfigPath": "~/.config/seavault/rclone/rclone.conf",
    "transfers": 8,
    "checkers": 16,
    "fastList": true,
    "checksum": "auto",
    "bandwidthLimit": "",
    "dryRunDefault": true
  },
  "runtime": {
    "channel": "stable",
    "pinnedVersion": "",
    "autoCheckUpdates": true,
    "autoInstallSecurityUpdates": false
  },
  "safety": {
    "defaultOperation": "copy",
    "allowDestructiveSync": false,
    "requireDryRunBeforeSync": true,
    "retainDeletedObjectsDays": 30,
    "verifyAfterTransfer": true
  }
}

CLI requirements:
Add these commands:

Vault operations:
- seavault init <vault-path-or-profile>
- seavault put <vault-path-or-profile> <local-file> <virtual-path>
- seavault get <vault-path-or-profile> <virtual-path> <local-output>
- seavault list <vault-path-or-profile>
- seavault remove <vault-path-or-profile> <virtual-path>
- seavault verify <vault-path-or-profile>
- seavault stats <vault-path-or-profile>

Rclone runtime operations:
- seavault rclone status
- seavault rclone install
- seavault rclone check-update
- seavault rclone update
- seavault rclone rollback
- seavault rclone version
- seavault rclone path
- seavault rclone verify-runtime

Remote profile operations:
- seavault remote add
- seavault remote list
- seavault remote show <name>
- seavault remote edit <name>
- seavault remote delete <name>
- seavault remote test <name>
- seavault remote dry-run <name>
- seavault remote push <name>
- seavault remote pull <name>
- seavault remote sync <name>
- seavault remote check <name>

Rclone config operations:
- seavault remote config create
- seavault remote config import
- seavault remote config export-redacted
- seavault remote config path
- seavault remote config validate

GUI requirements:
Add a Remote Repositories section with these tabs:

1. Overview
   - vault path
   - active remote profile
   - last push
   - last pull
   - last verify
   - rclone installed version
   - latest available rclone version
   - transport health

2. Rclone Runtime
   - install rclone
   - check for updates
   - update rclone
   - rollback rclone
   - choose stable, beta, or pinned version
   - show binary path
   - show SHA256 hash
   - show release verification status
   - show update policy controls

3. Remote Profiles
   - add local path target
   - add rclone target
   - edit target
   - delete target
   - test connection
   - choose default target
   - choose safe copy-only mode or advanced sync mode

4. Rclone Configuration
   - launch guided configuration flow
   - support direct configuration for common backends:
     - local
     - SFTP
     - S3-compatible
     - Backblaze B2
     - Azure Blob
     - Google Drive
     - OneDrive
     - Dropbox
     - Nextcloud/WebDAV
     - SMB where supported by rclone
   - import existing rclone.conf
   - store secrets using OS keychain where possible
   - display redacted config
   - validate config without uploading vault data

5. Transfer
   - dry-run
   - push
   - pull
   - safe bidirectional reconcile
   - advanced destructive mirror, disabled by default
   - progress
   - speed
   - ETA
   - transferred bytes
   - transferred objects
   - skipped objects
   - errors
   - cancel transfer
   - copy log to clipboard

6. Conflicts and Deletes
   - show manifest conflicts
   - show tombstones
   - show files pending delete propagation
   - show objects eligible for garbage collection
   - require explicit confirmation before garbage collection
   - never default to destructive remote cleanup

7. Validation
   - verify local vault
   - verify remote object inventory
   - run rclone check
   - run vault-aware check
   - export validation report

Rclone command strategy:
1. Use exec.CommandContext with argument arrays only.
2. Do not invoke a shell.
3. Do not concatenate command strings.
4. Always pass `--config <managed-config-path>`.
5. Always pass `--log-format date,time,level,msg`.
6. Capture progress and machine-readable statistics where possible.
7. Redact secrets from logs.
8. Redact access tokens, refresh tokens, client secrets, passwords, private keys, and provider credentials.
9. Do not log vault passwords.
10. Do not log plaintext file contents.
11. Avoid logging plaintext virtual paths except in the authenticated local GUI session.

Default push operation:
Use rclone copy, not rclone sync.

Example logical command:
rclone copy <vault>/.seavault <remote>/.seavault
  --config <managed-config>
  --transfers 8
  --checkers 16
  --fast-list when supported
  --immutable where safe and supported
  --progress
  --stats 1s

Default pull operation:
Use rclone copy from remote to local.

Example logical command:
rclone copy <remote>/.seavault <vault>/.seavault
  --config <managed-config>
  --transfers 8
  --checkers 16
  --fast-list when supported
  --progress
  --stats 1s

Dry run:
Add --dry-run and show the plan before transfer.

Verification:
Use rclone check where appropriate, then run vault-aware verify.

Example logical command:
rclone check <vault>/.seavault <remote>/.seavault
  --config <managed-config>
  --size-only by default
  --one-way for push verification where appropriate

Checksum mode:
1. Use checksum verification only when the backend supports compatible hashes.
2. Add backend capability detection.
3. Fall back to size and modtime when checksums are unavailable.
4. The vault’s own encrypted object integrity checks remain authoritative after pull.

Destructive sync policy:
1. Do not expose destructive sync as the default.
2. `rclone sync` may delete destination data, so it must be advanced-only.
3. Require a successful dry run before destructive sync.
4. Require a second confirmation in GUI.
5. Require typed confirmation in CLI.
6. Never delete chunks solely because rclone says they are absent locally.
7. Remote garbage collection must be vault-aware, retention-gated, and disabled by default.

Vault-aware sync algorithm:
1. Pull remote manifests and tombstones first.
2. Merge manifests locally.
3. Detect manifest conflicts.
4. Preserve conflicted versions as virtual conflict entries.
5. Respect tombstones so deleted files do not resurrect.
6. Push missing immutable encrypted chunks.
7. Push encrypted manifest shards and tombstones.
8. Verify local vault.
9. Verify remote inventory where feasible.
10. Offer garbage collection only after retention window expires.

Rclone configuration and key management:
1. Store rclone.conf under app config:
   - Linux: ~/.config/seavault/rclone/rclone.conf
   - macOS: ~/Library/Application Support/SeaVault/rclone/rclone.conf
   - Windows: %APPDATA%\SeaVault\rclone\rclone.conf
2. Do not store rclone.conf inside the vault.
3. Store sensitive backend credentials in OS keychain where possible.
4. If rclone requires secrets in rclone.conf for a backend, store that config outside the vault, restrict file permissions, and show a warning in the GUI.
5. Support importing an existing user rclone.conf by copying selected remotes into the app-managed config after user approval.
6. Support using an external rclone.conf by reference for advanced users, but default to app-managed config.
7. Add redacted config export for support.
8. Add per-profile credential test.

SFTP and SSH requirements through rclone:
1. Support rclone SFTP as the preferred SSH-based backend.
2. GUI must support:
   - generate Ed25519 SSH key
   - import existing key
   - reference existing key by path
   - copy public key
   - test SFTP connection
   - show remote host, user, port, and path before transfer
3. Store SSH key passphrases in OS keychain.
4. Do not store SSH private keys inside the vault.
5. Support SSH agent detection.
6. Support host key verification.
7. Store pinned host key fingerprints per profile where possible.
8. Warn when host key checking is disabled.
9. Do not store remote SSH passwords.
10. Optional bootstrap flow may help append public keys to authorized_keys, but it must be explicit and disabled by default.

Performance requirements:
1. Preserve Seafile-style content-defined chunking.
2. Keep target chunk size around 8 MiB unless changed by advanced settings.
3. Keep chunks immutable and content-addressed.
4. Keep manifests sharded.
5. Avoid one large encrypted container file.
6. Avoid one large encrypted global index.
7. Tune rclone defaults:
   - transfers: 8
   - checkers: 16
   - fast-list: auto
   - multi-thread streams: auto for large objects where supported
   - compression: off by default
8. Add backend-specific tuning presets:
   - local
   - SFTP
   - S3-compatible
   - B2
   - Azure Blob
   - Google Drive
   - OneDrive
   - Dropbox
   - WebDAV/Nextcloud
9. Provide advanced controls for bandwidth limit, transfers, checkers, fast-list, low-level retries, and timeout.
10. Make safe defaults conservative enough for cloud API rate limits.

Update and supply-chain security requirements:
1. The app must verify rclone runtime integrity before use.
2. The app must verify downloaded updates before activation.
3. Verification must include:
   - official source hostname validation
   - TLS
   - signed SHA256SUMS verification
   - archive SHA256 verification
   - extracted binary hash recording
   - `rclone version` execution check
4. Retain previous working rclone version.
5. Support rollback from GUI and CLI.
6. Show runtime provenance:
   - installed from official rclone downloads
   - version
   - channel
   - hash
   - install time
   - update check time
7. Add an offline enterprise install mode:
   - admin provides rclone archive
   - admin provides SHA256SUMS
   - app verifies hash and signature
   - app installs into managed runtime directory
8. Add policy file support:
   - allowUpdates: true or false
   - allowedChannels: stable, beta
   - pinnedVersion
   - allowedDownloadHosts
   - updateCheckIntervalHours
   - requireManualApproval
9. Do not auto-update during active transfer.
10. Do not auto-update in the middle of vault open, put, get, verify, or garbage collection.
11. Show update warnings but do not block access to existing vaults unless the managed rclone binary fails verification.

Testing requirements:
Add tests for:
1. rclone platform detection.
2. rclone artifact name resolution.
3. rclone download URL construction.
4. SHA256 verification.
5. signed checksum verification.
6. atomic install.
7. rollback.
8. update manifest persistence.
9. missing rclone bootstrap.
10. corrupted rclone binary detection.
11. fake rclone runner.
12. local rclone transport using temp directories.
13. rclone copy push.
14. rclone copy pull.
15. rclone check.
16. dry-run parsing.
17. transfer progress parsing.
18. cancellation.
19. backend config redaction.
20. local GUI API tests.
21. GUI runtime install/status/update endpoints.
22. profile create/edit/delete tests.
23. Windows path tests.
24. paths with spaces.
25. Unicode paths.
26. conflict merge tests.
27. tombstone retention tests.
28. no plaintext leakage into .seavault.
29. no secret leakage into logs.
30. CI smoke test using local rclone backend.

CI requirements:
1. Run gofmt.
2. Run go test ./...
3. Run go vet ./...
4. Build Linux amd64.
5. Build Linux arm64.
6. Build macOS amd64.
7. Build macOS arm64.
8. Build Windows amd64.
9. Run local vault smoke test.
10. Run GUI API smoke test.
11. Run rclone runtime unit tests with fake downloader.
12. Run rclone local-backend integration test where network is not required.
13. Do not require real cloud credentials in CI.

Documentation requirements:
Add:
- docs/rclone-transport.md
- docs/rclone-runtime-management.md
- docs/rclone-update-security.md
- docs/rclone-backend-presets.md
- docs/sftp-key-management.md
- docs/remote-repository-threat-model.md
- docs/cloud-provider-notes.md
- docs/admin-policy.md
- docs/validation-checklist.md
- docs/disaster-recovery.md

README updates:
1. Explain that the vault path is the encrypted local storage location.
2. Explain that rclone transports only .seavault.
3. Explain that rclone is managed by the app.
4. Explain first-run bootstrap.
5. Explain update and rollback.
6. Explain cloud setup through GUI.
7. Explain safe defaults.
8. Explain why `copy` is the default and destructive `sync` is advanced-only.
9. Include examples:
   - local folder target
   - SFTP target
   - S3-compatible target
   - Backblaze B2 target
   - Nextcloud/WebDAV target
   - OneDrive target
10. Include a security warning that provider-side encryption or rclone crypt is not a substitute for the app’s own client-side vault encryption.

Implementation constraints:
1. Keep the application cross-platform across Linux, macOS, and Windows.
2. Keep deployment simple.
3. Do not require FUSE, WinFsp, macFUSE, Java, Electron, Docker, or provider SDKs.
4. Keep the GUI browser-based unless replacing it with a smaller cross-platform native GUI can be justified.
5. Use the Go standard library where practical.
6. Use small, maintained dependencies only where necessary.
7. Do not break existing vault put/get/list/verify behavior.
8. Maintain backwards compatibility with existing v0.3 vaults where possible.
9. Provide migration if vault metadata changes.
10. Produce a full Git repository ZIP with source, tests, docs, CI, and a tested build path.

Acceptance criteria:
1. User can install the app on Linux, macOS, or Windows.
2. User can create a vault.
3. User can put a file.
4. User can get the file back.
5. User can install managed rclone from the GUI.
6. User can see managed rclone version and path.
7. User can check for rclone updates.
8. User can update rclone from the GUI.
9. User can rollback rclone from the GUI.
10. User can create a local rclone remote profile.
11. User can create an SFTP rclone remote profile.
12. User can create at least one object/cloud backend profile using rclone config.
13. User can dry-run push.
14. User can push encrypted .seavault to remote.
15. User can pull encrypted .seavault from remote.
16. User can verify the vault after pull.
17. User can see transfer progress.
18. User can cancel an active transfer.
19. User can view redacted logs.
20. No plaintext file content appears in the remote target.
21. No vault password appears in config or logs.
22. No rclone secrets appear in logs.
23. Corrupted rclone runtime is detected.
24. Corrupted downloaded rclone update is rejected.
25. Previous rclone version can be restored.
26. `go test ./...` passes.
27. `go vet ./...` passes.
28. Linux, macOS, and Windows builds complete.
29. Local rclone integration smoke test passes.
30. GUI API smoke test passes.

Deliverable:
Return a full Git repository ZIP containing:
- updated source code
- tests
- GUI changes
- CLI changes
- docs
- CI
- example profiles
- runtime policy examples
- migration notes
- validation checklist
- initial Git history with clear commits