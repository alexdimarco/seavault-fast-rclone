# Security notes

## Threat model

SeaVault assumes the cloud provider, cloud administrators, and sync transport may read, copy, delete, reorder, or replace files in the vault directory. The application encrypts and authenticates vault contents before data reaches that directory.

## Protected

- File contents.
- Virtual file paths and file metadata stored in encrypted manifests.
- Manifest and chunk integrity through AEAD tags.
- Wrong-chunk substitution through AAD and keyed object-ID verification.
- Password entry on the CLI through hidden terminal input.
- Optional password storage using the operating-system credential store.

## Not protected

- Vault existence.
- Approximate vault size.
- Number of encrypted objects and manifests.
- Sync timing and churn.
- Device compromise before encryption or after decryption.
- A malicious local GUI/WebDAV client running under the same user account.

## Key derivation

New vaults default to Argon2id. scrypt and PBKDF2-HMAC-SHA256 are available for compatibility or constrained environments. KDF parameters are stored in `vault.json` because they are required to unlock the vault and are not secret.

## Keychain behavior

The OS keychain stores only the vault password and uses the vault ID as the account key. This improves usability but changes the local-device risk model: anyone who can unlock the OS account and access the credential store may be able to unlock the vault.

## Sync conflicts

Sync-client conflict files are expected in real cloud folders. SeaVault treats duplicate manifest variants conservatively: it keeps the newest generation as the main file and preserves other live versions as conflict copies instead of silently discarding them. Delete tombstones suppress older live manifests so deleted files are not resurrected by stale conflicts.

## Production work still required

- Independent cryptographic review.
- Recovery-key design.
- Password rotation command.
- Signed release pipeline and reproducible build notes.
- Installer packages and auto-update policy.
- More exhaustive WebDAV compatibility testing.
- Fuzzing for encrypted object parsing.
- Admin policy controls for KDF floors, keychain use, and allowed vault locations.

## Rclone transport boundary

Rclone is used only as a transport runtime. It receives paths under `.seavault` and does not receive plaintext source files or decrypted virtual paths. Default remote operations use copy-safe transfers rather than destructive mirror sync.

The app-managed rclone binary is stored outside the vault, has its SHA256 hash recorded in a runtime manifest, and can be verified before use. Online installs verify the archive against official SHA256SUMS. Optional or required GPG verification is available when a local `gpg` executable is present.

## Remote credential handling

Remote profiles and rclone configuration are stored under app configuration, not in the vault. Redacted export removes common token, secret, password, and key fields. Some rclone backends still require credentials in `rclone.conf`; for those backends, restrict file permissions and prefer OS keychain or short-lived provider credentials where supported.

SSH private keys for SFTP are stored in app configuration and are never synchronized inside `.seavault`.
