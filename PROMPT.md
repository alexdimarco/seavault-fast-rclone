# Production implementation prompt

Design and implement a cross-platform client-side encrypted storage application similar in workflow to Cryptomator, but optimized with Seafile-style chunked storage efficiency. The application must store all encrypted vault data inside a configurable local directory so any cloud-sync client can synchronize it.

## Required architecture

- Language/runtime: Go or Rust with native builds for Linux, macOS, and Windows.
- Deployment: single binary first; optional installers later.
- GUI: local browser GUI or native toolkit GUI that does not require a cloud-provider SDK.
- Storage: content-defined chunking, keyed content-addressed chunk IDs, encrypted chunk objects, encrypted sharded manifests.
- Encryption: AEAD only; no unauthenticated CBC mode.
- KDFs: Argon2id default, scrypt alternative, PBKDF2 legacy compatibility only.
- Key management: random vault keys wrapped by a password-derived key; OS keychain integration; future password rotation through rewrapping.
- Sync compatibility: tolerate duplicate/conflicted manifest files; preserve conflict versions; use delete tombstones.
- Access modes: CLI, GUI, and local WebDAV-compatible endpoint. Consider optional FUSE, WinFsp, and macFUSE frontends as separate packages.

## Required security outcomes

- Plaintext never enters the configured vault directory.
- Virtual paths and file metadata are encrypted.
- Every encrypted object is authenticated.
- Object substitution is detected.
- Keychain use is optional and visible to users.
- The app can verify vault integrity offline.

## Required tests

- Round trip put/get/list/remove/verify.
- Wrong password failure.
- Chunk deduplication.
- KDF vectors for scrypt and PBKDF2; Argon2id interoperability vectors where practical.
- Manifest conflict preservation.
- Delete tombstone precedence over stale manifests.
- Path traversal rejection.
- Cross-platform builds for Linux, macOS, and Windows.
