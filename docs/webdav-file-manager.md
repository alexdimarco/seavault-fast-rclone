# Built-in WebDAV file manager

SeaVault includes an in-app WebDAV client/file manager so users do not need Finder, Windows Explorer, GNOME Files, KDE Dolphin, davfs2, WinFsp, macFUSE, FUSE, or another operating-system WebDAV client for the default workflow.

## Model

SeaVault still stores encrypted data in the vault directory:

```text
<vault>/.seavault/vault.json
<vault>/.seavault/objects/chunks/...
<vault>/.seavault/manifests/...
<vault>/.seavault/tombstones/...
```

When a vault is unlocked, the GUI exposes a local virtual plaintext view:

```text
/files/                      built-in browser file manager
/dav/<session-token>/        local WebDAV endpoint
```

All user-created files and folders live under the protected `content/` workspace. The WebDAV root shows `content/`; file operations occur inside it. Older vaults that do not have this structure are migrated automatically when opened.

The WebDAV endpoint never exposes raw `.seavault` internals or internal `.seavault-dir` directory markers.

## Supported operations

| Operation | WebDAV method | Notes |
|---|---|---|
| Browse folders | `PROPFIND` | Used by the in-app file manager. |
| Download file | `GET` | Decrypted response has `Cache-Control: no-store`. |
| Upload file | `PUT` | Encrypts into the vault immediately. |
| Create folder | `MKCOL` | Creates an encrypted `.seavault-dir` directory marker hidden from users and exports. |
| Delete | `DELETE` | Uses vault removal/tombstone handling. |
| Rename/move | `MOVE` | Moves files or directory prefixes inside the virtual view. |
| Copy | `COPY` | Copies files or directory prefixes inside the virtual view. |
| Lock compatibility | `LOCK`/`UNLOCK` | Implemented as lightweight compatibility responses. |

## Security controls

- `/dav/` requires a random per-GUI-session token.
- The token rotates when the vault closes or the GUI restarts.
- WebDAV runs only when a vault is open.
- The default GUI bind address remains localhost.
- Decrypted WebDAV responses include no-store headers.
- Path traversal is rejected.
- Absolute virtual paths are rejected.
- `.seavault` and `.seavault-dir` are blocked anywhere in user-controlled virtual paths.
- The protected `content/` workspace cannot be deleted or moved.
- Read-only mode rejects `PUT`, `DELETE`, `MKCOL`, `MOVE`, and `COPY`.
- The app does not log vault passwords or WebDAV session tokens.

## GUI workflow

1. Run `seavault gui`.
2. Open or create a vault.
3. Open `/files/` or use the Files section in the main GUI.
4. Browse the folder tree or breadcrumb path.
5. Upload files, upload a folder, drag files onto the drop zone, create folders, rename, copy, delete, or download.
6. Use read-only mode when exposing the local endpoint for browsing only.

## Why not OS-mounted WebDAV by default

OS-mounted WebDAV depends on native components and varies by platform. This project keeps the default path dependency-free by using a browser-based WebDAV client. Optional OS mount helpers can be added later without changing the vault format.
