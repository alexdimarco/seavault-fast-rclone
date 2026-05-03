# GUI and keychain notes

## GUI

Run:

```bash
seavault gui
```

The GUI opens a local browser page. It supports vault creation, opening, profile use, upload, download, delete, stats, and verification.

Use `Create vault and open` for first-time setup. A newly created vault is opened immediately. If saving the profile or the OS keychain entry fails, the vault remains open and the warning is shown in the status panel.

For the vault path, prefer `~/Nextcloud/seavault` or one of the suggested local encrypted-folder buttons. Do not use `/user/name/...`; macOS uses `/Users/name/...` and Linux uses `/home/name/...`.

## Keychain

CLI:

```bash
seavault keychain store work-cloud
seavault keychain status work-cloud
seavault keychain delete work-cloud
```

GUI:

- Select `Save password in OS keychain` when creating or opening a vault.
- Use `Open using keychain` later without typing the vault password.

## Platform requirements

| Platform | Mechanism | Requirement |
| --- | --- | --- |
| macOS | Keychain | Built-in `security` command |
| Windows | Credential Manager | Native Win32 credential APIs |
| Linux | Secret Service | `secret-tool` and an unlocked desktop keyring |

Linux headless servers usually do not have a Secret Service session. Use `SEAVAULT_PASSWORD` or a deployment-specific secret manager for automation.
