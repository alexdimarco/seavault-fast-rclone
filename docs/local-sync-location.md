# Local sync location configuration

The encrypted location is the vault directory passed to `seavault init`, `seavault gui`, or `seavault profile add`.

Paths can use `~`, `$HOME`, `${HOME}`, or `%USERPROFILE%`. The GUI and CLI expand these before creating/opening the vault.

## Recommended layout

```text
CloudSyncFolder/
  SeaVault/
    .seavault/
      vault.json
      objects/chunks/...
      manifests/...
```

Point the sync client at `CloudSyncFolder` or at `CloudSyncFolder/SeaVault`. Do not place plaintext source files inside `.seavault`.

## Profiles

Profiles are local aliases that avoid repeating long cloud-sync paths.

```bash
seavault profile add work-cloud "~/OneDrive - Example Org/SeaVault"
seavault put work-cloud ./budget.xlsx finance/budget.xlsx
```

Profile files are stored in the user configuration directory, not in the vault.

## Validation checklist

1. Create a vault inside the sync-client folder.
2. Put a test file into the vault.
3. Confirm the sync client uploads `.seavault` contents.
4. Confirm the cloud web UI shows encrypted-looking chunk and manifest files only.
5. Open the same vault on another device after sync completes.
6. Verify the vault on both devices.
7. Simulate a conflict by editing the same virtual file on two devices before sync reconciliation.
8. Confirm one version remains at the original path and the other appears as a `*.conflict-*` virtual file.
