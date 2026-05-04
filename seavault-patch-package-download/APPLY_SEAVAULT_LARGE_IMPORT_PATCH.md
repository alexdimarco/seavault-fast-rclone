# SeaVault large local import patch

This patch was generated against the clean repository ZIP you uploaded (`seavault-fast-clean-current.zip`) at commit:

```text
e08e5c4 gui handling error fix
```

It adds a bounded-memory large local import path without changing the existing browser upload, WebDAV file manager, rclone transport, managed rsync, keychain, or multi-vault workflows.

## What the patch adds

- `internal/importer`: streaming local import with progress state, cancellation, dry-run, and skip-existing support.
- CLI: `seavault put --large` and `seavault put --large --dry-run`.
- GUI API:
  - `POST /api/import-large/start`
  - `GET /api/import-large/status?id=<job>`
  - `POST /api/import-large/cancel?id=<job>`
- GUI Upload panel: `Start large local import` button plus dry-run and skip-existing controls.
- Rsync support for large imports is preflight-only. It does not stage/copy the full source tree, so it avoids duplicating a 1 TB folder.

## Apply

From a clean checkout of your current repository:

```bash
cd /path/to/seavault-fast-rclone

git status --short
# Expected: no output. If not clean, commit/stash/reset first.

git checkout master
git pull origin master

git checkout -b fix/large-local-import

git apply --check /path/to/seavault-large-import-clean-current.patch
git apply /path/to/seavault-large-import-clean-current.patch

gofmt -w cmd/seavault/main.go internal/importer/importer.go internal/webui/server.go

go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
```

## CLI smoke test

```bash
rm -rf /tmp/svlarge
mkdir -p /tmp/svlarge/src/dir
printf a >/tmp/svlarge/src/a.txt
printf b >/tmp/svlarge/src/dir/b.txt

printf 'testpass\n' | bin/seavault init --kdf scrypt --scrypt-n 16 --scrypt-r 1 --scrypt-p 1 /tmp/svlarge/vault
export SEAVAULT_PASSWORD=testpass

bin/seavault put --large --dry-run --method native /tmp/svlarge/vault /tmp/svlarge/src Archive
bin/seavault put --large --method native /tmp/svlarge/vault /tmp/svlarge/src Archive
bin/seavault list /tmp/svlarge/vault
```

Expected paths:

```text
content/Archive/a.txt
content/Archive/dir/b.txt
```

## GUI usage

Run:

```bash
bin/seavault gui
```

In **Upload into encrypted archive**:

1. Type the real local source folder path in **Import from local path**.
2. Type the destination prefix in **Virtual path or folder**.
3. Keep method as `native` for very large folders.
4. Use `Dry-run scan only` first.
5. Click **Start large local import**.

Do not drag 1 TB folders into the browser. The large import path lets the Go backend read the source folder directly while the browser only monitors the job.

## Validation performed here

The patch was verified against a clean extraction of your uploaded ZIP with:

```bash
git apply --check /mnt/data/seavault-large-import-clean-current.patch
git apply /mnt/data/seavault-large-import-clean-current.patch
go test ./...
go test ./internal/webui
go vet ./...
go build -o /tmp/seavault-verify ./cmd/seavault
```

The full `go test ./...` output was split across two tool calls because the environment output timed out while tests were still running, but all package tests completed successfully when run in sequence.
