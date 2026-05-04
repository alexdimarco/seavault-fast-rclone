package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testParams() ChunkParams {
	return ChunkParams{MinSize: 64, AvgSize: 128, MaxSize: 256}
}

func createTestVault(t *testing.T, root, password string) {
	t.Helper()
	if err := CreateWithOptions(root, password, CreateOptions{Chunk: testParams(), KDF: FastKDFConfigForTests()}); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTripFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "correct horse battery staple"
	createTestVault(t, root, password)

	src := filepath.Join(t.TempDir(), "source.txt")
	original := []byte(strings.Repeat("abc123", 1000))
	if err := os.WriteFile(src, original, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	results, err := v.PutPath(src, "docs/source.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ChunkCount == 0 {
		t.Fatalf("unexpected put results: %#v", results)
	}

	out := filepath.Join(t.TempDir(), "restored.txt")
	if err := v.GetPath("docs/source.txt", out); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Fatal("restored data differs from original")
	}
	if err := v.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReportReportsMissingChunk(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "pass"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("important content"), "content/report.txt", int64(len("important content")), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	rec := idx.Files["content/report.txt"]
	if len(rec.Chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	missing := rec.Chunks[0]
	if err := os.Remove(v.chunkPath(missing.ID)); err != nil {
		t.Fatal(err)
	}
	report, err := v.VerifyReport()
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatal("expected verification to fail")
	}
	if report.MissingChunks != 1 || len(report.Issues) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	issue := report.Issues[0]
	if issue.Kind != "missing_chunk" || issue.ChunkID != missing.ID || issue.Path != "content/report.txt" || issue.ChunkPath == "" {
		t.Fatalf("unexpected issue: %#v", issue)
	}
	if err := v.Verify(); err == nil {
		t.Fatal("expected Verify to return an error")
	}
}

func TestWrongPasswordFails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	createTestVault(t, root, "right")
	if _, err := Open(root, "wrong"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestDeduplicatesIdenticalChunks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "pass"
	createTestVault(t, root, password)
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	data := []byte(strings.Repeat("same-data-", 200))
	if err := os.WriteFile(a, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, data, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutPath(a, "a.bin"); err != nil {
		t.Fatal(err)
	}
	s1, err := v.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutPath(b, "b.bin"); err != nil {
		t.Fatal(err)
	}
	s2, err := v.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s2.Objects != s1.Objects {
		t.Fatalf("expected deduplicated object count to stay %d, got %d", s1.Objects, s2.Objects)
	}
}

func TestCleanVirtualPathRejectsTraversal(t *testing.T) {
	bad := []string{"../x", "a/../../b", "/../x"}
	for _, p := range bad {
		if _, err := CleanVirtualPath(p); err == nil {
			t.Fatalf("expected %q to be rejected", p)
		}
	}
}

func TestArgon2idAndScryptVaultsRoundTrip(t *testing.T) {
	cases := []KDFConfig{
		{Algorithm: "ARGON2ID", Time: 1, MemoryKiB: 32, Parallelism: 1},
		{Algorithm: "SCRYPT", ScryptN: 16, ScryptR: 1, ScryptP: 1},
	}
	for _, tc := range cases {
		t.Run(tc.Algorithm, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			password := "password"
			if err := CreateWithOptions(root, password, CreateOptions{Chunk: testParams(), KDF: tc}); err != nil {
				t.Fatal(err)
			}
			v, err := Open(root, password)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.PutReader(strings.NewReader("hello"), "hello.txt", 5, 0o600, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := v.WriteFileTo("hello.txt", &buf); err != nil {
				t.Fatal(err)
			}
			if buf.String() != "hello" {
				t.Fatalf("unexpected restore: %q", buf.String())
			}
		})
	}
}

func TestManifestConflictCopyIsPreserved(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("version one"), "doc.txt", int64(len("version one")), 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	orig := firstManifestFile(t, root, v)
	copyPath := strings.TrimSuffix(orig, ".manifest") + ".cloud-conflict.manifest"
	copyFile(t, orig, copyPath)
	if _, err := v.PutReader(strings.NewReader("version two"), "doc.txt", int64(len("version two")), 0o600, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["content/doc.txt"]; !ok {
		t.Fatalf("winning file missing: %#v", files)
	}
	foundConflict := false
	for p, rec := range files {
		if strings.HasPrefix(p, "content/doc.txt.conflict-") && rec.ConflictOf == "content/doc.txt" {
			foundConflict = true
		}
	}
	if !foundConflict {
		t.Fatalf("expected conflict copy to be preserved, files: %#v", files)
	}
}

func TestRemoveTombstoneWinsOverOlderConflictCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("old"), "doc.txt", 3, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	orig := firstManifestFile(t, root, v)
	copyPath := strings.TrimSuffix(orig, ".manifest") + ".old-sync-conflict.manifest"
	copyFile(t, orig, copyPath)
	if err := v.Remove("doc.txt"); err != nil {
		t.Fatal(err)
	}
	files, err := v.Files()
	if err != nil {
		t.Fatal(err)
	}
	for p := range files {
		if p == "content/doc.txt" || strings.HasPrefix(p, "content/doc.txt.conflict-") {
			t.Fatalf("older manifest should be suppressed by delete tombstone; files: %#v", files)
		}
	}
}

func firstManifestFile(t *testing.T, root string, v *Vault) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(filepath.Join(root, MetadataDirName, ManifestDirName), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".manifest") && found == "" {
			data, readErr := os.ReadFile(p)
			if readErr != nil {
				return readErr
			}
			id := manifestIDFromFileName(d.Name())
			rec, decErr := v.decryptManifest(data, id)
			if decErr == nil && !IsInternalVirtualPath(rec.Path) {
				found = p
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("manifest file not found")
	}
	return found
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExportPathDirectoryAllAndZip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("alpha"), "projects/site/a.txt", 5, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("beta"), "projects/site/nested/b.txt", 4, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("gamma"), "reports/q1.txt", 5, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}

	dryDest := filepath.Join(t.TempDir(), "dry")
	dry, err := v.ExportPath(nil, "projects/site", dryDest, ExportOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Files != 2 || dry.Bytes != 9 {
		t.Fatalf("unexpected dry run: %#v", dry)
	}
	if _, err := os.Stat(dryDest); !os.IsNotExist(err) {
		t.Fatalf("dry run should not create destination, stat err=%v", err)
	}

	exportDest := filepath.Join(t.TempDir(), "export")
	res, err := v.ExportPath(nil, "projects/site", exportDest, ExportOptions{Overwrite: OverwriteFail})
	if err != nil {
		t.Fatal(err)
	}
	if res.Exported != 2 {
		t.Fatalf("expected 2 exported files, got %#v", res)
	}
	assertFileString(t, filepath.Join(exportDest, "a.txt"), "alpha")
	assertFileString(t, filepath.Join(exportDest, "nested", "b.txt"), "beta")

	allDest := filepath.Join(t.TempDir(), "all")
	all, err := v.ExportPath(nil, ".", allDest, ExportOptions{Overwrite: OverwriteFail})
	if err != nil {
		t.Fatal(err)
	}
	if all.Exported != 3 {
		t.Fatalf("expected 3 exported files, got %#v", all)
	}
	assertFileString(t, filepath.Join(allDest, "reports", "q1.txt"), "gamma")

	zipDir := t.TempDir()
	zipRes, err := v.ExportPath(nil, "projects/site", zipDir, ExportOptions{Zip: true, Overwrite: OverwriteFail})
	if err != nil {
		t.Fatal(err)
	}
	if zipRes.Exported != 2 || !strings.HasSuffix(zipRes.DestPath, "site.zip") {
		t.Fatalf("unexpected zip result: %#v", zipRes)
	}
	if _, err := os.Stat(zipRes.DestPath); err != nil {
		t.Fatal(err)
	}
}

func TestExportOverwriteSkip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutReader(strings.NewReader("new"), "docs/a.txt", 3, 0o600, time.Now()); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := v.ExportPath(nil, "docs", dest, ExportOptions{Overwrite: OverwriteSkip})
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 || res.Exported != 0 {
		t.Fatalf("unexpected skip result: %#v", res)
	}
	assertFileString(t, filepath.Join(dest, "a.txt"), "old")
}

func assertFileString(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, string(got), want)
	}
}

func TestPutDirectoryContentsDoesNotIncludeSourceRootName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)

	src := filepath.Join(t.TempDir(), "Articles")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "nested", "one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "two.txt"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	results, err := v.PutDirectoryContents(src, "archive")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 imported files, got %#v", results)
	}
	paths, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"content/archive/nested/one.txt", "content/archive/two.txt"}
	if len(paths) != len(want) {
		t.Fatalf("unexpected paths: got %#v want %#v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("unexpected paths: got %#v want %#v", paths, want)
		}
	}
}

func TestOpenMigratesLegacyRootFilesIntoContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := "password"
	createTestVault(t, root, password)
	v, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := v.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.putReader(strings.NewReader("legacy"), "docs/legacy.txt", 6, 0o600, time.Now(), &idx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "docs/legacy.txt" {
		t.Fatalf("test setup expected legacy path, got %q", res.Path)
	}
	if err := v.saveFileManifest("docs/legacy.txt", idx.Files["docs/legacy.txt"]); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(root, password)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := migrated.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "content/docs/legacy.txt" {
		t.Fatalf("legacy root file was not migrated into content/: %#v", paths)
	}
	var buf bytes.Buffer
	if err := migrated.WriteFileTo("docs/legacy.txt", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "legacy" {
		t.Fatalf("unexpected migrated content %q", buf.String())
	}
}
