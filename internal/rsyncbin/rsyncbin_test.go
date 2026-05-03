package rsyncbin

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArtifactName(t *testing.T) {
	got := ArtifactName("3.4.2", "linux", "amd64")
	if got != "seavault-rsync-3.4.2-linux-amd64.zip" {
		t.Fatalf("unexpected artifact name: %s", got)
	}
}

func TestLatestParsesSourceIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<a href="rsync-3.3.0.tar.gz">old</a><a href="rsync-3.4.2.tar.gz">new</a>`))
	}))
	defer srv.Close()
	i := NewInstaller()
	i.SourceBaseURL = srv.URL
	li, err := i.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if li.Version != "3.4.2" || !strings.Contains(li.SourceURL, "rsync-3.4.2.tar.gz") {
		t.Fatalf("unexpected latest info: %#v", li)
	}
}

func TestInstallFromBinary(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	bin := filepath.Join(t.TempDir(), exeName(runtime.GOOS))
	if err := writeFakeRsync(bin, "3.4.2"); err != nil {
		t.Fatal(err)
	}
	i := NewInstaller()
	m, err := i.Install(context.Background(), InstallOptions{FromBinary: bin})
	if err != nil {
		t.Fatal(err)
	}
	if m.InstalledVersion != "3.4.2" || m.BinaryPath == bin {
		t.Fatalf("unexpected manifest: %#v", m)
	}
	if err := VerifyRuntime(m); err != nil {
		t.Fatal(err)
	}
}

func TestInstallOfflineArchive(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	work := t.TempDir()
	fake := filepath.Join(work, exeName(runtime.GOOS))
	if err := writeFakeRsync(fake, "3.4.2"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(work, "seavault-rsync-3.4.2.zip")
	if err := zipOne(archive, exeName(runtime.GOOS), fake); err != nil {
		t.Fatal(err)
	}
	i := NewInstaller()
	m, err := i.Install(context.Background(), InstallOptions{OfflineArchive: archive, Version: "3.4.2"})
	if err != nil {
		t.Fatal(err)
	}
	if m.InstalledVersion != "3.4.2" {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func writeFakeRsync(path, version string) error {
	body := "#!/usr/bin/bash\nif [ \"$1\" = \"--version\" ]; then echo 'rsync  version " + version + "  protocol version 31'; exit 0; fi\nexit 0\n"
	return os.WriteFile(path, []byte(body), 0o700)
}

func zipOne(zipPath, name, src string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o700)
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
