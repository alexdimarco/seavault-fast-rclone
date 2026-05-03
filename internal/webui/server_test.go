package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func postJSON(t *testing.T, s *Server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SeaVault-Token", s.token)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func getJSON(t *testing.T, s *Server, path string, dst any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if dst != nil {
		if err := json.Unmarshal(rr.Body.Bytes(), dst); err != nil {
			t.Fatalf("decode %s: %v body=%s", path, err, rr.Body.String())
		}
	}
	return rr.Code
}

func TestIndexUsesResponsiveCrossBrowserLayout(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("index failed: %d", rr.Code)
	}
	html := rr.Body.String()
	checks := []string{
		`<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`,
		`class="app-shell"`,
		`class="result-panel"`,
		`aria-live="polite"`,
		`grid-template-columns: minmax(0, 1fr) minmax(340px, 420px)`,
		`@media (max-width: 1180px)`,
		`@media (max-width: 720px)`,
		`* { box-sizing: border-box; }`,
		`input, select, textarea { width: 100%;`,
		`class="table-wrap"`,
		`id="compatWarning"`,
		`id="vaultSelect"`,
		`id="availableVaults"`,
		`Save vault location/password`,
		`webkitdirectory directory multiple`,
		`The browser could not reach the local SeaVault GUI service`,
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("responsive GUI markup missing %q", want)
		}
	}
}

func TestSavedVaultStatusListsProfiledVault(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "alpha")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath,
		"password":  "passphrase",
		"profile":   "alpha",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	if len(status.AvailableVaults) != 1 {
		t.Fatalf("expected one saved vault, got %#v", status.AvailableVaults)
	}
	got := status.AvailableVaults[0]
	if got.Name != "alpha" || got.VaultPath != vaultPath || !got.Open || got.Status != "open" {
		t.Fatalf("unexpected vault status: %#v", got)
	}
}

func TestInitCreatesAndOpensVault(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath,
		"password":  "passphrase",
		"profile":   "",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	if !status.Open || status.VaultPath != vaultPath {
		t.Fatalf("expected open vault at %q, got %#v", vaultPath, status)
	}
}

func TestInitExpandsTildePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": "~/Nextcloud/seavault",
		"password":  "passphrase",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	want := filepath.Join(home, "Nextcloud", "seavault")
	if !status.Open || status.VaultPath != want {
		t.Fatalf("expected open vault at %q, got %#v", want, status)
	}
}

func TestOpenAcceptsOlderCreateFormPayload(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	initResp := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath,
		"password":  "passphrase",
		"profile":   "",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if initResp.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", initResp.Code, initResp.Body.String())
	}
	_ = postJSON(t, s, "/api/close", map[string]any{})
	openResp := postJSON(t, s, "/api/open", map[string]any{
		"vaultPath":    vaultPath,
		"password":     "passphrase",
		"profile":      "work-cloud",
		"kdf":          "scrypt",
		"savePassword": false,
		"useKeychain":  false,
	})
	if openResp.Code != http.StatusOK {
		t.Fatalf("open failed: %d %s", openResp.Code, openResp.Body.String())
	}
}

func TestInitRejectsSlashUserPathBeforeMkdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only path shape")
	}
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": "/user/alex/Nextcloud/seavault",
		"password":  "passphrase",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Use ~/Nextcloud/seavault") {
		t.Fatalf("unexpected error: %s", rr.Body.String())
	}
}

func initOpenTestVault(t *testing.T, s *Server) string {
	t.Helper()
	vaultPath := filepath.Join(t.TempDir(), "cloud", "seavault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": vaultPath,
		"password":  "passphrase",
		"kdf":       "scrypt",
		"scryptN":   16,
		"scryptR":   1,
		"scryptP":   1,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	return vaultPath
}

func TestBrowserFolderUploadPreservesRelativePaths(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", "browser-root"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("relpaths", "folder/nested/a.txt"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("files", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("folder upload")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-SeaVault-Token", s.token)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
	}
	var files struct {
		Files []fileDTO `json:"files"`
	}
	if code := getJSON(t, s, "/api/files", &files); code != http.StatusOK {
		t.Fatalf("files failed: %d", code)
	}
	if len(files.Files) != 1 || files.Files[0].Path != "browser-root/folder/nested/a.txt" {
		t.Fatalf("unexpected files: %#v", files.Files)
	}
}

func TestUploadPathUsesRsync(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not available")
	}
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	src := filepath.Join(t.TempDir(), "source-dir")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "nested", "a.txt"), []byte("rsync gui"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := postJSON(t, s, "/api/upload-path", map[string]any{
		"sourcePath":  src,
		"virtualPath": "local-rsync",
		"method":      "rsync",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("upload path failed: %d %s", rr.Code, rr.Body.String())
	}
	var files struct {
		Files []fileDTO `json:"files"`
	}
	if code := getJSON(t, s, "/api/files", &files); code != http.StatusOK {
		t.Fatalf("files failed: %d", code)
	}
	if len(files.Files) != 1 || files.Files[0].Path != "local-rsync/nested/a.txt" {
		t.Fatalf("unexpected files: %#v", files.Files)
	}
}

func TestRcloneRemoteAndSSHKeyAPIs(t *testing.T) {
	t.Setenv("SEAVAULT_APP_HOME", t.TempDir())
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if code := getJSON(t, s, "/api/rclone/status", &st); code != http.StatusOK {
		t.Fatalf("rclone status failed: %d", code)
	}
	vaultPath := filepath.Join(t.TempDir(), "vault")
	remotePath := filepath.Join(t.TempDir(), "remote")
	rr := postJSON(t, s, "/api/remote", map[string]any{
		"name":       "local-copy",
		"type":       "local",
		"vaultPath":  vaultPath,
		"remotePath": remotePath,
		"backend":    "local",
		"transfers":  2,
		"checkers":   4,
		"fastList":   false,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("remote save failed: %d %s", rr.Code, rr.Body.String())
	}
	var rem map[string]any
	if code := getJSON(t, s, "/api/remotes", &rem); code != http.StatusOK {
		t.Fatalf("remote list failed: %d", code)
	}
	rr = postJSON(t, s, "/api/ssh-keys", map[string]any{"name": "gui"})
	if rr.Code != http.StatusOK {
		t.Fatalf("ssh key generate failed: %d %s", rr.Code, rr.Body.String())
	}
	var pub map[string]string
	if code := getJSON(t, s, "/api/ssh-key-public?name=gui_ed25519", &pub); code != http.StatusOK {
		t.Fatalf("ssh key public failed: %d", code)
	}
	if !strings.HasPrefix(pub["publicKey"], "ssh-ed25519 ") {
		t.Fatalf("unexpected public key: %q", pub["publicKey"])
	}
}

func TestExportAPIPlansAndExportsFolder(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", "docs/"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("files", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("export me")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-SeaVault-Token", s.token)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
	}
	dest := filepath.Join(t.TempDir(), "export")
	rr = postJSON(t, s, "/api/export", map[string]any{"virtualPath": "docs", "destPath": dest, "overwrite": "fail", "dryRun": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("export dry-run failed: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dry-run created destination, err=%v", err)
	}
	rr = postJSON(t, s, "/api/export", map[string]any{"virtualPath": "docs", "destPath": dest, "overwrite": "fail"})
	if rr.Code != http.StatusOK {
		t.Fatalf("export failed: %d %s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "export me" {
		t.Fatalf("exported file = %q", string(got))
	}
}

func TestRsyncStatusAPI(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if code := getJSON(t, s, "/api/rsync/status?binary=definitely-not-rsync", &st); code != http.StatusOK {
		t.Fatalf("rsync status failed: %d", code)
	}
	if available, _ := st["available"].(bool); available {
		t.Fatalf("expected fake rsync to be unavailable: %#v", st)
	}
}
