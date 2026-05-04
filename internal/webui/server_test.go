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
	"time"

	"github.com/example/seavault-fast/internal/appconfig"
)

func TestMain(m *testing.M) {
	appHome, err := os.MkdirTemp("", "seavault-webui-test-home-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("SEAVAULT_APP_HOME", appHome)
	code := m.Run()
	_ = os.RemoveAll(appHome)
	os.Exit(code)
}

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
		`selected folder name is already included`,
		`id="fileSummary"`,
		`id="folderSummary"`,
		`Import local path`,
		`Browser-selected folders cannot fill this field`,
		`value="`,
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
	if len(files.Files) != 1 || files.Files[0].Path != "content/browser-root/folder/nested/a.txt" {
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
	if len(files.Files) != 1 || files.Files[0].Path != "content/local-rsync/nested/a.txt" {
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
	if st["defaultHint"] == "" || st["os"] == "" {
		t.Fatalf("expected rsync status to include OS/default hint: %#v", st)
	}
}

func TestVaultMoveAPIUpdatesSavedProfile(t *testing.T) {
	appHome := filepath.Join(t.TempDir(), "app")
	t.Setenv("SEAVAULT_APP_HOME", appHome)
	root := t.TempDir()
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "old-vault")
	dst := filepath.Join(root, "new-vault")
	rr := postJSON(t, s, "/api/init", map[string]any{
		"vaultPath": src,
		"password":  "passphrase",
		"profile":   "move-me",
		"kdf":       "pbkdf2",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = postJSON(t, s, "/api/vault-move", map[string]any{
		"profileName":          "move-me",
		"destinationPath":      dst,
		"updateRemoteProfiles": true,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("move failed: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dst, ".seavault", "vault.json")); err != nil {
		t.Fatalf("destination metadata missing: %v", err)
	}
	var status statusResponse
	if code := getJSON(t, s, "/api/status", &status); code != http.StatusOK {
		t.Fatalf("status failed: %d", code)
	}
	found := false
	for _, v := range status.AvailableVaults {
		if v.Name == "move-me" {
			found = true
			if filepath.Clean(v.VaultPath) != filepath.Clean(dst) {
				t.Fatalf("profile path not moved: %s", v.VaultPath)
			}
		}
	}
	if !found {
		t.Fatal("moved profile not found in status")
	}
}

func davRequest(t *testing.T, s *Server, method, virtualPath string, body *bytes.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	urlPath := "/dav/" + s.token + "/" + strings.TrimPrefix(strings.ReplaceAll(virtualPath, "\\", "/"), "/")
	req := httptest.NewRequest(method, urlPath, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestIntegratedWebDAVFileManagerSmoke(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	filesReq := httptest.NewRequest(http.MethodGet, "/files/", nil)
	filesRR := httptest.NewRecorder()
	s.ServeHTTP(filesRR, filesReq)
	if filesRR.Code != http.StatusOK {
		t.Fatalf("/files failed: %d", filesRR.Code)
	}
	html := filesRR.Body.String()
	for _, want := range []string{"WebDAV file manager", "davPropfind", "PROPFIND", "Drop files here", "copyDavURL", "webdavStatusBox", "Select current folder"} {
		if !strings.Contains(html, want) {
			t.Fatalf("/files markup missing %q", want)
		}
	}

	rr := davRequest(t, s, http.MethodPut, "docs/a.txt", bytes.NewReader([]byte("alpha")), nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("PUT failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MKCOL", "empty-folder", nil, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("MKCOL failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MKCOL", "content/explicit-empty", nil, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("MKCOL under content failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodDelete, "content", nil, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected protected content delete rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "COPY", "", nil, map[string]string{"Destination": "/dav/" + s.token + "/root-copy"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected root COPY rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "PROPFIND", "", nil, map[string]string{"Depth": "1"})
	if rr.Code != 207 {
		t.Fatalf("PROPFIND root failed: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "/content/") {
		t.Fatalf("PROPFIND root did not include content folder: %s", rr.Body.String())
	}
	rr = davRequest(t, s, "PROPFIND", "docs", nil, map[string]string{"Depth": "1"})
	if rr.Code != 207 || !strings.Contains(rr.Body.String(), "a.txt") {
		t.Fatalf("PROPFIND nested failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodGet, "docs/a.txt", nil, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "alpha" {
		t.Fatalf("GET failed: %d %q", rr.Code, rr.Body.String())
	}
	if cache := rr.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("GET missing no-store header: %q", cache)
	}
	rr = davRequest(t, s, "COPY", "docs/a.txt", nil, map[string]string{"Destination": "/dav/" + s.token + "/docs/b.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("COPY failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, "MOVE", "docs/b.txt", nil, map[string]string{"Destination": "/dav/" + s.token + "/docs/c.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("MOVE failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodGet, "docs/c.txt", nil, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "alpha" {
		t.Fatalf("GET moved failed: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export-zip?path=docs&token="+s.token, nil)
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("ZIP download failed: %d content-type=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodDelete, "docs/c.txt", nil, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE failed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestIntegratedWebDAVSecurityControls(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	initOpenTestVault(t, s)

	badReq := httptest.NewRequest("PROPFIND", "/dav/not-the-token/", nil)
	badRR := httptest.NewRecorder()
	s.ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusForbidden {
		t.Fatalf("expected token rejection, got %d", badRR.Code)
	}

	rr := davRequest(t, s, http.MethodPut, ".SeAvAuLt/evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected case-insensitive .seavault rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, ".seavault/evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected .seavault rejection, got %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, "../evil", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected traversal rejection, got %d %s", rr.Code, rr.Body.String())
	}

	rr = postJSON(t, s, "/api/webdav", map[string]any{"readOnly": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("set readonly failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = davRequest(t, s, http.MethodPut, "docs/readonly.txt", bytes.NewReader([]byte("x")), nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected readonly write rejection, got %d %s", rr.Code, rr.Body.String())
	}

	oldToken := s.token
	rr = postJSON(t, s, "/api/close", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("close failed: %d %s", rr.Code, rr.Body.String())
	}
	if s.token == oldToken {
		t.Fatal("expected token rotation on close")
	}
	closedReq := httptest.NewRequest("PROPFIND", "/dav/"+s.token+"/", nil)
	closedRR := httptest.NewRecorder()
	s.ServeHTTP(closedRR, closedReq)
	if closedRR.Code != http.StatusConflict {
		t.Fatalf("expected WebDAV stopped when vault closes, got %d", closedRR.Code)
	}
}

func TestGuiAuthShowsLoginLandingAndProtectsAPI(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login landing failed: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "SeaVault login") {
		t.Fatalf("expected login landing page, got %q", rr.Body.String())
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	apiRR := httptest.NewRecorder()
	s.ServeHTTP(apiRR, apiReq)
	if apiRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected API to return 401, got %d %s", apiRR.Code, apiRR.Body.String())
	}
}

func TestGuiAuthSessionAllowsIndexAndLogoutClearsSession(t *testing.T) {
	s, err := NewWithConfig("", appconfig.Config{Version: appconfig.Version, GUI: appconfig.GUIConfig{Protocol: "http", Username: "alex", PasswordConfigured: true}})
	if err != nil {
		t.Fatal(err)
	}
	session := "test-session"
	s.authSessions[session] = time.Now().Add(time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: guiSessionCookie, Value: session})
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated index failed: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Logout") {
		t.Fatalf("expected logout link in authenticated UI")
	}

	logoutReq := httptest.NewRequest(http.MethodGet, "/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: guiSessionCookie, Value: session})
	logoutRR := httptest.NewRecorder()
	s.ServeHTTP(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", logoutRR.Code)
	}
	if _, ok := s.authSessions[session]; ok {
		t.Fatalf("logout did not remove server-side session")
	}
	if got := logoutRR.Header().Get("Clear-Site-Data"); got == "" {
		t.Fatalf("logout should ask the browser to clear local site data")
	}
}
