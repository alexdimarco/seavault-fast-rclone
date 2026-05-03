package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
