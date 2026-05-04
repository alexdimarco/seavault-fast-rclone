package webui

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/seavault-fast/internal/appconfig"
	"github.com/example/seavault-fast/internal/dependencies"
	"github.com/example/seavault-fast/internal/importer"
	"github.com/example/seavault-fast/internal/keychain"
	"github.com/example/seavault-fast/internal/localdav"
	"github.com/example/seavault-fast/internal/profile"
	"github.com/example/seavault-fast/internal/rclonebin"
	"github.com/example/seavault-fast/internal/remotes"
	"github.com/example/seavault-fast/internal/rsyncbin"
	"github.com/example/seavault-fast/internal/rsyncput"
	"github.com/example/seavault-fast/internal/sshkeys"
	"github.com/example/seavault-fast/internal/transport"
	localtransport "github.com/example/seavault-fast/internal/transport/local"
	rclonetransport "github.com/example/seavault-fast/internal/transport/rclone"
	"github.com/example/seavault-fast/internal/userpath"
	"github.com/example/seavault-fast/internal/vault"
	"github.com/example/seavault-fast/internal/vaultmove"
	"github.com/example/seavault-fast/internal/xcrypto/argon2"
)

type Server struct {
	mu             sync.Mutex
	vaultPath      string
	vault          *vault.Vault
	token          string
	webdavReadOnly bool
	keychainStatus keychain.Status
	config         appconfig.Config
	authSessions   map[string]time.Time
}

const guiAuthAccount = "seavault-gui-http-auth"
const guiSessionCookie = "seavault_gui_session"

//go:embed assets/svlogo/*.png assets/svlogo/*.ico assets/svlogo/README.txt
var svlogoAssets embed.FS

type apiError struct {
	Error string `json:"error"`
}

type initRequest struct {
	VaultPath         string `json:"vaultPath"`
	Password          string `json:"password"`
	Profile           string `json:"profile"`
	SavePassword      bool   `json:"savePassword"`
	KDF               string `json:"kdf"`
	Argon2Time        int    `json:"argon2Time"`
	Argon2MemoryKiB   int    `json:"argon2MemoryKiB"`
	Argon2Parallelism int    `json:"argon2Parallelism"`
	ScryptN           int    `json:"scryptN"`
	ScryptR           int    `json:"scryptR"`
	ScryptP           int    `json:"scryptP"`
	PBKDF2Iterations  int    `json:"pbkdf2Iterations"`
	MinChunkSize      int    `json:"minChunkSize"`
	AvgChunkSize      int    `json:"avgChunkSize"`
	MaxChunkSize      int    `json:"maxChunkSize"`
}

type openRequest struct {
	VaultPath    string `json:"vaultPath"`
	Password     string `json:"password"`
	UseKeychain  bool   `json:"useKeychain"`
	SavePassword bool   `json:"savePassword"`
	// These are accepted so older browser pages that reused the create form
	// payload can still open existing vaults without hitting DisallowUnknownFields.
	Profile string `json:"profile,omitempty"`
	KDF     string `json:"kdf,omitempty"`
}

type profileRequest struct {
	Name         string `json:"name"`
	VaultPath    string `json:"vaultPath"`
	Password     string `json:"password"`
	SavePassword bool   `json:"savePassword"`
}

type vaultMoveRequest struct {
	ProfileName          string `json:"profileName"`
	SourcePath           string `json:"sourcePath"`
	DestinationPath      string `json:"destinationPath"`
	Replace              bool   `json:"replace"`
	UpdateRemoteProfiles bool   `json:"updateRemoteProfiles"`
}

type rcloneInstallRequest struct {
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	FromBinary     string `json:"fromBinary"`
	OfflineArchive string `json:"offlineArchive"`
	OfflineSHA256  string `json:"offlineSHA256"`
	Signature      string `json:"signature"`
}

type rsyncInstallRequest struct {
	Version        string `json:"version"`
	FromBinary     string `json:"fromBinary"`
	OfflineArchive string `json:"offlineArchive"`
	OfflineSHA256  string `json:"offlineSHA256"`
	RuntimeBaseURL string `json:"runtimeBaseURL"`
	BuildID        string `json:"buildID"`
}

type remoteRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	VaultPath  string `json:"vaultPath"`
	RemotePath string `json:"remotePath"`
	Backend    string `json:"backend"`
	ConfigPath string `json:"configPath"`
	Transfers  int    `json:"transfers"`
	Checkers   int    `json:"checkers"`
	FastList   bool   `json:"fastList"`
	Bandwidth  string `json:"bandwidth"`
	AllowSync  bool   `json:"allowSync"`
}

type remoteRunRequest struct {
	Name      string `json:"name"`
	Operation string `json:"operation"`
}

type sshKeyRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type appConfigRequest struct {
	Config        appconfig.Config `json:"config"`
	GUIPassword   string           `json:"guiPassword"`
	ClearGUILogin bool             `json:"clearGuiLogin"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type logSaveRequest struct {
	Path string `json:"path"`
	Text string `json:"text"`
}

type statusResponse struct {
	Open            bool                `json:"open"`
	BrowserToken    string              `json:"browserToken,omitempty"`
	WebDAV          webdavStatusDTO     `json:"webdav"`
	VaultPath       string              `json:"vaultPath,omitempty"`
	VaultID         string              `json:"vaultId,omitempty"`
	Config          *vaultConfigDTO     `json:"config,omitempty"`
	Profiles        []profile.Entry     `json:"profiles"`
	AvailableVaults []vaultStatusDTO    `json:"availableVaults"`
	SuggestedPaths  []string            `json:"suggestedPaths"`
	KeychainStatus  keychain.Status     `json:"keychainStatus"`
	AppConfig       appconfig.Config    `json:"appConfig"`
	Dependencies    dependencies.Report `json:"dependencies"`
	AuthEnabled     bool                `json:"authEnabled"`
}

type webdavStatusDTO struct {
	Running  bool   `json:"running"`
	ReadOnly bool   `json:"readOnly"`
	URL      string `json:"url"`
	FilesURL string `json:"filesUrl"`
}

type webdavRequest struct {
	ReadOnly bool `json:"readOnly"`
}

type vaultStatusDTO struct {
	Name           string  `json:"name"`
	VaultPath      string  `json:"vaultPath"`
	VaultID        string  `json:"vaultId,omitempty"`
	Exists         bool    `json:"exists"`
	Open           bool    `json:"open"`
	Keychain       bool    `json:"keychain"`
	KeychainStatus string  `json:"keychainStatus,omitempty"`
	KeychainError  string  `json:"keychainError,omitempty"`
	Status         string  `json:"status"`
	Error          string  `json:"error,omitempty"`
	Files          int     `json:"files,omitempty"`
	Objects        int     `json:"objects,omitempty"`
	Referenced     int     `json:"referenced,omitempty"`
	ReferencedMB   float64 `json:"referencedMB,omitempty"`
}

type profileStatusDTO struct {
	Name           string `json:"name"`
	VaultPath      string `json:"vaultPath"`
	VaultID        string `json:"vaultId,omitempty"`
	Exists         bool   `json:"exists"`
	Open           bool   `json:"open"`
	Keychain       bool   `json:"keychain"`
	KeychainStatus string `json:"keychainStatus,omitempty"`
	KeychainError  string `json:"keychainError,omitempty"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

type vaultConfigDTO struct {
	Version      int                `json:"version"`
	KDF          vault.KDFConfig    `json:"kdf"`
	Crypto       vault.CryptoConfig `json:"crypto"`
	Chunk        vault.ChunkParams  `json:"chunk"`
	CreatedAt    string             `json:"createdAt"`
	ManifestMode string             `json:"manifestMode"`
}

type fileDTO struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Chunks     int    `json:"chunks"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
	ConflictOf string `json:"conflictOf,omitempty"`
}

type uploadResponse struct {
	Method      string            `json:"method"`
	RsyncBinary string            `json:"rsyncBinary,omitempty"`
	RsyncOutput string            `json:"rsyncOutput,omitempty"`
	Results     []vault.PutResult `json:"results"`
}

type uploadPathRequest struct {
	SourcePath  string `json:"sourcePath"`
	VirtualPath string `json:"virtualPath"`
	Method      string `json:"method"`
	RsyncBinary string `json:"rsyncBinary"`
	KeepStaging bool   `json:"keepStaging"`
}

type largeImportRequest struct {
	SourcePath   string `json:"sourcePath"`
	VirtualPath  string `json:"virtualPath"`
	Method       string `json:"method"`
	RsyncBinary  string `json:"rsyncBinary"`
	DryRun       bool   `json:"dryRun"`
	SkipExisting bool   `json:"skipExisting"`
}

type exportRequest struct {
	VirtualPath string `json:"virtualPath"`
	DestPath    string `json:"destPath"`
	Overwrite   string `json:"overwrite"`
	DryRun      bool   `json:"dryRun"`
	Zip         bool   `json:"zip"`
}

func New(initialVault string) (*Server, error) {
	cfg, err := appconfig.Load()
	if err != nil {
		return nil, err
	}
	return NewWithConfig(initialVault, cfg)
}

func NewWithConfig(initialVault string, cfg appconfig.Config) (*Server, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	cfg = appconfig.Normalize(cfg)
	s := &Server{token: token, keychainStatus: keychain.Check(), config: cfg, authSessions: make(map[string]time.Time)}
	if strings.TrimSpace(initialVault) != "" {
		resolved, err := resolveVaultArg(initialVault)
		if err != nil {
			return nil, err
		}
		s.vaultPath = resolved
	}
	return s, nil
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := svlogoAssets.ReadFile("assets/svlogo/favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) handleSVLogoAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clean := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/assets/svlogo/"))
	if clean == "/" || strings.Contains(clean, "..") {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(clean, "/")
	switch name {
	case "logo.png", "icon.png", "favicon-32.png", "favicon-64.png", "favicon-180.png":
		w.Header().Set("Content-Type", "image/png")
	case "favicon.ico":
		w.Header().Set("Content-Type", "image/x-icon")
	case "README.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		http.NotFound(w, r)
		return
	}
	data, err := svlogoAssets.ReadFile("assets/svlogo/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		s.handleFavicon(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/svlogo/") {
		s.handleSVLogoAsset(w, r)
		return
	}
	if r.URL.Path == "/login" {
		if r.Method == http.MethodPost {
			s.handleLogin(w, r)
			return
		}
		s.handleLoginPage(w, r, "")
		return
	}
	if r.URL.Path == "/logout" {
		s.handleLogout(w, r)
		return
	}
	if r.URL.Path == "/help" {
		s.handleHelp(w, r)
		return
	}
	if r.URL.Path == "/reset-config" {
		if r.Method == http.MethodPost {
			s.handleResetConfig(w, r)
			return
		}
		s.handleResetConfigPage(w, r, "")
		return
	}
	if s.guiAuthEnabled() && !s.requestAuthenticated(r) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "GUI login is required"})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/dav/") {
			http.Error(w, "SeaVault GUI login is required", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/files" || strings.HasPrefix(r.URL.Path, "/files/") {
			s.handleLoginPage(w, r, "")
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/files" || strings.HasPrefix(r.URL.Path, "/files/") {
		s.handleIndex(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/dav/") {
		s.handleWebDAV(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("X-SeaVault-Token") != s.token {
			writeJSON(w, http.StatusForbidden, apiError{Error: "invalid browser session token"})
			return
		}
	}

	switch r.URL.Path {
	case "/api/status":
		s.handleStatus(w, r)
	case "/api/init":
		s.handleInit(w, r)
	case "/api/open":
		s.handleOpen(w, r)
	case "/api/close":
		s.handleClose(w, r)
	case "/api/files":
		s.handleFiles(w, r)
	case "/api/upload":
		s.handleUpload(w, r)
	case "/api/upload-path":
		s.handleUploadPath(w, r)
	case "/api/import-large/start":
		s.handleLargeImportStart(w, r)
	case "/api/import-large/status":
		s.handleLargeImportStatus(w, r)
	case "/api/import-large/cancel":
		s.handleLargeImportCancel(w, r)
	case "/api/download":
		s.handleDownload(w, r)
	case "/api/export":
		s.handleExport(w, r)
	case "/api/export-zip":
		s.handleExportZipDownload(w, r)
	case "/api/file":
		s.handleFile(w, r)
	case "/api/webdav":
		s.handleWebDAVStatus(w, r)
	case "/api/verify":
		s.handleVerify(w, r)
	case "/api/stats":
		s.handleStats(w, r)
	case "/api/profiles":
		s.handleProfiles(w, r)
	case "/api/profile":
		s.handleProfile(w, r)
	case "/api/vault-move":
		s.handleVaultMove(w, r)
	case "/api/rclone/status":
		s.handleRcloneStatus(w, r)
	case "/api/rsync/status":
		s.handleRsyncStatus(w, r)
	case "/api/rsync/install":
		s.handleRsyncInstall(w, r)
	case "/api/rsync/update":
		s.handleRsyncUpdate(w, r)
	case "/api/rsync/rollback":
		s.handleRsyncRollback(w, r)
	case "/api/rclone/install":
		s.handleRcloneInstall(w, r)
	case "/api/rclone/update":
		s.handleRcloneUpdate(w, r)
	case "/api/rclone/rollback":
		s.handleRcloneRollback(w, r)
	case "/api/remotes":
		s.handleRemotes(w, r)
	case "/api/remote":
		s.handleRemote(w, r)
	case "/api/remote-run":
		s.handleRemoteRun(w, r)
	case "/api/ssh-keys":
		s.handleSSHKeys(w, r)
	case "/api/ssh-key-public":
		s.handleSSHKeyPublic(w, r)
	case "/api/app-config":
		s.handleAppConfig(w, r)
	case "/api/dependencies":
		s.handleDependencies(w, r)
	case "/api/log/save":
		s.handleSaveLog(w, r)
	default:
		http.NotFound(w, r)
	}
}

func hashGUIPassword(password string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt[:], 2, 64*1024, 1, 32)
	return "argon2id$v=1$t=2$m=65536$p=1$" + base64.RawStdEncoding.EncodeToString(salt[:]) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func verifyGUIPasswordHash(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 7 || parts[0] != "argon2id" || parts[1] != "v=1" || parts[2] != "t=2" || parts[3] != "m=65536" || parts[4] != "p=1" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(salt) == 0 {
		return false
	}
	stored, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil || len(stored) == 0 {
		return false
	}
	candidate := argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, uint32(len(stored)))
	return subtle.ConstantTimeCompare(candidate, stored) == 1
}

func (s *Server) guiAuthEnabled() bool {
	cfg := s.currentConfig()
	return strings.TrimSpace(cfg.GUI.Username) != "" && cfg.GUI.PasswordConfigured
}

func (s *Server) requestAuthenticated(r *http.Request) bool {
	if !s.guiAuthEnabled() {
		return true
	}
	c, err := r.Cookie(guiSessionCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.authSessions[c.Value]
	if !ok || now.After(expires) {
		delete(s.authSessions, c.Value)
		return false
	}
	s.authSessions[c.Value] = now.Add(12 * time.Hour)
	return true
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request, message string) {
	if !s.guiAuthEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginPage.Execute(w, struct{ Message string }{Message: message})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.guiAuthEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.handleLoginPage(w, r, "Could not read the login form.")
		return
	}
	cfg := s.currentConfig()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.GUI.Username)) == 1
	passOK := false
	if strings.TrimSpace(cfg.GUI.PasswordHash) != "" {
		passOK = verifyGUIPasswordHash(cfg.GUI.PasswordHash, password)
	} else {
		stored, err := keychain.Get(guiAuthAccount)
		if err != nil {
			s.handleLoginPage(w, r, "GUI login is using a legacy OS-keychain password, but SeaVault could not read it. Use Reset password and app configuration, then set the GUI login password again. Keychain detail: "+err.Error())
			return
		}
		passOK = subtle.ConstantTimeCompare([]byte(password), []byte(stored)) == 1
	}
	if !userOK || !passOK {
		s.handleLoginPage(w, r, "Invalid SeaVault GUI username or password.")
		return
	}
	session, err := randomToken()
	if err != nil {
		s.handleLoginPage(w, r, "Could not create a browser login session.")
		return
	}
	expires := time.Now().Add(12 * time.Hour)
	s.mu.Lock()
	s.authSessions[session] = expires
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: guiSessionCookie, Value: session, Path: "/", Expires: expires, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.EqualFold(cfg.GUI.Protocol, "https")})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(guiSessionCookie); err == nil {
		s.mu.Lock()
		delete(s.authSessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: guiSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
	w.Header().Set("Cache-Control", "no-store")
	if s.guiAuthEnabled() {
		s.handleLoginPage(w, r, "Logged out. The local browser session was cleared.")
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = helpPage.Execute(w, struct{ AuthEnabled bool }{AuthEnabled: s.guiAuthEnabled()})
}

func (s *Server) handleResetConfigPage(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = resetConfigPage.Execute(w, struct{ Message string }{Message: message})
}

func (s *Server) handleResetConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.handleResetConfigPage(w, r, "Could not read the reset form.")
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != "RESET" {
		s.handleResetConfigPage(w, r, "Type RESET exactly to reset the local application configuration and GUI login.")
		return
	}
	if p, err := appconfig.Path(); err == nil && strings.TrimSpace(p) != "" {
		if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) {
			s.handleResetConfigPage(w, r, "Could not remove app configuration: "+rmErr.Error())
			return
		}
	}
	_ = keychain.Delete(guiAuthAccount)
	newToken := mustRandomToken(s.tokenValue())
	s.mu.Lock()
	s.config = appconfig.Default()
	s.authSessions = make(map[string]time.Time)
	s.token = newToken
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: guiSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
	w.Header().Set("Cache-Control", "no-store")
	s.handleResetConfigPage(w, r, "Local application configuration and GUI login were reset. Vault data, saved vault locations, vault passwords, SSH keys, and remotes were not deleted.")
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, struct {
		Token          string
		InitialPath    string
		SuggestedPaths []string
		RsyncHint      string
		AuthEnabled    bool
	}{Token: s.token, InitialPath: s.vaultPath, SuggestedPaths: userpath.SuggestedVaultPaths(), RsyncHint: rsyncput.DefaultBinaryHint(), AuthEnabled: s.guiAuthEnabled()})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	entries, _ := profile.Entries()
	s.mu.Lock()
	open := s.vault != nil
	vaultPath := s.vaultPath
	var vaultID string
	var cfgDTO *vaultConfigDTO
	if s.vault != nil {
		cfg := s.vault.Config
		vaultID = s.vault.ID()
		cfgDTO = &vaultConfigDTO{Version: cfg.Version, KDF: cfg.KDF, Crypto: cfg.Crypto, Chunk: cfg.Chunk, CreatedAt: cfg.CreatedAt, ManifestMode: cfg.Crypto.ManifestMode}
	}
	s.mu.Unlock()
	resp := statusResponse{Open: open, BrowserToken: s.tokenValue(), WebDAV: s.webdavStatus(), VaultPath: vaultPath, VaultID: vaultID, Config: cfgDTO, Profiles: entries, AvailableVaults: s.availableVaultStatuses(entries), SuggestedPaths: userpath.SuggestedVaultPaths(), KeychainStatus: s.keychainStatus, AppConfig: s.currentConfig(), Dependencies: dependencies.Check(), AuthEnabled: s.guiAuthEnabled()}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req initRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	vaultPath, err := absVaultPath(req.VaultPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "password is required"})
		return
	}
	chunk := vault.ChunkParams{MinSize: req.MinChunkSize, AvgSize: req.AvgChunkSize, MaxSize: req.MaxChunkSize}
	if chunk == (vault.ChunkParams{}) {
		chunk = vault.DefaultChunkParams()
	}
	kdfCfg, err := kdfFromInitRequest(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if err := userpath.ValidateCreatableVaultPath(vaultPath); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if err := vault.CreateWithOptions(vaultPath, req.Password, vault.CreateOptions{Chunk: chunk, KDF: kdfCfg}); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	v, err := vault.Open(vaultPath, req.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "vault was created but could not be opened: " + err.Error()})
		return
	}
	s.mu.Lock()
	s.vaultPath = vaultPath
	s.vault = v
	s.mu.Unlock()
	warnings := []string{}
	if strings.TrimSpace(req.Profile) != "" {
		if _, err := profile.Add(req.Profile, vaultPath); err != nil {
			warnings = append(warnings, "vault opened, but profile was not saved: "+err.Error())
		}
	}
	if req.SavePassword {
		if err := keychain.Set(v.ID(), req.Password); err != nil {
			warnings = append(warnings, "vault opened, but password was not saved to the OS keychain: "+err.Error())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "opened": true, "vaultPath": vaultPath, "warnings": warnings})
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req openRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	vaultPath, err := resolveVaultArg(req.VaultPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	password := req.Password
	cfg, cfgErr := vault.ReadConfig(vaultPath)
	if strings.TrimSpace(password) == "" && req.UseKeychain {
		if cfgErr != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: cfgErr.Error()})
			return
		}
		if !s.keychainStatus.Available {
			writeJSON(w, http.StatusBadRequest, apiError{Error: keychainUnavailableMessage(s.keychainStatus)})
			return
		}
		p, err := keychain.Get(cfg.VaultID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "No saved keychain password was found for this vault. Enter the password manually, or use Open and save keychain after keychain access is available."})
			return
		}
		password = p
	}
	if strings.TrimSpace(password) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "password is required unless the OS keychain has this vault"})
		return
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	warnings := []string{}
	if req.SavePassword {
		id := v.ID()
		if cfgErr == nil && cfg.VaultID != "" {
			id = cfg.VaultID
		}
		if err := keychain.Set(id, password); err != nil {
			warnings = append(warnings, "vault opened, but password was not saved to the OS keychain: "+err.Error())
		}
	}
	s.mu.Lock()
	s.vaultPath = vaultPath
	s.vault = v
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "opened": true, "vaultPath": vaultPath, "warnings": warnings})
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	s.vault = nil
	s.token = mustRandomToken(s.token)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "browserToken": s.tokenValue(), "webdav": s.webdavStatus()})
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	files, err := v.Files()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	out := make([]fileDTO, 0, len(files))
	for p, rec := range files {
		out = append(out, fileDTO{Path: p, Size: rec.Size, Chunks: len(rec.Chunks), UpdatedAt: rec.UpdatedAt, ConflictOf: rec.ConflictOf})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	basePath := strings.TrimSpace(r.FormValue("path"))
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no uploaded file field named file or files"})
		return
	}
	relPaths := r.MultipartForm.Value["relpaths"]
	var results []vault.PutResult
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, fh := range files {
		f, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		rel := fh.Filename
		if i < len(relPaths) && strings.TrimSpace(relPaths[i]) != "" {
			rel = relPaths[i]
		}
		rel, err = cleanBrowserRelativePath(rel)
		if err != nil {
			_ = f.Close()
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		virtualPath := strings.TrimSpace(basePath)
		if virtualPath == "" || len(files) > 1 || len(relPaths) > 0 || strings.HasSuffix(virtualPath, "/") {
			virtualPath = path.Join(strings.TrimSuffix(basePath, "/"), rel)
		}
		res, err := v.PutReader(f, virtualPath, fh.Size, 0o600, time.Now().UTC())
		_ = f.Close()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, uploadResponse{Method: "browser", Results: results})
}

func (s *Server) handleUploadPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	var req uploadPathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.SourcePath) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "sourcePath is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := rsyncput.PutPath(r.Context(), v, req.SourcePath, req.VirtualPath, rsyncput.Options{Method: req.Method, RsyncBinary: req.RsyncBinary, KeepStaging: req.KeepStaging})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, uploadResponse{Method: res.Method, RsyncBinary: res.RsyncBinary, RsyncOutput: res.RsyncOutput, Results: res.Results})
}
func (s *Server) handleLargeImportStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	var req largeImportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.SourcePath) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "sourcePath is required"})
		return
	}
	job, err := importer.Start(context.Background(), v, req.SourcePath, importer.Options{VirtualPath: req.VirtualPath, Method: req.Method, RsyncBinary: req.RsyncBinary, DryRun: req.DryRun, SkipExisting: req.SkipExisting})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job.Progress())
}

func (s *Server) handleLargeImportStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "id is required"})
		return
	}
	job, ok := importer.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "large import job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job.Progress())
}

func (s *Server) handleLargeImportCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "id is required"})
		return
	}
	job, ok := importer.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "large import job not found"})
		return
	}
	job.Cancel()
	writeJSON(w, http.StatusOK, job.Progress())
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	vp, err := vault.NormalizeContentPath(r.URL.Query().Get("path"))
	if err != nil || vp == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "valid path query parameter is required"})
		return
	}
	rec, exists, err := v.FileInfo(vp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	name := path.Base(vp)
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", rec.Size))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	if r.Method == http.MethodHead {
		return
	}
	if err := v.WriteFileTo(vp, w); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	var req exportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DestPath) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "destination local folder or ZIP path is required"})
		return
	}
	dest, err := userpath.Abs(req.DestPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := v.ExportPath(r.Context(), req.VirtualPath, dest, vault.ExportOptions{Overwrite: req.Overwrite, Zip: req.Zip, DryRun: req.DryRun})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleExportZipDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	token := s.tokenValue()
	if token == "" || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(token)) != 1 {
		writeJSON(w, http.StatusForbidden, apiError{Error: "invalid browser session token"})
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	vp, err := vault.NormalizeContentPath(r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	files, err := v.Files()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	targets := make([]string, 0)
	if _, ok := files[vp]; ok && vp != "." {
		targets = append(targets, vp)
	} else {
		prefix := strings.Trim(vp, "/")
		if prefix == "." {
			prefix = ""
		}
		if prefix != "" {
			prefix += "/"
		}
		for p := range files {
			if prefix == "" || strings.HasPrefix(p, prefix) {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "virtual path not found"})
		return
	}
	sort.Strings(targets)
	zipName := strings.Trim(path.Base(strings.TrimSuffix(vp, "/")), ".")
	if zipName == "" || zipName == "/" {
		zipName = "seavault-export"
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zipName+".zip"))
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	zw := zip.NewWriter(w)
	defer zw.Close()
	prefixToStrip := ""
	if _, fileSelected := files[vp]; !fileSelected {
		prefixToStrip = strings.Trim(vp, "/")
		if prefixToStrip == "." {
			prefixToStrip = ""
		}
		if prefixToStrip != "" {
			prefixToStrip += "/"
		}
	}
	for _, p := range targets {
		rec := files[p]
		name := strings.TrimPrefix(p, prefixToStrip)
		if name == "" {
			name = path.Base(p)
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			h.SetModTime(t)
		}
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return
		}
		if err := v.WriteFileTo(p, fw); err != nil {
			return
		}
	}
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	vp, err := vault.NormalizeContentPath(r.URL.Query().Get("path"))
	if err != nil || vp == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "valid path query parameter is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := v.RemovePath(vp)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	if err := v.Verify(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	stats, err := v.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleVaultMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req vaultMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DestinationPath) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "destination path is required"})
		return
	}
	sourceArg := strings.TrimSpace(req.SourcePath)
	if sourceArg == "" {
		s.mu.Lock()
		sourceArg = s.vaultPath
		s.mu.Unlock()
	}
	if sourceArg == "" && strings.TrimSpace(req.ProfileName) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "select a saved vault or enter a source vault path before moving"})
		return
	}

	var res vaultmove.Result
	var err error
	if strings.TrimSpace(req.ProfileName) != "" {
		res, err = vaultmove.MoveProfile(req.ProfileName, req.DestinationPath, vaultmove.Options{Replace: req.Replace, UpdateRemoteProfiles: req.UpdateRemoteProfiles})
	} else {
		resolved, resolveErr := resolveVaultArg(sourceArg)
		if resolveErr != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: resolveErr.Error()})
			return
		}
		res, err = vaultmove.Move(resolved, req.DestinationPath, vaultmove.Options{Replace: req.Replace, UpdateMatchingProfiles: true, UpdateRemoteProfiles: req.UpdateRemoteProfiles})
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	reopened := false
	closedActive := false
	s.mu.Lock()
	wasActive := s.vault != nil && samePath(s.vaultPath, res.SourcePath)
	activeID := ""
	if wasActive && s.vault != nil {
		activeID = s.vault.ID()
		s.vault = nil
		s.vaultPath = res.DestinationPath
		closedActive = true
	}
	s.mu.Unlock()
	if wasActive && activeID != "" {
		if password, err := keychain.Get(activeID); err == nil && password != "" {
			if v, err := vault.Open(res.DestinationPath, password); err == nil {
				s.mu.Lock()
				s.vault = v
				s.vaultPath = res.DestinationPath
				s.mu.Unlock()
				reopened = true
				closedActive = false
			} else {
				res.Warnings = append(res.Warnings, "vault was moved, but it could not be reopened from the OS keychain: "+err.Error())
			}
		} else {
			res.Warnings = append(res.Warnings, "vault was moved and closed because no OS keychain password was available for automatic reopen")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "move": res, "reopened": reopened, "closedActive": closedActive})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	entries, err := profile.Entries()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.profileStatuses(entries)})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req profileRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		entry, err := profile.Add(req.Name, req.VaultPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		warnings := []string{}
		if req.SavePassword {
			if strings.TrimSpace(req.Password) == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "password is required to save this vault in the OS keychain"})
				return
			}
			cfg, err := vault.ReadConfig(entry.VaultPath)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
			if _, err := vault.Open(entry.VaultPath, req.Password); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "vault location saved, but the password could not open the vault: " + err.Error()})
				return
			}
			if err := keychain.Set(cfg.VaultID, req.Password); err != nil {
				warnings = append(warnings, "vault location saved, but password was not saved to the OS keychain: "+err.Error())
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profile": entry, "warnings": warnings})
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "name query parameter is required"})
			return
		}
		if err := profile.Remove(name); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleRsyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	st := rsyncput.Inspect(r.Context(), r.URL.Query().Get("binary"))
	if r.URL.Query().Get("checkUpdate") == "1" || strings.EqualFold(r.URL.Query().Get("checkUpdate"), "true") {
		st.Managed = rsyncbin.NewInstaller().Status(r.Context(), true)
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleRsyncInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req rsyncInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := rsyncbin.NewInstaller().Install(r.Context(), rsyncbin.InstallOptions{Version: req.Version, FromBinary: req.FromBinary, OfflineArchive: req.OfflineArchive, OfflineSHA256: req.OfflineSHA256, RuntimeBaseURL: req.RuntimeBaseURL, BuildID: req.BuildID})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "manifest": m})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRsyncUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req rsyncInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := rsyncbin.NewInstaller().Update(r.Context(), rsyncbin.InstallOptions{Version: req.Version, FromBinary: req.FromBinary, OfflineArchive: req.OfflineArchive, OfflineSHA256: req.OfflineSHA256, RuntimeBaseURL: req.RuntimeBaseURL, BuildID: req.BuildID})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "manifest": m})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRsyncRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	m, err := rsyncbin.Rollback()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRcloneStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	check := r.URL.Query().Get("checkUpdate") == "1" || strings.EqualFold(r.URL.Query().Get("checkUpdate"), "true")
	status := rclonebin.NewInstaller().Status(r.Context(), check)
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleRcloneInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req rcloneInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := rclonebin.NewInstaller().Install(r.Context(), rclonebin.InstallOptions{Version: req.Version, Channel: req.Channel, FromBinary: req.FromBinary, OfflineArchive: req.OfflineArchive, OfflineSHA256: req.OfflineSHA256, SignatureMode: req.Signature})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "manifest": m})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRcloneUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req rcloneInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := rclonebin.NewInstaller().Update(r.Context(), rclonebin.InstallOptions{Version: req.Version, Channel: req.Channel, SignatureMode: req.Signature})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "manifest": m})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRcloneRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	m, err := rclonebin.Rollback()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleRemotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	list, err := remotes.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"remotes": list, "rcloneConfigPath": remotes.DefaultRcloneConfigPath()})
}

func (s *Server) handleRemote(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req remoteRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		vaultPath := strings.TrimSpace(req.VaultPath)
		if vaultPath == "" {
			s.mu.Lock()
			vaultPath = s.vaultPath
			s.mu.Unlock()
		}
		if vaultPath == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "vaultPath is required unless a vault is open"})
			return
		}
		resolved, err := resolveVaultArg(vaultPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		p := remotes.DefaultProfile(req.Name, resolved, req.RemotePath, req.Backend)
		if strings.TrimSpace(req.Type) != "" {
			p.Type = strings.ToLower(strings.TrimSpace(req.Type))
		}
		p.Remote.Transfers = req.Transfers
		p.Remote.Checkers = req.Checkers
		p.Remote.FastList = req.FastList
		p.Remote.BandwidthLimit = req.Bandwidth
		p.Safety.AllowDestructiveSync = req.AllowSync
		if strings.TrimSpace(req.ConfigPath) != "" {
			cfg, err := remotes.ResolveConfigPath(req.ConfigPath)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
			p.Remote.RcloneConfigPath = cfg
		}
		entry, err := remotes.Add(p)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entry)
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "name query parameter is required"})
			return
		}
		if err := remotes.Remove(name); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleRemoteRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req remoteRunRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := runRemoteOperation(r.Context(), req.Name, req.Operation)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "result": res})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func runRemoteOperation(ctx context.Context, name, op string) (any, error) {
	p, ok, err := remotes.Get(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("remote profile %q not found", name)
	}
	if p.Type == "local" {
		t := localtransport.New(p)
		switch op {
		case "test":
			return t.Test(ctx)
		case "dry-run":
			return t.DryRunPush(ctx)
		case "push":
			return t.Push(ctx, transport.Options{})
		case "pull":
			return t.Pull(ctx, transport.Options{})
		case "check":
			return t.Check(ctx)
		}
	}
	bin, err := rclonebin.BinaryPath()
	if err != nil {
		return nil, err
	}
	t := rclonetransport.New(bin, p)
	switch op {
	case "test":
		return t.Test(ctx)
	case "dry-run":
		return t.DryRunPush(ctx)
	case "push":
		return t.Push(ctx, transport.Options{})
	case "pull":
		return t.Pull(ctx, transport.Options{})
	case "check":
		return t.Check(ctx)
	case "sync":
		return nil, fmt.Errorf("destructive sync is not available from the GUI; use safe push/pull or CLI after dry-run review")
	default:
		return nil, fmt.Errorf("unsupported remote operation %q", op)
	}
}

func (s *Server) handleSSHKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := sshkeys.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
	case http.MethodPost:
		var req sshKeyRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		var info sshkeys.Entry
		var err error
		if strings.TrimSpace(req.Path) != "" {
			info, err = sshkeys.Import(req.Name, req.Path)
		} else {
			info, err = sshkeys.Generate(r.Context(), req.Name)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleSSHKeyPublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "name query parameter is required"})
		return
	}
	pub, err := sshkeys.Public(name)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pub})
}

func (s *Server) currentConfig() appconfig.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *Server) handleDependencies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, dependencies.Check())
}

func (s *Server) handleAppConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": s.currentConfig(), "path": mustConfigPath()})
	case http.MethodPost:
		var req appConfigRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		cfg := appconfig.Normalize(req.Config)
		if strings.EqualFold(cfg.GUI.Protocol, "https") {
			host := r.Host
			if h, _, err := net.SplitHostPort(r.Host); err == nil {
				host = h
			}
			var err error
			cfg, err = appconfig.EnsureSelfSignedCertificate(cfg, host)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		previousCfg := s.currentConfig()
		if strings.TrimSpace(req.GUIPassword) == "" && strings.TrimSpace(cfg.GUI.PasswordHash) == "" && strings.TrimSpace(previousCfg.GUI.Username) == strings.TrimSpace(cfg.GUI.Username) {
			cfg.GUI.PasswordHash = previousCfg.GUI.PasswordHash
		}
		if req.ClearGUILogin {
			_ = keychain.Delete(guiAuthAccount)
			cfg.GUI.Username = ""
			cfg.GUI.PasswordConfigured = false
			cfg.GUI.PasswordHash = ""
		}
		if strings.TrimSpace(req.GUIPassword) != "" {
			if strings.TrimSpace(cfg.GUI.Username) == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "GUI username is required when setting a GUI password"})
				return
			}
			hash, err := hashGUIPassword(req.GUIPassword)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "GUI password verifier could not be created: " + err.Error()})
				return
			}
			cfg.GUI.PasswordHash = hash
			cfg.GUI.PasswordConfigured = true
			_ = keychain.Delete(guiAuthAccount)
		}
		if strings.TrimSpace(cfg.GUI.Username) == "" {
			cfg.GUI.PasswordConfigured = false
			cfg.GUI.PasswordHash = ""
		}
		if err := appconfig.Save(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": cfg, "path": mustConfigPath(), "restartRequired": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleSaveLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req logSaveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	logPath := strings.TrimSpace(req.Path)
	if logPath == "" {
		logPath = strings.TrimSpace(s.currentConfig().Log.FilePath)
	}
	if logPath == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "log path is required"})
		return
	}
	resolved, err := userpath.Abs(logPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if err := os.WriteFile(resolved, []byte(req.Text), 0o600); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": resolved})
}

func mustConfigPath() string {
	p, err := appconfig.Path()
	if err != nil {
		return ""
	}
	return p
}

func (s *Server) tokenValue() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

func mustRandomToken(fallback string) string {
	token, err := randomToken()
	if err != nil || token == "" {
		return fallback
	}
	return token
}

func (s *Server) webdavStatus() webdavStatusDTO {
	s.mu.Lock()
	defer s.mu.Unlock()
	running := s.vault != nil
	url := ""
	if running {
		url = "/dav/" + s.token + "/"
	}
	return webdavStatusDTO{Running: running, ReadOnly: s.webdavReadOnly, URL: url, FilesURL: "/files/"}
}

func (s *Server) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/dav/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing WebDAV session token", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	token := s.token
	validToken := token != "" && subtle.ConstantTimeCompare([]byte(parts[0]), []byte(token)) == 1
	v := s.vault
	readOnly := s.webdavReadOnly
	s.mu.Unlock()
	if !validToken {
		http.Error(w, "invalid WebDAV session token", http.StatusForbidden)
		return
	}
	if v == nil {
		http.Error(w, "no vault is open", http.StatusConflict)
		return
	}
	dav := &localdav.Server{Vault: v, ReadOnly: readOnly, Prefix: "/dav/" + token + "/"}
	dav.ServeHTTP(w, r)
}

func (s *Server) handleWebDAVStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.webdavStatus())
	case http.MethodPost:
		var req webdavRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		s.mu.Lock()
		s.webdavReadOnly = req.ReadOnly
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, s.webdavStatus())
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) availableVaultStatuses(entries []profile.Entry) []vaultStatusDTO {
	s.mu.Lock()
	activePath := s.vaultPath
	activeVault := s.vault
	s.mu.Unlock()

	out := make([]vaultStatusDTO, 0, len(entries))
	for _, e := range entries {
		st := vaultStatusDTO{Name: e.Name, VaultPath: e.VaultPath, Status: "saved"}
		if activeVault != nil && samePath(e.VaultPath, activePath) {
			st.Open = true
		}
		meta := filepath.Join(e.VaultPath, vault.MetadataDirName, "vault.json")
		if _, err := os.Stat(meta); err != nil {
			if os.IsNotExist(err) {
				st.Status = "missing"
				st.Error = "vault metadata was not found at " + meta
			} else {
				st.Status = "error"
				st.Error = err.Error()
			}
			out = append(out, st)
			continue
		}
		st.Exists = true
		cfg, err := vault.ReadConfig(e.VaultPath)
		if err != nil {
			st.Status = "error"
			st.Error = err.Error()
			out = append(out, st)
			continue
		}
		st.VaultID = cfg.VaultID
		if cfg.VaultID != "" {
			if !s.keychainStatus.Available {
				st.KeychainStatus = "unavailable"
				st.KeychainError = s.keychainStatus.Detail
			} else if p, err := keychain.Get(cfg.VaultID); err == nil && p != "" {
				st.Keychain = true
				st.KeychainStatus = "active"
			} else {
				st.KeychainStatus = "not saved"
			}
		}
		if st.Open {
			st.Status = "open"
			if stats, err := activeVault.Stats(); err == nil {
				st.Files = stats.Files
				st.Objects = stats.Objects
				st.Referenced = stats.Referenced
				st.ReferencedMB = stats.ReferencedMB
			}
		} else if st.Keychain {
			st.Status = "ready"
		} else {
			st.Status = "password required"
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) profileStatuses(entries []profile.Entry) []profileStatusDTO {
	vaults := s.availableVaultStatuses(entries)
	out := make([]profileStatusDTO, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, profileStatusDTO{Name: v.Name, VaultPath: v.VaultPath, VaultID: v.VaultID, Exists: v.Exists, Open: v.Open, Keychain: v.Keychain, KeychainStatus: v.KeychainStatus, KeychainError: v.KeychainError, Status: v.Status, Error: v.Error})
	}
	return out
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil {
		a = absA
	}
	if errB == nil {
		b = absB
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func (s *Server) currentVault(w http.ResponseWriter) (*vault.Vault, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "no vault is open"})
		return nil, false
	}
	return s.vault, true
}

func kdfFromInitRequest(req initRequest) (vault.KDFConfig, error) {
	switch strings.ToLower(strings.TrimSpace(req.KDF)) {
	case "", "argon2id", "argon2-id":
		return vault.KDFConfig{Algorithm: "ARGON2ID", Time: req.Argon2Time, MemoryKiB: req.Argon2MemoryKiB, Parallelism: req.Argon2Parallelism}, nil
	case "scrypt":
		return vault.KDFConfig{Algorithm: "SCRYPT", ScryptN: req.ScryptN, ScryptR: req.ScryptR, ScryptP: req.ScryptP}, nil
	case "pbkdf2", "pbkdf2-hmac-sha256":
		return vault.KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: req.PBKDF2Iterations}, nil
	default:
		return vault.KDFConfig{}, fmt.Errorf("unsupported KDF %q", req.KDF)
	}
}

func resolveVaultArg(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("vault path or profile is required")
	}
	if !strings.ContainsAny(input, `/\\`) && !filepath.IsAbs(input) {
		if e, ok, err := profile.Resolve(input); err != nil {
			return "", err
		} else if ok {
			return e.VaultPath, nil
		}
	}
	return absVaultPath(input)
}

func absVaultPath(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("vault path is required")
	}
	return userpath.Abs(input)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer io.Copy(io.Discard, r.Body)
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return false
	}
	return true
}

func keychainUnavailableMessage(st keychain.Status) string {
	msg := st.Summary
	if msg == "" {
		msg = "OS keychain unavailable"
	}
	if st.Backend != "" {
		msg += " (" + st.Backend + ")"
	}
	if st.Detail != "" {
		msg += ": " + st.Detail
	}
	if len(st.Missing) > 0 {
		msg += " Missing: " + strings.Join(st.Missing, ", ") + "."
	}
	msg += " Enter the vault password manually, or set SEAVAULT_PASSWORD before launching SeaVault."
	return msg
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
}

func cleanBrowserRelativePath(name string) (string, error) {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	name = strings.TrimPrefix(name, "/")
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("uploaded file name is empty")
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." || path.IsAbs(cleaned) {
		return "", fmt.Errorf("unsafe uploaded relative path %q", name)
	}
	return cleaned, nil
}

func contentType(name string) string {
	if ext := filepath.Ext(name); ext != "" {
		if typ := mime.TypeByExtension(ext); typ != "" {
			return typ
		}
	}
	return "application/octet-stream"
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/assets/svlogo/favicon-180.png">
<title>SeaVault Login</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; --bg:#f7f7f5; --fg:#111827; --panel:#ffffff; --border:#d1d5db; --button:#fff1e8; --button-border:#e3b6a5; --danger:#b42318; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1117; --fg:#f9fafb; --panel:#171a22; --border:#3b4252; --button:#33251f; --button-border:#704f43; } }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--fg); }
main { width:min(420px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:28px; box-shadow:0 8px 24px rgba(17,24,39,.08); }
h1 { margin:0 0 8px; font-size:1.45rem; }
p { line-height:1.45; }
.error { color:var(--danger); border:1px solid #ef4444; background:#fff1f0; padding:10px 12px; border-radius:10px; }
label { display:block; margin:14px 0; font-weight:600; }
input { width:100%; box-sizing:border-box; margin-top:6px; border:1px solid var(--border); border-radius:10px; padding:12px; font:inherit; }
button, a.button { display:inline-block; border:1px solid var(--button-border); background:var(--button); color:var(--fg); text-decoration:none; border-radius:10px; padding:11px 16px; font:inherit; cursor:pointer; margin:4px 6px 4px 0; }
small { color:#4b5563; }
</style>
</head>
<body>
<main>
  <h1>SeaVault login</h1>
  <p>Enter the local GUI username and password configured in SeaVault settings.</p>
  {{if .Message}}<p class="error">{{.Message}}</p>{{end}}
  <form method="post" action="/login" autocomplete="on">
    <label>Username <input name="username" autocomplete="username" autofocus required></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <button type="submit">Log in</button>
  </form>
  <p><a class="button" href="/reset-config">Reset password and app configuration</a> <a class="button" href="/help">Help</a></p>
  <p><small>Use reset if the configured GUI password is unavailable or the browser has a stale session. Logout clears the SeaVault browser session and local site storage for this origin.</small></p>
</main>
</body>
</html>`))

var resetConfigPage = template.Must(template.New("reset-config").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/assets/svlogo/favicon-180.png">
<title>Reset SeaVault configuration</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; --bg:#f7f7f5; --fg:#111827; --panel:#ffffff; --border:#d1d5db; --button:#fff1e8; --button-border:#e3b6a5; --danger:#b42318; --muted:#4b5563; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1117; --fg:#f9fafb; --panel:#171a22; --border:#3b4252; --button:#33251f; --button-border:#704f43; --muted:#cbd5e1; } }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--fg); }
main { width:min(620px, calc(100vw - 32px)); max-height:calc(100vh - 48px); overflow:auto; background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:28px; box-shadow:0 8px 24px rgba(17,24,39,.08); }
h1 { margin:0 0 8px; font-size:1.45rem; }
p, li { line-height:1.45; }
.message { border:1px solid var(--border); background:rgba(16,185,129,.08); padding:10px 12px; border-radius:10px; }
.warning { border:1px solid #ef4444; background:#fff1f0; color:var(--danger); padding:10px 12px; border-radius:10px; }
label { display:block; margin:14px 0; font-weight:600; }
input { width:100%; box-sizing:border-box; margin-top:6px; border:1px solid var(--border); border-radius:10px; padding:12px; font:inherit; }
button, a.button { display:inline-block; border:1px solid var(--button-border); background:var(--button); color:var(--fg); text-decoration:none; border-radius:10px; padding:11px 16px; font:inherit; cursor:pointer; }
small { color:var(--muted); }
</style>
</head>
<body>
<main>
  <h1>Reset SeaVault password and app configuration</h1>
  {{if .Message}}<p class="message">{{.Message}}</p>{{end}}
  <p class="warning">This resets only the local SeaVault application configuration and GUI login password. It does not delete encrypted vault data, saved vault locations, vault passwords, SSH keys, or remote repository profiles.</p>
  <form method="post" action="/reset-config" autocomplete="off">
    <label>Type RESET to confirm <input name="confirm" autocomplete="off" required></label>
    <button type="submit">Reset password and app configuration</button>
    <a class="button" href="/login">Back to login</a>
    <a class="button" href="/help">Help</a>
  </form>
  <p><small>After reset, reload SeaVault and configure HTTP/HTTPS, GUI login, logging, runtime sources, and certificate settings again.</small></p>
</main>
</body>
</html>`))

var helpPage = template.Must(template.New("help").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/assets/svlogo/favicon-180.png">
<title>SeaVault Help</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; --bg:#f7f7f5; --fg:#111827; --panel:#ffffff; --panel-2:#f3f4f6; --border:#d1d5db; --muted:#4b5563; --button:#fff1e8; --button-border:#e3b6a5; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1117; --fg:#f9fafb; --panel:#171a22; --panel-2:#111827; --border:#3b4252; --muted:#cbd5e1; --button:#33251f; --button-border:#704f43; } }
body { margin:0; background:var(--bg); color:var(--fg); }
header { position:sticky; top:0; z-index:2; background:var(--panel); border-bottom:1px solid var(--border); padding:16px 24px; }
main { padding:20px; max-width:1180px; margin:0 auto; }
h1 { margin:0 0 8px; }
h2 { margin-top:0; }
p, li { line-height:1.48; }
nav { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
a.button, nav a { display:inline-block; color:var(--fg); text-decoration:none; border:1px solid var(--button-border); background:var(--button); border-radius:10px; padding:8px 12px; }
.help-grid { display:grid; gap:16px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr)); align-items:start; }
.help-box { border:1px solid var(--border); border-radius:14px; background:var(--panel); padding:16px; max-height:420px; overflow:auto; }
.full { grid-column:1 / -1; max-height:520px; }
code { background:var(--panel-2); border:1px solid var(--border); border-radius:6px; padding:1px 4px; }
small, .hint { color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>SeaVault help</h1>
  <p class="hint">Step-by-step reference for the local SeaVault GUI, settings, runtime dependencies, and recovery options.</p>
  <nav aria-label="Help sections">
    <a href="/">Main app</a>{{if .AuthEnabled}}<a href="/logout">Logout</a>{{end}}<a href="/reset-config">Reset password/config</a>
    <a href="#start">How to start</a><a href="#vaults">Vaults</a><a href="#upload">Upload</a><a href="#webdav">WebDAV</a><a href="#remotes">Remote vaults</a><a href="#settings">Settings</a><a href="#security">Security</a><a href="#disclaimer">Disclaimer</a>
  </nav>
</header>
<main>
  <div class="help-grid">
    <section id="start" class="help-box full">
      <h2>How to start</h2>
      <p>SeaVault creates an encrypted vault folder. The safest first test is a small local vault on a local disk before using cloud sync or remote repositories.</p>
      <h3>Create a vault on a local disk</h3>
      <ol>
        <li>Create or choose an empty local folder, for example <code>~/SeaVaults/work</code> on Linux/macOS or <code>C:\Users\you\SeaVaults\work</code> on Windows.</li>
        <li>Open the main app and enter that path in the vault path field.</li>
        <li>Enter a strong vault password. Store it in your password manager. Losing this password can make the encrypted data unrecoverable.</li>
        <li>Select <strong>Create vault and open</strong>. SeaVault creates the protected <code>content/</code> workspace inside the vault.</li>
        <li>Upload a small test file, verify that it appears in WebDAV files, then download or export it to confirm recovery works.</li>
        <li>After the test succeeds, move the vault folder into a cloud sync folder only if that sync client is trusted for your use case.</li>
      </ol>
      <h3>Create a vault with a remote rclone destination</h3>
      <ol>
        <li>Create and test a local vault first. Remote repositories move encrypted vault objects, but the vault password still controls decryption.</li>
        <li>Install or configure rclone from <strong>Settings</strong> and confirm the dependency status is healthy.</li>
        <li>Create an rclone remote with the rclone configuration workflow for the storage target.</li>
        <li>Return to SeaVault and add a remote repository profile that points to the tested rclone remote path.</li>
        <li>Use <strong>Dry run</strong> or <strong>Check</strong> first, then use <strong>Push</strong> to upload encrypted vault data or <strong>Pull</strong> to restore it.</li>
      </ol>
      <h3>Amazon storage through rclone</h3>
      <ol>
        <li>For Amazon object storage, configure rclone with an S3-compatible remote and a bucket/path dedicated to SeaVault encrypted data.</li>
        <li>Use least-privilege AWS credentials limited to that bucket or prefix. Avoid using administrator credentials.</li>
        <li>Amazon EBS is block storage and is not normally an rclone remote by itself. To use EBS, mount it on a host and use a local path or expose it through a supported protocol.</li>
        <li>Run rclone <code>ls</code>, <code>copy --dry-run</code>, or SeaVault remote <strong>Check</strong> before using it for production data.</li>
      </ol>
      <h3>SSH/SFTP remote through rclone</h3>
      <ol>
        <li>Generate or import an SSH key from the <strong>SSH keys</strong> settings section.</li>
        <li>Install the public key on the server account that will hold the encrypted remote repository.</li>
        <li>Create an rclone SFTP remote using that key and a locked-down server path.</li>
        <li>Add the SFTP remote path as a SeaVault remote repository profile, then test with <strong>Dry run</strong> and <strong>Check</strong>.</li>
      </ol>
    </section>
    <section id="vaults" class="help-box">
      <h2>1. Vaults</h2>
      <ol>
        <li>Choose a saved vault or type a local vault path.</li>
        <li>Enter the vault password, or leave it blank only when an OS keychain password is active for that vault.</li>
        <li>Use <strong>Open typed vault</strong> for a manual path, <strong>Open selected using keychain</strong> for a saved keychain entry, or <strong>Create vault and open</strong> for a new vault.</li>
        <li>Use <strong>Save vault location/password</strong> to add the vault to the selector and optionally store the password in the OS keychain.</li>
      </ol>
    </section>
    <section id="upload" class="help-box">
      <h2>2. Upload and import</h2>
      <ol>
        <li>Use browser file upload for normal files.</li>
        <li>Use browser folder upload when the browser supports relative folder paths.</li>
        <li>Use local path ingest for large local folders. Native import avoids rsync dependencies.</li>
        <li>Use large local import for multi-GB or TB folder scans. The browser starts and monitors a backend job.</li>
      </ol>
    </section>
    <section id="webdav" class="help-box">
      <h2>3. WebDAV file manager</h2>
      <ol>
        <li>Open a vault first.</li>
        <li>Start WebDAV in read/write or read-only mode.</li>
        <li>Use the file manager for normal browsing, folder creation, drag/drop, download, and delete operations.</li>
        <li>The protected <code>content/</code> directory is the default user workspace.</li>
      </ol>
    </section>
    <section id="remotes" class="help-box full">
      <h2>4. Remote repositories</h2>
      <p>Remote repositories are optional locations used to synchronize or back up the encrypted vault data. They do not replace the need to remember the vault password.</p>
      <ul>
        <li><strong>Local remote:</strong> choose another disk, NAS mount, or external drive path for encrypted backup copies.</li>
        <li><strong>Rclone remote:</strong> use rclone for S3-compatible storage, SFTP, Backblaze B2, WebDAV, or other supported providers.</li>
        <li><strong>Amazon storage:</strong> use S3-compatible object storage for direct rclone remotes. For EBS or other block storage, mount the volume first and use it as a local path or expose it through a supported service.</li>
        <li><strong>SSH/SFTP:</strong> use the SSH keys page to create or import keys, then configure an rclone SFTP remote with that identity.</li>
        <li><strong>Validation:</strong> run dry-run, check, and a small test push/pull before relying on any remote for recovery.</li>
      </ul>
    </section>
    <section id="settings" class="help-box full">
      <h2>5. Settings page</h2>
      <ul>
        <li><strong>Local dependencies:</strong> shows OS keychain, WSL, rsync, rclone, and other local runtime checks.</li>
        <li><strong>WebDAV details:</strong> shows current WebDAV mode, path, URL, and file-manager state.</li>
        <li><strong>GUI protocol and certificate:</strong> choose HTTP or HTTPS. HTTPS uses the configured certificate files or app-managed self-signed certificate files.</li>
        <li><strong>GUI user and password:</strong> set local browser login. SeaVault stores a salted Argon2id password verifier in the local app configuration, not the plaintext password. Logout clears the browser session for this origin.</li>
        <li><strong>Reset password and app configuration:</strong> clears the GUI login and local app config when a password is lost or settings need to return to defaults.</li>
        <li><strong>Log settings:</strong> controls maximum in-memory entries, optional local log file path, persistent logging, manual save, and clear.</li>
        <li><strong>Runtime and WSL sources:</strong> sets rclone channel, rsync source URLs, managed runtime URL, and WSL install/update source.</li>
        <li><strong>Managed tools:</strong> install, register, update, or roll back managed rclone and rsync runtimes.</li>
        <li><strong>SSH keys:</strong> generate or import keys for rclone SFTP remotes.</li>
        <li><strong>Remote repositories:</strong> save rclone or local remote repository profiles and run push/pull operations.</li>
      </ul>
    </section>
    <section id="security" class="help-box full">
      <h2>6. Security and recovery</h2>
      <ul>
        <li>The vault password protects encrypted vault contents. The GUI login only protects the local browser interface.</li>
        <li>OS keychain availability depends on platform dependencies such as Secret Service on Linux, Keychain on macOS, or Credential Manager on Windows.</li>
        <li>Resetting GUI password/config does not decrypt or alter vault contents and does not remove saved vault password entries.</li>
        <li>For forgotten vault passwords, reset does not help. The vault password must be known or stored in the OS keychain.</li>
        <li>Use HTTPS with a self-signed certificate when local browser traffic must be encrypted. Trust warnings are expected unless the certificate is trusted locally.</li>
      </ul>
    </section>
    <section id="disclaimer" class="help-box full">
      <h2>7. Disclaimer and user responsibility</h2>
      <p>SeaVault is provided without warranty. The developer is not responsible for data loss, security incidents, service outages, incorrect configuration, failed backups, failed restores, account charges, remote-provider issues, credential exposure, regulatory consequences, or any other loss or damage arising from use of the app.</p>
      <p>By using the app, the user assumes all responsibility for configuration, passwords, keys, storage choices, backup validation, restore testing, legal and regulatory suitability, and operational risk.</p>
      <p>Before using SeaVault with important data, test vault creation, upload, export, remote push, remote pull, and restore on non-critical sample data.</p>
    </section>
  </div>
</main>
</body>
</html>`))

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en" data-token="{{.Token}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/assets/svlogo/favicon-180.png">
<title>SeaVault Fast | Crescendum</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #eef3f8;
  --fg: #10233d;
  --muted: #486079;
  --panel: #ffffff;
  --panel-2: #f5f9fc;
  --border: #cdd9e5;
  --control: #ffffff;
  --button: #edf8fa;
  --button-border: #6ec7ce;
  --danger: #b42318;
  --danger-bg: #fff1f0;
  --success: #0b7b6e;
  --success-bg: #edfdfa;
  --focus: #1461d2;
  --shadow: 0 10px 30px rgba(16, 35, 61, .08);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1117;
    --fg: #f9fafb;
    --muted: #c7ccd1;
    --panel: #171a22;
    --panel-2: #202532;
    --border: #3b4252;
    --control: #111827;
    --button: #33251f;
    --button-border: #815947;
    --danger: #ffb4ab;
    --danger-bg: #3a1715;
    --success: #a7f3d0;
    --success-bg: #073b2a;
    --focus: #7aa2ff;
    --shadow: none;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg); line-height: 1.45; }
header {
  padding: 18px clamp(14px, 3vw, 28px);
  border-bottom: 1px solid var(--border);
  background: linear-gradient(135deg, #0d2340 0%, #16355d 48%, #0d6f7c 100%);
  color: #f8fbff;
}
.header-row { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; }
.settings-button, .header-nav a {
  white-space:nowrap;
  text-decoration:none;
  padding:10px 14px;
  border-radius:999px;
  border:1px solid rgba(255,255,255,.18);
  background: rgba(255,255,255,.1);
  color:#f8fbff;
  transition: background .2s ease, border-color .2s ease, transform .2s ease;
}
.settings-button:hover, .header-nav a:hover { background: rgba(255,255,255,.18); border-color: rgba(255,255,255,.28); transform: translateY(-1px); }
.header-main { display:grid; gap:14px; min-width:0; }
.header-actions { display:flex; flex-wrap:wrap; gap:10px; justify-content:flex-end; }
.brand-lockup { display:flex; align-items:center; gap:16px; min-width:0; }
.brand-logo-img {
  width: min(340px, 42vw);
  height: auto;
  display: block;
  border-radius: 14px;
  background: #ffffff;
  padding: 6px 10px;
  box-shadow: 0 14px 28px rgba(0,0,0,.18);
  flex: 0 0 auto;
}
.brand-icon-img {
  width: 72px;
  height: 72px;
  display: block;
  border-radius: 18px;
  background: #ffffff;
  padding: 4px;
  box-shadow: 0 14px 28px rgba(0,0,0,.18);
}
.brand-copy { min-width:0; }
.brand-eyebrow {
  display:inline-flex;
  align-items:center;
  gap:8px;
  margin-bottom:4px;
  font-size:.76rem;
  letter-spacing:.08em;
  text-transform:uppercase;
  color:rgba(248,251,255,.76);
}
.brand-eyebrow a { color:inherit; text-decoration:none; }
.brand-eyebrow a:hover { color:#ffffff; text-decoration:underline; text-underline-offset:3px; }
.brand-eyebrow::before {
  content:"";
  width:26px;
  height:2px;
  border-radius:999px;
  background:#36d0d8;
}
.brand-title { margin:0 0 4px; font-size: clamp(1.7rem, 2.8vw, 2.35rem); line-height:1.05; }
.brand-copy p { max-width: 76ch; margin: 0; color: rgba(248,251,255,.88); }
.header-nav { display:flex; flex-wrap:wrap; gap:10px; margin-top: 6px; }
.app-shell { max-width: 1560px; margin: 0 auto; padding: clamp(12px, 2.4vw, 24px); display: grid; grid-template-columns: minmax(0, 1fr) minmax(340px, 420px); gap: clamp(12px, 2vw, 20px); align-items: start; }
.content { display: grid; gap: 16px; min-width: 0; }
section, aside { min-width: 0; border: 1px solid var(--border); border-radius: 16px; padding: clamp(14px, 2.2vw, 20px); background: var(--panel); box-shadow: var(--shadow); }
section h2, aside h2 { margin-top: 0; font-size: clamp(1.1rem, 2vw, 1.35rem); }
.result-panel { position: sticky; top: 16px; max-height: calc(100vh - 32px); overflow: auto; align-self: start; }
.form-grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 245px), 1fr)); align-items: start; }
label { display: grid; gap: 6px; font-size: .94rem; min-width: 0; }
input, select, button, textarea { font: inherit; max-width: 100%; min-width: 0; }
input, select, textarea { width: 100%; padding: 10px 11px; border-radius: 10px; border: 1px solid var(--border); background: var(--control); color: var(--fg); }
input[type="checkbox"] { width: auto; min-width: auto; }
input[type="file"] { overflow: hidden; text-overflow: ellipsis; }
button { cursor: pointer; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--button-border); background: var(--button); color: var(--fg); }
button:hover { filter: brightness(.98); }
button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 3px solid color-mix(in srgb, var(--focus) 35%, transparent); outline-offset: 2px; }
button.danger { border-color: var(--danger); background: var(--danger-bg); color: var(--danger); }
button.secondary { background: var(--panel-2); border-color: var(--border); }
button:disabled, body.busy button.operation { opacity: .55; cursor: not-allowed; }
small, .hint { color: var(--muted); }
.selection-summary { display: block; min-height: 2.4em; overflow-wrap: anywhere; }
.selection-summary.warning { color: var(--danger); }
pre { white-space: pre-wrap; overflow-wrap: anywhere; max-width: 100%; padding: 12px; border-radius: 12px; background: var(--panel-2); border: 1px solid var(--border); }
#status { min-height: 280px; }
#message { padding: 10px 12px; border-radius: 12px; background: var(--panel-2); border: 1px solid var(--border); margin-bottom: 12px; }
#message.error { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }
#message.success { background: var(--success-bg); color: var(--success); border-color: var(--success); }
progress { width: 100%; height: 18px; accent-color: var(--focus); }
table { width: 100%; border-collapse: collapse; min-width: 680px; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
.table-wrap { overflow-x: auto; width: 100%; -webkit-overflow-scrolling: touch; }
.raw-file-list.scroll-y { max-height: 760px; overflow: auto; border: 1px solid var(--border); border-radius: 12px; }
.raw-file-list.scroll-y table thead th { position: sticky; top: 0; background: var(--panel); z-index: 1; }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; word-break: break-word; }
.row-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.checkline { display: inline-flex; gap: 8px; align-items: center; width: auto; }
.pill { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); font-size: .8rem; }
.vault-list { display: grid; gap: 10px; margin-top: 14px; }
.vault-card { border: 1px solid var(--border); border-radius: 12px; padding: 10px; background: var(--panel-2); }
.vault-card header { all: unset; display: flex; justify-content: space-between; gap: 8px; align-items: start; margin-bottom: 6px; }
.vault-card .vault-name { font-weight: 700; overflow-wrap: anywhere; }
.vault-card .vault-path { font-size: .82rem; color: var(--muted); overflow-wrap: anywhere; }
.vault-card progress { height: 10px; margin-top: 8px; }
.status-open { border-color: var(--success); background: color-mix(in srgb, var(--success-bg) 60%, var(--panel-2)); }
.status-error, .status-missing { border-color: var(--danger); background: color-mix(in srgb, var(--danger-bg) 55%, var(--panel-2)); }
.status-warning { border-color: var(--button-border); background: color-mix(in srgb, var(--button) 70%, var(--panel-2)); }
.dependency-status { margin: 10px 0 14px; }
.settings-grid { display:grid; gap:16px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 360px), 1fr)); align-items:start; }
.settings-box { max-height: 520px; overflow:auto; border:1px solid var(--border); border-radius:12px; padding:12px; background:var(--panel-2); }
.log-view { min-height: 240px; max-height: 520px; overflow:auto; }
.webdav-indicator { margin-top:10px; }
.dependency-status small { display: block; margin-top: 4px; }
.jump-links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.jump-links a { color: var(--focus); text-decoration: none; padding: 4px 0; }
.jump-links a:hover { text-decoration: underline; }
.compat-warning { display: none; padding: 10px 12px; border-radius: 12px; background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); margin-top: 12px; }

.file-manager-grid { display: grid; grid-template-columns: minmax(180px, 260px) minmax(0, 1fr); gap: 12px; align-items: stretch; }
.folder-tree, .file-browser { border: 1px solid var(--border); border-radius: 12px; background: var(--panel-2); padding: 12px; min-width: 0; height: clamp(420px, 62vh, 720px); overflow: auto; }
.folder-tree { overflow-x: auto; overflow-y: auto; }
.folder-tree ul { margin: 0; padding-left: 18px; }
.folder-tree button, .breadcrumb button { padding: 5px 7px; border-radius: 8px; background: transparent; border-color: transparent; text-align: left; }
.breadcrumb { display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 10px; align-items: center; }
.drop-zone { border: 2px dashed var(--border); border-radius: 12px; padding: 14px; text-align: center; color: var(--muted); background: var(--panel); margin: 10px 0; }
.drop-zone.dragover { border-color: var(--focus); color: var(--fg); }
.file-table tr.selected { background: color-mix(in srgb, var(--focus) 12%, transparent); }
.file-table td:first-child { word-break: break-word; }
@media (max-width: 840px) { .file-manager-grid { grid-template-columns: 1fr; } .folder-tree, .file-browser { height: min(70vh, 560px); } }
@supports not (outline: 3px solid color-mix(in srgb, #2563eb 35%, transparent)) {
  button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 3px solid var(--focus); }
}
@media (max-width: 1180px) {
  .app-shell { grid-template-columns: 1fr; }
  .result-panel { position: static; max-height: none; order: -1; }
  #status { max-height: 320px; overflow: auto; }
}
@media (max-width: 720px) {
  header { padding: 14px; }
  .header-row { flex-direction: column; }
  .brand-lockup { align-items:flex-start; }
  .header-nav { width:100%; }
  .settings-button, .header-nav a { width:100%; text-align:center; }
  .app-shell { padding: 12px; gap: 12px; }
  section, aside { border-radius: 12px; padding: 14px; }
  .row-actions { display: grid; grid-template-columns: 1fr; }
  .row-actions button { width: 100%; }
  .checkline { width: 100%; }
  table { min-width: 620px; }
}
</style>
</head>
<body>
<header>
  <div class="header-row">
    <div class="header-main">
      <div class="brand-lockup">
        <img class="brand-logo-img" src="/assets/svlogo/logo.png" alt="SeaVault Fast">
        <div class="brand-copy">
          <div class="brand-eyebrow"><a href="https://crescendum.ca" target="_blank" rel="noopener noreferrer">Crescendum secure workspace</a></div>
          <h1 class="brand-title">Encrypted File Storage</h1>
          <p>The vault directory is the encrypted cloud-sync location. Put it inside OneDrive, Dropbox, Nextcloud, Syncthing, iCloud Drive, Google Drive, or any sync-client folder.</p>
        </div>
      </div>
    </div>
    <div class="header-actions"><a class="settings-button" href="/help">Help</a><a class="settings-button" href="#settings-panel">Settings</a>{{if .AuthEnabled}}<a class="settings-button" href="/logout">Logout</a>{{end}}</div>
  </div>
  <nav class="jump-links" aria-label="Page sections">
    <a href="#vault-panel">Vault</a>
    <a href="#upload-panel">Upload</a>
    <a href="#move-panel">Move vault</a>
    <a href="#export-panel">Export</a>
    <a href="/files/">WebDAV files</a>
    <a href="#remote-panel">Remote</a>
    <a href="#settings-panel">Settings</a>
    <a href="/help">Help</a>
    <a href="#managed-tools-panel">Managed tools</a>
    <a href="#keys-panel">SSH keys</a>
  </nav>
  <div id="compatWarning" class="compat-warning" role="alert"></div>
</header>
<main class="app-shell">
<div class="content">
<section id="vault-panel">
  <h2>Open or create vault</h2>
  <div class="form-grid">
    <label>Saved vault selector
      <select id="vaultSelect" onchange="selectSavedVault()">
        <option value="">Manual path or new vault</option>
      </select>
      <small>Choose a saved vault location, then open it with the saved keychain password or a typed password.</small>
    </label>
    <label>Vault path or saved name
      <input id="vaultPath" value="{{.InitialPath}}" placeholder="~/Nextcloud/seavault" autocomplete="off">
      <small>This is where encrypted chunks and manifests are stored. Use ~/Nextcloud/seavault or an existing local sync folder. On macOS use /Users/name, not /user/name.</small>
    </label>
    <label>Password
      <input id="password" type="password" autocomplete="current-password">
      <small>Leave blank only when using a saved OS keychain entry.</small>
    </label>
    <label>Saved vault name
      <input id="profile" placeholder="work-cloud" autocomplete="off">
      <small>Required to save the vault location in the dropdown.</small>
    </label>
    <label>KDF for new vaults
      <select id="kdf">
        <option value="argon2id">Argon2id default</option>
        <option value="scrypt">scrypt</option>
        <option value="pbkdf2">PBKDF2 legacy compatibility</option>
      </select>
    </label>
  </div>
  {{if .SuggestedPaths}}
  <div>
    <small>Suggested encrypted vault folders from this computer:</small>
    <p class="row-actions">{{range .SuggestedPaths}}<button type="button" data-path="{{.}}" onclick="fillPath(this.dataset.path)">{{.}}</button>{{end}}</p>
  </div>
  {{end}}
  <p class="row-actions">
    <button type="button" class="operation" onclick="openVault(false)">Open typed vault</button>
    <button type="button" class="operation" onclick="openVault(true)">Open selected using keychain</button>
    <button type="button" class="operation" onclick="initVault()">Create vault and open</button>
    <button type="button" class="operation" onclick="saveCurrentVaultProfile()">Save vault location/password</button>
    <button type="button" onclick="closeVault()">Close active vault</button>
    <label class="checkline"><input id="savePassword" type="checkbox"> Save password in OS keychain</label>
  </p>
  <p class="hint">Saved vault locations are stored in the app profile list. Passwords are stored separately in the OS keychain by vault ID. The encrypted vault folder can still be moved by your sync client.</p>
</section>

<section id="upload-panel">
  <h2>Upload into encrypted archive</h2>
  <p class="hint">Browser uploads are encrypted directly into the vault. For very large folders, the GUI sends smaller batches. Local path ingest lets the local GUI server read the folder directly. It uses native Go import by default, or optional managed/system rsync staging when selected.</p>
  <div class="form-grid">
    <label>Virtual path or folder
      <input id="uploadPath" placeholder="reports/" autocomplete="off">
      <small id="uploadPathHint">For one file, use an exact path such as reports/a.pdf. For selected browser folders, the selected folder name is already included in the upload path, so leave this blank or enter only the parent folder to avoid duplicate names.</small>
    </label>
    <label>Files from browser
      <input id="fileInput" type="file" multiple>
      <small id="fileSummary" class="selection-summary">No browser files selected.</small>
    </label>
    <label>Folder from browser
      <input id="folderInput" type="file" webkitdirectory directory multiple>
      <small id="folderSupportHint">Preserves relative paths where the browser supports folder selection.</small>
      <small id="folderSummary" class="selection-summary">No browser folder selected.</small>
    </label>
    <label>Import from local path (advanced)
      <input id="localSourcePath" placeholder="~/Documents/project-folder" autocomplete="off">
      <small>Optional. Type a local file or folder path only when you want the local GUI service to read it directly. Browser-selected folders cannot fill this field for security reasons.</small>
    </label>
    <label>Put method for local path ingest
      <select id="localPutMethod">
        <option value="auto">auto: managed rsync, system rsync, then native</option>
        <option value="native" selected>native: no rsync dependency</option>
        <option value="managed-rsync">managed rsync: use app-managed runtime</option>
        <option value="system-rsync">system rsync: use PATH or override</option>
        <option value="rsync">rsync alias: require system rsync</option>
      </select>
      <small>This setting only applies to the local path field, not browser file/folder uploads. Native is recommended unless you specifically need rsync staging.</small>
    </label>
    <label>Rsync binary override
      <input id="localRsyncBinary" value="{{.RsyncHint}}" placeholder="{{.RsyncHint}}" autocomplete="off">
      <small>Used only for system-rsync. Managed rsync uses the app-managed runtime path.</small>
    </label>
    <label>Large import options
      <span class="checkline"><input id="largeDryRun" type="checkbox"> Dry-run scan only</span>
      <span class="checkline"><input id="largeSkipExisting" type="checkbox" checked> Skip existing matching files</span>
      <small>Use Start large local import for multi-GB or TB folders. The browser only starts and monitors a backend job; it does not upload the folder.</small>
    </label>
  </div>
  <p class="row-actions">
    <button class="operation" onclick="uploadFiles('fileInput', false)">Upload selected files</button>
    <button class="operation" onclick="uploadFiles('folderInput', true)">Upload selected browser folder</button>
    <button class="operation" onclick="uploadLocalPath()">Import local path</button>
    <button class="operation" onclick="startLargeImport()">Start large local import</button>
    <button class="secondary" onclick="checkRsync()">Check rsync</button>
    <button class="danger" onclick="cancelActive()">Cancel active upload/export</button>
  </p>
</section>


<section id="move-panel">
  <h2>Move vault location</h2>
  <p class="hint">Move the encrypted vault folder to another local disk or sync-client folder. The OS keychain entry is kept because it is tied to the vault ID, not the path. Saved vault and matching remote profiles are updated after a successful move.</p>
  <div class="form-grid">
    <label>Saved vault to move
      <select id="moveProfile" onchange="fillMoveFromProfile()">
        <option value="">Use active/manual source path</option>
      </select>
      <small>Select a saved vault, or leave blank to move the active/manual source path.</small>
    </label>
    <label>Source vault path
      <input id="moveSource" placeholder="active vault or saved profile path" autocomplete="off">
      <small>Leave blank to move the active open vault, or enter a vault path/profile.</small>
    </label>
    <label>New vault location
      <input id="moveDest" placeholder="~/Nextcloud/seavault-new" autocomplete="off">
      <small>Choose the new encrypted vault folder location. Do not choose a folder inside the existing vault.</small>
    </label>
    <label>Move options
      <span class="checkline"><input id="moveUpdateRemotes" type="checkbox" checked> Update matching remote profiles</span>
      <span class="checkline"><input id="moveReplace" type="checkbox"> Replace existing destination if present</span>
      <small>Replace removes the destination path first. Use it only when you are certain it does not contain needed data.</small>
    </label>
  </div>
  <p class="row-actions">
    <button class="operation" onclick="moveVaultLocation()">Move vault location</button>
    <button class="secondary" onclick="prefillMoveFromActive()">Use active vault as source</button>
  </p>
</section>

<section id="export-panel">
  <h2>Export plaintext from vault</h2>
  <p class="hint">Exports decrypt files from the open vault to a local destination. The destination is never inside .seavault unless you explicitly type that path, which is not recommended.</p>
  <div class="form-grid">
    <label>Selected virtual folder or file
      <input id="exportPath" placeholder="projects/site or . for all files" autocomplete="off">
      <small>Use . to export the entire vault. Use a folder prefix to export that directory.</small>
    </label>
    <label>Destination local folder or ZIP path
      <input id="exportDest" placeholder="~/Desktop/seavault-export" autocomplete="off">
      <small>For ZIP export, enter a folder or a .zip path.</small>
    </label>
    <label>Overwrite policy
      <select id="exportOverwrite">
        <option value="fail">fail if destination exists</option>
        <option value="skip">skip existing files</option>
        <option value="replace">replace existing files</option>
      </select>
    </label>
    <label>ZIP option
      <span class="checkline"><input id="exportZip" type="checkbox"> Create ZIP archive instead of folders/files</span>
      <small>ZIP exports are written by the local GUI server.</small>
    </label>
  </div>
  <p class="row-actions">
    <button class="operation" onclick="exportVault(false, false)">Export selected folder/file</button>
    <button class="operation" onclick="exportVault(true, false)">Dry-run selected export</button>
    <button class="operation" onclick="exportVault(false, true)">Export entire vault</button>
    <button class="operation" onclick="exportVault(true, true)">Dry-run entire vault</button>
  </p>
</section>

<section id="files-panel">
  <h2>WebDAV file manager</h2>
  <p class="hint">This is SeaVault's built-in WebDAV client. It talks to the local same-origin WebDAV endpoint and does not depend on Finder, Windows Explorer, GNOME Files, KDE Dolphin, davfs2, WinFsp, macFUSE, or FUSE.</p>
  <p class="row-actions">
    <button class="operation" onclick="refreshDavFiles()">Refresh folder</button>
    <button class="operation" onclick="createDavFolder()">New folder</button>
    <button class="operation" onclick="downloadSelectedDav()">Download selected file</button>
    <button class="operation" onclick="downloadSelectedDavZip()">Download selected folder as ZIP</button>
    <button class="operation" onclick="renameSelectedDav()">Rename/move</button>
    <button class="operation" onclick="copySelectedDav()">Copy</button>
    <button class="danger operation" onclick="deleteSelectedDav()">Delete</button>
    <button class="secondary" onclick="copyDavURL()">Copy WebDAV URL</button>
    <label class="checkline"><input id="webdavReadOnly" type="checkbox" onchange="toggleWebDAVReadOnly()"> Read-only WebDAV mode</label>
  </p>
  <div class="form-grid">
    <label>Upload files through WebDAV
      <input id="davFileInput" type="file" multiple>
      <small>Files upload into the current WebDAV folder.</small>
    </label>
    <label>Upload folder through WebDAV
      <input id="davFolderInput" type="file" webkitdirectory directory multiple>
      <small>Folder uploads preserve browser-provided relative paths.</small>
    </label>
  </div>
  <div id="davDropZone" class="drop-zone">Drop files here to upload into the current folder.</div>
  <div class="file-manager-grid">
    <div class="folder-tree">
      <strong>Folder tree</strong>
      <div id="davTree"><p class="hint">Open a vault, then refresh.</p></div>
    </div>
    <div class="file-browser">
      <div id="davBreadcrumb" class="breadcrumb"></div>
      <div id="davTable" class="table-wrap"><p class="hint">Open a vault to browse files.</p></div>
    </div>
  </div>
</section>

<section id="legacy-files-panel">
  <h2>Advanced raw file list</h2>
  <p class="hint">Debug view of virtual paths and chunk counts. Use the WebDAV file manager above for normal file browsing.</p>
  <p class="row-actions"><button onclick="refreshFiles()">Refresh raw list</button><button onclick="verifyVault()">Verify</button><button onclick="loadStats()">Stats</button></p>
  <div id="files" class="table-wrap"></div>
</section>

<section>
  <h2>Saved vault locations</h2>
  <p class="hint">These locations appear in the vault dropdown. Passwords are only stored when you save them to the OS keychain.</p>
  <p><button onclick="refreshStatus()">Refresh saved vaults</button></p>
  <div id="profiles" class="table-wrap"></div>
</section>

<section id="managed-tools-panel">
  <h2>Managed rsync runtime</h2>
  <p class="hint">Managed rsync is optional. SeaVault works without it by using native Go import. Installing managed rsync only affects local path ingest, not browser uploads or rclone remote transport.</p>
  <div class="form-grid">
    <label>Version
      <input id="rsyncVersion" placeholder="latest upstream source release or 3.4.2" autocomplete="off">
      <small>Leave blank for latest source release when using a runtime URL.</small>
    </label>
    <label>Register existing rsync binary
      <input id="rsyncFromBinary" placeholder="/usr/bin/rsync" autocomplete="off">
      <small>Copies a verified existing rsync into SeaVault's managed runtime folder.</small>
    </label>
    <label>Offline runtime ZIP
      <input id="rsyncOfflineArchive" placeholder="/path/to/seavault-rsync-runtime.zip" autocomplete="off">
      <small>Use an enterprise-built SeaVault rsync runtime archive.</small>
    </label>
    <label>Runtime base URL
      <input id="rsyncRuntimeBaseURL" placeholder="optional enterprise runtime URL" autocomplete="off">
      <small>Advanced. Direct upstream rsync is source-first, so binary runtime artifacts should come from a controlled SeaVault build channel.</small>
    </label>
  </div>
  <p class="row-actions">
    <button onclick="rsyncStatus(true)">Status and source update check</button>
    <button class="operation" onclick="rsyncInstall()">Install/register managed rsync</button>
    <button class="operation" onclick="rsyncUpdate()">Update managed rsync</button>
    <button onclick="rsyncRollback()">Rollback managed rsync</button>
  </p>
  <pre id="rsyncStatus">No managed rsync status loaded.</pre>
</section>

<section>
  <h2>Rclone runtime</h2>
  <p class="hint">This app uses an app-managed rclone executable for remote transport. It does not require system rclone.</p>
  <div class="form-grid">
    <label>Version or channel
      <input id="rcloneVersion" placeholder="latest stable or v1.74.0" autocomplete="off">
      <small>Leave blank for latest stable.</small>
    </label>
    <label>Register existing binary for testing or offline use
      <input id="rcloneFromBinary" placeholder="/path/to/rclone" autocomplete="off">
      <small>Useful for offline or enterprise-controlled installs.</small>
    </label>
    <label>Signature mode
      <select id="rcloneSignature">
        <option value="optional">Optional GPG verification</option>
        <option value="required">Require GPG verification</option>
        <option value="skip">Skip GPG verification</option>
      </select>
    </label>
  </div>
  <p class="row-actions">
    <button onclick="rcloneStatus(true)">Status and check update</button>
    <button class="operation" onclick="rcloneInstall()">Install/register rclone</button>
    <button class="operation" onclick="rcloneUpdate()">Update rclone</button>
    <button onclick="rcloneRollback()">Rollback</button>
  </p>
  <pre id="rcloneStatus">No runtime status loaded.</pre>
</section>

<section id="remote-panel">
  <h2>Remote repositories</h2>
  <div class="form-grid">
    <label>Name <input id="remoteName" placeholder="research-b2-ca" autocomplete="off"></label>
    <label>Type <select id="remoteType"><option value="rclone">rclone</option><option value="local">local folder copy</option></select></label>
    <label>Vault path/profile <input id="remoteVault" placeholder="leave blank to use open vault" autocomplete="off"></label>
    <label>Remote path <input id="remotePath" placeholder="remote:bucket/path or ~/Backup/seavault" autocomplete="off"><small>For rclone, enter the provider path. The app transfers only .seavault.</small></label>
    <label>Backend label <input id="remoteBackend" value="local" placeholder="local, sftp, s3, b2, onedrive, webdav" autocomplete="off"></label>
    <label>Transfers <input id="remoteTransfers" type="number" value="8"></label>
    <label>Checkers <input id="remoteCheckers" type="number" value="16"></label>
    <label>Bandwidth limit <input id="remoteBandwidth" placeholder="optional, e.g. 10M" autocomplete="off"></label>
  </div>
  <p class="row-actions">
    <label class="checkline"><input id="remoteFastList" type="checkbox" checked> Use fast-list when supported</label>
    <button onclick="saveRemote()">Save remote profile</button>
    <button onclick="loadRemotes()">Refresh remotes</button>
  </p>
  <div id="remotes" class="table-wrap"></div>
  <pre id="remoteOutput">No remote action has run.</pre>
</section>

<section id="keys-panel">
  <h2>SSH keys for rclone SFTP</h2>
  <div class="form-grid">
    <label>Managed key name <input id="sshKeyName" placeholder="research-sftp" autocomplete="off"></label>
    <label>Import existing private key path <input id="sshKeyPath" placeholder="optional path to import" autocomplete="off"></label>
  </div>
  <p class="row-actions"><button onclick="generateSSHKey()">Generate/import key</button><button onclick="loadSSHKeys()">Refresh keys</button></p>
  <div id="sshKeys" class="table-wrap"></div>
</section>
<section id="settings-panel">
  <h2>Settings</h2>
  <p class="hint">Application settings are saved locally. Changing HTTP/HTTPS or certificate settings requires restarting the GUI.</p>
  <div class="settings-grid">
    <div class="settings-box">
      <h3>Local dependencies</h3>
      <div id="keychainStatusBox" class="dependency-status"><p class="hint">Dependency status will appear after refresh.</p></div>
      <div id="dependencyList"><p class="hint">Dependency list will appear after refresh.</p></div>
    </div>
    <div class="settings-box">
      <h3>WebDAV details</h3>
      <div id="webdavStatusBox"><p class="hint">WebDAV status will appear after refresh.</p></div>
    </div>
    <div class="settings-box">
      <h3>GUI protocol and certificate</h3>
      <div class="form-grid">
        <label>Protocol
          <select id="cfgProtocol"><option value="http">HTTP</option><option value="https">HTTPS</option></select>
          <small>HTTPS uses the configured certificate, or creates a local self-signed certificate.</small>
        </label>
        <label class="checkline"><input id="cfgSelfSigned" type="checkbox"> Use or create self-signed certificate</label>
        <label>Certificate file <input id="cfgCertFile" placeholder="blank creates app-managed certificate" autocomplete="off"></label>
        <label>Private key file <input id="cfgKeyFile" placeholder="blank creates app-managed key" autocomplete="off"></label>
      </div>
      <h3>GUI user and password</h3>
      <div class="form-grid">
        <label>Username <input id="cfgUsername" autocomplete="username" placeholder="optional local GUI user"></label>
        <label>Password <input id="cfgPassword" type="password" autocomplete="new-password" placeholder="stored in OS keychain when set"></label>
      </div>
      <p id="guiAuthStatus" class="hint">GUI login status will appear after settings load.</p>
      <p class="row-actions"><button class="danger" onclick="clearGuiLogin()">Clear GUI login</button><a class="settings-button danger" href="/reset-config">Reset password and app configuration</a></p>
      <p class="hint">SeaVault stores a salted Argon2id password verifier in local app configuration, not the plaintext password. This avoids OS-keychain dependency failures for GUI login. Use Reset password and app configuration if the GUI password is lost or the saved configuration should be restored to defaults.</p>
    </div>
    <div class="settings-box">
      <h3>Log settings</h3>
      <div class="form-grid">
        <label>Maximum in-memory log entries <input id="cfgLogMax" type="number" min="10" max="5000" value="200"></label>
        <label>Log file path <input id="cfgLogPath" placeholder="optional local log file path" autocomplete="off"></label>
        <label class="checkline"><input id="cfgLogPersist" type="checkbox"> Save log to file until cleared</label>
      </div>
      <p class="row-actions"><button onclick="saveLogToFile()">Save log to file</button><button class="danger" onclick="clearLog()">Clear log</button></p>
    </div>
    <div class="settings-box">
      <h3>Runtime and WSL sources</h3>
      <div class="form-grid">
        <label>Rclone release channel <input id="cfgRcloneChannel" placeholder="stable" autocomplete="off"></label>
        <label>Rsync source base URL <input id="cfgRsyncSource" placeholder="https://download.samba.org/pub/rsync" autocomplete="off"></label>
        <label>Rsync runtime base URL <input id="cfgRsyncRuntime" placeholder="https://.../seavault-rsync-runtime/releases/download" autocomplete="off"></label>
        <label>Windows WSL install/update source <input id="cfgWSLSource" placeholder="wsl.exe --install" autocomplete="off"></label>
      </div>
      <p class="hint">On Windows, WSL is listed as a local dependency because rsync-backed local ingest needs a Linux-compatible rsync environment.</p>
    </div>
  </div>
  <p class="row-actions"><button onclick="saveAppConfig()">Save settings</button><button onclick="loadAppConfig()">Reload settings</button></p>
  <h3>Application log</h3>
  <pre id="status" class="log-view">Loading...</pre>
</section>

</div>

<aside class="result-panel" aria-live="polite" aria-label="Result and progress">
  <h2>Result and progress</h2>
  <div id="message" role="status">Ready.</div>
  <progress id="progress" value="0" max="1"></progress>
  <p id="progressText"><small>No active operation.</small></p>
  <p class="row-actions"><button class="danger" onclick="cancelActive()">Cancel active operation</button><button class="secondary" onclick="clearOutput()">Clear</button><button class="secondary" onclick="refreshStatus()">Refresh vaults</button></p>
  <h3>WebDAV</h3>
  <div id="webdavQuickBox" class="webdav-indicator"><p class="hint">WebDAV status will appear after refresh.</p></div>
  <h3>Available saved vaults</h3>
  <div id="availableVaults" class="vault-list">Loading saved vaults...</div>
  <p class="hint">Detailed logs are available on the Settings page.</p>
</aside>
</main>
<script>
let token = document.documentElement.dataset.token;
let jsonHeaders = {'Content-Type':'application/json','X-SeaVault-Token':token};
let activeController = null;
let activeCancelled = false;
let lastStatus = null;
let currentDavPath = 'content';
let selectedDavPath = '';
let selectedDavIsDir = false;
let appLog = [];
let appConfig = null;
function updateSessionToken(t){ if(t && t !== token){ token = t; document.documentElement.dataset.token = t; jsonHeaders = {'Content-Type':'application/json','X-SeaVault-Token':token}; } }
function $(id){ return document.getElementById(id); }
function setProgress(done, total, text){ const p=$('progress'); p.max=Math.max(1,total||1); p.value=Math.min(p.max,done||0); $('progressText').innerHTML='<small>'+esc(text||'')+'</small>'; }
function setBusy(on){ document.body.classList.toggle('busy', !!on); document.querySelectorAll('button.operation').forEach(btn => { btn.disabled = !!on; }); }
function beginOperation(text){ if(activeController){ throw new Error('Another upload/export operation is already running. Cancel it or wait for it to finish.'); } activeCancelled=false; activeController = new AbortController(); setBusy(true); setProgress(0,1,text||'Starting...'); return activeController; }
function endOperation(text){ activeController=null; setBusy(false); setProgress(1,1,text||'Complete.'); }
function uploadProgressText(prefix, sentBytes, totalBytes, suffix){
  if(totalBytes > 0){
    const pct = Math.floor((Math.min(sentBytes, totalBytes) / totalBytes) * 100);
    return prefix + ' ' + fmtBytes(Math.min(sentBytes, totalBytes)) + ' of ' + fmtBytes(totalBytes) + ' (' + pct + '%)' + (suffix ? '. ' + suffix : '');
  }
  return prefix + (suffix ? ' ' + suffix : '');
}
function uploadRequest(method, url, body, headers, signal, onProgress){
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    Object.entries(headers || {}).forEach(([k,v]) => xhr.setRequestHeader(k, v));
    xhr.upload.onprogress = evt => {
      if(onProgress) onProgress(evt.loaded || 0, evt.lengthComputable ? evt.total : 0);
    };
    xhr.onload = () => resolve({
      ok: xhr.status >= 200 && xhr.status < 300,
      status: xhr.status,
      statusText: xhr.statusText,
      text: async () => xhr.responseText || '',
      json: async () => JSON.parse(xhr.responseText || '{}')
    });
    xhr.onerror = () => reject(new Error('The browser could not complete the upload request.'));
    xhr.onabort = () => reject(new DOMException('The browser upload was cancelled.', 'AbortError'));
    if(signal){
      if(signal.aborted){ xhr.abort(); return; }
      signal.addEventListener('abort', () => xhr.abort(), {once:true});
    }
    xhr.send(body || null);
  });
}
function cancelActive(){ if(activeController){ activeCancelled=true; activeController.abort(); setBusy(false); showError('Cancelling operation', 'The active browser request was cancelled. The server checks cancellation between files.'); } else { showHuman('No active operation', 'There is no running upload or export to cancel.'); } }
function clearOutput(){ $('message').className=''; $('message').textContent='Ready.'; setProgress(0,1,'No active operation.'); }
async function api(path, opts){
  opts = opts || {};
  if(opts.method && opts.method !== 'GET') opts.headers = Object.assign({}, opts.headers || {}, {'X-SeaVault-Token': token});
  let res;
  try { res = await fetch(path, opts); }
  catch(err) { throw new Error('The browser could not reach the local SeaVault GUI service. Confirm the seavault gui process is still running, then refresh this tab. Browser detail: ' + (err && err.message ? err.message : err)); }
  const ct = res.headers.get('content-type') || '';
  let body;
  if(ct.indexOf('application/json') >= 0){ body = await res.json(); } else { body = await res.text(); }
  if(body && body.browserToken) updateSessionToken(body.browserToken);
  if(!res.ok) throw new Error((body && body.error) || body || res.statusText);
  return body;
}
function showHuman(title, obj, level){
  $('message').className = level || '';
  $('message').textContent = title;
  appendLog(title, humanize(obj), level || 'info');
}
function showError(title, detail){
  $('message').className = 'error';
  $('message').textContent = title;
  appendLog(title, detail || '', 'error');
}
function appendLog(title, detail, level){
  const max = Number((appConfig && appConfig.log && appConfig.log.maxEntries) || ($('cfgLogMax') && $('cfgLogMax').value) || 200);
  appLog.push({time:new Date().toISOString(), level:level||'info', title:String(title||''), detail:String(detail||'')});
  while(appLog.length > Math.max(10, max || 200)) appLog.shift();
  renderLog();
}
function renderLog(){
  const box = $('status');
  if(!box) return;
  box.textContent = appLog.map(e => '['+e.time+'] '+e.level.toUpperCase()+': '+e.title+(e.detail?'\n'+e.detail:'')).join('\n\n');
  box.scrollTop = box.scrollHeight;
}
async function saveLogToFile(){
  try { const path = $('cfgLogPath') ? $('cfgLogPath').value : ''; const res = await api('/api/log/save',{method:'POST',headers:jsonHeaders,body:JSON.stringify({path:path,text:($('status')?$('status').textContent:'')})}); showHuman('Log saved', res, 'success'); }
  catch(e){ showError('Could not save log', e.message); }
}
function clearLog(){ appLog=[]; renderLog(); showHuman('Log cleared', 'Application log cleared from memory.'); }
function humanize(obj){
  if(typeof obj === 'string') return obj;
  if(!obj) return '';
  if(obj.results){
    let total = obj.results.reduce((n,r)=>n+(r.size||0),0);
    let created = obj.results.reduce((n,r)=>n+(r.newChunkCount||0),0);
    return 'Uploaded ' + obj.results.length + ' file(s) using ' + (obj.method || 'browser') + '.\nPlaintext was encrypted into the vault.\nTotal source size: ' + fmtBytes(total) + '.\nNew encrypted chunks: ' + created + '.\n\n' + JSON.stringify(obj, null, 2);
  }
  if(obj.files !== undefined && obj.destPath !== undefined){
    let action = obj.dryRun ? 'Dry run complete' : 'Export complete';
    let exported = obj.dryRun ? obj.files : obj.exported;
    return action + ': ' + exported + ' of ' + obj.files + ' file(s), ' + fmtBytes(obj.bytes || 0) + '.\nDestination: ' + obj.destPath + '\nOverwrite policy: ' + obj.overwrite + (obj.zip ? '\nZIP export: yes' : '\nZIP export: no') + '\n\n' + JSON.stringify(obj, null, 2);
  }
  if(obj.open !== undefined){
    return (obj.open ? 'Vault is open.' : 'No vault is open.') + (obj.vaultPath ? '\nVault path: ' + obj.vaultPath : '') + '\n\n' + JSON.stringify(obj, null, 2);
  }
  if(obj.move){ return 'Vault move complete.\nFrom: ' + obj.move.sourcePath + '\nTo: ' + obj.move.destinationPath + '\nUpdated saved vault locations: ' + (obj.move.updatedProfiles||0) + '\nUpdated remote profiles: ' + (obj.move.updatedRemotes||0) + (obj.reopened ? '\nVault reopened from OS keychain.' : (obj.closedActive ? '\nVault was moved and closed. Reopen it with a saved keychain password or typed password.' : '')) + ((obj.move.warnings||[]).length ? '\nWarnings: ' + obj.move.warnings.join('; ') : '') + '\n\n' + JSON.stringify(obj, null, 2); }
  if(obj.ok){ return 'Operation completed successfully.\n\n' + JSON.stringify(obj, null, 2); }
  return JSON.stringify(obj, null, 2);
}
function fmtBytes(n){ n=Number(n||0); const units=['B','KiB','MiB','GiB','TiB']; let i=0; while(n>=1024 && i<units.length-1){ n/=1024; i++; } return (i===0?String(n):n.toFixed(1))+' '+units[i]; }
function fillPath(p){ $('vaultPath').value = p; }

function prefillMoveFromActive(){
  if(lastStatus && lastStatus.vaultPath){ $('moveSource').value = lastStatus.vaultPath; showHuman('Move source selected', 'Using active vault as the move source: ' + lastStatus.vaultPath); }
  else showError('No active vault', 'Open a vault first, select a saved vault, or type a source path manually.');
}
function fillMoveFromProfile(){
  const sel = $('moveProfile');
  const opt = sel.options[sel.selectedIndex];
  if(!opt || !opt.value) return;
  $('moveSource').value = opt.dataset.path || '';
  showHuman('Move source selected', 'Selected saved vault ' + opt.value + ' at ' + (opt.dataset.path || '') + '.');
}
async function moveVaultLocation(){
  try {
    const req = {profileName:$('moveProfile').value, sourcePath:$('moveSource').value, destinationPath:$('moveDest').value, replace:$('moveReplace').checked, updateRemoteProfiles:$('moveUpdateRemotes').checked};
    if(!req.destinationPath.trim()){ showError('Destination required', 'Enter the new vault location before moving.'); return; }
    if(!req.profileName && !req.sourcePath.trim() && !(lastStatus && lastStatus.vaultPath)){ showError('Source required', 'Select a saved vault, use the active vault, or type a source vault path.'); return; }
    if(!req.sourcePath.trim() && lastStatus && lastStatus.vaultPath) req.sourcePath = lastStatus.vaultPath;
    const from = req.profileName || req.sourcePath;
    const ok = window.confirm('Move encrypted vault from "' + from + '" to "' + req.destinationPath + '"?\n\nThe app will update saved vault locations after the move. The keychain password remains tied to the vault ID.');
    if(!ok) return;
    beginOperation('Moving vault location...');
    const res = await api('/api/vault-move',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)});
    endOperation('Vault move complete.');
    showHuman('Vault moved', res, 'success');
    $('vaultPath').value = res.move && res.move.destinationPath ? res.move.destinationPath : req.destinationPath;
    await refreshStatus();
  } catch(e){ showError('Vault move failed', e.message); activeController=null; setBusy(false); }
}

function selectSavedVault(){
  const sel = $('vaultSelect');
  const opt = sel.options[sel.selectedIndex];
  if(!opt || !opt.value) return;
  $('vaultPath').value = opt.dataset.path || opt.value;
  $('profile').value = opt.dataset.name || '';
  showHuman('Saved vault selected', 'Selected ' + (opt.dataset.name || opt.value) + '. Click Open selected using keychain, or enter the password and open.');
}
function renderVaultSelector(status){
  const rows = status.availableVaults || [];
  const sel = $('vaultSelect');
  if(sel){
    const current = sel.value;
    sel.innerHTML = '<option value="">Manual path or new vault</option>' + rows.map(v => '<option value="'+esc(v.name)+'" data-name="'+esc(v.name)+'" data-path="'+esc(v.vaultPath)+'"'+((current && current===v.name) || (!current && status.vaultPath===v.vaultPath)?' selected':'')+'>'+esc(v.name)+' - '+esc(v.status)+'</option>').join('');
  }
  const moveSel = $('moveProfile');
  if(moveSel){
    const currentMove = moveSel.value;
    moveSel.innerHTML = '<option value="">Use active/manual source path</option>' + rows.map(v => '<option value="'+esc(v.name)+'" data-name="'+esc(v.name)+'" data-path="'+esc(v.vaultPath)+'"'+(currentMove===v.name?' selected':'')+'>'+esc(v.name)+' - '+esc(v.status)+'</option>').join('');
  }
}
function renderKeychainStatus(status){
  const box = $('keychainStatusBox');
  if(!box) return;
  const st = (status && status.keychainStatus) || {};
  const cls = st.available ? 'status-open' : (st.summary && st.summary.indexOf('may be unavailable') >= 0 ? 'status-warning' : 'status-missing');
  const missing = (st.missing || []).length ? '<small>Missing or unavailable: '+esc((st.missing || []).join(', '))+'</small>' : '';
  const detail = st.detail ? '<small>'+esc(st.detail)+'</small>' : '';
  box.innerHTML = '<div class="vault-card '+cls+'"><header><span class="vault-name">OS keychain</span><span class="pill">'+esc(st.available ? 'available' : 'unavailable')+'</span></header><small>Backend: '+esc(st.backend || 'unknown')+'</small>'+detail+missing+'</div>';
}
function keychainUnavailable(status){ return status && status.keychainStatus && !status.keychainStatus.available; }
function renderDependencies(status){
  const box = $('dependencyList');
  if(!box) return;
  const rows = (status && status.dependencies && status.dependencies.items) || [];
  box.innerHTML = rows.map(d => '<div class="vault-card '+(d.available?'status-open':'status-missing')+'"><header><span class="vault-name">'+esc(d.name)+'</span><span class="pill">'+esc(d.summary||'unknown')+'</span></header>'+(d.detail?'<small>'+esc(d.detail)+'</small>':'')+'</div>').join('') || '<p class="hint">No dependency data.</p>';
}
function renderWebDAVQuick(status){
  const box = $('webdavQuickBox');
  if(!box) return;
  const wd=(status&&status.webdav)||{};
  box.innerHTML = '<div class="vault-card '+(wd.running?'status-open':'status-missing')+'"><header><span class="vault-name">WebDAV</span><span class="pill">'+(wd.running?'on':'off')+'</span></header><small>'+(wd.readOnly?'read-only':'read/write')+'</small></div>';
}
function renderAppConfig(status){
  const cfg = (status && status.appConfig) || appConfig;
  if(!cfg) return;
  appConfig = cfg;
  if($('cfgProtocol')) $('cfgProtocol').value = cfg.gui && cfg.gui.protocol ? cfg.gui.protocol : 'http';
  if($('cfgSelfSigned')) $('cfgSelfSigned').checked = !!(cfg.gui && cfg.gui.selfSigned);
  if($('cfgCertFile')) $('cfgCertFile').value = (cfg.gui && cfg.gui.certFile) || '';
  if($('cfgKeyFile')) $('cfgKeyFile').value = (cfg.gui && cfg.gui.keyFile) || '';
  if($('cfgUsername')) $('cfgUsername').value = (cfg.gui && cfg.gui.username) || '';
  if($('guiAuthStatus')) { const configured = !!(cfg.gui && cfg.gui.passwordConfigured); const user = (cfg.gui && cfg.gui.username) || ''; $('guiAuthStatus').textContent = configured && user ? 'GUI login active for user ' + user + '. Use Logout to clear this browser session.' : (user ? 'GUI username is set, but no password is configured.' : 'GUI login is off.'); }
  if($('cfgLogMax')) $('cfgLogMax').value = (cfg.log && cfg.log.maxEntries) || 200;
  if($('cfgLogPath')) $('cfgLogPath').value = (cfg.log && cfg.log.filePath) || '';
  if($('cfgLogPersist')) $('cfgLogPersist').checked = !!(cfg.log && cfg.log.persist);
  if($('cfgRcloneChannel')) $('cfgRcloneChannel').value = (cfg.runtimeSources && cfg.runtimeSources.rcloneChannel) || 'stable';
  if($('cfgRsyncSource')) $('cfgRsyncSource').value = (cfg.runtimeSources && cfg.runtimeSources.rsyncSourceBaseUrl) || '';
  if($('cfgRsyncRuntime')) $('cfgRsyncRuntime').value = (cfg.runtimeSources && cfg.runtimeSources.rsyncRuntimeBaseUrl) || '';
  if($('cfgWSLSource')) $('cfgWSLSource').value = (cfg.runtimeSources && cfg.runtimeSources.wslInstallSource) || '';
}
async function loadAppConfig(){ try { const res=await api('/api/app-config'); appConfig=res.config; renderAppConfig({appConfig:appConfig}); showHuman('Settings loaded', res); } catch(e){ showError('Could not load settings', e.message); } }
async function saveAppConfig(){
  try {
    const cfg = {version:1, gui:{protocol:$('cfgProtocol').value, selfSigned:$('cfgSelfSigned').checked, certFile:$('cfgCertFile').value, keyFile:$('cfgKeyFile').value, username:$('cfgUsername').value, passwordConfigured: appConfig && appConfig.gui && appConfig.gui.passwordConfigured, passwordHash: appConfig && appConfig.gui && appConfig.gui.passwordHash}, log:{maxEntries:Number($('cfgLogMax').value||200), filePath:$('cfgLogPath').value, persist:$('cfgLogPersist').checked}, runtimeSources:{rcloneChannel:$('cfgRcloneChannel').value, rsyncSourceBaseUrl:$('cfgRsyncSource').value, rsyncRuntimeBaseUrl:$('cfgRsyncRuntime').value, wslInstallSource:$('cfgWSLSource').value}};
    const res=await api('/api/app-config',{method:'POST',headers:jsonHeaders,body:JSON.stringify({config:cfg, guiPassword:$('cfgPassword').value})});
    $('cfgPassword').value=''; appConfig=res.config; renderAppConfig({appConfig:appConfig}); showHuman('Settings saved', res, 'success');
    if(res.authEnabled || (res.config && res.config.gui && res.config.gui.passwordConfigured)) showHuman('GUI login active', 'Reload this page or click Logout to verify the login landing page.', 'success');
  } catch(e){ showError('Could not save settings', e.message); }
}
async function clearGuiLogin(){
  try {
    const cfg = {version:1, gui:{protocol:$('cfgProtocol').value, selfSigned:$('cfgSelfSigned').checked, certFile:$('cfgCertFile').value, keyFile:$('cfgKeyFile').value, username:'', passwordConfigured:false}, log:{maxEntries:Number($('cfgLogMax').value||200), filePath:$('cfgLogPath').value, persist:$('cfgLogPersist').checked}, runtimeSources:{rcloneChannel:$('cfgRcloneChannel').value, rsyncSourceBaseUrl:$('cfgRsyncSource').value, rsyncRuntimeBaseUrl:$('cfgRsyncRuntime').value, wslInstallSource:$('cfgWSLSource').value}};
    const res=await api('/api/app-config',{method:'POST',headers:jsonHeaders,body:JSON.stringify({config:cfg, clearGuiLogin:true})});
    $('cfgPassword').value=''; appConfig=res.config; renderAppConfig({appConfig:appConfig}); showHuman('GUI login cleared', res, 'success');
  } catch(e){ showError('Could not clear GUI login', e.message); }
}

function renderAvailableVaults(status){
  const box = $('availableVaults');
  if(!box) return;
  const rows = status.availableVaults || [];
  if(rows.length === 0){ box.innerHTML = '<p class="hint">No saved vaults yet. Create or open a vault, enter a saved vault name, select Save password in OS keychain if desired, then click Save vault location/password.</p>'; return; }
  box.innerHTML = rows.map(v => {
    const cls = v.open ? 'status-open' : (v.status === 'missing' ? 'status-missing' : (v.status === 'error' ? 'status-error' : ''));
    const pct = v.open ? 1 : (v.exists ? 0.55 : 0.15);
    const key = v.keychain ? 'keychain saved' : (v.keychainStatus === 'unavailable' ? 'keychain unavailable' : 'password required');
    const stats = v.open && v.files !== undefined ? '<br><small>'+Number(v.files||0)+' file(s), '+Number(v.objects||0)+' object(s), '+Number(v.referencedMB||0).toFixed(2)+' MiB referenced</small>' : '';
    const err = v.error ? '<br><small>'+esc(v.error)+'</small>' : (v.keychainError ? '<br><small>'+esc(v.keychainError)+'</small>' : '');
    const passwordId = 'vault-card-password-' + slug(v.name || v.vaultPath);
    const keyIndicator = v.keychain ? '<span class="pill">keychain active</span>' : (v.keychainStatus === 'unavailable' ? '<span class="pill">keychain unavailable</span>' : '<span class="pill">no keychain password</span>');
    const openLabel = v.keychainStatus === 'unavailable' ? 'Open with password' : 'Open';
    return '<article class="vault-card '+cls+'"><header><span class="vault-name">'+esc(v.name)+'</span><span class="pill">'+esc(v.status)+'</span></header><div class="vault-path">'+esc(v.vaultPath)+'</div><small>'+key+(v.open?' | active vault':'')+'</small>'+stats+err+'<progress value="'+pct+'" max="1"></progress><label>Password <input id="'+passwordId+'" type="password" autocomplete="current-password" placeholder="optional; blank uses keychain when active"></label><p class="row-actions">'+keyIndicator+'<button data-name="'+esc(v.name)+'" data-path="'+esc(v.vaultPath)+'" data-password-id="'+passwordId+'" onclick="openSavedVaultFromPassword(this.dataset.name,this.dataset.path,this.dataset.passwordId,false)">'+openLabel+'</button><button data-name="'+esc(v.name)+'" data-path="'+esc(v.vaultPath)+'" data-password-id="'+passwordId+'" onclick="openSavedVaultFromPassword(this.dataset.name,this.dataset.path,this.dataset.passwordId,true)">Open and save keychain</button><button data-name="'+esc(v.name)+'" data-path="'+esc(v.vaultPath)+'" onclick="selectVaultCard(this.dataset.name,this.dataset.path)">Select</button></p></article>';
  }).join('');
}
function selectVaultCard(name, path){ $('vaultPath').value = path; $('profile').value = name; const sel=$('vaultSelect'); if(sel) sel.value=name; showHuman('Saved vault selected', 'Selected ' + name + '.'); }
async function openSavedVault(name, path, useKeychain){
  $('vaultPath').value = name || path;
  $('profile').value = name || '';
  await openVault(useKeychain);
}
function slug(s){ return String(s || '').replace(/[^a-zA-Z0-9_-]/g, '_'); }
async function openSavedVaultFromPassword(name, path, passwordId, saveKeychain){
  const pw = passwordId && $(passwordId) ? $(passwordId).value : '';
  $('vaultPath').value = name || path;
  $('profile').value = name || '';
  $('password').value = pw;
  $('savePassword').checked = !!saveKeychain;
  await openVault(!pw);
}
function initPayload(){ return {vaultPath:$('vaultPath').value, password:$('password').value, profile:$('profile').value, savePassword:$('savePassword').checked, kdf:$('kdf').value}; }
function openPayload(useKeychain){ return {vaultPath:$('vaultPath').value, password:$('password').value, savePassword:$('savePassword').checked, useKeychain:useKeychain}; }
function localPathWarning(){ const p = $('vaultPath').value.trim(); if(p === '/user' || p.indexOf('/user/') === 0) return 'The path starts with /user. Use ~/Nextcloud/seavault, /Users/<name>/... on macOS, or /home/<name>/... on Linux.'; return ''; }
async function refreshStatus(){ try { const s = await api('/api/status'); if(s.browserToken) updateSessionToken(s.browserToken); lastStatus = s; renderVaultSelector(s); renderAvailableVaults(s); renderKeychainStatus(s); renderDependencies(s); renderWebDAVStatus(s); renderWebDAVQuick(s); renderAppConfig(s); showHuman('Status refreshed', s); await refreshFiles(); await refreshDavFiles(); await loadProfiles(); } catch(e){ showError('Could not refresh status', e.message); } }
async function saveCurrentVaultProfile(){
  try {
    const req = {name:$('profile').value, vaultPath:$('vaultPath').value, password:$('password').value, savePassword:$('savePassword').checked};
    if(!req.name.trim()){ showError('Saved vault name required', 'Enter a saved vault name before saving the vault location.'); return; }
    if(req.savePassword && !req.password.trim()){ showError('Password required', 'Enter the vault password before saving it to the OS keychain.'); return; }
    const res = await api('/api/profile',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)});
    if(req.savePassword) $('password').value='';
    showHuman('Saved vault updated', res, 'success');
    await refreshStatus();
  } catch(e){ showError('Could not save vault', e.message); }
}
async function initVault(){ try { const warn = localPathWarning(); if(warn){ showError('Invalid vault path', warn); return; } const res = await api('/api/init',{method:'POST',headers:jsonHeaders,body:JSON.stringify(initPayload())}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; lastStatus = status; renderVaultSelector(status); renderAvailableVaults(status); renderKeychainStatus(status); renderDependencies(status); renderWebDAVStatus(status); renderWebDAVQuick(status); renderAppConfig(status); showHuman('Vault created and opened', status, 'success'); await refreshFiles(); await refreshDavFiles(); await loadProfiles(); } catch(e){ showError('Could not create vault', e.message); } }
async function openVault(useKeychain){ try { const warn = localPathWarning(); if(warn){ showError('Invalid vault path', warn); return; } const res = await api('/api/open',{method:'POST',headers:jsonHeaders,body:JSON.stringify(openPayload(useKeychain))}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; lastStatus = status; renderVaultSelector(status); renderAvailableVaults(status); renderKeychainStatus(status); renderDependencies(status); renderWebDAVStatus(status); renderWebDAVQuick(status); renderAppConfig(status); showHuman('Vault opened', status, 'success'); await refreshFiles(); await refreshDavFiles(); await loadProfiles(); } catch(e){ showError('Could not open vault', e.message); } }
async function closeVault(){ try { const res = await api('/api/close',{method:'POST',headers:jsonHeaders,body:'{}'}); showHuman('Vault closed', res, 'success'); await refreshStatus(); } catch(e){ showError('Could not close vault', e.message); } }
function fileSizeTotal(files){ return Array.from(files || []).reduce((n,f)=>n+(f.size||0),0); }
function commonFolderRoot(files){
  for(const f of Array.from(files || [])){
    const rel = f.webkitRelativePath || '';
    if(rel && rel.indexOf('/') > 0) return rel.split('/')[0];
  }
  return '';
}
function summarizeNames(files, preserveFolders){
  const arr = Array.from(files || []);
  if(arr.length === 0) return 'No ' + (preserveFolders ? 'browser folder' : 'browser files') + ' selected.';
  const total = fmtBytes(fileSizeTotal(arr));
  if(preserveFolders){
    const root = commonFolderRoot(arr);
    const sample = arr.slice(0,3).map(f => f.webkitRelativePath || f.name).join(', ');
    return 'Selected folder ' + (root ? '"' + root + '" with ' : 'with ') + arr.length + ' file(s), ' + total + '. Sample: ' + sample + (arr.length > 3 ? ', ...' : '');
  }
  const sample = arr.slice(0,3).map(f => f.name).join(', ');
  return 'Selected ' + arr.length + ' file(s), ' + total + '. ' + sample + (arr.length > 3 ? ', ...' : '');
}
function updateUploadSelectionSummaries(){
  const fileInput = $('fileInput');
  const folderInput = $('folderInput');
  if(fileInput && $('fileSummary')) $('fileSummary').textContent = summarizeNames(fileInput.files, false);
  if(folderInput && $('folderSummary')){
    const root = commonFolderRoot(folderInput.files);
    let text = summarizeNames(folderInput.files, true);
    const prefix = $('uploadPath').value.trim().replace(/^\/+|\/+$/g, '');
    const box = $('folderSummary');
    box.className = 'selection-summary';
    if(root && prefix && prefix.toLowerCase().split('/').pop() === root.toLowerCase()){
      text += ' Warning: the virtual path ends with the same folder name. Use blank or a parent path if you do not want ' + root + '/' + root + '/... in the vault.';
      box.className = 'selection-summary warning';
    }
    box.textContent = text;
  }
}
function requireLocalSourcePath(){
  const p = $('localSourcePath').value.trim();
  if(p) return p;
  showError('Local path required', 'Enter a local file or folder path in the Import from local path field first. Browser-selected folders do not expose their full local disk path to the app. Use Upload selected browser folder for browser picks, or type a path such as ~/Documents/project-folder for server-side rsync/native import.');
  return '';
}
async function uploadFiles(inputId, preserveFolders){
  const input = $(inputId);
  let ctl;
  try {
    if(!input.files || input.files.length === 0){ showError('Nothing selected', preserveFolders ? 'Choose a browser folder first. The selected folder name is preserved automatically.' : 'Select one or more browser files first.'); return; }
    const files = Array.from(input.files);
    const totalBytes = fileSizeTotal(files);
    const batchSize = preserveFolders ? 40 : 80;
    const batches = [];
    for(let i=0; i<files.length; i+=batchSize) batches.push(files.slice(i,i+batchSize));
    ctl = beginOperation('Uploading 0 of ' + files.length + ' selected file(s)...');
    let allResults = [];
    let completedBytes = 0;
    let completedFiles = 0;
    for(let b=0; b<batches.length; b++){
      if(activeCancelled) throw new Error('upload cancelled');
      const fd = new FormData();
      fd.append('path', $('uploadPath').value);
      const batch = batches[b];
      const batchBytes = fileSizeTotal(batch);
      for(const f of batch){
        if(preserveFolders) fd.append('relpaths', f.webkitRelativePath || f.name);
        fd.append('files', f, f.name);
      }
      const batchLabel = 'batch ' + (b+1) + ' of ' + batches.length + ', files ' + (completedFiles+1) + '-' + (completedFiles+batch.length) + ' of ' + files.length;
      setProgress(totalBytes > 0 ? completedBytes : completedFiles, totalBytes > 0 ? totalBytes : files.length, uploadProgressText('Uploading', completedBytes, totalBytes, batchLabel));
      const res = await uploadRequest('POST', '/api/upload', fd, {'X-SeaVault-Token':token}, ctl.signal, loaded => {
        const sent = completedBytes + Math.min(loaded || 0, batchBytes || loaded || 0);
        setProgress(totalBytes > 0 ? sent : completedFiles, totalBytes > 0 ? totalBytes : files.length, uploadProgressText('Uploading', sent, totalBytes, batchLabel));
      });
      let body;
      try { body = await res.json(); } catch(_) { body = {error: await res.text()}; }
      if(!res.ok) throw new Error(body.error || res.statusText);
      allResults = allResults.concat(body.results || []);
      completedBytes += batchBytes;
      completedFiles += batch.length;
      setProgress(totalBytes > 0 ? completedBytes : completedFiles, totalBytes > 0 ? totalBytes : files.length, uploadProgressText('Uploaded', completedBytes, totalBytes, completedFiles + ' of ' + files.length + ' file(s) accepted by the server.'));
    }
    const summary = {method:'browser-batched', results:allResults};
    input.value='';
    updateUploadSelectionSummaries();
    endOperation('Upload complete.');
    showHuman('Upload complete', summary, 'success');
    await refreshFiles();
  } catch(e){
    if(e.name === 'AbortError') showError('Upload cancelled', 'The browser upload was cancelled. Files already imported before cancellation remain in the vault.');
    else showError('Upload failed', e.message + '\\n\\nFor very large folders, use the local path ingest field. It lets the local GUI server read the folder directly and avoids browser upload limits.');
    activeController = null;
    setBusy(false);
  }
}

async function uploadLocalPath(){
  let ctl;
  try {
    const sourcePath = requireLocalSourcePath();
    if(!sourcePath) return;
    const method = $('localPutMethod').value || 'auto';
    ctl = beginOperation('Encrypting local path into the vault with ' + method + ' ingest...');
    const req = {sourcePath:sourcePath, virtualPath:$('uploadPath').value, method:method, rsyncBinary:$('localRsyncBinary').value};
    const res = await api('/api/upload-path',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req),signal:ctl.signal});
    endOperation('Local path import complete.');
    showHuman('Local path import complete', res, 'success');
    await refreshFiles();
  } catch(e){ if(e.name === 'AbortError') showError('Upload cancelled', 'The local path ingest was cancelled.'); else showError('Local path import failed', e.message + '\n\nIf you selected a folder with the browser picker, use Upload selected browser folder. The browser cannot provide a real local disk path to the rsync import field.'); activeController=null; setBusy(false); }
}
let largeImportJobId = '';
async function startLargeImport(){
  try {
    const sourcePath = requireLocalSourcePath();
    if(!sourcePath) return;
    const req = {sourcePath:sourcePath, virtualPath:$('uploadPath').value, method:$('localPutMethod').value || 'native', rsyncBinary:$('localRsyncBinary').value, dryRun:$('largeDryRun').checked, skipExisting:$('largeSkipExisting').checked};
    const res = await api('/api/import-large/start',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)});
    largeImportJobId = res.jobId;
    beginOperation((req.dryRun?'Scanning':'Importing') + ' large local path...');
    showHuman('Large import started', res, 'success');
    pollLargeImport();
  } catch(e){ showError('Could not start large import', e.message); }
}
async function pollLargeImport(){
  if(!largeImportJobId) return;
  try {
    const res = await api('/api/import-large/status?id=' + encodeURIComponent(largeImportJobId));
    const done = ['completed','completed-with-errors','failed','cancelled'].indexOf(res.status) >= 0;
    const scanned = res.bytesScanned || 0;
    const imported = res.bytesImported || 0;
    setProgress(done ? 1 : imported, done ? 1 : Math.max(imported, scanned, 1), 'Status: ' + res.status + '. Files scanned: ' + (res.filesScanned||0) + ', imported: ' + (res.filesImported||0) + ', skipped: ' + (res.filesSkipped||0) + '. Current: ' + (res.currentPath || ''));
    showHuman('Large import status', res, done && res.status==='completed' ? 'success' : (res.status==='failed' ? 'error' : ''));
    if(done){ largeImportJobId=''; activeController=null; setBusy(false); await refreshFiles(); return; }
    setTimeout(pollLargeImport, 1500);
  } catch(e){ showError('Could not poll large import', e.message); largeImportJobId=''; activeController=null; setBusy(false); }
}
async function cancelLargeImport(){
  if(!largeImportJobId) return false;
  try { const res = await api('/api/import-large/cancel?id=' + encodeURIComponent(largeImportJobId), {method:'POST',headers:jsonHeaders,body:'{}'}); showHuman('Large import cancellation requested', res); return true; }
  catch(e){ showError('Could not cancel large import', e.message); return false; }
}
async function checkRsync(){ try { const raw=$('localRsyncBinary').value.trim(); const bin=encodeURIComponent(raw); const res=await api('/api/rsync/status?binary='+bin); const where = raw ? raw : 'managed rsync, then PATH search'; const msg = res.available ? 'Using ' + (res.binary || where) + '.\n' + (res.version || '') + '\nRecommended method: ' + (res.recommended || 'native') : 'Checked ' + where + '. ' + (res.error || 'rsync was not found; native import remains available.'); showHuman(res.available?'rsync is available':'rsync is not available', msg + '\n\n' + JSON.stringify(res, null, 2), res.available?'success':'error'); } catch(e){ showError('Could not check rsync', e.message); } }
async function rsyncStatus(check){ try { const res=await api('/api/rsync/status?checkUpdate='+(check?'1':'0')); $('rsyncStatus').textContent=JSON.stringify(res,null,2); showHuman('Managed rsync status loaded', res, res.managed && res.managed.runtimeOk ? 'success' : ''); } catch(e){ showError('Could not load rsync status', e.message); } }
async function rsyncInstall(){ try { const req={version:$('rsyncVersion').value, fromBinary:$('rsyncFromBinary').value, offlineArchive:$('rsyncOfflineArchive').value, runtimeBaseURL:$('rsyncRuntimeBaseURL').value}; const res=await api('/api/rsync/install',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)}); $('rsyncStatus').textContent=JSON.stringify(res,null,2); showHuman('Managed rsync installed', res, 'success'); $('localPutMethod').value='managed-rsync'; $('localRsyncBinary').value=res.binaryPath || ''; } catch(e){ showError('Could not install managed rsync', e.message); } }
async function rsyncUpdate(){ try { const req={version:$('rsyncVersion').value, fromBinary:$('rsyncFromBinary').value, offlineArchive:$('rsyncOfflineArchive').value, runtimeBaseURL:$('rsyncRuntimeBaseURL').value}; const res=await api('/api/rsync/update',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)}); $('rsyncStatus').textContent=JSON.stringify(res,null,2); showHuman('Managed rsync updated', res, 'success'); $('localPutMethod').value='managed-rsync'; $('localRsyncBinary').value=res.binaryPath || ''; } catch(e){ showError('Could not update managed rsync', e.message); } }
async function rsyncRollback(){ try { const res=await api('/api/rsync/rollback',{method:'POST',headers:jsonHeaders,body:'{}'}); $('rsyncStatus').textContent=JSON.stringify(res,null,2); showHuman('Managed rsync rolled back', res, 'success'); $('localRsyncBinary').value=res.binaryPath || ''; } catch(e){ showError('Could not rollback managed rsync', e.message); } }
async function exportVault(dryRun, allFiles){
  let ctl;
  try {
    ctl = beginOperation((dryRun?'Planning':'Exporting') + ' vault files...');
    const req = {virtualPath: allFiles ? '.' : $('exportPath').value, destPath:$('exportDest').value, overwrite:$('exportOverwrite').value, dryRun:dryRun, zip:$('exportZip').checked};
    if(!req.destPath){ showError('Destination required', 'Enter a destination local folder or ZIP path.'); activeController=null; setBusy(false); return; }
    if(!allFiles && !req.virtualPath){ showError('Virtual path required', 'Enter a virtual folder/file path, or use Export entire vault.'); activeController=null; setBusy(false); return; }
    const res = await api('/api/export',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req),signal:ctl.signal});
    endOperation(dryRun?'Dry-run complete.':'Export complete.');
    showHuman(dryRun?'Dry-run export complete':'Export complete', res, 'success');
  } catch(e){ if(e.name === 'AbortError') showError('Export cancelled', 'The export request was cancelled. Partially exported files may remain at the destination.'); else showError('Export failed', e.message); activeController=null; setBusy(false); }
}

function davURL(p){
  const base = (lastStatus && lastStatus.webdav && lastStatus.webdav.url) ? lastStatus.webdav.url : ('/dav/' + token + '/');
  const clean = String(p || '').replace(/^\/+/, '');
  return base + clean.split('/').filter(Boolean).map(encodeURIComponent).join('/') + (clean.endsWith('/') && clean ? '/' : '');
}
function davPathFromHref(href){
  let h = String(href || '');
  try { h = new URL(h, window.location.origin).pathname; } catch(_) {}
  const marker = '/dav/' + token + '/';
  if(h.indexOf(marker) >= 0) h = h.slice(h.indexOf(marker) + marker.length);
  h = decodeURIComponent(h).replace(/^\/+|\/+$/g, '');
  return h;
}
async function davFetch(method, p, opts){
  opts = opts || {};
  opts.method = method;
  opts.headers = Object.assign({}, opts.headers || {}, {'X-SeaVault-Token': token});
  const res = await fetch(davURL(p), opts);
  if(!res.ok) throw new Error(await res.text() || res.statusText);
  return res;
}
async function davPropfind(p){
  const res = await davFetch('PROPFIND', p, {headers:{'Depth':'1'}});
  const text = await res.text();
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  return Array.from(doc.getElementsByTagNameNS('DAV:', 'response')).map(node => {
    const hrefNode = node.getElementsByTagNameNS('DAV:', 'href')[0];
    const lenNode = node.getElementsByTagNameNS('DAV:', 'getcontentlength')[0];
    const modNode = node.getElementsByTagNameNS('DAV:', 'getlastmodified')[0];
    const collection = node.getElementsByTagNameNS('DAV:', 'collection').length > 0;
    const path = davPathFromHref(hrefNode ? hrefNode.textContent : '');
    return {path:path, name:path ? path.split('/').filter(Boolean).pop() : '/', isDir:collection, size:lenNode?Number(lenNode.textContent||0):0, modified:modNode?modNode.textContent:''};
  });
}
async function refreshDavFiles(){
  try {
    if(!(lastStatus && lastStatus.open)){ $('davTable').innerHTML='<p class="hint">Open a vault to browse files.</p>'; return; }
    const rows = await davPropfind(currentDavPath);
    renderDavBreadcrumb();
    renderDavTable(rows.filter(x => x.path !== currentDavPath.replace(/^\/+|\/+$/g,'')));
    await renderDavTree();
    renderWebDAVStatus(lastStatus);
  } catch(e){ showError('WebDAV browse failed', e.message); $('davTable').innerHTML='<p>'+esc(e.message)+'</p>'; }
}
function renderDavBreadcrumb(){
  const clean = currentDavPath || 'content';
  let parts = clean.split('/').filter(Boolean);
  if(parts.length === 0) parts = ['content'];
  if(parts[0] !== 'content') parts.unshift('content');
  let acc = '';
  const buttons = parts.map((part, idx) => {
    acc = acc ? (acc + '/' + part) : part;
    return (idx ? '<span class="crumb-sep">/</span>' : '') + '<button class="crumb-button" data-path="'+esc(acc)+'" onclick="openDavFolder(this.dataset.path)">'+esc(part)+'</button>';
  }).join('');
  const parent = parts.length > 1 ? parts.slice(0, -1).join('/') : 'content';
  let tools = '<button onclick="selectCurrentDavFolder()">Select current folder</button>';
  tools += '<button class="secondary" onclick="copyCurrentDavPath()">Copy full path</button>';
  if(clean !== 'content') tools += '<button class="secondary" onclick="openDavFolder('+JSON.stringify(parent)+')">Up one level</button>';
  $('davBreadcrumb').innerHTML =
    '<div class="dav-toolbar">' +
      '<div class="dav-toolbar-heading">' +
        '<span class="dav-toolbar-label">Current virtual path</span>' +
        '<span class="dav-toolbar-current">'+esc(clean)+'</span>' +
      '</div>' +
      '<div class="path-tools">' + tools + '</div>' +
    '</div>' +
    '<div class="full-path-bar">' + buttons + '</div>';
}
function copyCurrentDavPath(){
  const clean = currentDavPath || 'content';
  navigator.clipboard.writeText(clean).then(
    () => showHuman('WebDAV path copied', clean, 'success'),
    () => showError('Copy failed', 'The browser could not copy the current WebDAV path.')
  );
}
function selectCurrentDavFolder(){
  selectedDavPath = currentDavPath || 'content';
  selectedDavIsDir = true;
  setProgress(0,1,'Selected folder ' + selectedDavPath + '.');
  renderWebDAVStatus(lastStatus);
}
function renderDavTable(rows){
  rows.sort((a,b)=>(a.isDir===b.isDir?0:(a.isDir?-1:1)) || a.name.localeCompare(b.name));
  if(rows.length===0){ $('davTable').innerHTML='<p class="hint">This folder is empty.</p>'; selectedDavPath=''; selectedDavIsDir=false; return; }
  $('davTable').innerHTML = '<table class="file-table"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr></thead><tbody>' + rows.map(r => '<tr data-path="'+esc(r.path)+'" data-dir="'+(r.isDir?'1':'0')+'" onclick="selectDavRow(this)" ondblclick="davRowOpen(this)"><td class="path">'+esc(r.name || '/')+(r.isDir?' /':'')+'</td><td>'+(r.isDir?'folder':'file')+'</td><td>'+(r.isDir?'':fmtBytes(r.size))+'</td><td>'+esc(r.modified||'')+'</td></tr>').join('') + '</tbody></table>';
}
async function renderDavTree(){
  const files = await api('/api/files');
  const dirs = new Set(['content']);
  (files.files||[]).forEach(f => { let parts=String(f.path).split('/'); let acc=''; for(let i=0;i<parts.length-1;i++){ acc=acc?acc+'/'+parts[i]:parts[i]; dirs.add(acc); } });
  const sorted = Array.from(dirs).sort();
  $('davTree').innerHTML = '<ul>' + sorted.map(d => '<li><button data-path="'+esc(d)+'" onclick="openDavFolder(this.dataset.path)">'+esc(d)+'</button></li>').join('') + '</ul>';
}
function selectDavRow(row){
  document.querySelectorAll('.file-table tr.selected').forEach(r=>r.classList.remove('selected'));
  row.classList.add('selected');
  selectedDavPath = row.dataset.path || '';
  selectedDavIsDir = row.dataset.dir === '1';
  setProgress(0,1,'Selected ' + (selectedDavIsDir?'folder ':'file ') + (selectedDavPath || 'vault root') + '.');
  renderWebDAVStatus(lastStatus);
}
function davRowOpen(row){ if(row.dataset.dir==='1') openDavFolder(row.dataset.path || ''); else downloadDavPath(row.dataset.path || ''); }
async function openDavFolder(p){ currentDavPath = String(p||'').replace(/^\/+|\/+$/g,''); selectedDavPath=''; selectedDavIsDir=false; await refreshDavFiles(); }
async function createDavFolder(){
  try { const name = prompt('New folder name'); if(!name) return; const p = [currentDavPath, name].filter(Boolean).join('/'); await davFetch('MKCOL', p); showHuman('Folder created', 'Created folder ' + p + '. Empty folders are virtual until files are added.', 'success'); await refreshDavFiles(); }
  catch(e){ showError('Create folder failed', e.message); }
}
function downloadDavPath(p){ const a=document.createElement('a'); a.href=davURL(p); a.download=(p||'download').split('/').pop(); document.body.appendChild(a); a.click(); a.remove(); }
function downloadSelectedDav(){ if(!selectedDavPath || selectedDavIsDir){ showError('Select a file', 'Select a file before downloading. Use Download selected folder as ZIP for folders.'); return; } downloadDavPath(selectedDavPath); }
function downloadSelectedDavZip(){
  if(!selectedDavPath || !selectedDavIsDir){ showError('Select a folder', 'Select a folder before downloading it as a ZIP.'); return; }
  window.location = '/api/export-zip?path=' + encodeURIComponent(selectedDavPath) + '&token=' + encodeURIComponent(token);
  showHuman('ZIP download started', 'The selected folder is being streamed as a ZIP download by the local SeaVault server.');
}
async function renameSelectedDav(){
  try { if(!selectedDavPath){ showError('Select an item', 'Select a file or folder first.'); return; } const dst=prompt('Move/rename to virtual path:', selectedDavPath); if(!dst || dst===selectedDavPath) return; await davFetch('MOVE', selectedDavPath, {headers:{'Destination':davURL(dst)}}); showHuman('Move complete', 'Moved ' + selectedDavPath + ' to ' + dst + '.', 'success'); selectedDavPath=''; await refreshDavFiles(); }
  catch(e){ showError('Move failed', e.message); }
}
async function copySelectedDav(){
  try { if(!selectedDavPath){ showError('Select an item', 'Select a file or folder first.'); return; } const dst=prompt('Copy to virtual path:', selectedDavPath + '-copy'); if(!dst || dst===selectedDavPath) return; await davFetch('COPY', selectedDavPath, {headers:{'Destination':davURL(dst)}}); showHuman('Copy complete', 'Copied ' + selectedDavPath + ' to ' + dst + '.', 'success'); await refreshDavFiles(); }
  catch(e){ showError('Copy failed', e.message); }
}
async function deleteSelectedDav(){
  try { if(!selectedDavPath){ showError('Select an item', 'Select a file or folder first.'); return; } if(selectedDavPath === 'content'){ showError('Protected folder', 'content/ is the protected vault workspace and cannot be deleted.'); return; } if(!confirm('Delete ' + selectedDavPath + ' from the vault?')) return; await davFetch('DELETE', selectedDavPath); showHuman('Delete complete', 'Deleted ' + selectedDavPath + ' from the virtual vault view. Tombstones prevent deleted files from being resurrected by sync.', 'success'); selectedDavPath=''; await refreshDavFiles(); }
  catch(e){ showError('Delete failed', e.message); }
}

async function readAllDirectoryEntries(reader){
  const out=[];
  while(true){
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if(!batch || batch.length===0) break;
    out.push(...batch);
  }
  return out;
}
function fileFromEntry(entry){
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}
async function collectEntryFiles(entry, prefix){
  prefix = prefix || '';
  if(entry.isFile){
    const file = await fileFromEntry(entry);
    return [{file:file, rel:prefix + file.name}];
  }
  if(entry.isDirectory){
    const dirRel = prefix + entry.name;
    const reader = entry.createReader();
    const children = await readAllDirectoryEntries(reader);
    let out=[{dir:true, rel:dirRel}];
    for(const child of children){
      out = out.concat(await collectEntryFiles(child, dirRel + '/'));
    }
    return out;
  }
  return [];
}
async function collectDroppedUploadItems(dataTransfer){
  const items = Array.from((dataTransfer && dataTransfer.items) || []);
  if(items.length && items.some(i => typeof i.webkitGetAsEntry === 'function')){
    let out=[];
    for(const item of items){
      const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if(entry) out = out.concat(await collectEntryFiles(entry, ''));
    }
    if(out.length) return out;
  }
  return Array.from((dataTransfer && dataTransfer.files) || []).map(f => ({file:f, rel:f.webkitRelativePath || f.name}));
}
async function uploadDavItems(items){
  if(!items || items.length===0){ showError('Nothing to upload', 'This browser did not expose any files from the dropped item. Use the folder picker or local path ingest for folders.'); return; }
  const ctl=beginOperation('Uploading through WebDAV...');
  try{
    let uploaded=0;
    let createdDirs=0;
    const fileItems = items.filter(item => item && item.file);
    const totalBytes = fileItems.reduce((n,item)=>n+((item.file && item.file.size) || 0),0);
    let completedBytes = 0;
    for(let i=0;i<items.length;i++){
      const item=items[i];
      const rel=String(item.rel || (item.file && item.file.name) || '').replace(/^\/+|\/+$|^\.+$/g, '');
      if(!rel) continue;
      const dest=[currentDavPath || 'content', rel].filter(Boolean).join('/');
      if(item.dir){
        setProgress(totalBytes > 0 ? completedBytes : i, totalBytes > 0 ? totalBytes : items.length, 'Creating folder ' + rel + ' (' + (i+1) + ' of ' + items.length + ')');
        try { await davFetch('MKCOL', dest, {signal:ctl.signal}); } catch(e) { if(!/already exists|405|Method Not Allowed/i.test(String(e && e.message || e))) throw e; }
        createdDirs++;
        continue;
      }
      const fileSize = (item.file && item.file.size) || 0;
      setProgress(totalBytes > 0 ? completedBytes : i, totalBytes > 0 ? totalBytes : items.length, uploadProgressText('Uploading', completedBytes, totalBytes, (i+1) + ' of ' + items.length + ': ' + rel));
      const res = await uploadRequest('PUT', davURL(dest), item.file, {'X-SeaVault-Token':token}, ctl.signal, loaded => {
        const sent = completedBytes + Math.min(loaded || 0, fileSize || loaded || 0);
        setProgress(totalBytes > 0 ? sent : i, totalBytes > 0 ? totalBytes : items.length, uploadProgressText('Uploading', sent, totalBytes, (i+1) + ' of ' + items.length + ': ' + rel));
      });
      if(!res.ok) throw new Error(await res.text() || res.statusText);
      completedBytes += fileSize;
      uploaded++;
      setProgress(totalBytes > 0 ? completedBytes : i+1, totalBytes > 0 ? totalBytes : items.length, uploadProgressText('Uploaded', completedBytes, totalBytes, uploaded + ' file(s) complete.'));
    }
    endOperation('WebDAV upload complete.');
    showHuman('WebDAV upload complete', 'Uploaded ' + uploaded + ' file(s) and created ' + createdDirs + ' folder(s) in ' + (currentDavPath || 'content') + '.', 'success');
    await refreshDavFiles();
  } catch(e){ if(e.name==='AbortError') showError('WebDAV upload cancelled', 'The upload was cancelled. Files already written remain in the vault.'); else showError('WebDAV upload failed', humanFetchError(e)); activeController=null; setBusy(false); }
}
function humanFetchError(e){
  const msg = e && e.message ? e.message : String(e || 'unknown error');
  if(/NetworkError|Failed to fetch|Load failed/i.test(msg)) return msg + '\n\nThe browser could not complete the local WebDAV request. For folder drops, try the folder picker or local path ingest. If the vault was just closed or reopened, refresh the page and try again.';
  return msg;
}
async function uploadDavFiles(files, preserveFolders){
  if(!files || files.length===0){ showError('Nothing selected', 'Select files or a folder first.'); return; }
  const arr=Array.from(files).map(f => ({file:f, rel: preserveFolders ? (f.webkitRelativePath || f.name) : f.name}));
  await uploadDavItems(arr);
}

async function copyDavURL(){
  const url = window.location.origin + davURL(currentDavPath);
  try { await navigator.clipboard.writeText(url); showHuman('WebDAV URL copied', url, 'success'); }
  catch(_) { showHuman('Copy this WebDAV URL', url); }
}
async function toggleWebDAVReadOnly(){
  try { const res=await api('/api/webdav',{method:'POST',headers:jsonHeaders,body:JSON.stringify({readOnly:$('webdavReadOnly').checked})}); showHuman('WebDAV mode updated', res, 'success'); if(lastStatus) lastStatus.webdav = res; renderWebDAVStatus(lastStatus); }
  catch(e){ showError('Could not update WebDAV mode', e.message); }
}
function renderWebDAVStatus(status){
  const box=$('webdavStatusBox'); if(!box) return;
  const wd=(status&&status.webdav)||{};
  if($('webdavReadOnly')) $('webdavReadOnly').checked = !!wd.readOnly;
  const selected = selectedDavPath ? (selectedDavIsDir?'folder ':'file ') + selectedDavPath : 'none';
  box.innerHTML = '<div class="vault-card '+(wd.running?'status-open':'status-missing')+'"><header><span class="vault-name">WebDAV</span><span class="pill">'+(wd.running?'running':'stopped')+'</span></header><small>Mode: '+(wd.readOnly?'read-only':'read/write')+'<br>Current path: '+esc(currentDavPath||'vault root')+'<br>Selected: '+esc(selected)+'</small><div class="vault-path">'+esc(wd.url||'Open a vault to start WebDAV')+'</div><progress value="'+(wd.running?1:0.15)+'" max="1"></progress></div>';
  renderWebDAVQuick(status);
}
async function refreshFiles(){
  const box = $('files');
  try {
    const data = await api('/api/files');
    const rows = data.files || [];
    box.className = 'table-wrap raw-file-list' + (rows.length > 10 ? ' scroll-y' : '');
    if(rows.length === 0){ box.innerHTML = '<p>No files in the open vault.</p>'; return; }
    box.innerHTML = '<table><thead><tr><th>Path</th><th>Size</th><th>Chunks</th><th>Updated</th><th>Actions</th></tr></thead><tbody>' +
      rows.map(f => '<tr><td class="path">'+esc(f.path)+(f.conflictOf?' <small>conflict of '+esc(f.conflictOf)+'</small>':'')+'</td><td>'+fmtBytes(f.size)+'</td><td>'+f.chunks+'</td><td>'+esc(f.updatedAt||'')+'</td><td class="row-actions"><button onclick="downloadFile(\''+encodeURIComponent(f.path)+'\')">Download</button><button data-export-path="'+encodeURIComponent(dirname(f.path))+'" onclick="setExportPath(decodeURIComponent(this.dataset.exportPath))">Use folder</button><button class="danger" onclick="deleteFile(\''+encodeURIComponent(f.path)+'\')">Delete</button></td></tr>').join('') + '</tbody></table>';
  } catch(e){ box.className = 'table-wrap raw-file-list'; box.innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
function dirname(p){ const i=String(p).lastIndexOf('/'); return i>0?String(p).slice(0,i):'.'; }
function setExportPath(p){ $('exportPath').value = p || '.'; showHuman('Export path selected', 'Selected export path: ' + (p || '.')); }
function downloadFile(p){ window.location = '/api/download?path=' + p; }
async function deleteFile(p){ try { await api('/api/file?path='+p,{method:'DELETE',headers:jsonHeaders}); showHuman('File deleted', 'Deleted selected virtual path.', 'success'); await refreshFiles(); } catch(e){ showError('Delete failed', e.message); } }
async function verifyVault(){ try { const res = await api('/api/verify',{method:'POST',headers:jsonHeaders,body:'{}'}); showHuman('Vault verification passed', res, 'success'); } catch(e){ showError('Vault verification failed', e.message); } }
async function loadStats(){ try { const res = await api('/api/stats'); showHuman('Vault statistics', res); } catch(e){ showError('Could not load stats', e.message); } }
async function loadProfiles(){
  try {
    const data = await api('/api/profiles');
    const rows = data.profiles || [];
    $('profiles').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Vault path</th><th>Keychain</th><th>Password</th><th>Actions</th></tr></thead><tbody>'+rows.map(p=>{
      const passwordId = 'profile-password-' + slug(p.name || p.vaultPath);
      const keychain = p.keychain ? '<span class="pill">active</span>' : (p.keychainStatus === 'unavailable' ? '<span class="pill">unavailable</span>' : '<span class="pill">not saved</span>');
      const status = p.status ? '<br><small>'+esc(p.status)+(p.open?' | active vault':'')+'</small>' : '';
      const err = p.error ? '<br><small>'+esc(p.error)+'</small>' : (p.keychainError ? '<br><small>'+esc(p.keychainError)+'</small>' : '');
      return '<tr><td>'+esc(p.name)+status+err+'</td><td class="path">'+esc(p.vaultPath)+'</td><td>'+keychain+'</td><td><input id="'+passwordId+'" type="password" autocomplete="current-password" placeholder="enter password"></td><td class="row-actions"><button data-name="'+esc(p.name)+'" data-path="'+esc(p.vaultPath)+'" onclick="selectVaultCard(this.dataset.name,this.dataset.path)">Select</button><button data-name="'+esc(p.name)+'" data-path="'+esc(p.vaultPath)+'" data-password-id="'+passwordId+'" onclick="openSavedVaultFromPassword(this.dataset.name,this.dataset.path,this.dataset.passwordId,false)">Open</button><button data-name="'+esc(p.name)+'" data-path="'+esc(p.vaultPath)+'" data-password-id="'+passwordId+'" onclick="openSavedVaultFromPassword(this.dataset.name,this.dataset.path,this.dataset.passwordId,true)">Open and save keychain</button><button data-name="'+esc(p.name)+'" data-path="'+esc(p.vaultPath)+'" onclick="selectMoveProfile(this.dataset.name,this.dataset.path)">Move</button><button class="danger" data-name="'+esc(p.name)+'" onclick="deleteProfile(this.dataset.name)">Remove</button></td></tr>';
    }).join('')+'</tbody></table>' : '<p>No saved vault locations.</p>';
  }
  catch(e){ $('profiles').innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
function selectMoveProfile(name,path){ $('moveProfile').value=name; $('moveSource').value=path; $('moveDest').value=''; showHuman('Move source selected', 'Selected saved vault ' + name + '. Enter the new vault location, then click Move vault location.'); location.hash='move-panel'; }
async function deleteProfile(name){ try { await api('/api/profile?name='+encodeURIComponent(name),{method:'DELETE',headers:jsonHeaders}); showHuman('Saved vault removed', 'Removed saved vault location ' + name + '. The vault files and keychain password were not deleted.', 'success'); await refreshStatus(); } catch(e){ showError('Could not remove saved vault', e.message); } }
async function rcloneStatus(check){ try { const s = await api('/api/rclone/status?checkUpdate='+(check?'1':'0')); $('rcloneStatus').textContent = JSON.stringify(s,null,2); } catch(e){ $('rcloneStatus').textContent = e.message; } }
async function rcloneInstall(){ try { const req={version:$('rcloneVersion').value, channel:'stable', fromBinary:$('rcloneFromBinary').value, signature:$('rcloneSignature').value}; const res=await api('/api/rclone/install',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); showHuman('Rclone install/register complete', res, 'success'); } catch(e){ $('rcloneStatus').textContent=e.message; showError('Rclone install/register failed', e.message); } }
async function rcloneUpdate(){ try { const req={version:$('rcloneVersion').value, channel:'stable', signature:$('rcloneSignature').value}; const res=await api('/api/rclone/update',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); showHuman('Rclone update complete', res, 'success'); } catch(e){ $('rcloneStatus').textContent=e.message; showError('Rclone update failed', e.message); } }
async function rcloneRollback(){ try { const res=await api('/api/rclone/rollback',{method:'POST',headers:jsonHeaders,body:'{}'}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); showHuman('Rclone rollback complete', res, 'success'); } catch(e){ $('rcloneStatus').textContent=e.message; showError('Rclone rollback failed', e.message); } }
function remotePayload(){ return {name:$('remoteName').value,type:$('remoteType').value,vaultPath:$('remoteVault').value,remotePath:$('remotePath').value,backend:$('remoteBackend').value,transfers:Number($('remoteTransfers').value||8),checkers:Number($('remoteCheckers').value||16),fastList:$('remoteFastList').checked,bandwidth:$('remoteBandwidth').value}; }
async function saveRemote(){ try { const res=await api('/api/remote',{method:'POST',headers:jsonHeaders,body:JSON.stringify(remotePayload())}); $('remoteOutput').textContent=JSON.stringify(res,null,2); showHuman('Remote profile saved', res, 'success'); await loadRemotes(); } catch(e){ $('remoteOutput').textContent=e.message; showError('Remote profile save failed', e.message); } }
async function loadRemotes(){ try { const data=await api('/api/remotes'); const rows=data.remotes||[]; $('remotes').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Type</th><th>Vault</th><th>Remote</th><th>Actions</th></tr></thead><tbody>'+rows.map(r=>'<tr><td>'+esc(r.name)+'</td><td>'+esc(r.type)+'</td><td class="path">'+esc(r.vault)+'</td><td class="path">'+esc(r.remote.remotePath)+'</td><td class="row-actions"><button data-remote="'+encodeURIComponent(r.name)+'" onclick="remoteRun(decodeURIComponent(this.dataset.remote),\'test\')">Test</button><button data-remote="'+encodeURIComponent(r.name)+'" onclick="remoteRun(decodeURIComponent(this.dataset.remote),\'dry-run\')">Dry-run</button><button data-remote="'+encodeURIComponent(r.name)+'" onclick="remoteRun(decodeURIComponent(this.dataset.remote),\'push\')">Push</button><button data-remote="'+encodeURIComponent(r.name)+'" onclick="remoteRun(decodeURIComponent(this.dataset.remote),\'pull\')">Pull</button><button data-remote="'+encodeURIComponent(r.name)+'" onclick="remoteRun(decodeURIComponent(this.dataset.remote),\'check\')">Check</button><button class="danger" data-remote="'+encodeURIComponent(r.name)+'" onclick="deleteRemote(decodeURIComponent(this.dataset.remote))">Delete</button></td></tr>').join('')+'</tbody></table>' : '<p>No remote profiles saved.</p>'; } catch(e){ $('remotes').innerHTML='<p>'+esc(e.message)+'</p>'; } }
async function remoteRun(name,operation){ try { const res=await api('/api/remote-run',{method:'POST',headers:jsonHeaders,body:JSON.stringify({name:name,operation:operation})}); $('remoteOutput').textContent=JSON.stringify(res,null,2); showHuman('Remote '+operation+' complete', res, 'success'); } catch(e){ $('remoteOutput').textContent=e.message; showError('Remote '+operation+' failed', e.message); } }
async function deleteRemote(name){ try { const res=await api('/api/remote?name='+encodeURIComponent(name),{method:'DELETE',headers:jsonHeaders}); $('remoteOutput').textContent=JSON.stringify(res,null,2); showHuman('Remote profile deleted', res, 'success'); await loadRemotes(); } catch(e){ $('remoteOutput').textContent=e.message; showError('Remote profile delete failed', e.message); } }
async function generateSSHKey(){ try { const res=await api('/api/ssh-keys',{method:'POST',headers:jsonHeaders,body:JSON.stringify({name:$('sshKeyName').value,path:$('sshKeyPath').value})}); $('remoteOutput').textContent=JSON.stringify(res,null,2); showHuman('SSH key operation complete', res, 'success'); await loadSSHKeys(); } catch(e){ $('remoteOutput').textContent=e.message; showError('SSH key operation failed', e.message); } }
async function loadSSHKeys(){ try { const data=await api('/api/ssh-keys'); const rows=data.keys||[]; $('sshKeys').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Private key</th><th>Public key</th><th>Actions</th></tr></thead><tbody>'+rows.map(k=>'<tr><td>'+esc(k.name)+'</td><td class="path">'+esc(k.privatePath)+'</td><td class="path">'+esc(k.publicPath)+'</td><td><button data-key="'+encodeURIComponent(k.name)+'" onclick="showPublicKey(decodeURIComponent(this.dataset.key))">Show public key</button></td></tr>').join('')+'</tbody></table>' : '<p>No managed SSH keys.</p>'; } catch(e){ $('sshKeys').innerHTML='<p>'+esc(e.message)+'</p>'; } }
async function showPublicKey(name){ try { const res=await api('/api/ssh-key-public?name='+encodeURIComponent(name)); $('remoteOutput').textContent=res.publicKey; showHuman('Public key loaded', res.publicKey); } catch(e){ $('remoteOutput').textContent=e.message; showError('Could not load public key', e.message); } }
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function reportBrowserSupport(){
  const missing = [];
  if(!window.fetch) missing.push('Fetch API');
  if(!window.FormData) missing.push('file upload APIs');
  if(!window.AbortController) missing.push('cancel support');
  const testInput = document.createElement('input');
  testInput.type = 'file';
  const supportsFolder = 'webkitdirectory' in testInput || 'directory' in testInput;
  if(!supportsFolder) $('folderSupportHint').textContent = 'This browser may not support folder selection. Use local path ingest for folder imports.';
  if(missing.length){ const w=$('compatWarning'); w.style.display='block'; w.textContent='This browser is missing required features: ' + missing.join(', ') + '. Use a current Chromium, Edge, Safari, or Firefox release, or use the CLI.'; }
}
document.addEventListener('DOMContentLoaded', () => {
  const fileInput = $('fileInput');
  const folderInput = $('folderInput');
  const uploadPath = $('uploadPath');
  if(fileInput) fileInput.addEventListener('change', updateUploadSelectionSummaries);
  if(folderInput) folderInput.addEventListener('change', updateUploadSelectionSummaries);
  if(uploadPath) uploadPath.addEventListener('input', updateUploadSelectionSummaries);
  const davFileInput = $('davFileInput');
  const davFolderInput = $('davFolderInput');
  const dropZone = $('davDropZone');
  if(davFileInput) davFileInput.addEventListener('change', () => uploadDavFiles(davFileInput.files, false));
  if(davFolderInput) davFolderInput.addEventListener('change', () => uploadDavFiles(davFolderInput.files, true));
  if(dropZone){
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', async e => { e.preventDefault(); dropZone.classList.remove('dragover'); try { const items = await collectDroppedUploadItems(e.dataTransfer); await uploadDavItems(items); } catch(err){ showError('Folder drop failed', humanFetchError(err)); } });
  }
  updateUploadSelectionSummaries();
});
reportBrowserSupport();
appendLog('SeaVault GUI started','Ready.'); refreshStatus(); loadAppConfig(); rsyncStatus(false); rcloneStatus(false); loadRemotes(); loadSSHKeys();
</script>
</body>
</html>`))
