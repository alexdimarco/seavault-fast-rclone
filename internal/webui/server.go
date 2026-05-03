package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/seavault-fast/internal/keychain"
	"github.com/example/seavault-fast/internal/profile"
	"github.com/example/seavault-fast/internal/rclonebin"
	"github.com/example/seavault-fast/internal/remotes"
	"github.com/example/seavault-fast/internal/rsyncput"
	"github.com/example/seavault-fast/internal/sshkeys"
	"github.com/example/seavault-fast/internal/transport"
	localtransport "github.com/example/seavault-fast/internal/transport/local"
	rclonetransport "github.com/example/seavault-fast/internal/transport/rclone"
	"github.com/example/seavault-fast/internal/userpath"
	"github.com/example/seavault-fast/internal/vault"
)

type Server struct {
	mu        sync.Mutex
	vaultPath string
	vault     *vault.Vault
	token     string
}

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
	Name      string `json:"name"`
	VaultPath string `json:"vaultPath"`
}

type rcloneInstallRequest struct {
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	FromBinary     string `json:"fromBinary"`
	OfflineArchive string `json:"offlineArchive"`
	OfflineSHA256  string `json:"offlineSHA256"`
	Signature      string `json:"signature"`
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

type statusResponse struct {
	Open           bool            `json:"open"`
	VaultPath      string          `json:"vaultPath,omitempty"`
	VaultID        string          `json:"vaultId,omitempty"`
	Config         *vaultConfigDTO `json:"config,omitempty"`
	Profiles       []profile.Entry `json:"profiles"`
	SuggestedPaths []string        `json:"suggestedPaths"`
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

type exportRequest struct {
	VirtualPath string `json:"virtualPath"`
	DestPath    string `json:"destPath"`
	Overwrite   string `json:"overwrite"`
	DryRun      bool   `json:"dryRun"`
	Zip         bool   `json:"zip"`
}

func New(initialVault string) (*Server, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	s := &Server{token: token}
	if strings.TrimSpace(initialVault) != "" {
		resolved, err := resolveVaultArg(initialVault)
		if err != nil {
			return nil, err
		}
		s.vaultPath = resolved
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		s.handleIndex(w, r)
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
	case "/api/download":
		s.handleDownload(w, r)
	case "/api/export":
		s.handleExport(w, r)
	case "/api/file":
		s.handleFile(w, r)
	case "/api/verify":
		s.handleVerify(w, r)
	case "/api/stats":
		s.handleStats(w, r)
	case "/api/profiles":
		s.handleProfiles(w, r)
	case "/api/profile":
		s.handleProfile(w, r)
	case "/api/rclone/status":
		s.handleRcloneStatus(w, r)
	case "/api/rsync/status":
		s.handleRsyncStatus(w, r)
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
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, struct {
		Token          string
		InitialPath    string
		SuggestedPaths []string
	}{Token: s.token, InitialPath: s.vaultPath, SuggestedPaths: userpath.SuggestedVaultPaths()})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	entries, _ := profile.Entries()
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := statusResponse{Open: s.vault != nil, VaultPath: s.vaultPath, Profiles: entries, SuggestedPaths: userpath.SuggestedVaultPaths()}
	if s.vault != nil {
		cfg := s.vault.Config
		resp.VaultID = s.vault.ID()
		resp.Config = &vaultConfigDTO{Version: cfg.Version, KDF: cfg.KDF, Crypto: cfg.Crypto, Chunk: cfg.Chunk, CreatedAt: cfg.CreatedAt, ManifestMode: cfg.Crypto.ManifestMode}
	}
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
		p, err := keychain.Get(cfg.VaultID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
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
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	vp, err := vault.CleanVirtualPath(r.URL.Query().Get("path"))
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

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	v, ok := s.currentVault(w)
	if !ok {
		return
	}
	vp, err := vault.CleanVirtualPath(r.URL.Query().Get("path"))
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
	writeJSON(w, http.StatusOK, map[string]any{"profiles": entries})
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
		writeJSON(w, http.StatusOK, entry)
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
	writeJSON(w, http.StatusOK, rsyncput.Inspect(r.Context(), r.URL.Query().Get("binary")))
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

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en" data-token="{{.Token}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SeaVault Fast</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f7f7f5;
  --fg: #111827;
  --muted: #4b5563;
  --panel: #ffffff;
  --panel-2: #f3f4f6;
  --border: #d1d5db;
  --control: #ffffff;
  --button: #fff1e8;
  --button-border: #e3b6a5;
  --danger: #b42318;
  --danger-bg: #fff1f0;
  --success: #067647;
  --success-bg: #ecfdf3;
  --focus: #2563eb;
  --shadow: 0 8px 24px rgba(17, 24, 39, .08);
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
header { padding: 18px clamp(14px, 3vw, 28px); border-bottom: 1px solid var(--border); background: var(--panel); }
header h1 { margin: 0 0 6px; font-size: clamp(1.45rem, 2.6vw, 2rem); }
header p { max-width: 1120px; margin: 0; color: var(--muted); }
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
pre { white-space: pre-wrap; overflow-wrap: anywhere; max-width: 100%; padding: 12px; border-radius: 12px; background: var(--panel-2); border: 1px solid var(--border); }
#status { min-height: 280px; }
#message { padding: 10px 12px; border-radius: 12px; background: var(--panel-2); border: 1px solid var(--border); margin-bottom: 12px; }
#message.error { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }
#message.success { background: var(--success-bg); color: var(--success); border-color: var(--success); }
progress { width: 100%; height: 18px; accent-color: var(--focus); }
table { width: 100%; border-collapse: collapse; min-width: 680px; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
.table-wrap { overflow-x: auto; width: 100%; -webkit-overflow-scrolling: touch; }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; word-break: break-word; }
.row-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.checkline { display: inline-flex; gap: 8px; align-items: center; width: auto; }
.pill { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel-2); border: 1px solid var(--border); font-size: .8rem; }
.jump-links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.jump-links a { color: var(--focus); text-decoration: none; padding: 4px 0; }
.jump-links a:hover { text-decoration: underline; }
.compat-warning { display: none; padding: 10px 12px; border-radius: 12px; background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); margin-top: 12px; }
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
  <h1>SeaVault Fast</h1>
  <p>The vault directory is the encrypted cloud-sync location. Put it inside OneDrive, Dropbox, Nextcloud, Syncthing, iCloud Drive, Google Drive, or any sync-client folder.</p>
  <nav class="jump-links" aria-label="Page sections">
    <a href="#vault-panel">Vault</a>
    <a href="#upload-panel">Upload</a>
    <a href="#export-panel">Export</a>
    <a href="#files-panel">Files</a>
    <a href="#remote-panel">Remote</a>
    <a href="#keys-panel">SSH keys</a>
  </nav>
  <div id="compatWarning" class="compat-warning" role="alert"></div>
</header>
<main class="app-shell">
<div class="content">
<section id="vault-panel">
  <h2>Open or create vault</h2>
  <div class="form-grid">
    <label>Vault path or profile
      <input id="vaultPath" value="{{.InitialPath}}" placeholder="~/Nextcloud/seavault" autocomplete="off">
      <small>This is where encrypted chunks and manifests are stored. Use ~/Nextcloud/seavault or an existing local sync folder. On macOS use /Users/name, not /user/name.</small>
    </label>
    <label>Password
      <input id="password" type="password" autocomplete="current-password">
      <small>Leave blank only when using a saved OS keychain entry.</small>
    </label>
    <label>Profile name
      <input id="profile" placeholder="work-cloud" autocomplete="off">
      <small>Optional local alias for the vault path.</small>
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
    <button type="button" class="operation" onclick="openVault(false)">Open</button>
    <button type="button" class="operation" onclick="openVault(true)">Open using keychain</button>
    <button type="button" class="operation" onclick="initVault()">Create vault and open</button>
    <button type="button" onclick="closeVault()">Close</button>
    <label class="checkline"><input id="savePassword" type="checkbox"> Save password in OS keychain</label>
  </p>
</section>

<section id="upload-panel">
  <h2>Upload into encrypted archive</h2>
  <p class="hint">Browser uploads are encrypted directly into the vault. For very large folders, the GUI sends smaller batches. Local path ingest lets the local GUI server read the folder directly and can use rsync-assisted staging.</p>
  <div class="form-grid">
    <label>Virtual path or folder
      <input id="uploadPath" placeholder="reports/" autocomplete="off">
      <small>For one file, use an exact path such as reports/a.pdf. For folders, use a folder prefix such as reports/.</small>
    </label>
    <label>Files from browser
      <input id="fileInput" type="file" multiple>
      <small>Best for selected files.</small>
    </label>
    <label>Folder from browser
      <input id="folderInput" type="file" webkitdirectory directory multiple>
      <small id="folderSupportHint">Preserves relative paths where the browser supports folder selection.</small>
    </label>
    <label>Local file or folder path for rsync-assisted ingest
      <input id="localSourcePath" placeholder="~/Documents/project-folder" autocomplete="off">
      <small>The local GUI server reads this path and encrypts it into the vault.</small>
    </label>
    <label>Put method for local path ingest
      <select id="localPutMethod">
        <option value="auto">auto: prefer rsync, fall back to native</option>
        <option value="rsync">rsync: require rsync</option>
        <option value="native">native: no rsync staging</option>
      </select>
      <small>This setting does not apply to browser file/folder uploads.</small>
    </label>
    <label>Rsync binary override
      <input id="localRsyncBinary" placeholder="optional path or command name" autocomplete="off">
      <small>Leave blank to search PATH for rsync.</small>
    </label>
  </div>
  <p class="row-actions">
    <button class="operation" onclick="uploadFiles('fileInput', false)">Upload selected files</button>
    <button class="operation" onclick="uploadFiles('folderInput', true)">Upload selected browser folder</button>
    <button class="operation" onclick="uploadLocalPath()">Upload local path with rsync/auto</button>
    <button class="secondary" onclick="checkRsync()">Check rsync</button>
    <button class="danger" onclick="cancelActive()">Cancel active upload/export</button>
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
  <h2>Vault files</h2>
  <p class="row-actions"><button onclick="refreshFiles()">Refresh</button><button onclick="verifyVault()">Verify</button><button onclick="loadStats()">Stats</button></p>
  <div id="files" class="table-wrap"></div>
</section>

<section>
  <h2>Profiles</h2>
  <p><button onclick="loadProfiles()">Refresh profiles</button></p>
  <div id="profiles" class="table-wrap"></div>
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
</div>

<aside class="result-panel" aria-live="polite" aria-label="Result and progress">
  <h2>Result and progress</h2>
  <div id="message" role="status">Ready.</div>
  <progress id="progress" value="0" max="1"></progress>
  <p id="progressText"><small>No active operation.</small></p>
  <p class="row-actions"><button class="danger" onclick="cancelActive()">Cancel active operation</button><button class="secondary" onclick="clearOutput()">Clear</button></p>
  <pre id="status">Loading...</pre>
</aside>
</main>
<script>
const token = document.documentElement.dataset.token;
const jsonHeaders = {'Content-Type':'application/json','X-SeaVault-Token':token};
let activeController = null;
let activeCancelled = false;
function $(id){ return document.getElementById(id); }
function setProgress(done, total, text){ const p=$('progress'); p.max=Math.max(1,total||1); p.value=Math.min(p.max,done||0); $('progressText').innerHTML='<small>'+esc(text||'')+'</small>'; }
function setBusy(on){ document.body.classList.toggle('busy', !!on); document.querySelectorAll('button.operation').forEach(btn => { btn.disabled = !!on; }); }
function beginOperation(text){ if(activeController){ throw new Error('Another upload/export operation is already running. Cancel it or wait for it to finish.'); } activeCancelled=false; activeController = new AbortController(); setBusy(true); setProgress(0,1,text||'Starting...'); return activeController; }
function endOperation(text){ activeController=null; setBusy(false); setProgress(1,1,text||'Complete.'); }
function cancelActive(){ if(activeController){ activeCancelled=true; activeController.abort(); setBusy(false); showError('Cancelling operation', 'The active browser request was cancelled. The server checks cancellation between files.'); } else { showHuman('No active operation', 'There is no running upload or export to cancel.'); } }
function clearOutput(){ $('status').textContent=''; $('message').className=''; $('message').textContent='Ready.'; setProgress(0,1,'No active operation.'); }
async function api(path, opts){
  opts = opts || {};
  if(opts.method && opts.method !== 'GET') opts.headers = Object.assign({}, opts.headers || {}, {'X-SeaVault-Token': token});
  let res;
  try { res = await fetch(path, opts); }
  catch(err) { throw new Error('The browser could not reach the local SeaVault GUI service. Confirm the seavault gui process is still running, then refresh this tab. Browser detail: ' + (err && err.message ? err.message : err)); }
  const ct = res.headers.get('content-type') || '';
  let body;
  if(ct.indexOf('application/json') >= 0){ body = await res.json(); } else { body = await res.text(); }
  if(!res.ok) throw new Error((body && body.error) || body || res.statusText);
  return body;
}
function showHuman(title, obj, level){
  $('message').className = level || '';
  $('message').textContent = title;
  $('status').textContent = humanize(obj);
}
function showError(title, detail){
  $('message').className = 'error';
  $('message').textContent = title;
  $('status').textContent = detail || '';
}
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
  if(obj.ok){ return 'Operation completed successfully.\n\n' + JSON.stringify(obj, null, 2); }
  return JSON.stringify(obj, null, 2);
}
function fmtBytes(n){ n=Number(n||0); const units=['B','KiB','MiB','GiB','TiB']; let i=0; while(n>=1024 && i<units.length-1){ n/=1024; i++; } return (i===0?String(n):n.toFixed(1))+' '+units[i]; }
function fillPath(p){ $('vaultPath').value = p; }
function initPayload(){ return {vaultPath:$('vaultPath').value, password:$('password').value, profile:$('profile').value, savePassword:$('savePassword').checked, kdf:$('kdf').value}; }
function openPayload(useKeychain){ return {vaultPath:$('vaultPath').value, password:$('password').value, savePassword:$('savePassword').checked, useKeychain:useKeychain}; }
function localPathWarning(){ const p = $('vaultPath').value.trim(); if(p === '/user' || p.indexOf('/user/') === 0) return 'The path starts with /user. Use ~/Nextcloud/seavault, /Users/<name>/... on macOS, or /home/<name>/... on Linux.'; return ''; }
async function refreshStatus(){ try { const s = await api('/api/status'); showHuman('Status refreshed', s); await refreshFiles(); await loadProfiles(); } catch(e){ showError('Could not refresh status', e.message); } }
async function initVault(){ try { const warn = localPathWarning(); if(warn){ showError('Invalid vault path', warn); return; } const res = await api('/api/init',{method:'POST',headers:jsonHeaders,body:JSON.stringify(initPayload())}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; showHuman('Vault created and opened', status, 'success'); await refreshFiles(); await loadProfiles(); } catch(e){ showError('Could not create vault', e.message); } }
async function openVault(useKeychain){ try { const warn = localPathWarning(); if(warn){ showError('Invalid vault path', warn); return; } const res = await api('/api/open',{method:'POST',headers:jsonHeaders,body:JSON.stringify(openPayload(useKeychain))}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; showHuman('Vault opened', status, 'success'); await refreshFiles(); await loadProfiles(); } catch(e){ showError('Could not open vault', e.message); } }
async function closeVault(){ try { const res = await api('/api/close',{method:'POST',headers:jsonHeaders,body:'{}'}); showHuman('Vault closed', res, 'success'); await refreshFiles(); } catch(e){ showError('Could not close vault', e.message); } }
async function uploadFiles(inputId, preserveFolders){
  const input = $(inputId);
  let ctl;
  try {
    if(!input.files || input.files.length === 0){ showError('Nothing selected', 'Select one or more files first.'); return; }
    const files = Array.from(input.files);
    const batchSize = preserveFolders ? 40 : 80;
    const batches = [];
    for(let i=0; i<files.length; i+=batchSize) batches.push(files.slice(i,i+batchSize));
    ctl = beginOperation('Uploading 0 of ' + files.length + ' selected file(s)...');
    let allResults = [];
    for(let b=0; b<batches.length; b++){
      if(activeCancelled) throw new Error('upload cancelled');
      const fd = new FormData();
      fd.append('path', $('uploadPath').value);
      for(const f of batches[b]){
        if(preserveFolders) fd.append('relpaths', f.webkitRelativePath || f.name);
        fd.append('files', f, f.name);
      }
      setProgress(Math.min(b*batchSize, files.length), files.length, 'Uploading batch ' + (b+1) + ' of ' + batches.length + '...');
      const res = await fetch('/api/upload',{method:'POST',headers:{'X-SeaVault-Token':token},body:fd,signal:ctl.signal});
      let body;
      try { body = await res.json(); } catch(_) { body = {error: await res.text()}; }
      if(!res.ok) throw new Error(body.error || res.statusText);
      allResults = allResults.concat(body.results || []);
      setProgress(Math.min((b+1)*batchSize, files.length), files.length, 'Uploaded ' + Math.min((b+1)*batchSize, files.length) + ' of ' + files.length + ' file(s).');
    }
    const summary = {method:'browser-batched', results:allResults};
    input.value='';
    endOperation('Upload complete.');
    showHuman('Upload complete', summary, 'success');
    await refreshFiles();
  } catch(e){
    if(e.name === 'AbortError') showError('Upload cancelled', 'The browser upload was cancelled. Files already imported before cancellation remain in the vault.');
    else showError('Upload failed', e.message + '\n\nFor very large folders, use the local path ingest field. It lets the local GUI server read the folder directly and avoids browser upload limits.');
    activeController = null;
    setBusy(false);
  }
}
async function uploadLocalPath(){
  let ctl;
  try {
    ctl = beginOperation('Encrypting local path into the vault...');
    const req = {sourcePath:$('localSourcePath').value, virtualPath:$('uploadPath').value, method:$('localPutMethod').value, rsyncBinary:$('localRsyncBinary').value};
    const res = await api('/api/upload-path',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req),signal:ctl.signal});
    endOperation('Local path ingest complete.');
    showHuman('Local path ingest complete', res, 'success');
    await refreshFiles();
  } catch(e){ if(e.name === 'AbortError') showError('Upload cancelled', 'The local path ingest was cancelled.'); else showError('Local path ingest failed', e.message); activeController=null; setBusy(false); }
}
async function checkRsync(){ try { const bin=encodeURIComponent($('localRsyncBinary').value); const res=await api('/api/rsync/status?binary='+bin); showHuman(res.available?'rsync is available':'rsync is not available', res, res.available?'success':'error'); } catch(e){ showError('Could not check rsync', e.message); } }
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
async function refreshFiles(){
  try {
    const data = await api('/api/files');
    const rows = data.files || [];
    if(rows.length === 0){ $('files').innerHTML = '<p>No files in the open vault.</p>'; return; }
    $('files').innerHTML = '<table><thead><tr><th>Path</th><th>Size</th><th>Chunks</th><th>Updated</th><th>Actions</th></tr></thead><tbody>' +
      rows.map(f => '<tr><td class="path">'+esc(f.path)+(f.conflictOf?' <small>conflict of '+esc(f.conflictOf)+'</small>':'')+'</td><td>'+fmtBytes(f.size)+'</td><td>'+f.chunks+'</td><td>'+esc(f.updatedAt||'')+'</td><td class="row-actions"><button onclick="downloadFile(\''+encodeURIComponent(f.path)+'\')">Download</button><button data-export-path="'+encodeURIComponent(dirname(f.path))+'" onclick="setExportPath(decodeURIComponent(this.dataset.exportPath))">Use folder</button><button class="danger" onclick="deleteFile(\''+encodeURIComponent(f.path)+'\')">Delete</button></td></tr>').join('') + '</tbody></table>';
  } catch(e){ $('files').innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
function dirname(p){ const i=String(p).lastIndexOf('/'); return i>0?String(p).slice(0,i):'.'; }
function setExportPath(p){ $('exportPath').value = p || '.'; showHuman('Export path selected', 'Selected export path: ' + (p || '.')); }
function downloadFile(p){ window.location = '/api/download?path=' + p; }
async function deleteFile(p){ try { await api('/api/file?path='+p,{method:'DELETE',headers:jsonHeaders}); showHuman('File deleted', 'Deleted selected virtual path.', 'success'); await refreshFiles(); } catch(e){ showError('Delete failed', e.message); } }
async function verifyVault(){ try { const res = await api('/api/verify',{method:'POST',headers:jsonHeaders,body:'{}'}); showHuman('Vault verification passed', res, 'success'); } catch(e){ showError('Vault verification failed', e.message); } }
async function loadStats(){ try { const res = await api('/api/stats'); showHuman('Vault statistics', res); } catch(e){ showError('Could not load stats', e.message); } }
async function loadProfiles(){
  try { const data = await api('/api/profiles'); const rows = data.profiles || []; $('profiles').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Vault path</th></tr></thead><tbody>'+rows.map(p=>'<tr><td>'+esc(p.name)+'</td><td class="path">'+esc(p.vaultPath)+'</td></tr>').join('')+'</tbody></table>' : '<p>No profiles saved.</p>'; }
  catch(e){ $('profiles').innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
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
reportBrowserSupport();
refreshStatus(); rcloneStatus(false); loadRemotes(); loadSSHKeys();
</script>
</body>
</html>`))
