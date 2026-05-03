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
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/example/seavault-fast/internal/keychain"
	"github.com/example/seavault-fast/internal/profile"
	"github.com/example/seavault-fast/internal/rclonebin"
	"github.com/example/seavault-fast/internal/remotes"
	"github.com/example/seavault-fast/internal/rsyncingest"
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
	Results []vault.PutResult  `json:"results"`
	Ingest  rsyncingest.Report `json:"ingest"`
	Count   int                `json:"count"`
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
	case "/api/download":
		s.handleDownload(w, r)
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
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	basePath := strings.TrimSpace(r.FormValue("path"))
	ingestMode := strings.TrimSpace(r.FormValue("ingestMode"))
	rsyncBin := strings.TrimSpace(r.FormValue("rsyncBin"))
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "no uploaded file field named file or files"})
		return
	}
	relativePaths := r.MultipartForm.Value["relativePaths"]
	tmpRoot, err := os.MkdirTemp("", "seavault-upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	defer os.RemoveAll(tmpRoot)

	written := make([]string, 0, len(files))
	for i, fh := range files {
		rel := ""
		if i < len(relativePaths) {
			rel = relativePaths[i]
		}
		if strings.TrimSpace(rel) == "" {
			rel = fh.Filename
		}
		rel = strings.ReplaceAll(rel, "\\", "/")
		rel = strings.TrimLeft(rel, "/")
		cleanRel, err := vault.CleanVirtualPath(rel)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid upload relative path " + rel + ": " + err.Error()})
			return
		}
		target := filepath.Join(tmpRoot, filepath.FromSlash(cleanRel))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		src, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = io.Copy(out, src)
		}
		closeErr := outClose(out)
		_ = src.Close()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if closeErr != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: closeErr.Error()})
			return
		}
		written = append(written, cleanRel)
	}

	singleExact := len(written) == 1 && strings.TrimSpace(basePath) != "" && !strings.HasSuffix(strings.TrimSpace(basePath), "/") && !strings.Contains(written[0], "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	var result rsyncingest.Result
	if singleExact {
		result, err = rsyncingest.PutPath(r.Context(), v, filepath.Join(tmpRoot, filepath.FromSlash(written[0])), basePath, rsyncingest.Options{Mode: ingestMode, RsyncPath: rsyncBin, PreserveRootOnEmpty: false})
	} else {
		result, err = rsyncingest.PutDirectoryContents(r.Context(), v, tmpRoot, strings.TrimSuffix(basePath, "/"), rsyncingest.Options{Mode: ingestMode, RsyncPath: rsyncBin})
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "ingest": result.Report})
		return
	}
	writeJSON(w, http.StatusOK, uploadResponse{Results: result.Results, Ingest: result.Report, Count: len(result.Results)})
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

func (s *Server) handleRcloneStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	check := r.URL.Query().Get("checkUpdate") == "1" || strings.EqualFold(r.URL.Query().Get("checkUpdate"), "true")
	status := rclonebin.NewInstaller().Status(r.Context(), check)
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleRsyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, rsyncingest.Status(r.URL.Query().Get("rsyncBin")))
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

func outClose(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Close()
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SeaVault Fast</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, Segoe UI, sans-serif; }
body { margin: 0; background: Canvas; color: CanvasText; }
header { padding: 18px 24px; border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }
main { max-width: 1120px; margin: 0 auto; padding: 24px; display: grid; gap: 18px; }
section { border: 1px solid color-mix(in srgb, CanvasText 15%, transparent); border-radius: 14px; padding: 18px; background: color-mix(in srgb, Canvas 96%, CanvasText 4%); }
.grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); }
label { display: grid; gap: 6px; font-size: 0.92rem; }
input, select, button { font: inherit; padding: 10px; border-radius: 10px; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); background: Canvas; color: CanvasText; }
button { cursor: pointer; background: color-mix(in srgb, Highlight 16%, Canvas); }
button.danger { background: color-mix(in srgb, red 18%, Canvas); }
small { opacity: 0.76; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: 12px; border-radius: 10px; background: color-mix(in srgb, CanvasText 8%, Canvas); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid color-mix(in srgb, CanvasText 12%, transparent); }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
</style>
</head>
<body>
<header>
  <h1>SeaVault Fast</h1>
  <p>The vault directory is the encrypted cloud-sync location. Put it inside OneDrive, Dropbox, Nextcloud, Syncthing, iCloud Drive, Google Drive, or any sync-client folder.</p>
</header>
<main>
<section>
  <h2>Open or create vault</h2>
  <div class="grid">
    <label>Vault path or profile
      <input id="vaultPath" value="{{.InitialPath}}" placeholder="~/Nextcloud/seavault">
      <small>This is where encrypted chunks and manifests are stored. Use ~/Nextcloud/seavault or an existing local sync folder. On macOS use /Users/name, not /user/name.</small>
    </label>
    <label>Password
      <input id="password" type="password" autocomplete="current-password">
      <small>Leave blank only when using a saved OS keychain entry.</small>
    </label>
    <label>Profile name
      <input id="profile" placeholder="work-cloud">
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
    <button type="button" onclick="openVault(false)">Open</button>
    <button type="button" onclick="openVault(true)">Open using keychain</button>
    <button type="button" onclick="initVault()">Create vault and open</button>
    <button type="button" onclick="closeVault()">Close</button>
    <label style="display:inline-flex;gap:8px;align-items:center"><input id="savePassword" type="checkbox"> Save password in OS keychain</label>
  </p>
  <pre id="status">Loading...</pre>
</section>

<section>
  <h2>Upload into encrypted archive</h2>
  <p><small>Uploads are staged with rsync when available, then chunked and encrypted into the vault. Browser folder upload preserves relative paths; plaintext is removed from the temporary staging area after import.</small></p>
  <div class="grid">
    <label>Virtual path or folder
      <input id="uploadPath" placeholder="reports/">
      <small>For one file, use an exact path such as reports/a.pdf. For multiple files or folders, use a folder prefix such as reports/.</small>
    </label>
    <label>Files
      <input id="fileInput" type="file" multiple>
    </label>
    <label>Folder
      <input id="folderInput" type="file" multiple webkitdirectory directory>
      <small>Supported by Chromium, Edge, and Safari. Firefox may not expose folder selection.</small>
    </label>
    <label>Ingest method
      <select id="ingestMode">
        <option value="auto">auto: rsync if available, otherwise direct</option>
        <option value="rsync">require rsync</option>
        <option value="direct">direct fallback</option>
      </select>
    </label>
    <label>rsync binary path
      <input id="rsyncBin" placeholder="optional; default SEAVAULT_RSYNC or PATH">
    </label>
  </div>
  <p class="row-actions"><button onclick="uploadFiles()">Upload selected files/folder</button><button onclick="rsyncStatus()">Check rsync</button></p>
  <pre id="uploadOutput">No upload has run.</pre>
</section>

<section>
  <h2>Vault files</h2>
  <p class="row-actions"><button onclick="refreshFiles()">Refresh</button><button onclick="verifyVault()">Verify</button><button onclick="loadStats()">Stats</button></p>
  <div id="files"></div>
</section>

<section>
  <h2>Profiles</h2>
  <p><button onclick="loadProfiles()">Refresh profiles</button></p>
  <div id="profiles"></div>
</section>


<section>
  <h2>Rclone runtime</h2>
  <p>This app uses an app-managed rclone executable for remote transport. It does not require system rclone.</p>
  <div class="grid">
    <label>Version or channel
      <input id="rcloneVersion" placeholder="latest stable or v1.74.0">
      <small>Leave blank for latest stable. Use the update controls to replace the managed runtime after verification.</small>
    </label>
    <label>Register existing binary for testing or offline use
      <input id="rcloneFromBinary" placeholder="/path/to/rclone">
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
    <button onclick="rcloneInstall()">Install/register rclone</button>
    <button onclick="rcloneUpdate()">Update rclone</button>
    <button onclick="rcloneRollback()">Rollback</button>
  </p>
  <pre id="rcloneStatus">No runtime status loaded.</pre>
</section>

<section>
  <h2>Remote repositories</h2>
  <div class="grid">
    <label>Name
      <input id="remoteName" placeholder="research-b2-ca">
    </label>
    <label>Type
      <select id="remoteType">
        <option value="rclone">rclone</option>
        <option value="local">local folder copy</option>
      </select>
    </label>
    <label>Vault path/profile
      <input id="remoteVault" placeholder="leave blank to use open vault">
    </label>
    <label>Remote path
      <input id="remotePath" placeholder="remote:bucket/path or ~/Backup/seavault">
      <small>For rclone, enter the provider path. The app transfers only .seavault.</small>
    </label>
    <label>Backend label
      <input id="remoteBackend" value="local" placeholder="local, sftp, s3, b2, onedrive, webdav">
    </label>
    <label>Transfers
      <input id="remoteTransfers" type="number" value="8">
    </label>
    <label>Checkers
      <input id="remoteCheckers" type="number" value="16">
    </label>
    <label>Bandwidth limit
      <input id="remoteBandwidth" placeholder="optional, e.g. 10M">
    </label>
  </div>
  <p class="row-actions">
    <label style="display:inline-flex;gap:8px;align-items:center"><input id="remoteFastList" type="checkbox" checked> Use fast-list when supported</label>
    <button onclick="saveRemote()">Save remote profile</button>
    <button onclick="loadRemotes()">Refresh remotes</button>
  </p>
  <div id="remotes"></div>
  <pre id="remoteOutput">No remote action has run.</pre>
</section>

<section>
  <h2>SSH keys for rclone SFTP</h2>
  <div class="grid">
    <label>Managed key name
      <input id="sshKeyName" placeholder="research-sftp">
    </label>
    <label>Import existing private key path
      <input id="sshKeyPath" placeholder="optional path to import">
    </label>
  </div>
  <p class="row-actions">
    <button onclick="generateSSHKey()">Generate/import key</button>
    <button onclick="loadSSHKeys()">Refresh keys</button>
  </p>
  <div id="sshKeys"></div>
</section>

</main>
<script>
const token = document.documentElement.dataset.token;
const headers = {'Content-Type':'application/json','X-SeaVault-Token':token};
function $(id){ return document.getElementById(id); }
async function api(path, opts={}){
  opts.headers = Object.assign({}, opts.headers || {}, opts.method && opts.method !== 'GET' ? {'X-SeaVault-Token': token} : {});
  const res = await fetch(path, opts);
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await res.json() : await res.text();
  if(!res.ok) throw new Error((body && body.error) || body || res.statusText);
  return body;
}
function show(obj){ $('status').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); }
function uploadShow(obj){ $('uploadOutput').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); }
function fillPath(p){ $('vaultPath').value = p; }
function initPayload(){ return {vaultPath:$('vaultPath').value, password:$('password').value, profile:$('profile').value, savePassword:$('savePassword').checked, kdf:$('kdf').value}; }
function openPayload(useKeychain){ return {vaultPath:$('vaultPath').value, password:$('password').value, savePassword:$('savePassword').checked, useKeychain:useKeychain}; }
function localPathWarning(){ const p = $('vaultPath').value.trim(); if(p === '/user' || p.startsWith('/user/')) return 'The path starts with /user. Use ~/Nextcloud/seavault, /Users/<name>/... on macOS, or /home/<name>/... on Linux.'; return ''; }
async function refreshStatus(){ try { const s = await api('/api/status'); show(s); await refreshFiles(); await loadProfiles(); } catch(e){ show(e.message); } }
async function initVault(){ try { const warn = localPathWarning(); if(warn){ show(warn); return; } const res = await api('/api/init',{method:'POST',headers,body:JSON.stringify(initPayload())}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; show(status); await refreshFiles(); await loadProfiles(); } catch(e){ show(e.message); } }
async function openVault(useKeychain){ try { const warn = localPathWarning(); if(warn){ show(warn); return; } const res = await api('/api/open',{method:'POST',headers,body:JSON.stringify(openPayload(useKeychain))}); $('password').value=''; const status = await api('/api/status'); status.lastAction = res; show(status); await refreshFiles(); await loadProfiles(); } catch(e){ show(e.message); } }
async function closeVault(){ try { await api('/api/close',{method:'POST',headers,body:'{}'}); await refreshStatus(); } catch(e){ show(e.message); } }
async function uploadFiles(){
  try {
    const fd = new FormData();
    fd.append('path', $('uploadPath').value);
    fd.append('ingestMode', $('ingestMode').value);
    fd.append('rsyncBin', $('rsyncBin').value);
    const files = [...$('fileInput').files];
    const folders = [...$('folderInput').files];
    const all = files.concat(folders);
    if(all.length === 0) throw new Error('Select one or more files or a folder first.');
    for(const f of all){
      const rel = f.webkitRelativePath || f.name;
      fd.append('files', f, f.name);
      fd.append('relativePaths', rel);
    }
    const res = await fetch('/api/upload',{method:'POST',headers:{'X-SeaVault-Token':token},body:fd});
    const body = await res.json();
    if(!res.ok) throw new Error(body.error || res.statusText);
    uploadShow(body); $('fileInput').value=''; $('folderInput').value=''; await refreshFiles();
  } catch(e){ uploadShow(e.message); }
}
async function refreshFiles(){
  try {
    const data = await api('/api/files');
    const rows = data.files || [];
    if(rows.length === 0){ $('files').innerHTML = '<p>No files in the open vault.</p>'; return; }
    $('files').innerHTML = '<table><thead><tr><th>Path</th><th>Size</th><th>Chunks</th><th>Updated</th><th>Actions</th></tr></thead><tbody>' +
      rows.map(f => '<tr><td class="path">'+esc(f.path)+(f.conflictOf?' <small>conflict of '+esc(f.conflictOf)+'</small>':'')+'</td><td>'+f.size+'</td><td>'+f.chunks+'</td><td>'+esc(f.updatedAt||'')+'</td><td class="row-actions"><button onclick="downloadFile(\''+encodeURIComponent(f.path)+'\')">Download</button><button class="danger" onclick="deleteFile(\''+encodeURIComponent(f.path)+'\')">Delete</button></td></tr>').join('') + '</tbody></table>';
  } catch(e){ $('files').innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
function downloadFile(p){ window.location = '/api/download?path=' + p; }
async function deleteFile(p){ try { await api('/api/file?path='+p,{method:'DELETE',headers}); await refreshFiles(); } catch(e){ show(e.message); } }
async function verifyVault(){ try { const res = await api('/api/verify',{method:'POST',headers,body:'{}'}); show(res); } catch(e){ show(e.message); } }
async function loadStats(){ try { const res = await api('/api/stats'); show(res); } catch(e){ show(e.message); } }
async function loadProfiles(){
  try { const data = await api('/api/profiles'); const rows = data.profiles || []; $('profiles').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Vault path</th></tr></thead><tbody>'+rows.map(p=>'<tr><td>'+esc(p.name)+'</td><td class="path">'+esc(p.vaultPath)+'</td></tr>').join('')+'</tbody></table>' : '<p>No profiles saved.</p>'; }
  catch(e){ $('profiles').innerHTML = '<p>'+esc(e.message)+'</p>'; }
}
async function rsyncStatus(){ try { const s = await api('/api/rsync/status?rsyncBin='+encodeURIComponent($('rsyncBin').value)); uploadShow(s); } catch(e){ uploadShow(e.message); } }
async function rcloneStatus(check){ try { const s = await api('/api/rclone/status?checkUpdate='+(check?'1':'0')); $('rcloneStatus').textContent = JSON.stringify(s,null,2); } catch(e){ $('rcloneStatus').textContent = e.message; } }
async function rcloneInstall(){ try { const req={version:$('rcloneVersion').value, channel:'stable', fromBinary:$('rcloneFromBinary').value, signature:$('rcloneSignature').value}; const res=await api('/api/rclone/install',{method:'POST',headers,body:JSON.stringify(req)}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); } catch(e){ $('rcloneStatus').textContent=e.message; } }
async function rcloneUpdate(){ try { const req={version:$('rcloneVersion').value, channel:'stable', signature:$('rcloneSignature').value}; const res=await api('/api/rclone/update',{method:'POST',headers,body:JSON.stringify(req)}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); } catch(e){ $('rcloneStatus').textContent=e.message; } }
async function rcloneRollback(){ try { const res=await api('/api/rclone/rollback',{method:'POST',headers,body:'{}'}); $('rcloneStatus').textContent=JSON.stringify(res,null,2); } catch(e){ $('rcloneStatus').textContent=e.message; } }
function remotePayload(){ return {name:$('remoteName').value,type:$('remoteType').value,vaultPath:$('remoteVault').value,remotePath:$('remotePath').value,backend:$('remoteBackend').value,transfers:Number($('remoteTransfers').value||8),checkers:Number($('remoteCheckers').value||16),fastList:$('remoteFastList').checked,bandwidth:$('remoteBandwidth').value}; }
async function saveRemote(){ try { const res=await api('/api/remote',{method:'POST',headers,body:JSON.stringify(remotePayload())}); $('remoteOutput').textContent=JSON.stringify(res,null,2); await loadRemotes(); } catch(e){ $('remoteOutput').textContent=e.message; } }
async function loadRemotes(){ try { const data=await api('/api/remotes'); const rows=data.remotes||[]; $('remotes').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Type</th><th>Vault</th><th>Remote</th><th>Actions</th></tr></thead><tbody>'+rows.map(r=>'<tr><td>'+esc(r.name)+'</td><td>'+esc(r.type)+'</td><td class="path">'+esc(r.vault)+'</td><td class="path">'+esc(r.remote.remotePath)+'</td><td class="row-actions"><button onclick="remoteRun(\''+escAttr(r.name)+'\',\'test\')">Test</button><button onclick="remoteRun(\''+escAttr(r.name)+'\',\'dry-run\')">Dry-run</button><button onclick="remoteRun(\''+escAttr(r.name)+'\',\'push\')">Push</button><button onclick="remoteRun(\''+escAttr(r.name)+'\',\'pull\')">Pull</button><button onclick="remoteRun(\''+escAttr(r.name)+'\',\'check\')">Check</button><button class="danger" onclick="deleteRemote(\''+escAttr(r.name)+'\')">Delete</button></td></tr>').join('')+'</tbody></table>' : '<p>No remote profiles saved.</p>'; } catch(e){ $('remotes').innerHTML='<p>'+esc(e.message)+'</p>'; } }
async function remoteRun(name,operation){ try { const res=await api('/api/remote-run',{method:'POST',headers,body:JSON.stringify({name,operation})}); $('remoteOutput').textContent=JSON.stringify(res,null,2); } catch(e){ $('remoteOutput').textContent=e.message; } }
async function deleteRemote(name){ try { const res=await api('/api/remote?name='+encodeURIComponent(name),{method:'DELETE',headers}); $('remoteOutput').textContent=JSON.stringify(res,null,2); await loadRemotes(); } catch(e){ $('remoteOutput').textContent=e.message; } }
async function generateSSHKey(){ try { const res=await api('/api/ssh-keys',{method:'POST',headers,body:JSON.stringify({name:$('sshKeyName').value,path:$('sshKeyPath').value})}); $('remoteOutput').textContent=JSON.stringify(res,null,2); await loadSSHKeys(); } catch(e){ $('remoteOutput').textContent=e.message; } }
async function loadSSHKeys(){ try { const data=await api('/api/ssh-keys'); const rows=data.keys||[]; $('sshKeys').innerHTML = rows.length ? '<table><thead><tr><th>Name</th><th>Private key</th><th>Public key</th><th>Actions</th></tr></thead><tbody>'+rows.map(k=>'<tr><td>'+esc(k.name)+'</td><td class="path">'+esc(k.privatePath)+'</td><td class="path">'+esc(k.publicPath)+'</td><td><button onclick="showPublicKey(\''+escAttr(k.name)+'\')">Show public key</button></td></tr>').join('')+'</tbody></table>' : '<p>No managed SSH keys.</p>'; } catch(e){ $('sshKeys').innerHTML='<p>'+esc(e.message)+'</p>'; } }
async function showPublicKey(name){ try { const res=await api('/api/ssh-key-public?name='+encodeURIComponent(name)); $('remoteOutput').textContent=res.publicKey; } catch(e){ $('remoteOutput').textContent=e.message; } }
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function escAttr(s){ return String(s).replace(/[\\'"&<>]/g, c => ({'\\':'\\\\',"'":"\\'",'"':'&quot;','&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
refreshStatus(); rcloneStatus(false); loadRemotes(); loadSSHKeys();
</script>
</body>
</html>`))
