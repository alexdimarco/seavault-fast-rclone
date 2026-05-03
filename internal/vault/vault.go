package vault

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/example/seavault-fast/internal/userpath"
)

const (
	MetadataDirName = ".seavault"
	ConfigFileName  = "vault.json"
	IndexFileName   = "index.dat" // legacy single-index file, still readable.
)

type VaultConfig struct {
	Version     int          `json:"version"`
	VaultID     string       `json:"vaultId,omitempty"`
	CreatedAt   string       `json:"createdAt"`
	KDF         KDFConfig    `json:"kdf"`
	Crypto      CryptoConfig `json:"crypto"`
	Chunk       ChunkParams  `json:"chunk"`
	WrappedKeys string       `json:"wrappedKeys"`
	WrapNonce   string       `json:"wrapNonce"`
}

type KDFConfig struct {
	Algorithm   string `json:"algorithm"`
	Iterations  int    `json:"iterations,omitempty"`
	Salt        string `json:"salt"`
	ScryptN     int    `json:"scryptN,omitempty"`
	ScryptR     int    `json:"scryptR,omitempty"`
	ScryptP     int    `json:"scryptP,omitempty"`
	MemoryKiB   int    `json:"memoryKiB,omitempty"`
	Time        int    `json:"time,omitempty"`
	Parallelism int    `json:"parallelism,omitempty"`
}

type CryptoConfig struct {
	KeyWrap        string `json:"keyWrap"`
	ChunkAEAD      string `json:"chunkAEAD"`
	IndexAEAD      string `json:"indexAEAD"`
	ObjectID       string `json:"objectID"`
	Chunker        string `json:"chunker"`
	StorageMode    string `json:"storageMode"`
	ManifestMode   string `json:"manifestMode,omitempty"`
	ManifestShards int    `json:"manifestShards,omitempty"`
}

type CreateOptions struct {
	Chunk ChunkParams
	KDF   KDFConfig
}

type Vault struct {
	Root      string
	MetaRoot  string
	Config    VaultConfig
	keys      Keys
	chunkAEAD cipher.AEAD
	indexAEAD cipher.AEAD
}

type PutResult struct {
	Path          string
	Size          int64
	ChunkCount    int
	NewChunkCount int
}

type Stats struct {
	Files        int
	Referenced   int
	Objects      int
	ReferencedMB float64
}

func Create(root string, password string, params ChunkParams) error {
	return CreateWithOptions(root, password, CreateOptions{Chunk: params, KDF: DefaultKDFConfig()})
}

func CreateWithOptions(root string, password string, opts CreateOptions) error {
	var err error
	root, err = userpath.Abs(root)
	if err != nil {
		return err
	}
	if err := userpath.ValidateCreatableVaultPath(root); err != nil {
		return err
	}
	if password == "" {
		return errors.New("password must not be empty")
	}
	params := opts.Chunk
	if params == (ChunkParams{}) {
		params = DefaultChunkParams()
	}
	if err := params.Validate(); err != nil {
		return err
	}
	kdfCfg, err := NormalizeKDFConfig(opts.KDF, true)
	if err != nil {
		return err
	}
	meta := filepath.Join(root, MetadataDirName)
	if err := os.MkdirAll(filepath.Join(meta, "objects", "chunks"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(meta, ManifestDirName), 0o700); err != nil {
		return err
	}
	configPath := filepath.Join(meta, ConfigFileName)
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("vault already exists at %s", meta)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	salt, err := randomBytes(32)
	if err != nil {
		return err
	}
	master, err := randomBytes(32)
	if err != nil {
		return err
	}
	indexKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	vaultID, err := randomHex(16)
	if err != nil {
		return err
	}
	kdfCfg.Salt = base64.StdEncoding.EncodeToString(salt)
	nonce, wrapped, err := wrapKeys(password, kdfCfg, Keys{MasterKey: master, IndexKey: indexKey})
	if err != nil {
		return err
	}
	cfg := VaultConfig{
		Version:   2,
		VaultID:   vaultID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		KDF:       kdfCfg,
		Crypto: CryptoConfig{
			KeyWrap:        "AES-256-GCM",
			ChunkAEAD:      "AES-256-GCM",
			IndexAEAD:      "AES-256-GCM",
			ObjectID:       "HMAC-SHA256(indexKey, plaintextChunk)",
			Chunker:        "gear-hash content-defined chunking",
			StorageMode:    "cloud-folder content-addressed chunks plus encrypted sharded manifests",
			ManifestMode:   "encrypted-sharded-manifests-v2",
			ManifestShards: 256,
		},
		Chunk:       params,
		WrappedKeys: wrapped,
		WrapNonce:   nonce,
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(configPath, cfgJSON, 0o600)
}

func ReadConfig(root string) (VaultConfig, error) {
	root, err := userpath.Abs(root)
	if err != nil {
		return VaultConfig{}, err
	}
	cfgBytes, err := os.ReadFile(filepath.Join(root, MetadataDirName, ConfigFileName))
	if err != nil {
		return VaultConfig{}, err
	}
	var cfg VaultConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return VaultConfig{}, err
	}
	if cfg.VaultID == "" {
		cfg.VaultID = legacyVaultID(root, cfg)
	}
	return cfg, nil
}

func Open(root string, password string) (*Vault, error) {
	var err error
	root, err = userpath.Abs(root)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("password must not be empty")
	}
	cfg, err := ReadConfig(root)
	if err != nil {
		return nil, err
	}
	if cfg.Version != 1 && cfg.Version != 2 {
		return nil, fmt.Errorf("unsupported vault version %d", cfg.Version)
	}
	keys, err := unwrapKeys(password, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys)
	if err != nil {
		return nil, err
	}
	chunkKey := deriveSubkey(keys.MasterKey, "chunk-aead")
	indexKey := deriveSubkey(keys.MasterKey, "index-aead")
	chunkAEAD, err := newAESGCM(chunkKey)
	if err != nil {
		return nil, err
	}
	indexAEAD, err := newAESGCM(indexKey)
	if err != nil {
		return nil, err
	}
	return &Vault{Root: root, MetaRoot: filepath.Join(root, MetadataDirName), Config: cfg, keys: keys, chunkAEAD: chunkAEAD, indexAEAD: indexAEAD}, nil
}

func (v *Vault) ID() string {
	if v.Config.VaultID != "" {
		return v.Config.VaultID
	}
	return legacyVaultID(v.Root, v.Config)
}

func legacyVaultID(root string, cfg VaultConfig) string {
	b, _ := json.Marshal(struct {
		Root string
		Salt string
	}{Root: root, Salt: cfg.KDF.Salt})
	return hmacHex([]byte("seavault-legacy-vault-id"), b)[:32]
}

func (v *Vault) usesManifestStore() bool {
	return v.Config.Version >= 2 || v.Config.Crypto.ManifestMode != ""
}

func (v *Vault) LoadIndex() (Index, error) {
	if v.usesManifestStore() {
		idx, hasManifests, err := v.loadManifestIndex()
		if err != nil {
			return Index{}, err
		}
		if hasManifests {
			return idx, nil
		}
	}
	idx, err := v.loadLegacyIndex()
	if errors.Is(err, os.ErrNotExist) {
		return NewIndex(), nil
	}
	return idx, err
}

func (v *Vault) loadLegacyIndex() (Index, error) {
	data, err := os.ReadFile(filepath.Join(v.MetaRoot, IndexFileName))
	if err != nil {
		return Index{}, err
	}
	nonce, ct, err := decodeEncrypted(indexMagic, v.indexAEAD.NonceSize(), data)
	if err != nil {
		return Index{}, err
	}
	pt, err := v.indexAEAD.Open(nil, nonce, ct, []byte(indexAAD))
	if err != nil {
		return Index{}, errors.New("index decrypt failed: wrong password or damaged index")
	}
	var idx Index
	if err := json.Unmarshal(pt, &idx); err != nil {
		return Index{}, err
	}
	if idx.Files == nil {
		idx.Files = map[string]FileRecord{}
	}
	return idx, nil
}

func (v *Vault) SaveIndex(idx Index) error {
	idx.Version = 2
	idx.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if v.usesManifestStore() {
		return v.saveIndexAsManifests(idx)
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		return err
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(indexAAD))
	return atomicWriteFile(filepath.Join(v.MetaRoot, IndexFileName), encodeEncrypted(indexMagic, nonce, ct), 0o600)
}

func (v *Vault) PutPath(sourcePath string, virtualPath string) ([]PutResult, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	var results []PutResult
	var written []string
	if !info.IsDir() {
		vp := virtualPath
		if strings.TrimSpace(vp) == "" {
			vp = filepath.Base(sourcePath)
		}
		cleaned, err := CleanVirtualPath(vp)
		if err != nil {
			return nil, err
		}
		res, err := v.putFile(sourcePath, cleaned, &idx)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
		written = append(written, cleaned)
	} else {
		baseVirtual := virtualPath
		if strings.TrimSpace(baseVirtual) == "" {
			baseVirtual = filepath.Base(sourcePath)
		}
		err := filepath.WalkDir(sourcePath, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if name == MetadataDirName || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(sourcePath, p)
			if err != nil {
				return err
			}
			vp, err := virtualJoin(baseVirtual, rel)
			if err != nil {
				return err
			}
			res, err := v.putFile(p, vp, &idx)
			if err != nil {
				return err
			}
			results = append(results, res)
			written = append(written, vp)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if v.usesManifestStore() {
		for _, p := range written {
			if err := v.saveFileManifest(p, idx.Files[p]); err != nil {
				return nil, err
			}
		}
		return results, nil
	}
	return results, v.SaveIndex(idx)
}

func (v *Vault) putFile(sourcePath string, virtualPath string, idx *Index) (PutResult, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return PutResult{}, err
	}
	f, err := os.Open(sourcePath)
	if err != nil {
		return PutResult{}, err
	}
	defer f.Close()
	return v.putReader(f, virtualPath, info.Size(), uint32(info.Mode().Perm()), info.ModTime(), idx)
}

func (v *Vault) PutReader(r io.Reader, virtualPath string, size int64, mode uint32, modTime time.Time) (PutResult, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return PutResult{}, err
	}
	vp, err := CleanVirtualPath(virtualPath)
	if err != nil {
		return PutResult{}, err
	}
	if vp == "" {
		return PutResult{}, errors.New("virtual file path must not be empty")
	}
	res, err := v.putReader(r, vp, size, mode, modTime, &idx)
	if err != nil {
		return PutResult{}, err
	}
	if v.usesManifestStore() {
		return res, v.saveFileManifest(vp, idx.Files[vp])
	}
	return res, v.SaveIndex(idx)
}

func (v *Vault) putReader(r io.Reader, virtualPath string, size int64, mode uint32, modTime time.Time, idx *Index) (PutResult, error) {
	var refs []ChunkRef
	newCount := 0
	var total int64
	err := ForEachChunk(r, v.Config.Chunk, func(chunk []byte) error {
		total += int64(len(chunk))
		ref, created, err := v.storeChunk(chunk)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
		if created {
			newCount++
		}
		return nil
	})
	if err != nil {
		return PutResult{}, err
	}
	if modTime.IsZero() {
		modTime = time.Now().UTC()
	}
	if mode == 0 {
		mode = 0o600
	}
	if size < 0 {
		size = total
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	generation := unixNanoOrNow(now)
	if old, ok := idx.Files[virtualPath]; ok && old.Generation >= generation {
		generation = old.Generation + 1
	}
	idx.Files[virtualPath] = FileRecord{Size: size, Mode: mode, ModTime: modTime.UTC().Format(time.RFC3339Nano), UpdatedAt: now, Generation: generation, Chunks: refs}
	return PutResult{Path: virtualPath, Size: size, ChunkCount: len(refs), NewChunkCount: newCount}, nil
}

func (v *Vault) storeChunk(plaintext []byte) (ChunkRef, bool, error) {
	id := hmacHex(v.keys.IndexKey, plaintext)
	ref := ChunkRef{ID: id, Size: len(plaintext)}
	objectPath := v.chunkPath(id)
	if _, err := os.Stat(objectPath); err == nil {
		return ref, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ChunkRef{}, false, err
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		return ChunkRef{}, false, err
	}
	nonce, err := randomBytes(v.chunkAEAD.NonceSize())
	if err != nil {
		return ChunkRef{}, false, err
	}
	aad := []byte(chunkAADPrefix + id)
	ct := v.chunkAEAD.Seal(nil, nonce, plaintext, aad)
	if err := atomicWriteFile(objectPath, encodeEncrypted(chunkMagic, nonce, ct), 0o600); err != nil {
		return ChunkRef{}, false, err
	}
	return ref, true, nil
}

func (v *Vault) GetPath(virtualPath string, destPath string) error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	vp, err := CleanVirtualPath(virtualPath)
	if err != nil {
		return err
	}
	if rec, ok := idx.Files[vp]; ok {
		return v.restoreFile(rec, destPath)
	}
	prefix := vp
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var matches []string
	for p := range idx.Files {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	sort.Strings(matches)
	for _, p := range matches {
		rel := p
		if prefix != "" {
			rel = strings.TrimPrefix(p, prefix)
		}
		target := filepath.Join(destPath, filepath.FromSlash(rel))
		if err := v.restoreFile(idx.Files[p], target); err != nil {
			return fmt.Errorf("restore %s: %w", p, err)
		}
	}
	return nil
}

func (v *Vault) restoreFile(rec FileRecord, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".seavault-restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	var writeErr error
	defer func() {
		tmp.Close()
		if writeErr != nil {
			os.Remove(tmpName)
		}
	}()
	for _, ref := range rec.Chunks {
		chunk, err := v.loadChunk(ref)
		if err != nil {
			writeErr = err
			return err
		}
		if _, err := tmp.Write(chunk); err != nil {
			writeErr = err
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	mode := os.FileMode(rec.Mode)
	if mode == 0 {
		mode = 0o600
	}
	_ = os.Chmod(tmpName, mode)
	if rec.ModTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			_ = os.Chtimes(tmpName, t, t)
		}
	}
	return os.Rename(tmpName, destPath)
}

func (v *Vault) WriteFileTo(virtualPath string, w io.Writer) error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	vp, err := CleanVirtualPath(virtualPath)
	if err != nil {
		return err
	}
	rec, ok := idx.Files[vp]
	if !ok {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	for _, ref := range rec.Chunks {
		chunk, err := v.loadChunk(ref)
		if err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) loadChunk(ref ChunkRef) ([]byte, error) {
	data, err := os.ReadFile(v.chunkPath(ref.ID))
	if err != nil {
		return nil, err
	}
	nonce, ct, err := decodeEncrypted(chunkMagic, v.chunkAEAD.NonceSize(), data)
	if err != nil {
		return nil, err
	}
	pt, err := v.chunkAEAD.Open(nil, nonce, ct, []byte(chunkAADPrefix+ref.ID))
	if err != nil {
		return nil, fmt.Errorf("chunk %s decrypt/authenticate failed", ref.ID)
	}
	if len(pt) != ref.Size {
		return nil, fmt.Errorf("chunk %s size mismatch", ref.ID)
	}
	actual := hmacHex(v.keys.IndexKey, pt)
	if !constantTimeStringEqual(actual, ref.ID) {
		return nil, fmt.Errorf("chunk %s object ID mismatch", ref.ID)
	}
	return pt, nil
}

func (v *Vault) List() ([]string, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Vault) FileInfo(virtualPath string) (FileRecord, bool, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return FileRecord{}, false, err
	}
	vp, err := CleanVirtualPath(virtualPath)
	if err != nil {
		return FileRecord{}, false, err
	}
	rec, ok := idx.Files[vp]
	return rec, ok, nil
}

func (v *Vault) Files() (map[string]FileRecord, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	out := make(map[string]FileRecord, len(idx.Files))
	for k, rec := range idx.Files {
		rec.Chunks = append([]ChunkRef(nil), rec.Chunks...)
		out[k] = rec
	}
	return out, nil
}

func (v *Vault) Remove(virtualPath string) error {
	removed, err := v.RemovePath(virtualPath)
	if err != nil {
		return err
	}
	if removed == 0 {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	return nil
}

func (v *Vault) RemovePath(virtualPath string) (int, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return 0, err
	}
	vp, err := CleanVirtualPath(virtualPath)
	if err != nil {
		return 0, err
	}
	var targets []string
	if _, ok := idx.Files[vp]; ok {
		targets = append(targets, vp)
	} else {
		prefix := vp
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		for p := range idx.Files {
			if prefix == "" || strings.HasPrefix(p, prefix) {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		return 0, fmt.Errorf("virtual path %q not found", virtualPath)
	}
	generations := make(map[string]int64, len(targets))
	nowBase := time.Now().UTC().UnixNano()
	for i, p := range targets {
		generation := nowBase + int64(i)
		if rec, ok := idx.Files[p]; ok && rec.Generation >= generation {
			generation = rec.Generation + 1
		}
		generations[p] = generation
	}
	for _, p := range targets {
		delete(idx.Files, p)
	}
	if v.usesManifestStore() {
		for _, p := range targets {
			if err := v.saveTombstone(p, generations[p]); err != nil {
				return 0, err
			}
		}
		return len(targets), nil
	}
	return len(targets), v.SaveIndex(idx)
}

func (v *Vault) Verify() error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for _, ref := range idx.Files[p].Chunks {
			if _, err := v.loadChunk(ref); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
	}
	return nil
}

func (v *Vault) GarbageCollect() (removed int, err error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for _, rec := range idx.Files {
		for _, ref := range rec.Chunks {
			live[ref.ID] = true
		}
	}
	err = filepath.WalkDir(filepath.Join(v.MetaRoot, "objects", "chunks"), func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".chunk") {
			return nil
		}
		id := strings.TrimSuffix(name, ".chunk")
		if !live[id] {
			if err := os.Remove(p); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

func (v *Vault) Stats() (Stats, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return Stats{}, err
	}
	live := map[string]int{}
	var referencedBytes int64
	for _, rec := range idx.Files {
		for _, ref := range rec.Chunks {
			live[ref.ID] = ref.Size
			referencedBytes += int64(ref.Size)
		}
	}
	objects := 0
	_ = filepath.WalkDir(filepath.Join(v.MetaRoot, "objects", "chunks"), func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".chunk") {
			objects++
		}
		return nil
	})
	return Stats{Files: len(idx.Files), Referenced: len(live), Objects: objects, ReferencedMB: float64(referencedBytes) / 1024.0 / 1024.0}, nil
}

func (v *Vault) chunkPath(id string) string {
	prefix := id
	if len(prefix) > 2 {
		prefix = id[:2]
	}
	return filepath.Join(v.MetaRoot, "objects", "chunks", prefix, id+".chunk")
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func Copy(dst io.Writer, src io.Reader) (int64, error) { return io.Copy(dst, src) }
