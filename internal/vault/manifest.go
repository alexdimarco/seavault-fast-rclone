package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ManifestDirName = "manifests"

type ManifestRecord struct {
	Version   int        `json:"version"`
	Path      string     `json:"path"`
	UpdatedAt string     `json:"updatedAt"`
	Deleted   bool       `json:"deleted,omitempty"`
	File      FileRecord `json:"file,omitempty"`
}

type manifestCandidate struct {
	Record ManifestRecord
	ID     string
	Name   string
	Source string
}

func (v *Vault) loadManifestIndex() (Index, bool, error) {
	root := filepath.Join(v.MetaRoot, ManifestDirName)
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return NewIndex(), false, nil
	} else if err != nil {
		return Index{}, false, err
	}

	var candidates []manifestCandidate
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.Contains(strings.ToLower(name), ".manifest") {
			return nil
		}
		id := manifestIDFromFileName(name)
		if id == "" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rec, err := v.decryptManifest(data, id)
		if err != nil {
			return fmt.Errorf("manifest %s: %w", p, err)
		}
		if rec.Path == "" {
			return nil
		}
		candidates = append(candidates, manifestCandidate{Record: rec, ID: id, Name: name, Source: p})
		return nil
	})
	if err != nil {
		return Index{}, false, err
	}
	if len(candidates) == 0 {
		return NewIndex(), false, nil
	}

	byPath := map[string][]manifestCandidate{}
	for _, c := range candidates {
		cleaned, err := CleanVirtualPath(c.Record.Path)
		if err != nil || cleaned == "" {
			continue
		}
		if expected := v.manifestID(cleaned); expected != c.ID {
			continue
		}
		c.Record.Path = cleaned
		byPath[cleaned] = append(byPath[cleaned], c)
	}

	idx := NewIndex()
	for p, list := range byPath {
		sort.SliceStable(list, func(i, j int) bool { return candidateCompare(list[i], list[j]) > 0 })
		winner := list[0]
		if !winner.Record.Deleted {
			rec := normalizeRecordMetadata(winner.Record.File, winner.Record.UpdatedAt)
			idx.Files[p] = rec
		}
		for i := 1; i < len(list); i++ {
			loser := list[i]

			if loser.Record.Deleted == winner.Record.Deleted && sameFileRecord(loser.Record.File, winner.Record.File) {
				_ = os.Remove(loser.Source)
				continue
			}

			if loser.Record.Deleted {
				_ = os.Remove(loser.Source)
				continue
			}

			if winner.Record.Deleted {
				winnerGen := winner.Record.File.Generation
				if winnerGen == 0 {
					winnerGen = unixNanoOrNow(winner.Record.UpdatedAt)
				}
				loserGen := loser.Record.File.Generation
				if loserGen == 0 {
					loserGen = unixNanoOrNow(loser.Record.UpdatedAt)
				}
				if loserGen < winnerGen {
					_ = os.Remove(loser.Source)
					continue
				}
			}

			conflict := conflictPath(p, loser.Record.UpdatedAt, loser.Name)
			rec := normalizeRecordMetadata(loser.Record.File, loser.Record.UpdatedAt)
			rec.ConflictOf = p
			idx.Files[conflict] = rec
			if err := v.saveFileManifest(conflict, rec); err == nil {
				_ = os.Remove(loser.Source)
			}
		}
	}
	idx.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return idx, true, nil
}

func manifestIDFromFileName(name string) string {
	lower := strings.ToLower(name)
	idx := strings.Index(lower, ".manifest")
	if idx <= 0 {
		return ""
	}
	prefix := name[:idx]
	if len(prefix) >= 64 && isHex(prefix[:64]) {
		return prefix[:64]
	}
	if isHex(prefix) {
		return prefix
	}
	return ""
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func normalizeRecordMetadata(rec FileRecord, updatedAt string) FileRecord {
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = updatedAt
	}
	if rec.Generation == 0 {
		rec.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	return rec
}

func candidateCompare(a, b manifestCandidate) int {
	ag, bg := a.Record.File.Generation, b.Record.File.Generation
	if a.Record.Deleted && ag == 0 {
		ag = unixNanoOrNow(a.Record.UpdatedAt)
	}
	if b.Record.Deleted && bg == 0 {
		bg = unixNanoOrNow(b.Record.UpdatedAt)
	}
	if ag != bg {
		if ag > bg {
			return 1
		}
		return -1
	}
	at, aerr := time.Parse(time.RFC3339Nano, a.Record.UpdatedAt)
	bt, berr := time.Parse(time.RFC3339Nano, b.Record.UpdatedAt)
	if aerr == nil && berr == nil && !at.Equal(bt) {
		if at.After(bt) {
			return 1
		}
		return -1
	}
	if a.Record.UpdatedAt != b.Record.UpdatedAt {
		if a.Record.UpdatedAt > b.Record.UpdatedAt {
			return 1
		}
		return -1
	}
	if a.Record.Deleted != b.Record.Deleted {
		if a.Record.Deleted {
			return 1
		}
		return -1
	}
	if a.ID > b.ID {
		return 1
	}
	if a.ID < b.ID {
		return -1
	}
	return 0
}

func conflictPath(original string, updatedAt string, sourceName string) string {
	stamp := updatedAt
	if t, err := time.Parse(time.RFC3339Nano, updatedAt); err == nil {
		stamp = t.UTC().Format("20060102T150405Z")
	}
	stamp = strings.NewReplacer(":", "", "/", "-", "\\", "-", ".", "-").Replace(stamp)
	seed := sha256.Sum256([]byte(sourceName + "\x00" + updatedAt))
	suffix := hex.EncodeToString(seed[:])[:12]
	dir, file := path.Split(original)
	if file == "" {
		file = "conflict"
	}
	return path.Join(strings.TrimSuffix(dir, "/"), file+".conflict-"+stamp+"-"+suffix)
}

func (v *Vault) saveIndexAsManifests(idx Index) error {
	for p, rec := range idx.Files {
		if rec.ConflictOf != "" {
			continue
		}
		if err := v.saveFileManifest(p, rec); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) saveFileManifest(virtualPath string, rec FileRecord) error {
	cleaned, err := CleanVirtualPath(virtualPath)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", virtualPath)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = now
	}
	if rec.Generation == 0 {
		rec.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	rec.ConflictOf = ""
	mr := ManifestRecord{Version: 1, Path: cleaned, UpdatedAt: rec.UpdatedAt, File: rec}
	return v.saveManifestRecord(mr)
}

func (v *Vault) saveTombstone(virtualPath string, generation int64) error {
	cleaned, err := CleanVirtualPath(virtualPath)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", virtualPath)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if generation <= 0 {
		generation = unixNanoOrNow(now)
	}
	rec := ManifestRecord{Version: 1, Path: cleaned, UpdatedAt: now, Deleted: true, File: FileRecord{UpdatedAt: now, Generation: generation}}
	return v.saveManifestRecord(rec)
}

func (v *Vault) saveManifestRecord(rec ManifestRecord) error {
	cleaned, err := CleanVirtualPath(rec.Path)
	if err != nil || cleaned == "" {
		return fmt.Errorf("invalid manifest path %q", rec.Path)
	}
	rec.Path = cleaned
	if rec.Version == 0 {
		rec.Version = 1
	}
	if rec.UpdatedAt == "" {
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.File.UpdatedAt == "" {
		rec.File.UpdatedAt = rec.UpdatedAt
	}
	if rec.File.Generation == 0 {
		rec.File.Generation = unixNanoOrNow(rec.UpdatedAt)
	}
	id := v.manifestID(cleaned)
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		return err
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(manifestAADPrefix+id))
	return atomicWriteFile(v.manifestPath(id), encodeEncrypted(manifestMagic, nonce, ct), 0o600)
}

func (v *Vault) decryptManifest(data []byte, id string) (ManifestRecord, error) {
	nonce, ct, err := decodeEncrypted(manifestMagic, v.indexAEAD.NonceSize(), data)
	if err != nil {
		return ManifestRecord{}, err
	}
	pt, err := v.indexAEAD.Open(nil, nonce, ct, []byte(manifestAADPrefix+id))
	if err != nil {
		return ManifestRecord{}, errors.New("manifest decrypt/authenticate failed")
	}
	var rec ManifestRecord
	if err := json.Unmarshal(pt, &rec); err != nil {
		return ManifestRecord{}, err
	}
	return rec, nil
}

func (v *Vault) manifestID(virtualPath string) string {
	return hmacHex(v.keys.IndexKey, []byte("manifest:"+virtualPath))
}

func (v *Vault) manifestPath(id string) string {
	prefix := id
	if len(prefix) > 2 {
		prefix = id[:2]
	}
	return filepath.Join(v.MetaRoot, ManifestDirName, prefix, id+".manifest")
}

func sameFileRecord(a, b FileRecord) bool {
	if a.Size != b.Size || len(a.Chunks) != len(b.Chunks) {
		return false
	}
	for i := range a.Chunks {
		if a.Chunks[i] != b.Chunks[i] {
			return false
		}
	}
	return true
}

func unixNanoOrNow(ts string) int64 {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UnixNano()
	}
	return time.Now().UTC().UnixNano()
}
