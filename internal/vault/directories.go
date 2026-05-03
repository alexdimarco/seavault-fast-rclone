package vault

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// EnsureContentLayout creates the protected content/ workspace and migrates
// older vaults whose user files lived at the virtual root into content/.
// It is intentionally called by Open so older vaults are upgraded before any
// WebDAV, GUI, CLI, or sync operation can mutate them further.
func (v *Vault) EnsureContentLayout() error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	if idx.Files == nil {
		idx = NewIndex()
	}
	rootMarker := path.Join(ContentRootName, DirectoryMarkerName)
	hasRootMarker := false
	if _, ok := idx.Files[rootMarker]; ok {
		hasRootMarker = true
	}
	changed := false

	if !hasRootMarker {
		idx.Files[rootMarker] = markerFileRecord()
		changed = true
	}

	// Move pre-content user records into content/. Paths already under content/
	// are treated as new-layout records and are not double-prefixed. A legacy
	// file named exactly "content" is moved to content/content to free the
	// protected workspace directory name.
	paths := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, oldPath := range paths {
		if oldPath == rootMarker || IsInternalVirtualPath(oldPath) {
			continue
		}
		if strings.HasPrefix(oldPath, ContentRootName+"/") {
			continue
		}
		newPath := path.Join(ContentRootName, oldPath)
		if oldPath == ContentRootName {
			newPath = path.Join(ContentRootName, ContentRootName)
		}
		if _, exists := idx.Files[newPath]; exists {
			newPath = conflictPath(newPath, time.Now().UTC().Format(time.RFC3339Nano), oldPath)
		}
		rec := idx.Files[oldPath]
		idx.Files[newPath] = rec
		delete(idx.Files, oldPath)
		changed = true
	}

	if !changed {
		return nil
	}
	if v.usesManifestStore() {
		for p, rec := range idx.Files {
			if err := v.saveFileManifest(p, rec); err != nil {
				return err
			}
		}
		for _, oldPath := range paths {
			if oldPath == rootMarker || IsInternalVirtualPath(oldPath) || strings.HasPrefix(oldPath, ContentRootName+"/") {
				continue
			}
			if err := v.saveTombstone(oldPath, 0); err != nil {
				return err
			}
		}
		return nil
	}
	return v.SaveIndex(idx)
}

func (v *Vault) EnsureDirectory(virtualPath string) error {
	marker, err := directoryMarkerPath(virtualPath)
	if err != nil {
		return err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	if _, ok := idx.Files[marker]; ok {
		return nil
	}
	idx.Files[marker] = markerFileRecord()
	if v.usesManifestStore() {
		return v.saveFileManifest(marker, idx.Files[marker])
	}
	return v.SaveIndex(idx)
}

func (v *Vault) DirectoryExists(virtualPath string) (bool, error) {
	vp, err := normalizeContentDirPath(virtualPath)
	if err != nil {
		return false, err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return false, err
	}
	return directoryExistsInIndex(idx.Files, vp), nil
}

func directoryExistsInIndex(files map[string]FileRecord, vp string) bool {
	vp = strings.Trim(vp, "/")
	if vp == "" {
		return true
	}
	if _, ok := files[path.Join(vp, DirectoryMarkerName)]; ok {
		return true
	}
	prefix := strings.TrimSuffix(vp, "/") + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func normalizeMigratedPathForMessage(input string) string {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return fmt.Sprintf("%q", input)
	}
	return vp
}
