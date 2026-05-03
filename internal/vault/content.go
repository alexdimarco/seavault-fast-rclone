package vault

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	ContentRootName     = "content"
	DirectoryMarkerName = ".seavault-dir"
)

// NormalizeContentPath maps user-visible paths into the protected content root.
// The empty path and "." select the content root. Paths already under content/
// are kept as-is; every other valid user path is prefixed with content/.
func NormalizeContentPath(input string) (string, error) {
	vp, err := CleanVirtualPath(input)
	if err != nil {
		return "", err
	}
	if vp == "" || vp == "." {
		return ContentRootName, nil
	}
	if containsReservedSegment(vp) {
		return "", fmt.Errorf("reserved virtual path %q is not allowed", input)
	}
	if vp == ContentRootName || strings.HasPrefix(vp, ContentRootName+"/") {
		return vp, nil
	}
	return path.Join(ContentRootName, vp), nil
}

func normalizeContentFilePath(input string) (string, error) {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if vp == "" || vp == ContentRootName || strings.HasSuffix(vp, "/") {
		return "", fmt.Errorf("virtual file path must be inside %s/", ContentRootName)
	}
	if IsDirectoryMarkerPath(vp) {
		return "", fmt.Errorf("reserved virtual path %q is not allowed", input)
	}
	return vp, nil
}

func normalizeContentDirPath(input string) (string, error) {
	vp, err := NormalizeContentPath(input)
	if err != nil {
		return "", err
	}
	if IsDirectoryMarkerPath(vp) {
		return "", fmt.Errorf("reserved virtual path %q is not allowed", input)
	}
	return vp, nil
}

func containsReservedSegment(vp string) bool {
	for _, seg := range strings.Split(vp, "/") {
		if seg == MetadataDirName || seg == DirectoryMarkerName {
			return true
		}
	}
	return false
}

func IsDirectoryMarkerPath(vp string) bool {
	vp = strings.Trim(vp, "/")
	return vp == DirectoryMarkerName || strings.HasSuffix(vp, "/"+DirectoryMarkerName)
}

func IsInternalVirtualPath(vp string) bool {
	if vp == "" {
		return false
	}
	if IsDirectoryMarkerPath(vp) {
		return true
	}
	return containsReservedSegment(vp)
}

func directoryMarkerPath(dir string) (string, error) {
	vp, err := normalizeContentDirPath(dir)
	if err != nil {
		return "", err
	}
	return path.Join(vp, DirectoryMarkerName), nil
}

func markerFileRecord() FileRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return FileRecord{Size: 0, Mode: 0o700, ModTime: now, UpdatedAt: now, Generation: unixNanoOrNow(now), Chunks: nil}
}

func visibleIndex(idx Index) Index {
	out := NewIndex()
	out.UpdatedAt = idx.UpdatedAt
	for p, rec := range idx.Files {
		if IsInternalVirtualPath(p) {
			continue
		}
		out.Files[p] = rec
	}
	return out
}
