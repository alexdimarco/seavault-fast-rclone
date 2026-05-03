package vault

import "time"

type Index struct {
	Version   int                   `json:"version"`
	UpdatedAt string                `json:"updatedAt"`
	Files     map[string]FileRecord `json:"files"`
}

type FileRecord struct {
	Size       int64      `json:"size"`
	Mode       uint32     `json:"mode"`
	ModTime    string     `json:"modTime"`
	UpdatedAt  string     `json:"updatedAt,omitempty"`
	Generation int64      `json:"generation,omitempty"`
	Chunks     []ChunkRef `json:"chunks"`
	ConflictOf string     `json:"conflictOf,omitempty"`
}

type ChunkRef struct {
	ID   string `json:"id"`
	Size int    `json:"size"`
}

func NewIndex() Index {
	return Index{Version: 2, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Files: map[string]FileRecord{}}
}
